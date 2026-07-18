package caddyipinfofree

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	ID_MODULE_HANDLER = "http.handlers.ipinfo-free"
)

// Let xcaddy know, there is something to do here
func init() {
	caddy.RegisterModule(IPInfoFreeHandler{})
	httpcaddyfile.RegisterHandlerDirective("ipinfo_free", parseCaddyfileHandler)
}

type MMDBResult = map[string]any

type IPInfoFreeHandler struct {
	Mode string `json:"mode,omitempty"`

	ctx   caddy.Context    `json:"-"`
	state *IPInfoFreeState `json:"-"`
}

// CaddyModule returns the Caddy module information
func (IPInfoFreeHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  ID_MODULE_HANDLER,
		New: func() caddy.Module { return new(IPInfoFreeHandler) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *IPInfoFreeHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Consume directive as we only have one anway
	d.Next()
	// Consume next argument optionally as mode
	d.Args(&m.Mode)
	// We don't expected more arguments
	if d.NextArg() {
		return d.ArgErr()
	}

	return nil
}

func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m IPInfoFreeHandler
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

func (m *IPInfoFreeHandler) Validate() error {
	return nil
}

func (m *IPInfoFreeHandler) Provision(ctx caddy.Context) error {
	// Extract the ipinfo free state that is provisioned globally
	app, err := ctx.App(ID_MODULE_STATE)
	if err != nil {
		return errors.New("failed to retrieve state")
	}
	m.state = app.(*IPInfoFreeState)
	// Remember the context of the provisioning
	m.ctx = ctx

	return nil
}

func (m *IPInfoFreeHandler) lookupIP(ip netip.Addr) (*MMDBResult, error) {
	// If there is an uninitialized ip, ignore lookup request
	if !ip.IsValid() {
		return nil, errors.New("IP cannot be nil for lookup")
	}
	// If there is no database, ignore lookup request
	if m.state.db == nil {
		return nil, errors.New("no database found")
	}
	// Allocate lookup record result
	var record MMDBResult
	// Query database by given ip
	err := m.state.db.Lookup(ip).Decode(&record)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// We only care about the first ip in the X-Forwarded-For header
func firstForwardedFor(header string) string {
	if comma := strings.IndexByte(header, ','); comma >= 0 {
		header = header[:comma]
	}
	return strings.TrimSpace(header)
}

func (m *IPInfoFreeHandler) getClientIP(r *http.Request) (netip.Addr, error) {
	// We handle the remote address as default fallback value
	ipCandidate, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	// Overwrite value depending on mode
	switch m.Mode {
	case "", "enabled", "true", "on", "1", "strict":
		// Keep remote address
	case "forwarded":
		// Read ip from official header
		if candidate := firstForwardedFor(r.Header.Get("X-Forwarded-For")); candidate != "" {
			ipCandidate = candidate
		}
	case "trusted":
		// Read ip from official header if it comes from a trusted proxy
		trustedProxy, _ := caddyhttp.GetVar(r.Context(), caddyhttp.TrustedProxyVarKey).(bool)
		if candidate := firstForwardedFor(r.Header.Get("X-Forwarded-For")); candidate != "" && trustedProxy {
			ipCandidate = candidate
		}
	default:
		// Get the caddy replacer and replace all placeholders within mode
		repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		if !ok {
			return netip.Addr{}, errors.New("caddy replacer missing from request context")
		}
		if newCandidate := repl.ReplaceAll(m.Mode, ""); newCandidate == "" {
			if m.state.ErrorOnInvalidIP {
				m.state.logger.Warn("ipinfo_free directive maps to an empty value, defaulting to remote address")
			}
		} else {
			ipCandidate = newCandidate
		}
	}

	return netip.ParseAddr(ipCandidate)
}

func (m IPInfoFreeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	switch m.Mode {
	case "disabled", "false", "off", "0":
		break
	case "", "enabled", "true", "on", "1", "strict", "forwarded", "trusted":
		fallthrough
	default:
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

		ip, err := m.getClientIP(r)

		var geoip *MMDBResult
		// Only lookup when we got an IP
		if err == nil {
			geoip, err = m.lookupIP(ip)
		}

		if err != nil {
			repl.Set("ipinfo_free.error", err.Error())

			// Make sure to be silent when invalid ip is presented and it is configured to be silent
			if m.state.ErrorOnInvalidIP {
				m.state.logger.Error(err.Error())
			}

			return next.ServeHTTP(w, r)
		}

		repl.Set("ipinfo_free.error", nil)
		repl.Set("ipinfo_free.ip", ip.String())

		for key, value := range *geoip {
			repl.Set("ipinfo_free."+key, value)
		}
	}

	return next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Module                = (*IPInfoFreeHandler)(nil)
	_ caddy.Provisioner           = (*IPInfoFreeHandler)(nil)
	_ caddy.Validator             = (*IPInfoFreeHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*IPInfoFreeHandler)(nil)
	_ caddyfile.Unmarshaler       = (*IPInfoFreeHandler)(nil)
)
