package caddyipinfofree

import (
	"errors"
	"net"
	"net/http"
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
	// Extract the ipinfo free state that is porivisioned globally
	app, err := ctx.App(ID_MODULE_STATE)
	if err != nil {
		return errors.New("failed to retrieve state")
	}
	m.state = app.(*IPInfoFreeState)
	// Rmember the context of the provisioning
	m.ctx = ctx

	return nil
}

// Definee struct for ipinfo database format (not all fields filled depending on database type)
type IPInfoRecord struct {
	Country       string `maxminddb:"country"`
	CountryName   string `maxminddb:"country_name"`
	Continent     string `maxminddb:"continent"`
	ContinentName string `maxminddb:"continent_name"`
	ASN           string `maxminddb:"asn"`
	ASName        string `maxminddb:"as_name"`
	ASDomain      string `maxminddb:"as_domain"`
}

func (m *IPInfoFreeHandler) lookupIP(ip net.IP) (*IPInfoRecord, error) {
	// If there is an empty ip, ignore lookup request
	if ip == nil {
		return nil, errors.New("IP cannot be nil for lookup")
	}
	// If there is no database, ignore lookup request
	if m.state.db == nil {
		return nil, errors.New("no database found")
	}
	// Allocate lookup record result
	var record IPInfoRecord
	// Query database by given ip
	err := m.state.db.Lookup(ip, &record)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

func (m *IPInfoFreeHandler) getClientIP(r *http.Request) net.IP {
	// We handle the remote address as default fallback value
	ipCandidate := strings.Split(r.RemoteAddr, ":")[0]
	// Overwrite value depending on mode
	switch m.Mode {
	case "":
	case "enabled":
	case "true":
	case "on":
	case "1":
	case "strict":
		break
	case "forwarded":
		// Read ip from official header
		if header := r.Header.Get("X-Forwarded-For"); header != "" {
			ipCandidate = header
		}
	case "trusted":
		// Read ip from official header if it comes from a trusted proxy
		trustedProxy := caddyhttp.GetVar(r.Context(), caddyhttp.TrustedProxyVarKey).(bool)
		if header := r.Header.Get("X-Forwarded-For"); header != "" && trustedProxy {
			ipCandidate = header
		}
	default:
		// Get the caddy replacer and replace all placeholders within mode
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		if newCandidate := repl.ReplaceAll(m.Mode, ""); newCandidate == "" {
			m.state.logger.Warn("ipinfo_free directive maps to an empty value, defaulting to remote address")
		} else {
			ipCandidate = newCandidate
		}
	}

	return net.ParseIP(ipCandidate)
}

func (m IPInfoFreeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	switch m.Mode {
	case "disabled", "false", "off", "0":
		break
	case "", "enabled", "true", "on", "1", "strict", "forwarded", "trusted":
		fallthrough
	default:
		ip := m.getClientIP(r)
		geoip, err := m.lookupIP(ip)
		if err == nil {
			repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

			repl.Set("ipinfo_free.ip", ip.String())
			repl.Set("ipinfo_free.country", geoip.Country)
			repl.Set("ipinfo_free.country_name", geoip.CountryName)
			repl.Set("ipinfo_free.continent", geoip.Continent)
			repl.Set("ipinfo_free.continent_name", geoip.ContinentName)
			repl.Set("ipinfo_free.asn", geoip.ASN)
			repl.Set("ipinfo_free.as_name", geoip.ASName)
			repl.Set("ipinfo_free.as_domain", geoip.ASDomain)
		} else {
			m.state.logger.Error(err.Error())
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
