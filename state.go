package caddyipinfofree

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/go-co-op/gocron/v2"
	"github.com/oschwald/maxminddb-golang"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

const (
	DEFAULT_CRON = "10 16 * * *"

	CRON_NAME_UPDATE         = "update"
	CRON_NAME_INITIAL_UPDATE = "initial-update"

	ID_MODULE_STATE = "caddy.states.ipinfo-free"
)

// Let xcaddy know, there is something to do here
func init() {
	caddy.RegisterModule(IPInfoFreeState{})
	httpcaddyfile.RegisterGlobalOption("ipinfo_free_config", parseCaddyfileConfig)
}

// Define our module with optional json fields that can be stored by caddy
type IPInfoFreeState struct {
	Url              string `json:"url,omitempty"`
	Cron             string `json:"cron,omitempty"`
	Path             string `json:"path,omitempty"`
	ErrorOnInvalidIP bool   `json:"error_on_invalid_ip,omitempty"`

	logger    *zap.Logger       `json:"-"`
	ctx       caddy.Context     `json:"-"`
	scheduler gocron.Scheduler  `json:"-"`
	db        *maxminddb.Reader `json:"-"`
}

// CaddyModule returns the Caddy module information
func (IPInfoFreeState) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  ID_MODULE_STATE,
		New: func() caddy.Module { return new(IPInfoFreeState) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (m *IPInfoFreeState) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Consume directive as we only have one anyway
	d.Next()
	// Consume next token to determine block or direct url
	var possibleUrl string
	if d.Args(&possibleUrl) {
		// If not block, we don't expect more tokens after url
		if d.NextArg() {
			return d.ArgErr()
		}
		// If last token, remember value as url
		m.Url = possibleUrl
		return nil
	}
	// Iterate of remaining tokens to consume config block
	for d.Next() {
		var value string
		// Get current token value as key
		key := d.Val()
		// Consume left over arguments
		if !d.Args(&value) {
			fmt.Println(key)
			continue
		}
		// Consume all config keys we accept
		switch key {
		case "url":
			m.Url = value
		case "cron":
			m.Cron = value
		case "path":
			m.Path = value
		case "error_on_invalid_ip":
			{
				// Parse value with strconv
				val, err := strconv.ParseBool(value)
				if err != nil {
					return d.WrapErr(err)
				}
				m.ErrorOnInvalidIP = val
			}
		default:
			// If key not known, throw error
			return d.ArgErr()
		}
	}

	return nil
}

func parseCaddyfileConfig(d *caddyfile.Dispenser, _ any) (any, error) {
	// Initialize an empty module
	m := new(IPInfoFreeState)
	// Extract values from caddyfile
	err := m.UnmarshalCaddyfile(d)
	// Return new app from module with possible error
	return httpcaddyfile.App{
		Name:  ID_MODULE_STATE,
		Value: caddyconfig.JSON(m, nil),
	}, err
}

func validateIPInfoFreeUrl(givenUrl string) (*url.URL, error) {
	// Example or expected data url:
	// https://ipinfo.io/data/free/asn.mmdb?token=magicduck
	// New Lite Database Format:
	// https://ipinfo.io/data/ipinfo_lite.mmdb?token=magicduck

	u, err := url.Parse(givenUrl)
	if err != nil {
		return u, err
	}

	if u.Scheme != "https" {
		return u, errors.New("expected a https url")
	}

	if u.Hostname() != "ipinfo.io" {
		return u, errors.New("invalid ipinfo url hostname. expected ipinfo.io")
	}

	switch u.Path {
	case "/data/free/asn.mmdb", "/data/free/country.mmdb", "/data/free/country_asn.mmdb":
	case "/data/ipinfo_lite.mmdb":
	default:
		return u, errors.New("invalid ipinfo free dataset path")
	}

	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return u, err
	}

	if _, ok := q["token"]; !ok {
		return u, errors.New("expected a access token in the ipinfo url")
	}

	return u, nil
}

func (m *IPInfoFreeState) Validate() error {
	// Verify given ipinfo url
	if parsedUrl, err := validateIPInfoFreeUrl(m.Url); err != nil {
		return err
	} else {
		m.logger.Info("ipinfo configured to use", zap.String("database_type", path.Base(parsedUrl.Path)))
	}

	// Verify crontab
	if _, err := cron.ParseStandard(m.Cron); err != nil {
		return err
	}

	return nil
}

// Structure to unmarshal response from https://ipinfo.io/data/free/country.mmdb/checksums?token=magicduck
type IPInfoFreeChecksumResponse struct {
	Checksums struct {
		MD5    string `json:"md5"`
		SHA1   string `json:"sha1"`
		SHA256 string `json:"sha256"`
	} `json:"checksums"`
}

func (m *IPInfoFreeState) getLatestDatabaseChecksums() (*IPInfoFreeChecksumResponse, error) {
	// Example: https://ipinfo.io/data/free/country.mmdb/checksums?token=magicduck

	// Parse data url to extract necessary parameters
	u, err := url.Parse(m.Url)
	if err != nil {
		return nil, err
	}

	// Parse query from data url
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, err
	}

	// Extract token query parameters
	token, ok := q["token"]
	if !ok {
		return nil, errors.New("expected a access token in the ipinfo url")
	}

	// Build new URL for checksum endpoint
	url := fmt.Sprintf("https://ipinfo.io/%s/checksums?token=%s", u.Path, token[0])

	// Request checksum endpoint
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	// Parse JSON response
	var checksums IPInfoFreeChecksumResponse

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&checksums)
	if err != nil {
		return nil, err
	}

	m.logger.Debug("current ipinfo checksums", zap.String("database_type", path.Base(u.Path)), zap.String("checksum_sha256", checksums.Checksums.SHA256))

	// Return latest checksums
	return &checksums, nil
}

func (m *IPInfoFreeState) getFilepath() string {
	u, err := url.Parse(m.Url)
	if err != nil {
		return path.Join(u.Path, "unknown.mmdb")
	}
	return path.Join(m.Path, path.Base(u.Path))
}

func (m *IPInfoFreeState) checkIfUpdateIsNecessary() (bool, *IPInfoFreeChecksumResponse, error) {
	// Request latest checksums published by ipinfo
	checksums, err := m.getLatestDatabaseChecksums()
	if err != nil {
		return false, checksums, err
	}

	// If file does not exist yet, update is necessary independent of checksums
	if _, err := os.Stat(m.getFilepath()); err != nil {
		return true, checksums, nil
	}

	// Generate checksum of currently stored database
	currentChecksum, err := generateSha256ForFile(m.getFilepath())

	// Compare checksums, if different, update is necessary
	if checksums.Checksums.SHA256 != currentChecksum {
		return true, checksums, err
	}

	// There is no other case that is possible which would require an database update
	return false, checksums, nil
}

func (m *IPInfoFreeState) runUpdate() error {
	// Check if import is necessary (if db nil and database file exists)
	if _, err := os.Stat(m.getFilepath()); m.db == nil && err == nil {
		// Open file and overwrite current instance if loaded ok
		// NOTE: No closing of old database necessary, as it is nil
		if newDb, err := maxminddb.Open(m.getFilepath()); err == nil {
			m.db = newDb
		}
	}

	// Check if downloading an update of the database is necessary
	isNecessary, newChecksums, err := m.checkIfUpdateIsNecessary()
	if err != nil {
		return err
	}

	if isNecessary {
		m.logger.Debug("new database available, starting download")

		// Request database
		resp, err := http.Get(m.Url)
		if err != nil {
			return errors.New("failed to connect to ipinfo")
		}

		// check response code
		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			return errors.New("too many requests for database download (limit: 10 per day per ip)")
		case http.StatusOK:
			break
		default:
			return errors.New("unexpected response from ipinfo")
		}

		// Rename current database
		databaseFilepath := m.getFilepath()
		os.Rename(databaseFilepath, databaseFilepath+".old")

		// Store new downloaded database
		f, err := os.Create(databaseFilepath)
		if err != nil {
			return err
		}
		defer f.Close()

		// Write response to file
		if _, err := io.Copy(f, resp.Body); err != nil {
			return err
		}

		// Verify checksum
		currentChecksum, err := generateSha256ForFile(databaseFilepath)
		if err != nil {
			return err
		}
		if currentChecksum != newChecksums.Checksums.SHA256 {
			return errors.New("newly downloaded database has checksum mismatch")
		}

		// Create new reader for new database file
		newDb, err := maxminddb.Open(databaseFilepath)
		if err != nil {
			return err
		}

		// Replace database instance with new one and close old one correctly
		oldDb := m.db
		m.db = newDb
		if oldDb != nil {
			oldDb.Close()
		}

		// Clean-up by deleting old database
		os.Remove(databaseFilepath + ".old")

		m.logger.Info("new database downloaded from ipinfo", zap.String("filepath", databaseFilepath), zap.String("checksum", currentChecksum))
	}

	return nil
}

func (m *IPInfoFreeState) Provision(ctx caddy.Context) error {
	// Remember logger and context
	m.logger = ctx.Logger()
	m.ctx = ctx
	// Fallback for contab value
	m.Cron = cmp.Or(m.Cron, DEFAULT_CRON)
	// Path fallback to random temporary path
	m.Path = cmp.Or(m.Path, path.Join(os.TempDir(), "caddy_ipinfo_free"))
	// Initialize scheduler
	if scheduler, err := gocron.NewScheduler(
		gocron.WithLocation(time.UTC),
		gocron.WithLogger(newZapGocronLogger(m.logger.Name(), m.logger)),
	); err != nil {
		return err
	} else {
		m.scheduler = scheduler
	}
	// Initialize update job
	if _, err := m.scheduler.NewJob(
		gocron.CronJob(m.Cron, false),
		gocron.NewTask(
			errorToLogsWrapper(m.logger, m.runUpdate),
		),
		gocron.WithName(CRON_NAME_UPDATE),
	); err != nil {
		return err
	}
	// Initialize initial update run
	if _, err := m.scheduler.NewJob(
		gocron.OneTimeJob(
			gocron.OneTimeJobStartImmediately(),
		),
		gocron.NewTask(
			errorToLogsWrapper(m.logger, m.runUpdate),
		),
		gocron.WithName(CRON_NAME_INITIAL_UPDATE),
	); err != nil {
		return err
	}
	// Make sure target path exists
	if err := os.MkdirAll(m.Path, os.FileMode(0744)); err != nil {
		return err
	}

	return nil
}

func (m *IPInfoFreeState) Start() error {
	// Start scheduler
	m.scheduler.Start()
	return nil
}

func (m *IPInfoFreeState) Stop() error {
	// Stop scheduler and currently running jobs
	m.scheduler.StopJobs()
	return nil
}

func (m *IPInfoFreeState) Cleanup() error {
	// Cleanup the scheduler
	if err := m.scheduler.Shutdown(); err != nil {
		return err
	}
	// Ensure there is a database to cleanup
	if m.db != nil {
		// Close database for cleanup
		if err := m.db.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Module          = (*IPInfoFreeState)(nil)
	_ caddy.Provisioner     = (*IPInfoFreeState)(nil)
	_ caddy.CleanerUpper    = (*IPInfoFreeState)(nil)
	_ caddy.Validator       = (*IPInfoFreeState)(nil)
	_ caddyfile.Unmarshaler = (*IPInfoFreeState)(nil)
)
