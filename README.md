<p align="center">
	<picture>
		<source media="(prefers-color-scheme: dark)" srcset="https://user-images.githubusercontent.com/1128849/210187358-e2c39003-9a5e-4dd5-a783-6deb6483ee72.svg">
		<source media="(prefers-color-scheme: light)" srcset="https://user-images.githubusercontent.com/1128849/210187356-dfb7f1c5-ac2e-43aa-bb23-fc014280ae1f.svg">
		<img src="https://user-images.githubusercontent.com/1128849/210187356-dfb7f1c5-ac2e-43aa-bb23-fc014280ae1f.svg" alt="Caddy" width="200">
	</picture>
    &nbsp;&nbsp;&nbsp;&nbsp;
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://github.com/oltdaniel/caddy-ipinfo-free/assets/53529846/10bb1c41-f738-440f-8bb1-7be970fc7826">
		<source media="(prefers-color-scheme: light)" srcset="https://github.com/oltdaniel/caddy-ipinfo-free/assets/53529846/42055591-fad7-4bae-8ee8-1632e52bd3c4">
		<img src="https://github.com/oltdaniel/caddy-ipinfo-free/assets/53529846/42055591-fad7-4bae-8ee8-1632e52bd3c4" alt="IPInfo" width="200">
	</picture>
	<br>
	<h3 align="center">Caddy x IPInfo</h3>
</p>

> This project does not affiliate with Caddy nor IPInfo. It only extends Caddy with custom code to integrate the free databases provided by IPInfo into Caddy. Logo Copyright belongs to the corresponding project.

# Caddy IPInfo free

Easy country and ASN lookup by IP with the free IPInfo database.

> This module is still in development. Breaking changes will likely come. No stability checks yet.

## Example

```
{
    # Required as a third-party handler
    order ipinfo_free first
    # Configure module
    ipinfo_free_config {
        url https://ipinfo.io/data/free/country.mmdb?token=magicduck
        cron "10 16 * * *"
        path /tmp/caddy_ipinfo
    }
}

:8080 {
    ipinfo_free "{http.request.uri.query.ip}"

    header Content-Type text/plain
    respond <<TEXT
    IP: {ipinfo_free.ip}
                
    Country: {ipinfo_free.country_name} ({ipinfo_free.country})
    Continent: {ipinfo_free.continent_name} ({ipinfo_free.continent})
    ASN: {ipinfo_free.asn} {ipinfo_free.as_name} {ipinfo_free.as_domain}
    TEXT 200
}
```

```bash
$ curl "http://localhost:8080/?ip=1.1.1.1"
IP: 1.1.1.1
            
Country: Australia (AU)
Continent: Oceania (OC)
ASN: AS13335 Cloudflare, Inc. cloudflare.com
```

## Why?

IPInfo distributes their country and ASN databases for free every 24h with full accuracy. With this module and a few lines of config in your `Caddyfile`, you can query the database anywhere with anything.

## Usage

Build a custom binary with this module enabled.

```bash
CADDY_VERSION=master xcaddy build --with github.com/oltdaniel/caddy-ipinfo-free
./caddy run
```

## Directives

### `ipinfo_free_config` (global)

#### Examples
```
ipinfo_free_config https://ipinfo.io/data/free/country.mmdb?token=magicduck

ipinfo_free_config {
    url https://ipinfo.io/data/free/country.mmdb?token=magicduck
    cron "10 16 * * *"
    path /tmp/caddy_ipinfo
}
```

#### Values

| Name | Values | Description |
|-|-|-|
| `url` | valid ipinfo free database url | This url can be easily found in the [Dashboard](https://ipinfo.io/account/data-downloads) of IPInfo after creating an account. Simply choose a database of your choice in the MMDB format and paste the url here. |
| `cron` | valid crontab notation<br><br>Default: `10 16 * * *` | Customize how often you want to check for a new database. The official time is published by IPInfo in their FAQ [here](https://ipinfo.io/faq/article/141-when-do-the-updates-happen). Timezone is UTC. |
| `path` | valid path to store the database<br><br>Default: [`os.TempDir()`](https://pkg.go.dev/os#TempDir) with directory `caddy_ipinfo_free` | This will be the path where the databases are stored after download. As there are different kinds of databases, we only accept a path and not a specific filename. Each database will be stored here by their corresponding names from the configured url.<br><br>If the configured path does not exist, the directories will be created. If not path is given, a temporary directory will be created in the systems temporary directory with the name `caddy_ipinfo_free`. |

### `ipinfo_free` (handler)

#### Examples

```
ipinfo_free
ipinfo_free 1
ipinfo_free on
ipinfo_free true
ipinfo_free enabled
ipinfo_free forwarded
ipinfo_free trusted
ipinfo_free "{http.request.uri.query.ip}"
```

| Values | Description |
|-|-|
| `disabled`, `false`, `off`, `0` | Explicit disabling of looking up ip information. |
| `enabled`, `true`, `on`, `1`, `strict`, empty | The remote address of the request will be used to lookup the ip information. |
| `forwarded` | Use the IP set in the `X-Forwarded-For` Header if present, else it will fallback to the remote address of the request. |
| `trusted` | Same as `forwarded` but it will make sure that the ip from which the request comes is listed as a trusted proxy in the current caddy environment. |
| any value that is an IPv4 or IPv6 | The mode field supportes the [Caddy placeholders ](https://caddyserver.com/docs/json/apps/http/#docs) which allows you to fully customize the IP that is used for lookup.<br><br>**NOTE**: If the value maps to an empty string, the remote address of the client will be used as a fallback. |

## Placeholder Variables

| Variable | Example |
|-|-|
| `ipinfo_free.ip` | `1.1.1.1` |
| `ipinfo_free.country` | `AU` |
| `ipinfo_free.country_name` | `Australia` |
| `ipinfo_free.continent` | `OC` |
| `ipinfo_free.continent_name`| `Oceania` |
| `ipinfo_free.asn` | `AS13335` |
| `ipinfo_free.as_name` | `Cloudflare, Inc.` | 
| `ipinfo_free.as_domain` | `cloudflare.com` |

## Advanced Examples

> Just replace the body of the server from the Caddyfile example on top.

### Change Response for Countries

This is a simple example on how the response can be changed for certain countries.

```
ipinfo_free

header Content-Type text/plain

@dach expression ({ipinfo_free.country} in ["DE", "CH", "AT"])

respond @dach "Hallo Besucher aus der DACH-Region!"
respond "Hello visistor from {ipinfo_free.country_name}"
```

### Simple GeoIP API

Simply query with `http://localhost:8080/?ip=IP`.

```
ipinfo_free "{http.request.uri.query.ip}"

header Content-Type text/plain
respond <<TEXT
IP: {ipinfo_free.ip}
            
Country: {ipinfo_free.country_name} ({ipinfo_free.country})
Continent: {ipinfo_free.continent_name} ({ipinfo_free.continent})
ASN: {ipinfo_free.asn} {ipinfo_free.as_name} {ipinfo_free.as_domain}
TEXT 200
```

### More?

Do you have a neat way of using this library in your Caddyfile? Feel free to submit it.

## Internals

This module will automatically update the database from ipinfo and store it in the configured path. You can freely configure the `cron` option to update the database in a timely manner of your choosing. However, the most frequent update rate that should be used is hourly as the database will only be updated by IPInfo every 24 hours.

### Resources

- [IPInfo Database Download rate limits](https://community.ipinfo.io/t/announcement-we-are-adding-rate-limits-to-data-downloads/358)
- [IPInfo Update Schedule](https://ipinfo.io/faq/article/141-when-do-the-updates-happen)
- [Caddy order option](https://caddyserver.com/docs/caddyfile/options#order)

## Development

Clone, create example config and run with xcaddy.

```bash
git clone https://github.com/oltdaniel/caddy-ipinfo-free.git
cd caddy-ipinfo-free

CADDY_VERSION=master xcaddy run
# or
CADDY_VERSION=master xcaddy build --with github.com/oltdaniel/caddy-ipinfo-free=.
./caddy run
```

## License

<p>IP address data powered by <a href="https://ipinfo.io">IPinfo</a></p>

[MIT License](./LICENSE)
