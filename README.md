# grep-cp

`grep-cp` (grep + MCP) is a read-only [MCP](https://modelcontextprotocol.io) server that you install
on a central log box (for example an rsyslog aggregator). It searches that box's rotated log tree
in-process, so AI clients such as Claude Code can look through production logs safely, quickly
and within fixed limits.

- **In-process search.** It uses the ripgrep library crates (SIMD literals, linear-time regex) and
  never runs a shell, so nothing can be injected.
- **Time-aware.** Hourly rotated filenames map to time buckets, so files outside the window are
  never opened. When the line timestamp format is configured, lines are also filtered by time,
  reads stop early once past the window, and the live file is binary-searched to the window start.
- **Handles rotation.** It reads gzip (including multi-member pigz output), zstd, uncompressed
  rotations (delaycompress), and live files that are truncated in place (copytruncate). Live files
  are never memory-mapped, and a file that shrinks mid-read produces a warning, not a crash.
- **Polite to a shared box.** All searches share one small worker pool sized to the CPU quota
  (`search_threads`). Requests take turns on it, each keeps only a few files in flight, and the
  server limits how many requests run at once. Directory scans and planning also run off the
  async threads, under that limit and the request deadline. Each request has a scan budget, an
  output budget and a deadline, and can be cancelled. The systemd unit runs the server niced,
  at low IO priority, with a CPU quota and memory limits.
- **Read-only and sandboxed.** Every path is confined to the log root. HTTPS is served directly
  with rustls (there is no plain HTTP), with optional client certificates (mTLS). Requests are
  rate-limited per client IP, output is redacted, and every call is audit-logged. There is no
  application-level login: access control is the network (see [Security model](#security-model)).

Paths, filename patterns, rotation rules, ID formats and service descriptions all come from a
config file, so nothing is specific to one environment.

## Tools

| Tool | Purpose |
|---|---|
| `server_info` | Box name, timezone, now, retention, bucket size, line parsing, ID decoders, limits |
| `list_services` | Service directories (unreadable ones flagged) with optional descriptions |
| `list_files` | A service's files: host, live/rotated, bucket interval, compression, size |
| `grep_logs` | Main search: literal or regex, time window, hosts, context, `order=first\|last` |
| `count_matches` | Counts only, `group_by = file \| host \| bucket \| minute` |
| `grep_by_id` | Decodes the time embedded in an ID, then runs a narrowly scoped literal search |
| `tail_live` | Last N lines of the live file(s), optionally filtered (never follows) |
| `read_context` | Lines around a hit (service + file + byte offset), without searching again |
| `locate` | Which services/hosts contain a literal, when the service is unknown |

Time inputs can be RFC3339 (`2026-06-02T10:00:00Z`), `YYYY-MM-DD HH:MM` in the box timezone,
`last: "30m"`, or `date` + `hours`. Patterns are literals unless `fixed_string: false`.

Typical flow: `list_services` or `locate` finds the service, `count_matches` finds the busy
period, `grep_logs` searches a narrow window, and `read_context` expands a hit.

## Expected layout

The config describes the layout, so it can vary. A typical rsyslog tree looks like this:

```
/var/log/remote/
  <service>/
    <host>.log                        # live, appended continuously (copytruncate)
    <host>.log.YYYY-MM-DD-HH-MM.gz    # rotated hourly
    <host>.log.YYYY-MM-DD-HH-MM       # newest rotation may be uncompressed (delaycompress)
```

See [`config.example.toml`](config.example.toml) for every option.

## Build

```bash
cargo build --release
# Static binary for the box (match the arch that `grep-cp doctor` reports):
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

## Install on the box

```bash
sudo deploy/install.sh --log-root /var/log/remote
```

The script creates the `grep-cp` system user, installs the binary to `/usr/local/bin`, and writes
`/etc/grep-cp/config.toml` from the example. It grants read ACLs on the log root, including default
ACLs so new hourly files stay readable, and installs the systemd unit. It keeps an existing config
and certificates. Then:

```bash
# TLS certificate and key (key must not be world-readable)
sudo cp cert.pem key.pem /etc/grep-cp/tls/
sudo chown root:grep-cp /etc/grep-cp/tls/*.pem && sudo chmod 0640 /etc/grep-cp/tls/key.pem

# Check the config against the real box: timezone, filename matches, line timestamps,
# rotation suffix semantics, file sizes, ACLs, certificate expiry
sudo -u grep-cp grep-cp doctor --config /etc/grep-cp/config.toml

sudo systemctl enable --now grep-cp
```

To pick up a renewed certificate without a restart, run `systemctl reload grep-cp` (SIGHUP). With
`reload = "watch"` (the default), certificate files are also picked up automatically when they
change.

**Restrict who can reach the port (default `8765`).** grep-cp has no login of its own: anyone who can
connect can search the logs. Firewall the port to your VPN or office ranges, put it behind a proxy
that authenticates, and/or require client certificates with `[server.tls] client_ca`.

## Connect a client

Over HTTPS (Claude Code):

```bash
claude mcp add --transport http logs-eu1 https://logbox.example.com:8765/mcp
```

Over SSH with stdio. SSH is the authentication and the server runs with your own permissions. Your
user must be able to read the config file, for example by being in the `grep-cp` group.

```bash
claude mcp add logs-eu1 -- ssh logbox grep-cp serve --stdio --config /etc/grep-cp/config.toml
```

Register each box as its own server (for example `logs-eu1`, `logs-us1`). Every result carries the
box name.

## CLI

```
grep-cp serve [--stdio | --http]    run the MCP server (transport defaults to the config)
grep-cp doctor                      check config assumptions against this box
grep-cp check-config                validate the config file
grep-cp plan --service S --last 2h  dry run: which files a search would scan
```

All commands take `--config PATH` (or `GREP_CP_CONFIG`, default `/etc/grep-cp/config.toml`). Logs go
to stderr; set `GREP_CP_LOG=debug` for more detail and `GREP_CP_LOG_FORMAT=json` for JSON.

## Security model

- **No application-level authentication.** Over HTTPS, anyone who can reach the port can use every
  tool. Access control is the network (firewall, VPN, or an authenticating reverse proxy) plus
  optional mTLS (`client_ca`). `doctor` and the server log warn when mTLS is off. Over stdio, SSH
  is the authentication.
- Runs as the dedicated `grep-cp` user and never as root. Unreadable service directories are
  reported as unreadable.
- No tool accepts a raw path. Paths are built from the root, a validated service name and a
  filename taken from a directory listing, and symlinks that point outside the root are ignored.
- There is no code path that writes, deletes or executes anything.
- Redaction rules (`[[redaction]]`) are applied to every returned line and field before output
  leaves the process. Redaction hides known secret formats; it is not access control. A caller who
  can search can still probe for a secret's existence with `count_matches`, so restrict access to
  the server itself.
- Log text is written by remote senders and is untrusted. The server instructions tell clients
  never to follow instructions found in log lines.
- The audit log records one event per call: caller (`https:<client-ip>` or `stdio:<user>`), tool, arguments (including the pattern),
  files, bytes, matches, elapsed time and outcome. Output is never logged.

## Development

```bash
cargo test            # unit tests + engine tests (compared against `rg -z -c`) + MCP end-to-end
cargo test --test e2e # rmcp client ↔ `grep-cp serve --stdio` against a generated log tree
```

## License

[MIT](LICENSE)
