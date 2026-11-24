#!/usr/bin/env bash
# Installs grepcp on a log box: system user, binary, config skeleton, read ACLs on the log root,
# and the systemd unit. Idempotent: an existing config and certificates are kept.
#
# Usage (as root, from the repo or a release bundle):
#   deploy/install.sh [--binary PATH] [--log-root PATH] [--no-acl] [--include-private] [--no-systemd]
#
# Service dirs with no group/other access (e.g. root:root 0700) are treated as deliberately private
# and left alone (grepcp reports them as unreadable) unless --include-private is given.
set -euo pipefail

BINARY=""
LOG_ROOT="/var/log/remote"
DO_ACL=1
INCLUDE_PRIVATE=0
DO_SYSTEMD=1
USER_NAME="grepcp"
ETC="/etc/grepcp"
BIN_DST="/usr/local/bin/grepcp"
UNIT_DST="/etc/systemd/system/grepcp.service"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "==> $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)     BINARY="${2:?--binary needs a path}"; shift 2 ;;
    --log-root)   LOG_ROOT="${2:?--log-root needs a path}"; shift 2 ;;
    --no-acl)     DO_ACL=0; shift ;;
    --include-private) INCLUDE_PRIVATE=1; shift ;;
    --no-systemd) DO_SYSTEMD=0; shift ;;
    -h|--help)    sed -n '2,10p' "$0"; exit 0 ;;
    *)            die "unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root"
[[ "$LOG_ROOT" == /* ]] || die "--log-root must be an absolute path"
[[ -d "$LOG_ROOT" ]] || die "log root $LOG_ROOT does not exist"

if [[ -z "$BINARY" ]]; then
  arch="$(uname -m)"
  for cand in \
    "$REPO/target/$arch-unknown-linux-musl/release/grepcp" \
    "$REPO/target/release/grepcp" \
    "$HERE/grepcp" \
    "$REPO/grepcp"; do
    if [[ -x "$cand" ]]; then BINARY="$cand"; break; fi
  done
fi
[[ -n "$BINARY" && -x "$BINARY" ]] || die "no grepcp binary found; build it or pass --binary PATH"

# 1. System user (no login, no home).
if id -u "$USER_NAME" >/dev/null 2>&1; then
  say "user $USER_NAME exists"
else
  say "creating system user $USER_NAME"
  nologin="$(command -v nologin || echo /usr/sbin/nologin)"
  useradd --system --no-create-home --home-dir /nonexistent --shell "$nologin" "$USER_NAME"
fi

# 2. Binary.
say "installing $BINARY -> $BIN_DST"
install -o root -g root -m 0755 "$BINARY" "$BIN_DST"

# 3. Config dir, config skeleton, TLS dir.
install -d -o root -g "$USER_NAME" -m 0750 "$ETC" "$ETC/tls"
if [[ -f "$ETC/config.toml" ]]; then
  say "keeping existing $ETC/config.toml"
else
  [[ -f "$REPO/config.example.toml" ]] || die "config.example.toml not found next to the repo"
  say "writing $ETC/config.toml from config.example.toml (root = $LOG_ROOT)"
  sed "s|^root = \".*\"|root = \"$LOG_ROOT\"|" "$REPO/config.example.toml" > "$ETC/config.toml"
  chown root:"$USER_NAME" "$ETC/config.toml"
  chmod 0640 "$ETC/config.toml"
fi

# 4. Read access to the log root. Default ACLs make new hourly files readable too.
if [[ $DO_ACL -eq 1 ]]; then
  command -v setfacl >/dev/null || die "setfacl not found (install the 'acl' package) or pass --no-acl"
  say "granting $USER_NAME read access to $LOG_ROOT (ACLs, recursive + default)"
  # The root itself: traverse/list, and a default ACL so new service dirs are readable.
  setfacl -m "g:$USER_NAME:rX" -m "d:g:$USER_NAME:rX" "$LOG_ROOT"
  granted=0
  skipped=()
  for dir in "$LOG_ROOT"/*/; do
    [[ -d "$dir" ]] || continue
    dir="${dir%/}"
    mode="$(stat -c '%a' "$dir")"
    if [[ $INCLUDE_PRIVATE -eq 0 && $(( 8#$mode & 8#077 )) -eq 0 ]]; then
      skipped+=("$(basename "$dir") ($mode)")
      continue
    fi
    setfacl -R -m "g:$USER_NAME:rX" "$dir"
    find "$dir" -type d -exec setfacl -m "d:g:$USER_NAME:rX" {} +
    granted=$((granted + 1))
  done
  say "read access granted on $granted service dirs"
  if [[ ${#skipped[@]} -gt 0 ]]; then
    say "left private (no group/other access): ${skipped[*]}"
    say "  rerun with --include-private to grant those too"
  fi
else
  say "skipping ACLs (--no-acl): make sure $USER_NAME can read $LOG_ROOT another way"
fi

# 5. systemd unit.
if [[ $DO_SYSTEMD -eq 1 ]]; then
  command -v systemctl >/dev/null || die "systemctl not found; pass --no-systemd"
  say "installing $UNIT_DST"
  sed "s|^ReadOnlyPaths=/var/log/remote$|ReadOnlyPaths=$LOG_ROOT|" "$HERE/grepcp.service" > "$UNIT_DST"
  chmod 0644 "$UNIT_DST"
  systemctl daemon-reload
fi

cat <<EOF

grepcp installed. Next steps:
  1. Put the TLS certificate (full chain) and key in $ETC/tls/cert.pem and $ETC/tls/key.pem:
       chown root:$USER_NAME $ETC/tls/*.pem && chmod 0640 $ETC/tls/key.pem
  2. Restrict who can reach the port (default 8765): there is no application-level authentication.
     Firewall it to your VPN/office ranges, put it behind an authenticating proxy, and/or require
     client certificates with [server.tls] client_ca.
  3. Edit $ETC/config.toml (box_name, timezone, file_regex, [line], services).
  4. Check assumptions on this box:
       sudo -u $USER_NAME $BIN_DST doctor --config $ETC/config.toml
  5. Start:
       systemctl enable --now grepcp && journalctl -u grepcp -f
EOF
