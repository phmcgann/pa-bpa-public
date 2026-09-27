#!/usr/bin/env bash
# PA BPA Dashboard installer for macOS (also works on Linux).
#
# Install, or update to the latest release, by pasting this into Terminal:
#
#   curl -fsSL https://github.com/phmcgann/pa-bpa-public/releases/latest/download/install.sh | bash
#
# It needs Docker Desktop installed (see docs/INSTALL.md). It never asks questions.
# What it does:
#   1. Checks Docker is installed and running (starts Docker Desktop if it isn't).
#   2. Downloads this release's stack files into ~/pa-bpa.
#   3. First install only: creates a random admin password and database password, and
#      writes them to ~/pa-bpa/.env and ~/pa-bpa/pa-bpa-login.txt.
#   4. Downloads the images and starts the dashboard at http://localhost:8080.
#   5. Waits until it answers, then opens it in your browser.
# Running it again updates to the newest release and keeps your data and password.
#
# Optional settings (put them before "bash", e.g. `... | PA_BPA_PORT=9090 bash`):
#   PA_BPA_VERSION   a specific release such as v1.2.0 (default: the latest)
#   PA_BPA_DIR       where to install (default: ~/pa-bpa)
#   PA_BPA_PORT      the port on this computer (default: 8080; first install only)

set -euo pipefail

REPO="phmcgann/pa-bpa-public"
VERSION="${PA_BPA_VERSION:-latest}"
DIR="${PA_BPA_DIR:-$HOME/pa-bpa}"
PORT="${PA_BPA_PORT:-8080}"
CADDY_IMAGE="caddy:2.10-alpine"
if [ -n "${PA_BPA_BASE_URL:-}" ]; then
  BASE_URL="$PA_BPA_BASE_URL"            # testing or a mirror
elif [ "$VERSION" = "latest" ]; then
  BASE_URL="https://github.com/$REPO/releases/latest/download"
else
  BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
fi

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1;33m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32m✓\033[0m %s\n' "$*"; }
fail() { printf '\n\033[1;31mInstall stopped:\033[0m %s\n' "$*" >&2; exit 1; }

step "1/5  Checking Docker"
if ! command -v docker >/dev/null 2>&1; then
  fail "Docker isn't installed. Install Docker Desktop first (docs/INSTALL.md, step 1), open it once, then run this command again."
fi
if ! docker info >/dev/null 2>&1; then
  if [ "$(uname -s)" = "Darwin" ]; then
    echo "    Docker Desktop isn't running. Starting it..."
    open -a Docker || fail "couldn't start Docker Desktop. Open it from Applications, wait until it says it's running, then run this command again."
  else
    echo "    Waiting for the Docker service..."
  fi
  printf '    Waiting for Docker to be ready (up to 3 minutes) '
  for _ in $(seq 1 90); do
    if docker info >/dev/null 2>&1; then break; fi
    printf '.'; sleep 2
  done
  echo
  docker info >/dev/null 2>&1 || fail "Docker didn't become ready. Open Docker Desktop, wait until it says it's running, then run this command again."
fi
docker compose version >/dev/null 2>&1 || fail "this Docker has no 'docker compose'. Update Docker Desktop to the latest version, then run this command again."
ok "Docker is running ($(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'version unknown'))"

step "2/5  Downloading the release files"
mkdir -p "$DIR"
cd "$DIR"
for f in docker-compose.yml Caddyfile; do
  curl -fsSL --retry 3 -o "$f.download" "$BASE_URL/$f" \
    || fail "couldn't download $f from $BASE_URL. Check your internet connection and that the release exists."
  mv "$f.download" "$f"
done
ok "Saved to $DIR"

FRESH=0
PASSWORD=""
step "3/5  Settings"
if [ -f .env ]; then
  ok "Keeping your existing settings and password (.env)"
  PORT="$(sed -n 's/^HTTP_BIND=.*:\([0-9][0-9]*\)$/\1/p' .env | head -n 1)"
  PORT="${PORT:-8080}"
else
  if docker volume inspect pa-bpa_db_data >/dev/null 2>&1; then
    fail "this computer still has the database from an earlier install, but its settings file ($DIR/.env) is missing, so the new password couldn't open it.
  - To keep your old assessments: put your old .env file back into $DIR, then run this command again.
  - To start over and ERASE the old assessments, run this, then run the install command again:
      docker volume rm pa-bpa_db_data pa-bpa_caddy_data pa-bpa_caddy_config"
  fi
  FRESH=1
  port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
  if port_busy "$PORT"; then
    orig="$PORT"
    for p in $(seq $((PORT + 1)) $((PORT + 20))); do
      if ! port_busy "$p"; then PORT="$p"; break; fi
    done
    [ "$PORT" = "$orig" ] && fail "port $orig and the next 20 are in use. Run again with a free port: PA_BPA_PORT=9090"
    echo "    Port $orig is already in use on this computer, so using $PORT instead."
  fi
  gen() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1" || true; }
  PASSWORD="$(gen 20)"
  DB_PASSWORD="$(gen 32)"
  echo "    Creating the admin password hash (downloads a small helper image the first time)..."
  HASH="$(docker run --rm "$CADDY_IMAGE" caddy hash-password --plaintext "$PASSWORD" </dev/null | tr -d '\r\n')"
  case "$HASH" in \$2*) ;; *) fail "couldn't create the password hash (got: $HASH)";; esac
  umask 077
  cat > .env <<EOF
# PA BPA Dashboard settings. Created by the installer on $(date '+%Y-%m-%d %H:%M').
# Keep this file private: it holds the database password.

POSTGRES_USER=pabpa
POSTGRES_PASSWORD=$DB_PASSWORD
POSTGRES_DB=pabpa

# Where the dashboard listens. 127.0.0.1 means only this computer can open it.
HTTP_BIND=127.0.0.1:$PORT
HTTPS_BIND=127.0.0.1:$((PORT + 363))
SITE_ADDRESS=:80

# The login. The hash must stay in single quotes.
BASIC_AUTH_USER=admin
BASIC_AUTH_HASH='$HASH'

# Optional: Palo Alto Strata Cloud Manager BPA (docs/INSTALL.md, "Optional settings").
SCM_CLIENT_ID=
SCM_CLIENT_SECRET=
SCM_TSG_ID=

# PAN-OS security advisories feed. Set to off if this computer has no internet access.
PAN_ADVISORY_FEED=on
EOF
  cat > pa-bpa-login.txt <<EOF
PA BPA Dashboard login
Address:  http://localhost:$PORT
Username: admin
Password: $PASSWORD
EOF
  chmod 600 .env pa-bpa-login.txt
  ok "Created a random admin password (saved in $DIR/pa-bpa-login.txt)"
fi

step "4/5  Downloading and starting the dashboard (the first time takes a few minutes)"
if [ "${PA_BPA_SKIP_PULL:-0}" != "1" ]; then
  docker compose pull --quiet </dev/null || fail "couldn't download the images. Check your internet connection, then run this command again."
fi
docker compose up -d --remove-orphans </dev/null || fail "the dashboard didn't start. Run 'docker compose logs' in $DIR to see why."
ok "Containers started"

step "5/5  Waiting for the dashboard to answer"
URL="http://localhost:$PORT"
code=""
for _ in $(seq 1 90); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/health" || true)"
  [ "$code" = "401" ] || [ "$code" = "200" ] && break
  sleep 2
done
[ "$code" = "401" ] || [ "$code" = "200" ] || fail "the dashboard didn't answer at $URL after 3 minutes. Run 'docker compose ps' and 'docker compose logs' in $DIR to see why."
if [ -f pa-bpa-login.txt ]; then
  PW="$(sed -n 's/^Password: //p' pa-bpa-login.txt)"
  running="$(curl -s -u "admin:$PW" "http://127.0.0.1:$PORT/health" | sed -n 's/.*"version": *"\([^"]*\)".*/\1/p')"
  [ -n "$running" ] && ok "Running version $running"
fi
ok "The dashboard is up at $URL"

if [ "${PA_BPA_NO_BROWSER:-0}" != "1" ]; then
  if command -v open >/dev/null 2>&1; then open "$URL" || true
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" >/dev/null 2>&1 || true
  fi
fi

echo
bold "PA BPA Dashboard is ready: $URL"
if [ "$FRESH" = "1" ]; then
  echo
  bold "Log in with:"
  echo "    Username: admin"
  echo "    Password: $PASSWORD"
  echo "    (also saved in $DIR/pa-bpa-login.txt)"
fi
cat <<EOF

To update later, run the same install command again. Your data and password are kept.
To stop it:   cd "$DIR" && docker compose stop
To start it:  cd "$DIR" && docker compose start
EOF
