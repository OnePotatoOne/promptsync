#!/bin/sh
# Install the promptsync binary and a per-user service definition.
#
# Usage: ./install.sh [binary] [server|agent] [project-dir]
#   binary       path to the promptsync executable (default: ./promptsync)
#   role         server or agent (default: agent)
#   project-dir  where the personal config directory lives (default: $PWD)
#
# The config directory (project-dir/config) is created on first use and is
# git-ignored by this repository.
set -eu

BIN_SRC="${1:-./promptsync}"
ROLE="${2:-agent}"
PROJECT_DIR="${PROJECT_DIR:-${3:-$PWD}}"
BIN_DIR="${PROMPTSYNC_BIN_DIR:-$HOME/.local/bin}"
CONFIG_DIR="${PROMPTSYNC_CONFIG_DIR:-$PROJECT_DIR/config}"
BIN="$BIN_DIR/promptsync"

if [ ! -f "$BIN_SRC" ]; then
    echo "binary not found: $BIN_SRC" >&2
    exit 1
fi
case "$ROLE" in
    server|agent) ;;
    *) echo "role must be 'server' or 'agent'" >&2; exit 1 ;;
esac

mkdir -p "$BIN_DIR" "$CONFIG_DIR"
install -m 0755 "$BIN_SRC" "$BIN" 2>/dev/null || {
    cp "$BIN_SRC" "$BIN"
    chmod 0755 "$BIN"
}

# Create config.toml from templates/config.toml when the directory is empty.
"$BIN" --config-dir "$CONFIG_DIR" init >/dev/null 2>&1 || true

# Warn when the personal config directory would be picked up by git.
if [ -d "$PROJECT_DIR/.git" ] && command -v git >/dev/null 2>&1; then
    if ! git -C "$PROJECT_DIR" check-ignore -q "config/config.toml"; then
        echo "WARNING: $CONFIG_DIR is not ignored by $PROJECT_DIR/.gitignore" >&2
        echo "         add '/config/' to .gitignore before committing." >&2
    fi
fi

case "$(uname -s)" in
    Linux)
        UNIT_DIR="$HOME/.config/systemd/user"
        mkdir -p "$UNIT_DIR"
        src="$(dirname "$0")/systemd/promptsync-$ROLE.service.in"
        if [ -f "$src" ]; then
            sed -e "s#__BIN__#$BIN#g" \
                -e "s#__CONFIG_DIR__#$CONFIG_DIR#g" \
                -e "s#__PROJECT_DIR__#$PROJECT_DIR#g" \
                "$src" > "$UNIT_DIR/promptsync-$ROLE.service"
            echo "installed $UNIT_DIR/promptsync-$ROLE.service"
            echo "enable with: systemctl --user daemon-reload && systemctl --user enable --now promptsync-$ROLE"
        fi
        ;;
    Darwin)
        PLIST_DIR="$HOME/Library/LaunchAgents"
        LOG_DIR="$CONFIG_DIR/logs"
        mkdir -p "$PLIST_DIR" "$LOG_DIR"
        src="$(dirname "$0")/launchd/com.cindy.promptsync.$ROLE.plist"
        dst="$PLIST_DIR/com.cindy.promptsync.$ROLE.plist"
        if [ -f "$src" ]; then
            sed -e "s#__BIN__#$BIN#g" \
                -e "s#__CONFIG_DIR__#$CONFIG_DIR#g" \
                -e "s#__PROJECT_DIR__#$PROJECT_DIR#g" \
                -e "s#__LOG_DIR__#$LOG_DIR#g" "$src" > "$dst"
            echo "installed $dst"
            echo "load with: launchctl load -w $dst"
        fi
        ;;
    *)
        echo "unsupported platform for service installation; binary installed at $BIN" >&2
        ;;
esac

echo
echo "binary:      $BIN"
echo "config dir:  $CONFIG_DIR"
echo "next:        $BIN --config-dir \"$CONFIG_DIR\" status"
echo "             $BIN --config-dir \"$CONFIG_DIR\" $ROLE   # foreground test"
