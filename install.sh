#!/usr/bin/env bash
# Install diskaudit for yourself (default) or for everyone on the machine.
#
#   ./install.sh                  for your user: ~/.local/bin and your applications menu
#   sudo ./install.sh --system    for all users: /usr/local/bin and the system applications menu
#   ./install.sh --prefix DIR     into DIR/bin and DIR/share/applications (e.g. a shared lab folder)
#   ./install.sh --no-desktop     skip the "Disk Audit" menu entry
#   ./install.sh --uninstall      remove it (add the same --system or --prefix you installed with)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
prefix="$HOME/.local"
mode=install
desktop=1

usage() { sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --system) prefix=/usr/local ;;
    --prefix) [ $# -ge 2 ] || { echo "install.sh: --prefix needs a folder" >&2; exit 2; }; prefix="$2"; shift ;;
    --prefix=*) prefix="${1#*=}" ;;
    --no-desktop) desktop=0 ;;
    --uninstall) mode=uninstall ;;
    -h|--help) usage; exit 0 ;;
    *) echo "install.sh: unknown option $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

prefix="${prefix%/}"
bindir="$prefix/bin"
appdir="$prefix/share/applications"
bin="$bindir/diskaudit"
app="$appdir/diskaudit.desktop"

refresh_menu() {
  if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$appdir" 2>/dev/null || true
  fi
}

if [ "$mode" = uninstall ]; then
  rm -f "$bin" "$app"
  refresh_menu
  echo "Removed $bin and $app"
  echo "Scan history (~/.local/share/diskaudit) and reports (~/disk-audit) were left in place."
  exit 0
fi

# Use a Python 3.9+, preferring the system one so an active conda environment doesn't matter.
python=""
for cand in "${PYTHON:-}" /usr/bin/python3 "$(command -v python3 2>/dev/null || true)"; do
  [ -n "$cand" ] && [ -x "$cand" ] || continue
  if "$cand" -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
    python="$cand"
    break
  fi
done
if [ -z "$python" ]; then
  echo "install.sh: diskaudit needs Python 3.9 or newer. Point to one with PYTHON=/path/to/python3 ./install.sh" >&2
  exit 1
fi

mkdir -p "$bindir"
tmp="$(mktemp "$bindir/.diskaudit.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
{ echo "#!$python"; tail -n +2 "$here/src/diskaudit.py"; } > "$tmp"
chmod 755 "$tmp"
mv -f "$tmp" "$bin"
trap - EXIT
echo "Installed $bin (using $python)"

if [ "$desktop" = 1 ]; then
  mkdir -p "$appdir"
  sed "s|@BIN@|$bin|g" "$here/share/diskaudit.desktop.in" > "$app"
  chmod 644 "$app"
  refresh_menu
  echo "Installed $app (\"Disk Audit\" in the applications menu)"
fi

case ":$PATH:" in
  *":$bindir:"*) echo "Run it with: diskaudit" ;;
  *) echo "Note: $bindir is not on your PATH. Run it as $bin, or add this line to ~/.bashrc:"
     echo "  export PATH=\"$bindir:\$PATH\"" ;;
esac
