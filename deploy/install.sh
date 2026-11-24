#!/usr/bin/env bash
# Installs or removes honet as a systemd service. Run as root:
#   sudo ./install.sh            install / upgrade
#   sudo ./install.sh --uninstall
# Expects honet-linux-<arch> (and optionally honet.service) next to this script.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bin=/usr/local/bin/honet
unit=/etc/systemd/system/honet.service

if [[ $EUID -ne 0 ]]; then
	echo "Please run as root: sudo $0 $*" >&2
	exit 1
fi

if [[ "${1:-}" == "--uninstall" ]]; then
	systemctl disable --now honet 2>/dev/null || true
	rm -f "$unit" "$bin"
	systemctl daemon-reload
	echo "honet removed. Your data is still in /var/lib/honet."
	echo "To delete it as well: sudo rm -rf /var/lib/honet && sudo userdel honet"
	exit 0
fi

case "$(uname -m)" in
	armv6l) arch=armv6 ;;
	armv7l) arch=armv7 ;;
	aarch64 | arm64) arch=arm64 ;;
	x86_64) arch=amd64 ;;
	*) echo "Unsupported machine: $(uname -m)" >&2; exit 1 ;;
esac

src="$here/honet-linux-$arch"
if [[ ! -f "$src" ]]; then
	echo "Missing $src — copy dist/honet-linux-$arch next to this script." >&2
	exit 1
fi

unit_src="$here/systemd/honet.service"
[[ -f "$unit_src" ]] || unit_src="$here/honet.service"
if [[ ! -f "$unit_src" ]]; then
	echo "Missing honet.service next to this script." >&2
	exit 1
fi

if ! id honet >/dev/null 2>&1; then
	useradd --system --no-create-home --shell /usr/sbin/nologin honet
fi

systemctl stop honet 2>/dev/null || true
install -m 0755 "$src" "$bin"
install -m 0644 "$unit_src" "$unit"
systemctl daemon-reload
systemctl enable --now honet

echo "Waiting for honet to start..."
sleep 5
if ! systemctl is-active --quiet honet; then
	echo "honet did not start. Last log lines:" >&2
	journalctl -u honet -n 30 --no-pager >&2
	exit 1
fi

ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "honet is running: https://${ip:-<this-pi>}:8443"
echo "(The certificate is self-signed; your browser will warn once.)"
journalctl -u honet -n 50 --no-pager | grep -A2 "SETUP CODE" || echo "No setup code in the log: an admin account already exists."
