#!/usr/bin/env bash
# Download the public project; all interactive input is read from /dev/tty.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo 'Запустите команду через sudo bash.' >&2
  exit 1
fi
if ! command -v apt-get >/dev/null || ! command -v systemctl >/dev/null; then
  echo 'Нужен Ubuntu 24.04 или Debian 12 с systemd.' >&2
  exit 1
fi
if [ ! -r /dev/tty ]; then
  echo 'Запустите установку из интерактивного SSH-терминала.' >&2
  exit 1
fi
if [ -f /etc/am-portal/config.json ]; then
  echo 'AM Portal уже установлен. Обновление описано в README; данные не изменены.' >&2
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=l
apt-get update
apt-get install -y ca-certificates curl python3 tar
workdir="$(mktemp -d /tmp/am-portal-install.XXXXXXXX)"
trap 'rm -rf -- "$workdir"' EXIT
curl --fail --silent --show-error --location --retry 3 \
  https://github.com/Ma33x/am-portal/archive/refs/heads/main.tar.gz \
  --output "$workdir/source.tar.gz"
tar -xzf "$workdir/source.tar.gz" --directory "$workdir"
python3 "$workdir/am-portal-main/install.py" </dev/tty
