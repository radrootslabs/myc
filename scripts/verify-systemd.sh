#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repository_root"

if [ "$(uname -s)" != Linux ]; then
  echo "systemd_qualification_unavailable: Linux is required" >&2
  exit 1
fi
if ! command -v systemd-analyze >/dev/null 2>&1; then
  echo "systemd_qualification_unavailable: systemd-analyze is required" >&2
  exit 1
fi

systemd_major=$(systemd-analyze --version | awk 'NR == 1 { print $2 }')
case "$systemd_major" in
  ''|*[!0-9]*)
    echo "systemd_qualification_invalid: cannot determine systemd version" >&2
    exit 1
    ;;
esac
if [ "$systemd_major" -lt 252 ]; then
  echo "systemd_qualification_invalid: systemd 252 or newer is required" >&2
  exit 1
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/myc-systemd.XXXXXX")
cleanup() {
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

sed 's|^ExecStart=/usr/bin/myc --profile service-host --instance %i run$|ExecStart=/bin/true|' \
  packaging/systemd/myc@.service >"$temporary_directory/myc@.service"
if [ "$(grep -c '^ExecStart=/bin/true$' "$temporary_directory/myc@.service")" -ne 1 ]; then
  echo "systemd_qualification_invalid: exact ExecStart was not admitted" >&2
  exit 1
fi

systemd-analyze verify "$temporary_directory/myc@.service"
systemd-analyze security --offline=yes --threshold=30 --no-pager \
  "$temporary_directory/myc@.service" >/dev/null

echo "systemd qualification ok: myc"
