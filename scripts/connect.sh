#!/usr/bin/env bash
# Connect to a booted ICH SSH ramdisk over USB. Recipe proven 2026-11-03 (iPhone12,5/A13).
#
# Two non-obvious facts this encodes:
#   1. usbmuxd's default preflight opens a lockdownd session on device port 62078; a ramdisk has
#      no lockdownd, preflight fails, and usbmuxd DROPS the device -> iproxy "No connected device
#      found". So usbmuxd must run with -p/--no-preflight.
#   2. dropbear/micro_inetd listens on device port 22 (NOT 2222; 2222 is dropbear's compiled
#      default string, not the live listener).
#
# Usage:
#   scripts/connect.sh                 # interactive root shell
#   scripts/connect.sh --demote        # demote production mode in DFU, THEN boot (see caveats below)
#   scripts/connect.sh 'mount_ich'     # run a command (NOTE: mount_ich may drop the session,
#                                      #   see the SEP caveat at the bottom)
# Env overrides: LPORT (host port, 2323), DPORT (device port, 22), PW (password, alpine),
#   DEMOTE (1 = same as --demote), USBLITER8CTL (path to the control tool).
#
# --demote: sends ONE control transfer (CUSTOM_DEMOTE) via usbliter8ctl from PWNED DFU, before
#   boot, so the booted OS reports a demoted AP and lets you write e.g. com.apple.System.boot-nonce
#   (production CPFM:03 otherwise returns "privilege violation"). Off by default ON PURPOSE: per
#   docs/design/BASEBAND_AND_CELLULAR.md the hardware demote's persistence and its effect on
#   SEP/AMFI/Secure Boot are UNVERIFIED on a CPFM:03 part, and a failed demote costs a re-pwn. It
#   must run in pwned DFU (05ac:1227); if the device is already booted it is skipped with a note.
set -u
LPORT="${LPORT:-2323}"; DPORT="${DPORT:-22}"; PW="${PW:-alpine}"
DEMOTE="${DEMOTE:-0}"
if [ "${1:-}" = "--demote" ]; then DEMOTE=1; shift; fi   # leading flag; rest of "$@" is still the remote cmd
log(){ printf '>> %s\n' "$*" >&2; }

start_usbmuxd(){
  # root + --no-preflight (default daemon drops to the usbmux user AND preflights -> won't hold a ramdisk)
  sudo sh -c 'pkill -x usbmuxd; sleep 1; /usr/sbin/usbmuxd -f -p >/tmp/umux.log 2>&1 &'
  sleep 2
}
start_iproxy(){
  pkill -f "iproxy $LPORT " 2>/dev/null
  ( iproxy "$LPORT" "$DPORT" >/tmp/iproxy.log 2>&1 & )
  sleep 2
}
do_ssh(){
  # ServerAlive* holds an idle session open through the usbmux relay and surfaces a real drop
  # in ~60s instead of a silent hang. It does NOT stop a device-side panic (nothing client-side can).
  local a=(ssh -p "$LPORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
           -o ConnectTimeout=8 -o ServerAliveInterval=15 -o ServerAliveCountMax=4
           -o TCPKeepAlive=yes root@localhost "$@")
  if command -v sshpass >/dev/null 2>&1; then sshpass -p "$PW" "${a[@]}"; else "${a[@]}"; fi
}
demote_device(){
  # ONE control transfer (bmReqType 0x21, bReq 7 = CUSTOM_DEMOTE) to the pwned-DFU device. No
  # download, no reboot -> device STAYS in DFU (05ac:1227), so boot.sh runs right after. Needs
  # root for the raw ctrl_transfer; pyusb is in /usr system site-packages so sudo python3 sees it.
  local ctl="${USBLITER8CTL:-$ROOT_DIR/../usbliter8-src/usbliter8ctl}"
  if [ ! -x "$ctl" ]; then
    log "ERROR: usbliter8ctl not found/executable at '$ctl' (set USBLITER8CTL=/path/to/usbliter8ctl)"; exit 1
  fi
  log "DEMOTE: sending CUSTOM_DEMOTE from pwned DFU via '$ctl' (sudo/face-auth)"
  if sudo python3 "$ctl" demote; then
    log "DEMOTE: control transfer sent; device still in pwned DFU -> booting."
  else
    log "ERROR: demote failed. Device must be in PWNED DFU (irecovery -q => PWND:[usbliter8]). Re-pwn and retry."
    exit 1
  fi
}

# 1) make sure a ramdisk is booted (05ac:12a8). If the device is in pwned DFU (05ac:1227),
#    boot the known-good macOS chain first.
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CHAIN="${CHAIN:-d431ap-26.6.2-23G90-macos}"
if lsusb 2>/dev/null | grep -q "05ac:12a8"; then
  log "ramdisk already booted (05ac:12a8)"
  [ "$DEMOTE" = 1 ] && log "NOTE: --demote ignored; device is already booted. Demote runs only in DFU before boot -> re-pwn into DFU and re-run with --demote."
elif lsusb 2>/dev/null | grep -q "05ac:1227"; then
  [ "$DEMOTE" = 1 ] && demote_device
  log "device in DFU; booting chain '$CHAIN'"
  ( cd "$ROOT_DIR" && BOOTCHAIN_NAME="$CHAIN" ./boot.sh --no-logo )
  log "waiting for normal-mode USB (up to 60s)..."
  booted=0
  for _ in $(seq 30); do
    lsusb 2>/dev/null | grep -q "05ac:12a8" && { booted=1; break; }
    sleep 2
  done
  if [ "$booted" != 1 ]; then
    log "boot did NOT reach normal mode (no 05ac:12a8 after 60s); device likely in Recovery (05ac:1281)."
    log "re-pwn and retry, or check the chain."
    exit 1
  fi
  log "normal-mode USB up (05ac:12a8)"
else
  log "No Apple device in DFU or normal mode. Re-pwn into DFU (irecovery -q => PWND: usbliter8) and retry."
  exit 1
fi

# 2) usbmuxd with --no-preflight (start it if not already running that way)
pgrep -af 'usbmuxd .*-p' >/dev/null 2>&1 || { log "starting usbmuxd --no-preflight (sudo/face-auth)"; start_usbmuxd; }
# 3) iproxy host:LPORT -> device:DPORT
start_iproxy

# 4) connect; retry ONLY on a fast failure (never established). A session that lasted a few
#    seconds was real — exit with its status instead of auto-reconnecting (that caused a
#    face-auth/reconnect cascade every time a shell closed).
for i in 1 2 3 4 5; do
  log "connect attempt $i (host $LPORT -> device $DPORT)"
  t0=$(date +%s); do_ssh "$@"; rc=$?; t1=$(date +%s)
  if [ $((t1 - t0)) -ge 4 ]; then exit "$rc"; fi   # real session happened -> done
  log "failed fast ($((t1-t0))s, rc=$rc); re-grabbing device (fresh usbmuxd -p + iproxy)"
  start_usbmuxd; start_iproxy
done

log "Could not establish SSH after retries."
log "If usbmuxd shows no device (grep -i 'detected\\|refused' /tmp/umux.log), the ramdisk dropped"
log "off USB -> re-pwn into DFU and re-boot, then run this again."
exit 1

# SEP caveat: 'mount_ich' mounts the NAND volumes; the Data mount is SEP-gated. This chain runs a
# 26.6.2 kernel with a 27.0.1 SEP (device NAND is 27.0.1), a known mismatch, so mount_ich can fault
# and drop the session/device. If so, mount only System/Preboot read-only, or build a chain whose
# SEP matches the kernel. A plain shell (no mount_ich) is the stable baseline.
