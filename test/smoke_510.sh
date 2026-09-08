#!/system/bin/sh
# test/smoke_510.sh - on-device smoke test for the resident loader agent.
# Push the tree to /data/local/tmp/kpm then, as root:
#   su -c sh /data/local/tmp/kpm/test/smoke_510.sh /data/local/tmp/kpm
#
# Typical flow: load agent -> ioctl LOAD the .kpm -> check /dev/suzhi_NQ ->
# status -> unload -> rmmod agent.
set -e
R="${1:-/data/local/tmp/kpm}"

echo "== [1] /proc/kallsyms readable + anchor present =="
head -1 /proc/kallsyms
grep -m1 ' kallsyms_lookup_name$' /proc/kallsyms || { echo "FATAL: no kallsyms_lookup_name"; exit 1; }

echo "== [2] agent not already loaded =="
lsmod | grep kpm_host && { echo "FATAL: agent already loaded"; exit 1; }

echo "== [3] load agent + push .kpm (optional args forwarded verbatim) =="
"$R/helper/suzhi_loader" load \
  "$R/build/kpm_host-gki-5.10.ko" \
  "$R/suzhi_NQ.kpm" \
  && echo "OK load"
"$R/helper/suzhi_loader" status
ls -l /dev/suzhi_NQ 2>/dev/null || { echo "WARN: /dev/suzhi_NQ missing"; }

echo "== [4] runtime link check =="
dmesg | grep -Ei 'kpm: (l9|succeed|init_fn|host ready)' | tail -20

echo "== [5] unload the .kpm, then drop the agent =="
"$R/helper/suzhi_loader" unload
"$R/helper/suzhi_loader" status
rmmod kpm_host 2>/dev/null || lsmod | grep kpm_host || true
lsmod | grep kpm_host && { echo "WARN: agent still loaded"; } || echo "OK agent removed"
echo "== smoke done =="