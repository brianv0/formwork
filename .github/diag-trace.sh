#!/usr/bin/env bash
# TEMPORARY: loop FW-E2E-094 under a connect() trace until a confined client is refused its own
# Gateway port, then print what that connect() actually carried.
set -u
csrutil status || true
out="$RUNNER_TEMP/connect.trace"
sudo dtrace -q -o "$out" -n '
syscall::connect:entry, syscall::connect_nocancel:entry
{ self->sa = (uintptr_t)arg1; self->len = arg2; self->on = 1; }
syscall::connect:return, syscall::connect_nocancel:return
/self->on/
{
  this->b = (uint8_t *)copyin(self->sa, 28);
  printf("%d %d %s %s len=%d fam=%d port=%d errno=%d ", walltimestamp/1000000, pid, execname, probefunc,
    self->len, this->b[1], (this->b[2] << 8) | this->b[3], errno);
  printf("%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
    this->b[4], this->b[5], this->b[6], this->b[7], this->b[8], this->b[9], this->b[10], this->b[11],
    this->b[12], this->b[13], this->b[14], this->b[15], this->b[16], this->b[17], this->b[18], this->b[19],
    this->b[20], this->b[21], this->b[22], this->b[23]);
  self->on = 0;
}
syscall::connectx:return
{ printf("%d %d %s connectx errno=%d\n", walltimestamp/1000000, pid, execname, errno); }
' &
dt=$!
sleep 5
reproduced=0
for i in $(seq 1 40); do
  log="$RUNNER_TEMP/run-$i.log"
  if ! FW_REQUIRE_EXERCISED=1 cargo test -q -p formwork-cli --test fep6_run --locked fw_e2e_094 -- --nocapture >"$log" 2>&1; then
    echo "######## run $i failed"
    grep -E "expected|deny\(1\) network|listener started" "$log" | cut -c1-300 | head -40
    reproduced=1
    break
  fi
  echo "run $i ok"
done
sleep 2
sudo kill "$dt"; sleep 2
echo "=== trace lines: $(wc -l < "$out")"
echo "=== every refused connect (errno != 0 and != 36/EINPROGRESS)"
grep -v -E "errno=(0|36) " "$out" | grep -v connectx | head -80
echo "=== connectx calls"
grep -c connectx "$out" || true
grep connectx "$out" | sort | uniq -c | sort -rn | head -20
echo "reproduced=$reproduced"
