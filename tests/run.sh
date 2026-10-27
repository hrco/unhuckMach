#!/bin/bash
# tests/run.sh — runs everywhere (Linux CI or a Mac). On macOS it also runs a
# real --quick audit into a temp dir and checks the report structure.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  FAIL %s\n       %s\n' "$1" "${2:-}"; }
assert_eq() { if [ "$2" = "$3" ]; then ok "$1"; else fail "$1" "expected [$3] got [$2]"; fi; }
assert_contains() { case "$2" in *"$3"*) ok "$1";; *) fail "$1" "missing [$3] in: $2";; esac; }
assert_not_contains() { case "$2" in *"$3"*) fail "$1" "unexpected [$3] in: $2";; *) ok "$1";; esac; }

echo "== syntax"
bash -n "$ROOT/audit-mac.sh" && ok "audit-mac.sh parses" || fail "audit-mac.sh parses"
bash -n "$ROOT/lib/checks.sh" && ok "lib/checks.sh parses" || fail "lib/checks.sh parses"
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -S warning -x "$ROOT/audit-mac.sh" "$ROOT/lib/checks.sh"; then ok "shellcheck"; else fail "shellcheck"; fi
else
  echo "  skip shellcheck (not installed)"
fi

echo "== cli"
out=$("$ROOT/audit-mac.sh" --version); assert_contains "--version" "$out" "unhuckMach audit-mac"
out=$("$ROOT/audit-mac.sh" --help);    assert_contains "--help" "$out" "Usage"
"$ROOT/audit-mac.sh" --bogus >/dev/null 2>&1; assert_eq "unknown option exits 64" "$?" "64"

echo "== lib: battery"
. "$ROOT/lib/checks.sh"
UH_FLAGS_FILE=""
assert_eq "health pct 4000/5000" "$(uh_battery_health_pct 4000 5000)" "80"
assert_eq "health pct bad input" "$(uh_battery_health_pct abc 5000)" "0"
assert_eq "health pct zero design" "$(uh_battery_health_pct 1 0)" "0"
out=$(uh_battery_verdict 72 1200 "Service Recommended")
assert_contains "worn battery -> HIGH" "$out" "[HIGH] Battery health 72%"
assert_contains "cycles -> HIGH" "$out" "cycle count 1200"
assert_contains "condition -> HIGH" "$out" "Service Recommended"
out=$(uh_battery_verdict 95 120 Normal); assert_eq "healthy battery -> no flags" "$out" ""
out=$(uh_wake_summary <"$HERE/fixtures/pmset-log.txt")
assert_contains "wake summary counts" "$out" "dark_wakes=2 user_wakes=1 sleeps=3"
assert_not_contains "few dark wakes -> no flag" "$out" "[MED]"
out=$( { for i in $(seq 1 31); do echo "x DarkWake y"; done; } | uh_wake_summary )
assert_contains "many dark wakes -> MED" "$out" "[MED] 31 dark wakes"

IOREG_FIXTURE='  |   "MaxCapacity" = 100
  |   "CycleCount" = 52
  |   "BatteryData" = {"FullChargeCapacity"=4801,"NominalChargeCapacity"=4968,"DesignCapacity"=4800,"MaxCapacity"=100}'
assert_eq "ioreg nested FullChargeCapacity" "$(uh_ioreg_num "$IOREG_FIXTURE" FullChargeCapacity)" "4801"
assert_eq "ioreg nested DesignCapacity" "$(uh_ioreg_num "$IOREG_FIXTURE" DesignCapacity)" "4800"
assert_eq "ioreg top-level CycleCount" "$(uh_ioreg_num "$IOREG_FIXTURE" CycleCount)" "52"
assert_eq "ioreg missing key" "$(uh_ioreg_num "$IOREG_FIXTURE" AppleRawMaxCapacity)" ""
assert_eq "etime dd-hh:mm:ss" "$(uh_etime_hours 01-06:40:53)" "30"
assert_eq "etime hh:mm:ss" "$(uh_etime_hours 04:46:14)" "4"
assert_eq "etime mm:ss" "$(uh_etime_hours 06:04)" "0"
out=$(uh_runaway_check 2360 168.8 01-06:40:53 /x/VTEncoderXPCService); assert_contains "runaway -> HIGH" "$out" "[HIGH] runaway process: pid 2360 VTEncoderXPCService at 168.8% CPU, running 30h"
out=$(uh_runaway_check 1 95.0 00:20 /x/y); assert_eq "short burst not runaway" "$out" ""
out=$(uh_runaway_check 1 40.0 05:00:00 /x/y); assert_eq "low cpu not runaway" "$out" ""
out=$(uh_sleep_blocker_check '   pid 666(Claude): [0x0000005c000180e3] 31:06:21 NoIdleSleepAssertion named: "Electron"  ')
assert_contains "sleep blocker 31h -> MED" "$out" "[MED] 'Claude' has kept the Mac from sleeping for 31:06:21"
out=$(uh_sleep_blocker_check '   pid 714(sharingd): [0x00012d2e00019440] 00:03:43 PreventUserIdleSystemSleep named: "Handoff"  ')
assert_eq "short assertion ignored" "$out" ""

echo "== lib: paths"
uh_is_system_path /usr/bin/ssh && ok "system path" || fail "system path"
uh_is_system_path /Users/x/bin/ssh && fail "non-system path" || ok "non-system path"
uh_is_suspicious_path /tmp/agent && ok "/tmp suspicious" || fail "/tmp suspicious"
uh_is_suspicious_path /Users/x/.hidden/agent && ok "hidden dir suspicious" || fail "hidden dir suspicious"
uh_is_suspicious_path /Users/Shared/x && ok "Users/Shared suspicious" || fail "Users/Shared suspicious"
uh_is_suspicious_path /Applications/Slack.app/Contents/MacOS/Slack && fail "app not suspicious" || ok "app not suspicious"
uh_is_suspicious_path /opt/homebrew/bin/node && fail "homebrew not suspicious" || ok "homebrew not suspicious"
uh_is_suspicious_path /Users/x/.nvm/versions/node/v22.0.0/bin/node && fail "nvm not suspicious" || ok "nvm not suspicious"
uh_is_suspicious_path /Users/x/.cursor/extensions/x/bin/server && fail "cursor not suspicious" || ok "cursor not suspicious"
uh_is_suspicious_path /Users/x/.hermes/tools/python/bin/python3 && fail "hermes not suspicious" || ok "hermes not suspicious"
uh_is_suspicious_path /Users/x/.Trash/app && ok "Trash suspicious" || fail "Trash suspicious"
assert_eq "hidden component" "$(uh_hidden_component /Users/x/.cargo/bin/rg)" ".cargo"
uh_hidden_component /usr/bin/ssh >/dev/null && fail "no hidden component" || ok "no hidden component"
uh_is_trusted_dev_path /opt/homebrew/bin/node && ok "homebrew trusted" || fail "homebrew trusted"
uh_is_trusted_dev_path /Users/x/.cargo/bin/rg && ok "cargo trusted" || fail "cargo trusted"
uh_is_trusted_dev_path /Users/x/.evil/bin/rg && fail ".evil not trusted" || ok ".evil not trusted"
uh_is_apple_label com.apple.foo && ok "apple label" || fail "apple label"
uh_is_apple_label com.evil.foo && fail "non-apple label" || ok "non-apple label"

echo "== lib: codesign classification"
assert_eq "apple"    "$(uh_classify_codesign_output "$(cat "$HERE/fixtures/codesign-apple.txt")")" "apple"
assert_eq "dev id"   "$(uh_classify_codesign_output "$(cat "$HERE/fixtures/codesign-dev.txt")")" "developer:Developer ID Application: Slack Technologies, LLC (BQR82RBBHL)"
assert_eq "adhoc"    "$(uh_classify_codesign_output "$(cat "$HERE/fixtures/codesign-adhoc.txt")")" "adhoc"
assert_eq "unsigned" "$(uh_classify_codesign_output "$(cat "$HERE/fixtures/codesign-unsigned.txt")")" "unsigned"
assert_eq "missing file" "$(uh_codesign_authority /nonexistent/zzz)" "missing"

echo "== lib: text filters"
out=$(uh_hosts_nondefault <"$HERE/fixtures/hosts-custom.txt")
assert_eq "hosts custom entries" "$out" "$(printf '0.0.0.0 apple.com\n185.0.0.1 www.paypal.com')"
out=$(uh_rc_suspicious <"$HERE/fixtures/zshrc-bad.txt")
assert_contains "rc: curl|bash"  "$out" "4:curl -fsSL"
assert_contains "rc: nohup /tmp" "$out" "5:nohup"
assert_contains "rc: base64 -d"  "$out" "6:eval"
assert_contains "rc: DYLD"       "$out" "7:export DYLD_INSERT_LIBRARIES"
assert_not_contains "rc: commented line ignored" "$out" "2:#"
out=$(uh_rc_suspicious <"$HERE/fixtures/zshrc-good.txt"); assert_eq "rc: clean file" "$out" ""
assert_eq "tcc name" "$(uh_tcc_service_name kTCCServiceListenEvent)" "Input Monitoring (keylogger-capable)"

echo "== lib: flags file"
UH_FLAGS_FILE="$(mktemp)"; uh_flag HIGH "demo" >/dev/null
assert_eq "flag written" "$(cat "$UH_FLAGS_FILE")" "[HIGH] demo"; rm -f "$UH_FLAGS_FILE"; UH_FLAGS_FILE=""

echo "== platform"
if [ "$(uname -s)" = "Darwin" ]; then
  TMP="$(mktemp -d)"
  "$ROOT/audit-mac.sh" --quick --out "$TMP" >/dev/null 2>&1; rc=$?
  assert_eq "quick audit exits 0" "$rc" "0"
  [ -s "$TMP/report.txt" ] && ok "report.txt written" || fail "report.txt written"
  [ -e "$TMP/FLAGS.txt" ]  && ok "FLAGS.txt created"   || fail "FLAGS.txt created"
  for s in "0. System identity" "2. Battery" "3. Persistence" "4. Network" "5. Accounts" "6. Privacy" "7. Applications" "8. Running processes" "SUMMARY"; do
    grep -q "## $s" "$TMP/report.txt" && ok "section '$s'" || fail "section '$s'"
  done
  echo "  (report kept at $TMP for inspection)"
else
  "$ROOT/audit-mac.sh" --quick --out /tmp/x >/dev/null 2>&1; assert_eq "refuses non-macOS with exit 2" "$?" "2"
fi

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
