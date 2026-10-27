#!/bin/bash
# audit-mac.sh — read-only compromise / malware audit for a MacBook.
#
# Collects evidence about persistence, network, accounts, privacy grants,
# running processes and battery/power behaviour into one report, then prints a
# list of FLAGS worth a closer look.  It changes NOTHING on the machine.
#
# Usage:  sudo ./audit-mac.sh [--quick] [--deep] [--out DIR]
#   --quick   skip the slow parts (per-app signatures, unified log, SUID scan)
#   --deep    include the slow parts (default is in between)
#   --out     report directory (default: ~/Desktop/unhuckmach-<timestamp>)
#
# Run it with sudo for full coverage (root launch daemons, sudoers, system TCC,
# login items via sfltool).  Without sudo it still runs; limited checks are
# marked "(needs sudo)".  Give Terminal "Full Disk Access" in
# System Settings > Privacy & Security to read the TCC databases.

set -u
VERSION="0.1.0"
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/checks.sh
. "$HERE/lib/checks.sh"

MODE="normal"
OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --quick) MODE="quick";;
    --deep)  MODE="deep";;
    --out)   shift; OUT="${1:-}";;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    --version) echo "unhuckMach audit-mac $VERSION"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 64;;
  esac
  shift
done

if [ "$(uname -s)" != "Darwin" ]; then
  echo "audit-mac.sh only runs on macOS (uname says $(uname -s))." >&2
  exit 2
fi

# ---------- who is the real user --------------------------------------------------
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  REAL_USER="$SUDO_USER"
else
  REAL_USER="$(id -un)"
fi
REAL_HOME="$(dscl . -read "/Users/$REAL_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[ -n "$REAL_HOME" ] || REAL_HOME="$HOME"
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1

STAMP="$(date +%Y%m%d-%H%M%S)"
[ -n "$OUT" ] || OUT="$REAL_HOME/Desktop/unhuckmach-$STAMP"
mkdir -p "$OUT" || { echo "cannot create $OUT" >&2; exit 1; }
REPORT="$OUT/report.txt"
UH_FLAGS_FILE="$OUT/FLAGS.txt"
: >"$REPORT"; : >"$UH_FLAGS_FILE"
export UH_FLAGS_FILE

main() {

section() { printf '\n================================================================\n## %s\n================================================================\n' "$*"; }
sub()     { printf '\n--- %s\n' "$*"; }
run() {   # run <description> -- <command...>   (never aborts the audit)
  local desc="$1"; shift; [ "${1:-}" = "--" ] && shift
  printf '\n$ %s\n' "$*"
  "$@" 2>&1 || printf '(exit %s)\n' "$?"
}
needs_sudo() { [ $IS_ROOT -eq 1 ] || printf '(needs sudo: %s)\n' "$*"; [ $IS_ROOT -eq 1 ]; }

echo "unhuckMach audit-mac $VERSION  mode=$MODE  $(date)"
echo "user=$REAL_USER home=$REAL_HOME root=$IS_ROOT  report=$OUT"

# ================================================================================
section "0. System identity"
run sw -- sw_vers
run model -- sysctl -n hw.model
run uptime -- uptime
run arch -- uname -m
run bootargs -- sh -c 'nvram boot-args 2>/dev/null || echo "boot-args: not set (good)"'

# ================================================================================
section "1. Security baseline (SIP, Gatekeeper, FileVault, firewall, updates)"
run sip -- csrutil status
case "$(csrutil status 2>/dev/null)" in *disabled*) uh_flag HIGH "System Integrity Protection is DISABLED";; esac

run gatekeeper -- spctl --status
case "$(spctl --status 2>/dev/null)" in *disabled*) uh_flag HIGH "Gatekeeper assessments are DISABLED";; esac

run filevault -- fdesetup status
case "$(fdesetup status 2>/dev/null)" in *Off*) uh_flag MED "FileVault is OFF (disk not encrypted)";; esac

run firewall -- /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
case "$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)" in *disabled*) uh_flag LOW "Application firewall is disabled";; esac

run xprotect -- /usr/libexec/PlistBuddy -c 'Print:CFBundleShortVersionString' /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist
run updates -- sh -c 'softwareupdate --history 2>/dev/null | tail -8'
run secureboot -- sh -c 'bputil -d 2>/dev/null | grep -iE "security mode|boot" | head -5 || echo "(bputil needs sudo / Apple silicon)"'

# ================================================================================
section "2. Battery & power (the reported symptom)"
run batt -- pmset -g batt
sub "Battery health from ioreg"
IOREG="$(ioreg -rn AppleSmartBattery 2>/dev/null)"
printf '%s\n' "$IOREG" | grep -E '"(CycleCount|DesignCapacity|AppleRawMaxCapacity|NominalChargeCapacity|MaxCapacity|Temperature|PermanentFailureStatus|AtCriticalLevel|FullyCharged|IsCharging|ExternalConnected)"'
MAXCAP=$(uh_ioreg_num "$IOREG" AppleRawMaxCapacity)
[ -n "$MAXCAP" ] || MAXCAP=$(uh_ioreg_num "$IOREG" FullChargeCapacity)
[ -n "$MAXCAP" ] || MAXCAP=$(uh_ioreg_num "$IOREG" NominalChargeCapacity)
DESCAP=$(uh_ioreg_num "$IOREG" DesignCapacity)
CYCLES=$(uh_ioreg_num "$IOREG" CycleCount)
PCT=$(uh_battery_health_pct "${MAXCAP:-0}" "${DESCAP:-0}")
COND=$(system_profiler SPPowerDataType 2>/dev/null | sed -n 's/^ *Condition: *//p' | head -1)
echo "health=${PCT}% (max ${MAXCAP:-?} / design ${DESCAP:-?} mAh) cycles=${CYCLES:-?} condition=${COND:-?}"
uh_battery_verdict "$PCT" "${CYCLES:-}" "$COND"

sub "Power assertions (what keeps the Mac awake)"
run assertions -- sh -c 'pmset -g assertions | sed -n "/Listed by owning process/,\$p" | head -40'
sub "Sleep/wake history (last 300 log lines)"
WAKELOG="$(pmset -g log 2>/dev/null | grep -E 'Wake|DarkWake|Sleep' | tail -300)"
printf '%s\n' "$WAKELOG" | tail -40
printf '%s\n' "$WAKELOG" | uh_wake_summary
run pmsettings -- pmset -g custom
sub "Top CPU consumers right now"
run topcpu -- sh -c 'ps -Ao pid,user,%cpu,%mem,etime,comm -r | head -20'
ps -Ao pid,%cpu,etime,comm -r | tail -n +2 | head -15 | while read -r pid cpu etime comm; do
  uh_runaway_check "$pid" "$cpu" "$etime" "$comm"
done
pmset -g assertions 2>/dev/null | grep -E 'NoIdleSleepAssertion|PreventUserIdleSystemSleep|PreventSystemSleep' | grep -E '^ *pid' | while read -r line; do
  uh_sleep_blocker_check "$line"
done
sub "Energy impact over the last week (coalition stats, if available)"
run powermetrics -- sh -c 'if [ "$(id -u)" -eq 0 ]; then powermetrics -n 1 -i 1000 --samplers tasks 2>/dev/null | head -40; else echo "(needs sudo)"; fi'

# ================================================================================
section "3. Persistence (launch agents/daemons, login items, cron, hooks, extensions)"
inspect_plists() {   # inspect_plists <dir> <label>
  local dir="$1" tag="$2" f label prog auth
  [ -d "$dir" ] || { echo "(no $dir)"; return; }
  for f in "$dir"/*.plist; do
    [ -e "$f" ] || continue
    label=$(/usr/libexec/PlistBuddy -c 'Print:Label' "$f" 2>/dev/null)
    prog=$(/usr/libexec/PlistBuddy -c 'Print:ProgramArguments:0' "$f" 2>/dev/null)
    [ -n "$prog" ] || prog=$(/usr/libexec/PlistBuddy -c 'Print:Program' "$f" 2>/dev/null)
    auth=$(uh_codesign_authority "$prog")
    printf '%-10s %-45s %-50s %s  (%s)\n' "$tag" "${label:-?}" "${prog:-?}" "$auth" "$(basename "$f")"
    [ -n "$prog" ] || uh_flag LOW "$tag $(basename "$f") has no Program/ProgramArguments the script understands — open it and read it"
    if ! uh_is_apple_label "$label"; then
      case "$auth" in
        adhoc) if uh_is_trusted_dev_path "$prog"; then uh_flag LOW "$tag '$label' runs ad-hoc signed $prog (normal for homebrew/dev tools)"
               else uh_flag HIGH "$tag '$label' runs $prog which is $auth ($f)"; fi;;
        unsigned|missing|unknown) uh_flag HIGH "$tag '$label' runs $prog which is $auth ($f)";;
      esac
      if uh_is_suspicious_path "$prog"; then uh_flag HIGH "$tag '$label' runs from a suspicious location: $prog"; fi
    fi
  done
}
sub "Launch daemons/agents outside /System (label, program, signature)"
inspect_plists /Library/LaunchDaemons LaunchD
inspect_plists /Library/LaunchAgents  LaunchA
inspect_plists "$REAL_HOME/Library/LaunchAgents" UserLA
sub "Loaded non-Apple launchd jobs (user session)"
run launchctl -- sh -c 'launchctl list | grep -v "com.apple\." | head -60'
if [ $IS_ROOT -eq 1 ]; then
  sub "Loaded non-Apple launchd jobs (system domain)"
  run launchctl_sys -- sh -c 'launchctl print system 2>/dev/null | sed -n "/services = {/,/}/p" | grep -v "com.apple\." | head -60'
fi
sub "Login items & background items (System Settings > General > Login Items)"
run loginitems -- osascript -e 'tell application "System Events" to get the name of every login item'
if needs_sudo sfltool; then run btm -- sh -c 'sfltool dumpbtm 2>/dev/null | grep -E "^ *(Name|Type|URL|Developer Name|Identifier)" | head -120'; fi
sub "Cron / at / periodic"
run crontab -- sh -c "crontab -u $REAL_USER -l 2>&1"
if needs_sudo crontabs; then run cronroot -- sh -c 'ls -la /usr/lib/cron/tabs/ 2>/dev/null; for t in /usr/lib/cron/tabs/*; do [ -f "$t" ] && { echo "== $t"; cat "$t"; }; done'; fi
run atq -- atq
run periodic -- sh -c 'ls -la /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly 2>/dev/null | grep -vE "^total|^d|[0-9]{3}\.[a-z]"'
sub "Login/logout hooks, emond, StartupItems, ScriptingAdditions"
run hooks -- sh -c 'defaults read com.apple.loginwindow LoginHook 2>/dev/null; defaults read com.apple.loginwindow LogoutHook 2>/dev/null; echo "(no hooks is normal)"'
run emond -- sh -c 'ls -la /etc/emond.d/rules/ 2>/dev/null; ls /private/var/db/emondClients 2>/dev/null'
run startupitems -- sh -c 'ls -la /Library/StartupItems /Library/ScriptingAdditions 2>/dev/null || echo "(none - good)"'
sub "Shell startup files: lines that look like droppers"
for rc in "$REAL_HOME/.zshrc" "$REAL_HOME/.zprofile" "$REAL_HOME/.zshenv" "$REAL_HOME/.zlogin" "$REAL_HOME/.bash_profile" "$REAL_HOME/.bashrc" "$REAL_HOME/.profile" /etc/zshrc /etc/zprofile /etc/zshenv /etc/profile /etc/bashrc; do
  [ -f "$rc" ] || continue
  hits=$(uh_rc_suspicious <"$rc")
  if [ -n "$hits" ]; then
    echo "== $rc"; printf '%s\n' "$hits"
    uh_flag MED "suspicious line(s) in $rc — read them"
  fi
done
echo "(checked rc files)"
sub "Kernel & system extensions, configuration profiles (MDM)"
run kext -- sh -c 'kextstat 2>/dev/null | grep -v com.apple || echo "(no third-party kexts)"'
run sysext -- systemextensionsctl list
run profiles -- sh -c 'profiles list 2>&1; profiles status -type enrollment 2>&1'
case "$(profiles status -type enrollment 2>/dev/null)" in
  *"MDM enrollment: Yes"*) uh_flag HIGH "This Mac is enrolled in MDM (someone can manage it remotely). Expected only on a company device.";;
esac
PCOUNT=$(profiles list 2>/dev/null | grep -c 'profileIdentifier')
[ "${PCOUNT:-0}" -gt 0 ] && uh_flag MED "$PCOUNT configuration profile(s) installed — review in System Settings > Privacy & Security > Profiles"

# ================================================================================
section "4. Network (listeners, connections, DNS, proxies, hosts, sharing)"
sub "Listening TCP/UDP sockets with owning process"
run listen -- sh -c 'lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null; lsof -nP -iUDP 2>/dev/null | grep -v "\*:\*->" | head -40'
sub "Established connections"
run estab -- sh -c 'lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk "{print \$1, \$2, \$3, \$9}" | sort | uniq -c | sort -rn | head -60'
sub "DNS, proxies, VPN/tunnel interfaces"
run dns -- sh -c 'scutil --dns | grep -E "nameserver|search domain" | sort -u'
run proxy -- scutil --proxy
PROXYON=$(scutil --proxy 2>/dev/null | grep -E '(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable) : 1')
[ -n "$PROXYON" ] && uh_flag HIGH "A system proxy is enabled: $PROXYON — traffic may be intercepted"
run tunnels -- sh -c 'ifconfig | grep -E "^(utun|tun|tap|bridge|gif|stf)[0-9]+" || echo "(no tunnels)"'
run services -- networksetup -listallnetworkservices
sub "/etc/hosts non-default entries"
HOSTS=$(uh_hosts_nondefault </etc/hosts)
if [ -n "$HOSTS" ]; then printf '%s\n' "$HOSTS"; uh_flag MED "/etc/hosts has custom entries (can redirect sites)"; else echo "(stock hosts file)"; fi
sub "Remote access services"
run remote -- sh -c 'ps -axo comm | grep -iE "sshd|screensharingd|ARDAgent|AppleVNCServer|RemoteDesktop|teamviewer|anydesk|rustdesk|zoho|splashtop|logmein|chrome_remote|ngrok|cloudflared|tailscaled" | sort -u || true'
if needs_sudo systemsetup; then run remotelogin -- systemsetup -getremotelogin; fi
RL=$(launchctl print system/com.apple.screensharing 2>/dev/null | grep -c 'state = running')
[ "${RL:-0}" -gt 0 ] && uh_flag MED "Screen Sharing service is running"
for r in teamviewer anydesk rustdesk splashtop logmein ngrok; do
  if ps -axo comm | grep -qi "$r"; then uh_flag HIGH "Remote-control tool '$r' is running — if you did not install it, this is how someone gets in"; fi
done
run sharing -- sh -c 'launchctl list 2>/dev/null | grep -iE "smbd|AppleFileServer|screensharing|RemoteDesktop|ssh" || echo "(no sharing daemons in user domain)"'

# ================================================================================
section "5. Accounts & access (users, admins, sudoers, ssh keys, login history)"
run users -- sh -c 'dscl . list /Users UniqueID | awk "\$2 >= 500 || \$1 == \"root\""'
run admins -- dscl . -read /Groups/admin GroupMembership
run hidden -- sh -c 'dscl . list /Users IsHidden 2>/dev/null | grep -v " 0$" || echo "(no hidden users)"'
HIDDEN=$(dscl . list /Users IsHidden 2>/dev/null | grep -v ' 0$' | grep -v '^_')
[ -n "$HIDDEN" ] && uh_flag HIGH "Hidden user account(s): $HIDDEN"
run guest -- sh -c 'defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo 0'
run autologin -- sh -c 'defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo "(no auto-login)"'
run rootenabled -- sh -c 'dscl . -read /Users/root AuthenticationAuthority 2>/dev/null | grep -q ";ShadowHash;" && echo "ROOT ACCOUNT IS ENABLED" || echo "root account disabled (normal)"'
dscl . -read /Users/root AuthenticationAuthority 2>/dev/null | grep -q ';ShadowHash;' && uh_flag HIGH "The root account is enabled"
if needs_sudo sudoers; then
  run sudoers -- sh -c 'grep -vE "^\s*#|^\s*$|^Defaults" /etc/sudoers; ls -la /etc/sudoers.d 2>/dev/null; cat /etc/sudoers.d/* 2>/dev/null'
  EXTRA=$(cat /etc/sudoers.d/* 2>/dev/null | grep -vE '^\s*#|^\s*$')
  [ -n "$EXTRA" ] && uh_flag MED "Extra sudoers rules in /etc/sudoers.d: $EXTRA"
fi
sub "SSH"
run sshdir -- sh -c "ls -la '$REAL_HOME/.ssh' 2>/dev/null || echo '(no ~/.ssh)'"
if [ -s "$REAL_HOME/.ssh/authorized_keys" ]; then
  run authkeys -- cat "$REAL_HOME/.ssh/authorized_keys"
  uh_flag MED "~/.ssh/authorized_keys exists — every key in it can log in as you if Remote Login is on"
fi
sub "Login history"
run last -- sh -c 'last -25 2>/dev/null'

# ================================================================================
section "6. Privacy grants (TCC): who may record the screen, log keys, use mic/camera"
tcc_dump() {   # tcc_dump <db> <tag>
  local db="$1" tag="$2" rows line client svc val
  [ -f "$db" ] || { echo "($tag TCC db not found)"; return; }
  rows=$(sqlite3 "$db" "select client, service, auth_value from access where auth_value in (2,3) and service in ('kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceListenEvent','kTCCServiceMicrophone','kTCCServiceCamera','kTCCServiceSystemPolicyAllFiles','kTCCServicePostEvent','kTCCServiceAppleEvents','kTCCServiceLocation') order by service;" 2>&1)
  case "$rows" in
    *"unable to open"*|*"authorization denied"*|*"not authorized"*)
      echo "($tag: cannot read — give Terminal Full Disk Access, then re-run)"; return;;
  esac
  printf '%s\n' "$rows" | while IFS='|' read -r client svc val; do
    [ -n "$client" ] || continue
    printf '%-8s %-40s %s\n' "$tag" "$(uh_tcc_service_name "$svc")" "$client"
    case "$svc" in
      kTCCServiceScreenCapture|kTCCServiceListenEvent|kTCCServiceAccessibility)
        case "$client" in com.apple.*) ;; *) uh_flag MED "$tag TCC: '$client' has $(uh_tcc_service_name "$svc") — expected? (zoom/teams/1password are normal; unknown names are not)";; esac;;
    esac
  done
}
tcc_dump "$REAL_HOME/Library/Application Support/com.apple.TCC/TCC.db" user
if needs_sudo system-TCC; then tcc_dump "/Library/Application Support/com.apple.TCC/TCC.db" system; fi

# ================================================================================
section "7. Applications, downloads, browser extensions, odd files"
sub "Recent quarantine (download) events — what came in through the browser lately"
QDB="$REAL_HOME/Library/Preferences/com.apple.LaunchServices/com.apple.LaunchServices.QuarantineEventsV2"
run quarantine -- sh -c "sqlite3 '$QDB' \"select datetime(LSQuarantineTimeStamp + 978307200, 'unixepoch'), LSQuarantineAgentName, LSQuarantineDataURLString from LSQuarantineEvent order by LSQuarantineTimeStamp desc limit 30;\" 2>&1 | cut -c1-200 | sed 's/^Parse error.*no such table.*/(this macOS no longer keeps a quarantine event table; check Finder > Downloads and Safari > Downloads manually)/'"
sub "Applications and their signing authority"
if [ "$MODE" = "quick" ]; then
  run apps -- sh -c 'ls -lt /Applications | head -40'
else
  for app in /Applications/*.app "$REAL_HOME/Applications"/*.app; do
    [ -d "$app" ] || continue
    a=$(uh_codesign_authority "$app")
    printf '%-60s %s\n' "$(basename "$app")" "$a"
    case "$a" in unsigned|adhoc) uh_flag MED "App '$(basename "$app")' is $a — Gatekeeper would normally block this; how did it get here?";; esac
  done
fi
sub "Browser extensions"
run chrome -- sh -c "for d in '$REAL_HOME/Library/Application Support/Google/Chrome/Default/Extensions' '$REAL_HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions' '$REAL_HOME/Library/Application Support/Microsoft Edge/Default/Extensions'; do [ -d \"\$d\" ] || continue; echo \"== \$d\"; for e in \"\$d\"/*/*/manifest.json; do [ -f \"\$e\" ] && printf '%s  ' \"\$(basename \"\$(dirname \"\$(dirname \"\$e\")\")\")\" && /usr/libexec/PlistBuddy -c 'Print:name' \"\$e\" 2>/dev/null || grep -m1 '\"name\"' \"\$e\"; done; done; echo '(end)'"
run safari -- sh -c 'pluginkit -mAvvv -p com.apple.Safari.extension 2>/dev/null | grep -E "^\s*(Display Name|Path)" | head -40 || echo "(none)"'
run firefox -- sh -c "ls '$REAL_HOME/Library/Application Support/Firefox/Profiles'/*/extensions 2>/dev/null || echo '(no firefox)'"
sub "Executables in temp / shared / hidden locations (classic malware drop zones)"
run tmpexec -- sh -c 'find /tmp /private/tmp /var/tmp /Users/Shared -maxdepth 2 -type f -perm -u+x 2>/dev/null | head -40; echo "(end)"'
TMPX=$(find /tmp /private/tmp /var/tmp /Users/Shared -maxdepth 2 -type f -perm -u+x 2>/dev/null | head -5)
[ -n "$TMPX" ] && uh_flag MED "Executable files in temp/shared dirs: $(printf '%s ' $TMPX)"
run hiddenhome -- sh -c "ls -lad '$REAL_HOME'/.[!.]* 2>/dev/null | grep -vE '\.(zsh|bash|git|ssh|config|cache|npm|cargo|docker|vscode|cursor|claude|local|Trash|DS_Store|CFUserTextEncoding|zcompdump|viminfo|lesshst|node|nvm|pyenv|rustup|gnupg|aws|azure|kube|m2|gradle|bundle|gem|yarn|pnpm|oh-my-zsh|p10k|hushlogin|profile|zprofile|zshenv|zlogin|zsh_history|bash_history|bash_profile|bashrc|python_history|sqlite_history|cups|Xauthority|android|ollama|bun|deno|terraform|cocoapods|swiftpm|matplotlib|ipython|jupyter|conda|continuum|codeium|aider|openai|anthropic)' || echo '(nothing unusual)'"
sub "Recently modified executables in user-writable bin dirs (14 days)"
run recentbin -- sh -c "find /usr/local/bin /opt/homebrew/bin /usr/local/sbin '$REAL_HOME/bin' '$REAL_HOME/.local/bin' -type f -mtime -14 2>/dev/null | head -40; echo '(end)'"
if [ "$MODE" = "deep" ]; then
  sub "SUID / SGID binaries outside /System and /usr (deep)"
  run suid -- sh -c 'find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | grep -vE "^/(System|usr|bin|sbin|Library/Apple)/" ; echo "(end)"'
fi

# ================================================================================
section "8. Running processes: unsigned, hidden-path, or from odd locations"
ps -axo pid,ppid,user,%cpu,etime,comm | tail -n +2 | while read -r pid ppid user cpu etime comm; do
  uh_is_system_path "$comm" && continue
  case "$comm" in /Applications/*|/System/*|/Library/Apple/*|/opt/homebrew/*|/usr/local/*|/nix/*) ;; 
    *) if uh_is_suspicious_path "$comm"; then
         echo "SUSPICIOUS-PATH pid=$pid ppid=$ppid user=$user cpu=$cpu up=$etime $comm"
         uh_flag HIGH "process $pid ($comm) runs from a suspicious path (user=$user cpu=$cpu)"
       fi;;
  esac
done
if [ "$MODE" != "quick" ]; then
  sub "Signature of every distinct running executable (non-Apple shown)"
  ps -axo comm | tail -n +2 | sort -u | while read -r comm; do
    uh_is_system_path "$comm" && continue
    [ -e "$comm" ] || continue
    a=$(uh_codesign_authority "$comm")
    case "$a" in apple) ;; *) printf '%-80s %s\n' "$comm" "$a";; esac
    case "$a" in
      unsigned) uh_flag MED "running process $comm is unsigned";;
      adhoc) uh_is_trusted_dev_path "$comm" || uh_flag MED "running process $comm is ad-hoc signed outside homebrew/dev dirs";;
    esac
  done
fi
sub "Processes with network connections but no app bundle"
run netproc -- sh -c 'lsof -nP -i 2>/dev/null | awk "NR>1{print \$1}" | sort | uniq -c | sort -rn | head -30'

# ================================================================================
if [ "$MODE" = "deep" ]; then
section "9. Unified log — sudo, ssh, screen sharing, new launchd jobs (last 2 days, deep)"
run logsudo -- sh -c 'log show --last 2d --style compact --predicate "process == \"sudo\" OR process == \"sshd\" OR process == \"screensharingd\" OR (process == \"backgroundtaskmanagementd\" AND eventMessage CONTAINS \"added\")" 2>/dev/null | tail -150'
run logtcc -- sh -c 'log show --last 2d --style compact --predicate "subsystem == \"com.apple.TCC\" AND eventMessage CONTAINS \"Granting\"" 2>/dev/null | tail -60'
fi

# ================================================================================
section "SUMMARY"
if [ -s "$UH_FLAGS_FILE" ]; then
  echo "Flags (HIGH first):"
  grep '^\[HIGH\]' "$UH_FLAGS_FILE"; grep '^\[MED\]' "$UH_FLAGS_FILE"; grep '^\[LOW\]' "$UH_FLAGS_FILE"
else
  echo "No flags raised. That is not proof of a clean machine, but nothing obvious stands out."
fi
echo
echo "Full report: $REPORT"
echo "Flags:       $UH_FLAGS_FILE"
echo "Next: go through CHECKLIST.md with the report open. Do not paste the report to strangers — it lists your accounts, apps and connections."
[ $IS_ROOT -eq 1 ] && chown -R "$REAL_USER" "$OUT" 2>/dev/null
return 0
}

# everything printed goes to the console and to the report; tee finishes before exit
main 2>&1 | tee -a "$REPORT"
exit "${PIPESTATUS[0]}"
