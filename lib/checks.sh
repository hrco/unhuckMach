#!/bin/bash
# lib/checks.sh — pure helper functions used by audit-mac.sh and the tests.
# Must stay compatible with macOS's stock /bin/bash (3.2): no associative
# arrays, no mapfile, no ${var,,} case conversion.

# ---------- output helpers ----------------------------------------------------
UH_FLAGS_FILE="${UH_FLAGS_FILE:-}"

uh_flag() {
  # uh_flag <severity: HIGH|MED|LOW> <message>
  local sev="$1"; shift
  local msg="$*"
  printf '  [%s] %s\n' "$sev" "$msg"
  if [ -n "$UH_FLAGS_FILE" ]; then
    printf '[%s] %s\n' "$sev" "$msg" >>"$UH_FLAGS_FILE"
  fi
}

# ---------- battery -----------------------------------------------------------
# uh_battery_health_pct <max_capacity> <design_capacity> -> integer percent
uh_battery_health_pct() {
  local max="$1" design="$2"
  case "$max$design" in *[!0-9]*|"") echo 0; return 1;; esac
  if [ "$design" -eq 0 ]; then echo 0; return 1; fi
  echo $(( max * 100 / design ))
}

# uh_battery_verdict <health_pct> <cycle_count> <condition> -> prints verdict line(s)
uh_battery_verdict() {
  local pct="$1" cycles="$2" cond="$3"
  if [ "$pct" -gt 0 ] && [ "$pct" -lt 80 ]; then
    uh_flag HIGH "Battery health ${pct}% (<80%): a worn battery drops suddenly from 100% on its own — hardware, not malware"
  elif [ "$pct" -gt 0 ] && [ "$pct" -lt 90 ]; then
    uh_flag LOW "Battery health ${pct}%: moderate wear, sudden drops are plausible without any compromise"
  fi
  case "$cycles" in
    ''|*[!0-9]*) ;;
    *) if [ "$cycles" -ge 1000 ]; then
         uh_flag HIGH "Battery cycle count ${cycles} (>=1000): at/over rated life"
       elif [ "$cycles" -ge 700 ]; then
         uh_flag LOW "Battery cycle count ${cycles}: ageing"
       fi;;
  esac
  case "$cond" in
    ""|Normal|normal) ;;
    *) uh_flag HIGH "Battery condition reported as '${cond}' (expected 'Normal')";;
  esac
}

# uh_ioreg_num <ioreg text> <key> -> first integer value for "key" = N or "key"=N (nested dicts too)
uh_ioreg_num() {
  printf '%s\n' "$1" | sed -n "s/.*\"$2\" *= *\([0-9][0-9]*\).*/\1/p" | head -1
}

# uh_etime_hours <ps etime: [[dd-]hh:]mm:ss> -> whole hours
uh_etime_hours() {
  local e="$1" d=0 h=0 rest
  case "$e" in *-*) d="${e%%-*}"; e="${e#*-}";; esac
  rest="$e"
  case "$rest" in
    *:*:*) h="${rest%%:*}";;
    *) h=0;;
  esac
  case "$d$h" in *[!0-9]*) echo 0; return;; esac
  echo $(( d * 24 + h ))
}

# uh_runaway_check <pid> <%cpu> <etime> <comm>: flags a process burning >90% CPU for >1h
uh_runaway_check() {
  local pid="$1" cpu="$2" etime="$3" comm="$4" hours whole
  whole="${cpu%%.*}"
  case "$whole" in ''|*[!0-9]*) return;; esac
  hours=$(uh_etime_hours "$etime")
  if [ "$whole" -ge 90 ] && [ "$hours" -ge 1 ]; then
    uh_flag HIGH "runaway process: pid $pid $(basename "$comm") at ${cpu}% CPU, running ${hours}h — this alone empties a battery in 1–2h. Find its parent: ps -o ppid= -p $pid"
  fi
}

# uh_sleep_blocker_check <pmset assertion line>: flags an app holding a sleep assertion >6h
uh_sleep_blocker_check() {
  local line="$1" name dur h
  name=$(printf '%s\n' "$line" | sed -n 's/^ *pid [0-9]*(\([^)]*\)).*/\1/p')
  dur=$(printf '%s\n' "$line" | sed -n 's/^ *pid [0-9]*([^)]*): \[[^]]*\] \([0-9:]*\) .*/\1/p')
  [ -n "$dur" ] || return 0
  h="${dur%%:*}"
  case "$h" in ''|*[!0-9]*) return 0;; esac
  if [ "$h" -ge 6 ]; then
    uh_flag MED "'$name' has kept the Mac from sleeping for ${dur} (h:m:s). On battery that means no sleep when idle — quit it when unplugged"
  fi
}

# uh_wake_summary < pmset -g log text  -> prints counts of wake kinds
uh_wake_summary() {
  local dark=0 user=0 sleep=0 line
  while IFS= read -r line; do
    case "$line" in
      *DarkWake*)            dark=$((dark+1));;
      *"Wake from"*)         user=$((user+1));;
      *"Entering Sleep"*)    sleep=$((sleep+1));;
    esac
  done
  printf 'dark_wakes=%d user_wakes=%d sleeps=%d\n' "$dark" "$user" "$sleep"
  if [ "$dark" -ge 30 ]; then
    uh_flag MED "${dark} dark wakes in the log window: Power Nap / Wake-on-LAN / Bluetooth wake drains battery while 'asleep'"
  fi
}

# ---------- paths & signatures --------------------------------------------------
# uh_is_system_path <path> -> 0 if under an Apple-managed location
uh_is_system_path() {
  case "$1" in
    /System/*|/usr/bin/*|/usr/sbin/*|/usr/libexec/*|/bin/*|/sbin/*|/usr/lib/*|/Library/Apple/*) return 0;;
    *) return 1;;
  esac
}

# Hidden directories that normal developer tooling lives in (not suspicious by themselves).
UH_KNOWN_DOTDIRS=" .nvm .cargo .rustup .local .pyenv .bun .deno .vscode .vscode-insiders .vscode-server .cursor .claude .codeium .windsurf .zed .docker .orbstack .colima .lima .rd .npm .yarn .pnpm .gem .rbenv .asdf .sdkman .volta .fnm .fvm .pub-cache .gradle .m2 .ollama .config .cache .oh-my-zsh .tmux .vim .nix-profile .nix-defexpr .krew .kube .minikube .ghcup .stack .cabal .opam .foundry .conda .miniconda3 .mamba .pixi .uv .rye .poetry .jenv .gvm .goenv .go .cocoapods .swiftpm .android .flutter .expo .continue .aider .pipx .virtualenvs .venv .espressif .platformio .arduino15 .wrangler .supabase .vercel .fly .op .1password .iterm2 .hammerspoon .karabiner .warp .ghostty .codex .gemini .grok .grokbot .hermes .opencode .antigravity-ide .cua-driver .oci .thumbnails .continue "

# uh_hidden_component <path> -> prints the first path component that starts with a dot
uh_hidden_component() {
  local rest="$1" c
  while [ -n "$rest" ]; do
    c="${rest%%/*}"
    case "$c" in .?*) echo "$c"; return 0;; esac
    case "$rest" in */*) rest="${rest#*/}";; *) rest="";; esac
  done
  return 1
}

uh_is_known_dotdir() { case "$UH_KNOWN_DOTDIRS" in *" $1 "*) return 0;; *) return 1;; esac; }

# uh_is_suspicious_path <path> -> 0 if an executable lives somewhere malware likes
uh_is_suspicious_path() {
  local p="$1" h
  case "$p" in
    /tmp/*|/private/tmp/*|/var/tmp/*|/private/var/tmp/*|/Users/Shared/*|/var/folders/*|/private/var/folders/*|*/Library/Caches/*|*/.Trash/*) return 0;;
  esac
  h=$(uh_hidden_component "$p") || return 1
  uh_is_known_dotdir "$h" && return 1
  return 0
}

# uh_is_trusted_dev_path <path> -> 0 for homebrew / nix / known dev dotdirs, where ad-hoc
# signatures are normal (Apple silicon ad-hoc signs every locally built binary).
uh_is_trusted_dev_path() {
  local p="$1" h
  case "$p" in /opt/homebrew/*|/usr/local/*|/nix/*|/opt/local/*) return 0;; esac
  h=$(uh_hidden_component "$p") || return 1
  uh_is_known_dotdir "$h"
}

# uh_codesign_authority <path> -> prints "apple" | "developer:<name>" | "adhoc" | "unsigned" | "missing"
uh_codesign_authority() {
  local p="$1" out
  [ -e "$p" ] || { echo missing; return; }
  out=$(codesign -dv --verbose=2 "$p" 2>&1)
  uh_classify_codesign_output "$out"
}

# uh_classify_codesign_output <codesign -dv output>  (pure, testable)
uh_classify_codesign_output() {
  local out="$1"
  case "$out" in
    *"code object is not signed"*) echo unsigned; return;;
    *"Authority=Software Signing"*|*"Authority=Apple Mac OS Application Signing"*) echo apple; return;;
    *"Signature=adhoc"*) echo adhoc; return;;
  esac
  local auth
  auth=$(printf '%s\n' "$out" | sed -n 's/^Authority=\(.*\)$/\1/p' | head -1)
  if [ -n "$auth" ]; then echo "developer:$auth"; else echo unknown; fi
}

# ---------- text filters ----------------------------------------------------------
# uh_hosts_nondefault < /etc/hosts -> prints entries that are not the stock macOS ones
uh_hosts_nondefault() {
  grep -vE '^[[:space:]]*#|^[[:space:]]*$' \
  | grep -vE '^(127\.0\.0\.1[[:space:]]+localhost|255\.255\.255\.255[[:space:]]+broadcasthost|::1[[:space:]]+localhost)[[:space:]]*$'
}

# uh_rc_suspicious < shell rc file -> prints lines that look like droppers / persistence
uh_rc_suspicious() {
  grep -nE 'curl[^|]*\|[[:space:]]*(ba|z)?sh|wget[^|]*\|[[:space:]]*(ba|z)?sh|base64[[:space:]]+(-d|--decode)|nohup[[:space:]]|python[23]?[[:space:]]+-c|osascript[[:space:]]+-e|/tmp/|/var/tmp/|launchctl[[:space:]]+(load|bootstrap)|crontab[[:space:]]+-|chflags[[:space:]]+hidden|\\.(dylib|so)\b|DYLD_INSERT_LIBRARIES|LD_PRELOAD' \
  | grep -vE '^[0-9]+:[[:space:]]*#'
}

# uh_is_apple_label <launchd label> -> 0 if it is an Apple label
uh_is_apple_label() {
  case "$1" in com.apple.*|"") return 0;; *) return 1;; esac
}

# uh_tcc_service_name <kTCCService...> -> friendly name
uh_tcc_service_name() {
  case "$1" in
    kTCCServiceScreenCapture)        echo "Screen Recording";;
    kTCCServiceAccessibility)        echo "Accessibility (control the Mac)";;
    kTCCServiceListenEvent)          echo "Input Monitoring (keylogger-capable)";;
    kTCCServiceMicrophone)           echo "Microphone";;
    kTCCServiceCamera)               echo "Camera";;
    kTCCServiceSystemPolicyAllFiles) echo "Full Disk Access";;
    kTCCServiceLocation)             echo "Location";;
    kTCCServicePostEvent)            echo "Send keystrokes";;
    kTCCServiceAppleEvents)          echo "Automation (AppleEvents)";;
    *)                               echo "$1";;
  esac
}
