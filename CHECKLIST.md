# MacBook compromise review — checklist

Work through this with `report.txt` and `FLAGS.txt` from `audit-mac.sh` open.
Each test says **what to run / look at**, **what normal looks like**, and **what is a red flag**.

Rule of thumb: one odd thing is usually a coincidence. Two or three odd things that
point at the same process or the same time window is a finding.

---

## 0. The battery symptom first (100% → sudden drop)

The script's section 2 answers this. Three causes, in order of likelihood:

| Test | Normal | Red flag |
|---|---|---|
| Battery health (`AppleRawMaxCapacity / DesignCapacity`) | ≥ 85 % | < 80 % → the gauge lies, battery is worn. **Not a hack.** |
| Cycle count | < 700 | ≥ 1000 → end of rated life |
| Condition (`system_profiler SPPowerDataType`) | `Normal` | `Service Recommended`, `Replace Soon` |
| Dark wakes in `pmset -g log` | a handful per night | dozens per night → Power Nap / Wake-on-LAN / Bluetooth drains while "asleep" |
| Top CPU (`ps -r`) with lid closed or idle | WindowServer, kernel_task, mds low | an unknown name at 50–100 % CPU constantly |
| Power assertions (`pmset -g assertions`) | none, or Music/Zoom while in use | a process you do not know holding `PreventUserIdleSystemSleep` |

If health < 80 % **and** no process stands out: the battery is the explanation. Calibrate
(drain to shutdown, charge to 100 % uninterrupted) once, then book a battery service.
Only if the battery is healthy and a process is burning CPU do the malware sections matter.

Fixes for dark wakes that are not malware: System Settings → Battery → Options → turn off
*Wake for network access* and *Enable Power Nap*; Bluetooth → Advanced → no wake by devices.

---

## 1. Security baseline

| Test | Normal | Red flag |
|---|---|---|
| `csrutil status` | `enabled` | `disabled` — only an attacker or you in Recovery can do this |
| `spctl --status` | `assessments enabled` | `disabled` |
| `fdesetup status` | `FileVault is On` | Off on a laptop |
| `nvram boot-args` | not set | anything set (e.g. `amfi_get_out_of_my_way`) |
| `profiles status -type enrollment` | `MDM enrollment: No` | `Yes` on a personal Mac — someone can push config and apps remotely |
| Profiles installed | none | any you did not install (VPN, "certificate", "WiFi" profiles are a classic) |
| `softwareupdate --history` | recent dates | no updates for months |

## 2. Persistence — how malware survives a reboot

Where the script looks: `/Library/LaunchDaemons`, `/Library/LaunchAgents`,
`~/Library/LaunchAgents`, login items (`sfltool dumpbtm`), cron, `at`, login hooks,
`emond`, shell rc files, kexts, system extensions.

| Test | Normal | Red flag |
|---|---|---|
| Launch item signature column | `apple` or `developer:<vendor you know>` | `unsigned`, `adhoc`, `missing`, or a developer you have never heard of |
| Launch item program path | `/Applications/X.app/...`, `/usr/local/...`, `/opt/homebrew/...` | `/tmp`, `/Users/Shared`, `~/Library/...` hidden dir, `/var/folders`, or a random-looking name like `com.update.helper` |
| Label | reverse-DNS of a vendor | typo-squats: `com.apple.softwareupdate.plist` in `/Library/LaunchAgents` (Apple never puts anything there), `com.google.keystone` is legit but `com.googIe...` is not |
| `crontab -l` | empty | anything, especially `@reboot` or every-minute jobs |
| `~/.zshrc` etc. | aliases, PATH, brew/nvm | `curl ... \| bash`, `base64 -d`, `nohup`, `/tmp/`, `DYLD_INSERT_LIBRARIES` |
| Login items in System Settings | apps you installed | names you do not recognise, or "Unknown developer" |
| `kextstat` non-Apple | none on Apple silicon | any |
| `systemextensionsctl list` | VPN / security tools you installed | an unknown Network or Endpoint extension (can see every packet / every file event) |

Manual follow-up for anything flagged:
```bash
cat /Library/LaunchDaemons/<name>.plist
codesign -dv --verbose=4 "<program path>"
ls -la@ "<program path>"          # @ shows quarantine attribute and when it was downloaded
mdls -name kMDItemWhereFroms "<program path>"
```

## 3. Network

| Test | Normal | Red flag |
|---|---|---|
| `lsof -nP -iTCP -sTCP:LISTEN` | `rapportd`, `ControlCenter`, `sharingd`, dev servers you started | `sshd` / `screensharingd` you did not enable; a listener on a high random port owned by a process from §8 |
| Established connections grouped by process | browsers, Mail, Messages, cloud sync, Spotify | a process you cannot name holding a long-lived connection; many connections to one raw IP |
| `scutil --dns` nameservers | your router (192.168.x.1), 1.1.1.1, 8.8.8.8, 9.9.9.9 | an unknown public IP |
| `scutil --proxy` | all `Enable : 0` | any proxy or PAC URL enabled — full traffic interception |
| `/etc/hosts` | the 3 stock lines | redirects for banks, apple.com, update servers |
| `ifconfig` tunnels | `utun0-3` are normal (iCloud Private Relay, VPN you use) | a tunnel from a VPN you never installed |
| Remote tools in `ps` | none, or one you use | TeamViewer / AnyDesk / RustDesk / ngrok / cloudflared you did not install |
| System Settings → General → Sharing | everything off | Remote Login, Screen Sharing, Remote Management on |

Deeper, when a suspicious process appears: install **LuLu** (Objective-See, free) and let it
alert on every new outbound connection for a day. Note every process it asks about.

## 4. Accounts & access

| Test | Normal | Red flag |
|---|---|---|
| `dscl . list /Users UniqueID` ≥ 500 | you, maybe family | an account you did not create |
| Hidden users | none | any |
| `dscl . -read /Groups/admin GroupMembership` | root + you | an extra admin |
| root account | disabled | enabled |
| Guest / auto-login | off | on |
| `/etc/sudoers.d` | empty | `NOPASSWD` rules |
| `~/.ssh/authorized_keys` | absent or your own keys | a key you do not recognise |
| `last` | your logins, `reboot`, `shutdown` | logins at hours you were asleep, `ttys` sessions you did not open |

Then, **from a different device**: check Apple ID → Devices for unknown devices,
Google/Microsoft account → security → sessions, and sign out everything you do not recognise.

## 5. Privacy grants (TCC) — the surveillance check

System Settings → Privacy & Security. Open each of these and read every entry:

| Permission | Normal holders | Red flag |
|---|---|---|
| Screen Recording | Zoom, Teams, Loom, OBS, CleanShot | anything else, especially a "helper" or no icon |
| Input Monitoring | Karabiner, BetterTouchTool, Logi Options | unknown = keylogger-capable |
| Accessibility | window managers, 1Password, Alfred/Raycast, Rectangle | unknown = can click and type as you |
| Microphone / Camera | conferencing, browsers | unknown |
| Full Disk Access | Terminal (you just added it), backup tools, AV | unknown |
| Automation | apps you set up Shortcuts/scripts for | unknown |

Also: the orange (mic) / green (camera) dot in the menu bar appearing when nothing of yours
is running is a direct indicator. Click it to see the process name.

## 6. Applications and downloads

| Test | Normal | Red flag |
|---|---|---|
| Quarantine events (last 30 downloads) | things you remember downloading | installers / `.dmg` / `.pkg` you do not remember, especially from short-link or raw-IP URLs |
| App signature column | `developer:...` of the vendor, `apple` | `unsigned` / `adhoc` apps that are not your own builds |
| Browser extensions | ones you installed | unknown IDs; "search", "coupon", "PDF converter", "VPN" extensions you never added |
| Executables in `/tmp`, `/Users/Shared` | none | any |
| Hidden dirs in `~` | dotfiles of dev tools | `.something` you cannot explain, recently modified |

Second-opinion scanners (free, reputable):
- **KnockKnock** (Objective-See) — lists everything persistently installed with VirusTotal lookups. Best single tool for this job.
- **Malwarebytes for Mac** — one-off scan, then uninstall if you want.
- Apple's own XProtect runs in the background already; the script prints its version.

## 7. Running processes

| Test | Normal | Red flag |
|---|---|---|
| `SUSPICIOUS-PATH` lines | none | any — note the pid and `lsof -p <pid>` it |
| Non-Apple running executables and signature | your apps, homebrew tools | `unsigned` / `adhoc` daemons, names mimicking Apple (`com.apple.*` from non-System paths), single-letter or random names |
| Processes with network connections | browsers, sync clients, mail | a name from the previous two rows |

For any suspect pid:
```bash
lsof -p <pid>            # files, libraries and sockets it has open
ps -p <pid> -o lstart,command
sudo fs_usage -w -f filesys <pid>   # live view of what it touches (Ctrl-C to stop)
```

## 8. Decision

**Probably clean** — no HIGH flags, battery health < 80 % or heavy dark wakes: fix power
settings / battery and stop here.

**Suspicious** — one HIGH flag you cannot explain, or two MED flags pointing at the same
thing: run KnockKnock, remove the item (unload the launch agent, delete the plist and the
program, remove the login item), change your passwords **from another device**, re-run the
audit after a reboot.

**Compromised** — unknown admin user, MDM enrolment, SIP off, Screen Recording / Input
Monitoring granted to an unknown app, remote-control tool you did not install, or a
persistent item that comes back after removal:
1. Disconnect from Wi-Fi now. Do not log in to anything else from this Mac.
2. From a phone or other computer: change Apple ID password, enable 2FA, remove unknown
   devices; then email, bank, password manager.
3. Back up only documents (not apps, not Library) to an external disk.
4. System Settings → General → Transfer or Reset → **Erase All Content and Settings**.
   Set up as new; do not restore from the Time Machine backup made while compromised.
5. If you believe you are personally targeted: turn on **Lockdown Mode** after the reset.

## 9. Things that are *not* evidence of hacking

- Fans spinning after an update: Spotlight (`mds`, `mdworker`) and Photos re-indexing.
- `rapportd`, `sharingd`, `identityservicesd`, `nsurlsessiond` using the network: iCloud/Handoff.
- `utun` interfaces: iCloud Private Relay.
- `kernel_task` at high CPU: thermal management, not a process you can kill.
- Battery jumping 100 % → 85 % → 60 %: worn cells or a stale gauge — see §0.
