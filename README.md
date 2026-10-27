# unhuckMach

Read-only audit script + review checklist for a MacBook you suspect is compromised
(or that just drains battery in a way you cannot explain).

It does not install anything, does not change settings, does not send data anywhere.
It writes one report folder on your Desktop and prints a list of flags.

## Run it (on the Mac)

```bash
git clone https://github.com/hrco/unhuckMach.git
cd unhuckMach
sudo ./audit-mac.sh            # full coverage; ~1–2 minutes
# or: ./audit-mac.sh --quick   # no sudo, skips signature checks of every app/process
# or: sudo ./audit-mac.sh --deep   # adds SUID scan + 2 days of unified log (slow)
```

Before the first run, give Terminal **Full Disk Access**
(System Settings → Privacy & Security → Full Disk Access), otherwise the privacy-grant
(TCC) and download-history sections print "cannot read".

Output: `~/Desktop/unhuckmach-<timestamp>/report.txt` and `FLAGS.txt`.
Then open [CHECKLIST.md](CHECKLIST.md) and go through the sections that raised flags.

The report contains your usernames, apps, connections and download history.
Do not paste it into public forums or to people you do not fully trust.

## What it checks

| Section | Covers |
|---|---|
| 0–1 | macOS version, SIP, Gatekeeper, FileVault, firewall, XProtect version, boot-args, MDM |
| 2 | **Battery**: health %, cycle count, condition, dark wakes, power assertions, top CPU |
| 3 | Persistence: launch daemons/agents (+ code signature of each program), login items, cron/at, login hooks, emond, shell rc droppers, kexts, system extensions, profiles |
| 4 | Network: listeners, established connections per process, DNS, proxies, tunnels, `/etc/hosts`, remote-access tools, sharing services |
| 5 | Accounts: users, hidden users, admins, root, guest/auto-login, sudoers, `authorized_keys`, login history |
| 6 | Privacy grants (TCC): Screen Recording, Input Monitoring, Accessibility, mic, camera, Full Disk Access |
| 7 | Apps: last 30 downloads (quarantine db), app signatures, browser extensions, executables in temp/shared dirs, hidden dirs, recently changed binaries |
| 8 | Running processes from suspicious paths, unsigned running executables, processes with sockets |
| 9 | (`--deep`) unified log: sudo, ssh, screen sharing, new background items, TCC grants |

Flags are `[HIGH]`, `[MED]`, `[LOW]`. A flag is a reason to look, not a verdict —
the checklist says what is normal for each one.

## Tests

```bash
tests/run.sh
```

Runs on Linux/CI (syntax, CLI, every helper in `lib/checks.sh` against fixtures) and on
macOS additionally performs a real `--quick` audit into a temp dir and checks the report
structure. Compatible with the stock macOS `/bin/bash` 3.2.

## Layout

```
audit-mac.sh      the audit
lib/checks.sh     pure helpers (battery maths, path/signature classification, text filters)
CHECKLIST.md      manual review guide: normal vs red flag per test, what to do next
tests/run.sh      test runner + tests/fixtures/
```
