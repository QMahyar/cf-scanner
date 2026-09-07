# Keeping Cloudflare ranges fresh

CF-Scanner bundles the official Cloudflare range lists, but Cloudflare
re-publishes them occasionally. Run `cf-scanner ranges refresh` (and
`--ipv6` if you scan IPv6) to update the copies in the data dir:

- Linux/macOS: `~/.local/share/cf-scanner` (or `$XDG_DATA_HOME`)
- Windows: `%APPDATA%\cf-scanner`
- Termux: `$PREFIX/var/home`-relative data dir (`cf-scanner` prints the
  exact path in errors)

A failed refresh never breaks a scan: the scan keeps the last-good file
and logs one warning. The refresh fetches
`https://api.cloudflare.com/client/v4/ips` over HTTPS and verifies the
SHA-256 sidecar of any xray download; only official Cloudflare URLs are
fetched.

## cron (Linux/macOS)

Weekly is plenty; the lists move slowly.

```cron
# m h dom mon dow  command
0 6 * * 1  /usr/local/bin/cf-scanner ranges refresh --ipv6
```

On macOS use launchd or the same line in a user crontab.

## systemd timer (Linux)

`~/.config/systemd/user/cf-scanner-ranges.service`:

```ini
[Unit]
Description=Refresh cf-scanner Cloudflare ranges

[Service]
Type=oneshot
ExecStart=%h/.local/bin/cf-scanner ranges refresh --ipv6
```

`~/.config/systemd/user/cf-scanner-ranges.timer`:

```ini
[Unit]
Description=Weekly cf-scanner range refresh

[Timer]
OnCalendar=Mon 06:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable with `systemctl --user enable --now cf-scanner-ranges.timer`.

## Windows Task Scheduler

```powershell
$action  = New-ScheduledTaskAction -Execute "$env:APPDATA\cf-scanner\cf-scanner.exe" `
             -Argument "ranges refresh --ipv6"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
Register-ScheduledTask -TaskName "cf-scanner range refresh" `
    -Action $action -Trigger $trigger -RunLevel Limited
```

## Termux

Termux has no cron by default; use `termux-job-scheduler` (Termux:API
add-on) or `cronie` from the Termux repo:

```sh
pkg install cronie termux-services
sv-enable crond
crontab -e   # add: 0 6 * * 1 $PREFIX/bin/cf-scanner ranges refresh --ipv6
```

The refresh command runs entirely offline-safe: if the network is down
the existing files stay in place and the scan proceeds on them.
