# Scheduled capture (MYB-11.8)

`mybench capture enable` combines the explicitly named repository binding
hooks with one daily OS-native reconciliation scan. It never starts a resident
mybench daemon.

## Enable and disable

First accept sources and repositories into the private scan config, then opt
the same repositories into continuous capture:

```sh
mybench init --detect claude,codex,git --root /path/you/chose --accept-all
mybench capture enable --repo /path/you/accepted
```

Scheduled mode is the default. Linux uses a systemd user oneshot service and
timer; macOS uses a launchd agent with `KeepAlive=false`. Both run only the
installed executable as `mybench scan --quiet --scheduled` once per day. They
contain no watch/repository arguments, content, filenames, nonces, keys,
credentials, network flags, or publication flags. If the owner selected an
explicit data-home root, the job preserves that operational root so it reads
the same private config and ledger. The hidden marker only lets the CLI record
scheduled-run health.

Private transcript preimage retention remains off by default. Owners who have
separately approved that local retention must opt the scheduled job in:

```sh
mybench capture enable --archive --repo /path/you/accepted
```

That explicit choice is stored in the private schedule receipt and adds only
`--archive` to the generated scan command. It changes no source paths, network
access, or publication behavior. `--archive --no-schedule` is refused because
there would be no scheduled scan to honor the retention choice.

If no supported user scheduler is reachable, enable the explicit manual
fallback:

```sh
mybench capture enable --repo /path/you/accepted --no-schedule
```

This installs the named repository hooks and records `manual` schedule state;
it does not invent a cron job or keep a process alive. `mybench status` shows
the distinction.

Clean teardown is explicit and idempotent:

```sh
mybench capture disable --repo /path/you/accepted
```

Disable removes only exact mybench-owned post-commit hooks, opt-in markers,
private enrollment/schedule state, and owned unit/plist files. A foreign,
symlinked, hardlinked, or malformed file is refused rather than overwritten or
removed. The consented scan config and append-only ledger remain intact.

## Failure and privacy behavior

The scheduled process exits after one scan. A failed run has no shell parent
to block and does not disable the timer/agent; the next daily activation still
runs. The private 0600 schedule receipt records only UTC attempt/success times,
the numeric exit code, result class, backend, installed executable path,
optional explicit data-home root, and the archive-retention boolean. Status
reports the failure without retrying or repairing it.

Plain scheduled scans remain offline. OpenTimestamps network refresh requires
the explicit `scan --upgrade` flag, which generated jobs never contain. No
schedule action publishes a report, anchor, package, or other artifact.
