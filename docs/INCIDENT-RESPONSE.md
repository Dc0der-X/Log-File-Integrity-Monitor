# Incident response runbook

What to do when LogSentry fires. Written for whoever is on call at 03:00, so it
leads with the actions and explains afterwards.

> **The first rule:** if a log file was tampered with, the host is compromised
> until proven otherwise. Log tampering is not a symptom of a misconfiguration.
> It is post-exploitation cleanup, and it means someone was already inside with
> enough privilege to write to `/var/log`.

---

## Triage by verdict

| Verdict | Urgency | First move |
|---|---|---|
| `APPENDED`, `ROTATED` | None | Nothing. Normal activity |
| `NEW` | Same day | Identify what wrote the file |
| `PERMS` | Same day | Compare against your configuration baseline |
| `TIMESTOMP` | **Now** | Almost never benign — go to §3 |
| `MODIFIED` | **Now** | §3 |
| `TRUNCATED`, `DELETED` | **Now** | §3 |
| `SEAL` broken | **Now** | §2 — the monitoring itself is suspect |

---

## 1. Before you touch anything

Do these in order, and do not skip step 2.

**1. Do not run `logsentry accept`.** It rebuilds the baseline from what is on
disk right now — the attacker's version — and destroys your ability to prove
what changed. The prompt exists for exactly this reason.

**2. Preserve the evidence you already have.**

```bash
# Copy the baseline, the seal, and the scan off the host, to somewhere the
# host cannot reach.
scp -r /var/lib/logsentry/ evidence@ir-station:/cases/$(hostname)-$(date +%F)/
scp /var/log/logsentry/events.jsonl evidence@ir-station:/cases/…/
```

The baseline is a cryptographic record of what the files looked like before.
That is the single most valuable artefact you have, and it lives on the host
the attacker controls.

**3. Snapshot the current state of the affected files.**

```bash
sudo cp -a /var/log/auth.log /var/log/auth.log.$(date +%s).evidence
sudo md5sum /var/log/auth.log* > /tmp/current-hashes.txt
```

`cp -a` preserves timestamps and ownership.

**4. Capture the report.**

```bash
sudo logsentry report --format html -o ~/incident-$(date +%F-%H%M).html
sudo logsentry report --format json > ~/incident-$(date +%F-%H%M).json
```

`report` re-renders the last scan without re-reading the files, so it will not
disturb the timestamps you just preserved.

---

## 2. If the seal is broken

```
[x] BASELINE SEAL BROKEN
```

`baseline.db` was modified after it was sealed. Someone tried to make their log
edits look legitimate by rewriting the record of what "legitimate" means.

**Every clean result produced since is unreliable.** Treat this as the most
serious finding LogSentry can produce.

1. **Do not re-seal.** `logsentry init` would overwrite the evidence.
2. Get `baseline.db`, `baseline.seal` and every `baseline.db.<timestamp>`
   archive off the host now.
3. Look for an earlier archive that still verifies. `accept` archives each
   superseded baseline, so there may be a trustworthy record from before the
   tampering:
   ```bash
   ls -la /var/lib/logsentry/baseline.db.*
   ```
4. Establish who could write to `/var/lib/logsentry`. It is mode `0700` and
   root-owned, so realistically: root, or someone who reached root.
5. Escalate. This is a confirmed intrusion, not a monitoring glitch.

If you were running with `BASELINE_SEAL_KEY` held **off** the host, a broken
seal means the attacker could not forge it — which is the control working as
designed. If the key was in `/etc/logsentry/logsentry.conf` on the monitored
host, assume they had it.

---

## 3. If log content was altered

### Establish what changed

The JSON output gives you the specifics:

```bash
logsentry report --format json | grep -A3 '"severity": "HIGH"'
```

You will get the file, the baseline size, and the current size. For a
`MODIFIED` verdict, the region that changed is the first `baseline_size` bytes.

### Recover the original content, if you can

You almost never recover it from the host itself. Look, in this order:

1. **Your central log server.** If you ship logs off-box, the pre-tampering
   version is already there. This is the reason to ship logs off-box.
2. **The rotated archives.** `auth.log.1`, `auth.log.2.gz` — an attacker who
   edited the live file often forgets the archives.
3. **Backups and filesystem snapshots.** ZFS/Btrfs snapshots, LVM, your backup
   system. Restore to a scratch location, never over the evidence.
4. **`journalctl`.** On systemd hosts the journal is a separate store from
   `/var/log/*.log`, with its own binary format. An attacker who edited the
   text logs may not have touched it:
   ```bash
   journalctl --since "2026-09-03 09:00" --until "2026-09-03 12:00" -u ssh
   ```

### Diff what you recovered

```bash
diff <(zcat /var/log/auth.log.1.gz) /var/log/auth.log
```

The lines that are missing are the ones the attacker wanted gone. **They are
your best lead** — they usually name the source IP, the account used, and the
time of the intrusion.

### Pivot from what was removed

```bash
# The account that appears in the removed lines
sudo lastlog | grep -v 'Never logged in'
sudo last -F | head -40

# Persistence
sudo crontab -l; sudo ls -la /etc/cron.*/ /var/spool/cron/
sudo systemctl list-units --type=service --state=running
ls -la ~/.ssh/authorized_keys /root/.ssh/authorized_keys

# Files written around the time of the tampering
sudo find / -xdev -newermt "2026-09-03 09:00" ! -newermt "2026-09-03 12:00" \
     -type f -ls 2>/dev/null | head -50
```

Cross-reference against the `NEW` findings — a file that appeared in
`/var/log` since the baseline is a strong candidate for a dropped payload, and
`.`-prefixed names there are not normal.

---

## 4. If a file was truncated or deleted

`TRUNCATED` on a log file has essentially no benign explanation outside of
rotation, which LogSentry already accounts for. Someone ran `: > file`,
`truncate`, or `rm`.

```bash
# How much was destroyed
logsentry report --format json | grep -B2 -A2 TRUNCATED

# Is the file still held open by a process? The content may be recoverable
# from /proc even after deletion.
sudo lsof +L1 | grep -i log
sudo ls -la /proc/*/fd/ 2>/dev/null | grep -i deleted
```

If a process still holds the deleted inode open, you can recover it:

```bash
sudo cp /proc/<pid>/fd/<fd> /tmp/recovered.log
```

Do this **before** restarting anything. Restarting the service closes the
descriptor and the content is gone for good.

---

## 5. Containment

Once you have preserved evidence and know roughly what happened:

1. **Isolate the host** — network segment or security group, not shutdown. A
   shutdown destroys memory-resident evidence and any deleted-but-open files.
2. **Do not reboot** for the same reason.
3. **Rotate credentials** that the host held: SSH keys, API tokens, database
   passwords, cloud instance credentials. Assume everything readable on that
   box is now known.
4. **Check laterally.** If you have a fleet, run `logsentry check` across it —
   the same actor is often on more than one host:
   ```bash
   ansible all -m command -a "logsentry check --quiet" --become
   ```
5. **Preserve, then rebuild.** Image the disk if the case warrants it. Do not
   clean and return a compromised host to service; rebuild from known-good
   media.

---

## 6. After the incident

**Only once the investigation is closed**, re-establish a baseline on the
rebuilt host:

```bash
sudo logsentry init          # on a host you have reason to trust
sudo logsentry check         # confirm clean
sudo logsentry status        # confirm the seal
```

Then close the gaps the incident exposed:

- **Ship logs off-host in real time.** Everything in this runbook was harder
  than it needed to be because the only copy was on the compromised machine.
- **Move the seal key off the host.** Set `BASELINE_SEAL_KEY` from removable
  media or a management station, so a root attacker cannot forge the seal.
- **Put the baseline on append-only or read-only storage** where the platform
  supports it (S3 Object Lock, a WORM volume, a read-only mount).
- **Shorten the interval** on high-value hosts. `CHECK_INTERVAL=15` costs very
  little and narrows the window.
- **Alert on the monitor going quiet.** A check that stops running is itself a
  signal; a systemd timer that stops firing should page someone.

---

## Quick reference

```bash
logsentry verify                       # is the baseline itself trustworthy?
logsentry status                       # age, file count, seal state
logsentry report --format json         # machine-readable last scan
logsentry report --format html -o r.html
ls -la /var/lib/logsentry/baseline.db.*  # archived baselines = history
```

**Never during an active investigation:**

```bash
logsentry init      # overwrites the root of trust
logsentry accept    # blesses the attacker's version as normal
```

---

**See also:** [DETECTION-LOGIC.md](DETECTION-LOGIC.md) ·
[ARCHITECTURE.md](ARCHITECTURE.md) · [USAGE.md](USAGE.md)
