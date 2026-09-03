# Detection logic

How LogSentry decides that a change to a log file is routine, suspicious, or an
emergency — and why the obvious approaches fail.

---

## 1. Why comparing digests is not enough

The textbook file-integrity check is:

```bash
md5sum /var/log/auth.log > auth.log.md5    # baseline
md5sum -c auth.log.md5                     # later
```

This is correct and useless at the same time. It is correct because any change
to the file changes the digest. It is useless because `auth.log` changes every
few seconds by design — `sshd` writes to it, `sudo` writes to it, `cron` writes
to it. Run that check on a real host and it fails continuously.

The predictable consequences:

1. The alert fires constantly.
2. Someone silences it "until we have time to tune it".
3. Nobody ever has time.
4. When it matters, the channel is muted.

An integrity monitor for log files has to distinguish **growth**, which is what
log files do, from **modification of what was already written**, which is what
attackers do. Those two events produce identical evidence under a whole-file
digest comparison.

## 2. The prefix hash

At baseline time LogSentry records, for each file:

| Field | Why |
|---|---|
| `hash` | Digest of the entire file |
| `size` | Byte count — the boundary of the region the digest covers |
| `mtime` | Modification time, to catch backdating |
| `inode` | To recognise rotation |
| `mode`, `owner`, `group` | Metadata drift is a finding of its own |

The size is the important one, and not for the reason it looks. It is not there
as a cheap change check. It is there because **`size` marks the exact boundary
of the bytes that `hash` covers.**

At check time:

```bash
head -c "$baseline_size" "$file" | md5sum      # digest of the baselined region, today
```

If that equals the baseline digest, then every byte that existed when the
baseline was taken is still exactly where it was, unchanged. Anything after
that boundary is new material, appended after the fact.

```
  baseline           ┌──────────── S bytes, digest H ────────────┐
                     │ Sep 3 09:14 sshd: Accepted publickey …    │
                     │ Sep 3 10:03 sshd: Failed password …       │
                     │ Sep 3 10:07 sshd: Accepted password root  │
                     └───────────────────────────────────────────┘

  append             ┌──────────── S bytes, digest H ────────────┬─── new ───┐
                     │ …unchanged…                               │ Sep 3 11:41│
                     └───────────────────────────────────────────┴───────────┘
                       hash(head -c S) == H          →  APPENDED    INFO

  rewrite            ┌──────────── S bytes, digest H' ───────────┬─── new ───┐
                     │ Sep 3 10:07 sshd: Connection closed …     │ Sep 3 11:41│
                     └───────────────────────────────────────────┴───────────┘
                       hash(head -c S) != H          →  MODIFIED    HIGH
```

That comparison is the whole engine. Everything else is handling the cases
where it does not apply.

**Implementation:** [`lib/common.sh`](../lib/common.sh) → `ls_hash_prefix()`,
[`lib/detect.sh`](../lib/detect.sh) → `ls_classify()`.

## 3. The decision table

Evaluated in this order. `S`/`H` are the baseline size and digest; `s`/`h` are
today's.

| # | Condition | Verdict | Severity |
|---|---|---|---|
| 1 | Path does not exist | `DELETED` | CRITICAL |
| 2 | Path exists but is unreadable | `UNREADABLE` | HIGH |
| 3 | mode/owner/group differ | `PERMS` *(also emitted)* | MEDIUM |
| 4 | new mtime **<** old mtime | `TIMESTOMP` *(also emitted)* | MEDIUM |
| 5 | `h == H` and `s == S` | `OK` | — |
| 6 | `s < S` and an archived sibling exists | `ROTATED` | INFO |
| 7 | `s < S` | `TRUNCATED` | CRITICAL |
| 8 | `s == S` and `h != H` | `MODIFIED` | HIGH |
| 9 | `s > S` and `hash(head -c S) == H` | `APPENDED` | INFO |
| 10 | `s > S` and `hash(head -c S) != H` | `MODIFIED` | HIGH |
| 11 | On disk, absent from the baseline | `NEW` | LOW |

Rules 3 and 4 are *additive*: a file can produce a `PERMS` finding and a
`MODIFIED` finding in the same scan, because "someone loosened the permissions"
and "someone edited the content" are two separate facts an analyst needs.

### Why rule 5 still hashes the file

Size and mtime unchanged almost always means the file is untouched — and
"almost" is not a standard an integrity tool gets to work to. An in-place edit
of identical length followed by `touch -r` to restore the timestamp is a
textbook anti-forensic move, and it leaves size and mtime pristine.

So LogSentry always computes the digest. The size comparison only decides
*which* digest to take: the whole file, or the prefix.

### Why rule 8 exists separately

Same size, different content. There is no benign explanation for a log file
whose byte count is identical but whose content changed — logging appends, it
does not overwrite in place. This is deliberate tampering, and the detail line
says so: *"size unchanged at 922 bytes but the digest differs — content swapped
in place."*

Any monitor that compares size and mtime and stops there returns **clean** for
this case. It is the first thing the test suite checks
(`inplace_edit_same_size_is_high`).

### Why rule 10 exists separately

The file grew *and* the earlier bytes changed. A shortcut like "size went up,
therefore an append, therefore fine" waves this straight through, and that
shortcut is exactly how an attacker would want the tool to be written: rewrite
the history, then append enough filler to end up larger than the baseline.

Covered by `append_that_rewrites_history_is_high`.

## 4. The rotation problem

`logrotate` does this, nightly, on every Linux host:

```
mv auth.log auth.log.1      # or auth.log-20260903, or auth.log.1.gz
touch auth.log              # fresh file, new inode, 0 bytes
```

To an integrity monitor that is indistinguishable from a log wipe: the file at
`/var/log/auth.log` just shrank from 4 MB to nothing. A tool that cries
CRITICAL every night at 06:25 gets muted within a week — the same failure mode
as alerting on appends, arriving by a different route.

LogSentry checks two things before calling a shrink a wipe:

1. **Did the inode change?** Rotation replaces the file; truncation
   (`: > file`) reuses it. An inode change is evidence of replacement.
2. **Is there an archived copy alongside?** `ls_looks_rotated()` looks for
   `auth.log.1`, `auth.log.0`, `auth.log.1.gz`, and `auth.log-*`. Rotation
   leaves the old content behind; a wipe does not.

Both true → `ROTATED`, INFO. Otherwise → `TRUNCATED`, CRITICAL.

**This heuristic is honest about its limits.** An attacker who knows the tool
can rename the file to `auth.log.1` before truncating and land in the INFO
bucket. Two defences: `logsentry accept` archives the superseded baseline so
the rotation is at least *recorded*, and the archived siblings are themselves
monitored if they are inside a watched directory and not excluded. If you would
rather have the false positives, remove `*.gz` from `EXCLUDE_PATTERNS` and
treat every rotation as a reviewable event.

**Implementation:** [`lib/detect.sh`](../lib/detect.sh) → `ls_looks_rotated()`.
Tested by `rotation_is_not_a_wipe`.

## 5. Timestomping

`touch -t 202001010000 /var/log/auth.log` sets the modification time to
whatever the attacker likes. Tools that trust `mtime` to decide whether to
re-read a file can be walked straight past the evidence.

LogSentry never uses `mtime` to decide whether to hash — it hashes
unconditionally. `mtime` is used for exactly one thing: **detecting that it
moved backwards.** Time does not run backwards on a healthy system, so a file
whose mtime is earlier than it was at baseline had its timestamp set by hand.

That is `TIMESTOMP`, MEDIUM. It is rarely the only finding — in the demo it
appears next to the `MODIFIED` it was meant to conceal.

## 6. Severity and exit codes

| Severity | Exit | Meaning | Response |
|---|---|---|---|
| INFO | 0 | Normal log activity | None |
| LOW | 1 | Worth a look | Review during the day |
| MEDIUM | 1 | Configuration or metadata drift | Review same day |
| HIGH | 2 | Log content was altered | Investigate now |
| CRITICAL | 3 | Content destroyed, or the baseline itself is compromised | Incident response |

The process exits with the **highest** severity it found. A monitoring agent
needs no output parser:

```bash
logsentry check --quiet
case $? in
  0) ;;                                  # clean
  1) notify "logsentry: review needed" ;;
  2) page  "logsentry: log tampering" ;;
  3) page  "logsentry: CRITICAL"      ;;
esac
```

Under systemd, `SuccessExitStatus=0 1 2 3` in the unit keeps a detection from
being reported as a unit failure — the findings go to syslog and the JSONL
event file, which is where they belong.

## 7. What this does not catch

- **A compromised baseline.** If the attacker rewrites `baseline.db` to match
  their edited logs, every check comes back clean. This is what the seal exists
  for; see [ARCHITECTURE.md](ARCHITECTURE.md#threat-model).
- **Log entries that were never written.** Stopping `rsyslog` before acting
  leaves nothing to tamper with. Monitor that your logging daemon is running.
- **Tampering entirely within the check interval on a file that is then
  restored byte-for-byte.** If the file is returned to its exact original
  content, there is nothing left to detect. In practice attackers remove
  evidence rather than restore it.
- **In-memory tampering** before the data is ever written to disk. LogSentry
  watches files, not processes.

---

**See also:** [ARCHITECTURE.md](ARCHITECTURE.md) ·
[INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md) · [USAGE.md](USAGE.md)
