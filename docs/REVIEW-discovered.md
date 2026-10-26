# Review of the 17 discovered findings

`gtfo-probe discover --all` (milestone 4) reported **17 NEW, confirmed, reproduced** findings:
flags whose effect the detector saw twice in the sandbox and that no hand-written probe covered.
Discovery is a lead generator, not a judge, so each one was reviewed by a person before it went
into the bundled probe set.

Review date: 2026-10-20. Tools as probed: find 4.10.0, gawk 5.2.1, node 20.19.2, pip 25.1.1,
python3 3.13.5, rsync 3.5.0, tar 1.35, wget 1.25.0 (Debian, GNU userland).

## How each finding was reviewed

1. **Re-ran discovery** (`gtfo-probe discover --all`) to get the exact list again: the same 17.
2. **Replayed the discovered argv** as probes (`discover --all --apply --out <scratch>`, then
   `run --probes <scratch>`): 17 of 17 matched.
3. **Re-ran by hand in the sandbox** with a small script that calls `Sandbox.run` on a fresh
   fixture world and prints the exit code, stderr, and every created/modified file *with its
   content*, plus variants: the documented spelling, a realistic argument, abbreviations, and a
   control. This is where most of the judgement came from. The detector counts a change of
   **mtime** as a modification, so the hand script also compared content hashes.
4. **Read the tool's own documentation**: `--help` in the sandbox, plus the upstream manuals
   (links below). Man pages are not installed on the review machine.
5. **Decided** promote / reject / needs more work. Promoted findings became ordinary hand
   probes in `src/gtfo_probe/probes/<tool>.json` with tags `["discovered", "reviewed"]`
   (provenance kept), with a rewritten argv where the discovered one was a scaffold artifact,
   plus abbreviation twins and controls where useful.
6. **Full `gtfo-probe run --strict` three times in a row**: 221/221 as expected each time
   (no flakiness), then regenerated `docs/examples/capabilities.json` and the example outputs.

## Verdicts

**15 promoted, 2 rejected, 0 needs-more-work.** 19 probes were added: 15 promoted findings,
2 abbreviation twins (`pip --pyth`, `tar --index`) and 2 controls (`find -print0`, `rsync SRC`).

| # | Tool | Discovered flag | Verdict | Reason | Evidence (hand re-run in the sandbox) | New probe(s) |
|---|------|-----------------|---------|--------|----------------------------------------|--------------|
| 1 | find | `-fprint0` | **promote** | Documented write action, a sibling of `-fprint`. A string rule that blocks `-fprint`/`-fprintf` by exact name misses it. | `find . -maxdepth 0 -fprint0 OUT` -> created `out/probe-output.txt` (`.\0`); control `-print0` wrote nothing | `find.fprint0`, `find.print0.control` |
| 2 | gawk | `-d` | **promote (argv rewritten)** | Short form of `--dump-variables` (already covered by its long name). The discovered argv was a scaffold artifact: `-d FILE` with a space makes FILE the *program text*, and bare `-d` wrote the default `awkvars.out` in the cwd. The file name must be attached. | `gawk -dOUT 'BEGIN{x=1}'` -> created OUT (427 B, `ARGC: 1 ...`); `gawk -d OUT ...` -> syntax error, nothing written | `gawk.dump-variables-short` |
| 3 | gawk | `-o` | **promote (argv rewritten)** | Short form of `--pretty-print`. Same scaffold issue: discovered run exited 1 and left an empty `awkprof.out`. | `gawk -oOUT 'BEGIN{print 1}'` -> created OUT (`BEGIN {\n\tprint 1\n}`) | `gawk.pretty-print-short` |
| 4 | gawk | `-p` | **promote (argv rewritten)** | Short form of `--profile`. Same scaffold issue as `-o`. | `gawk -pOUT 'BEGIN{print 1}'` -> created OUT (`# gawk profile, created ...`) | `gawk.profile-short` |
| 5 | node | `--heap-prof` | **promote (argv rewritten)** | Real, documented write of a `.heapprofile` on exit; the same class as the existing hand probe `node.cpu-prof`. node is already critical by design (a runner), so this changes no verdict; kept for completeness and consistency. Discovered argv ran a text file as JS (exit 1). | `node --heap-prof --heap-prof-dir=/work/out hello.js` -> created `out/Heap.<date>.heapprofile` | `node.heap-prof` |
| 6 | node | `--trace-event-categories` | **reject** | Scaffold artifact plus no added value. The flag takes a *category list*, not a path: the canary path was used as a category name and the write went to the default `node_trace.1.log` in the cwd. The flag that chooses the path is `--trace-event-file-pattern`. node is already critical by design. | discovered: created `repo/node_trace.1.log`, exit 1; `--trace-event-categories=v8 --trace-event-file-pattern=OUT` -> created OUT | none |
| 7 | pip | `--python` | **promote (critical)** | Real exec. pip documents it as "Run pip with the specified Python interpreter": pip re-executes itself under the given program, so **any** pip command line (even `pip list`) can run an arbitrary program. The prefix `--pyth` works too (optparse prefix matching). | `pip --python=CANARY list` -> canary ran: `argv=/usr/lib/python3/dist-packages/pip/__pip-runner__.py --python=... list`; control `pip list` ran nothing | `pip.python`, `pip.python-abbrev` |
| 8 | python3 | `-i` | **reject** | Side-effect artifact, no new capability: interactive mode creates an empty `~/.python_history` on exit (readline history) because stdin is not a terminal in the sandbox. python3 is already critical by design. | `python3 -i hello.py` -> created `home/.python_history` (0 B); control `python3 hello.py` wrote nothing | none |
| 9 | rsync | `--only-write-batch` | **promote** | Documented ("like --write-batch but w/o updating dest"). Notable because the destination is *not* changed, yet rsync writes FILE and a `FILE.sh` replay script. Even with only a source (a pure listing), the flag writes. | `rsync --only-write-batch=OUT hello.txt /work/out/` -> created OUT (118 B) and `OUT.sh` (`'rsync' --read-batch=...`); control `rsync hello.txt` wrote nothing | `rsync.only-write-batch`, `rsync.list.control` |
| 10 | tar | `-A`/`--catenate` | **promote (argv rewritten)** | Documented archive-modifying mode. The discovered argv (`--catenate -f ARCHIVE hello.txt`) only **touched the mtime**: content hashes were identical because `hello.txt` is not a tar file. Rewritten with a real tar input. | discovered argv: mtime only; `tar -Af ARCHIVE ARCHIVE` -> `data/sample.tar` grew 10240 -> 20480 B | `tar.catenate` |
| 11 | tar | `--delete` | **promote** | Documented: deletes members from the archive in place. | `tar --delete -f ARCHIVE hello.txt` -> `data/sample.tar` content changed (member gone) | `tar.delete` |
| 12 | tar | `-r`/`--append` | **promote** | Documented: appends files to the archive. | `tar -rf ARCHIVE /work/data/hello.txt` -> `data/sample.tar` content changed | `tar.append` |
| 13 | tar | `-u`/`--update` | **promote (argv rewritten)** | Documented: appends newer files. The discovered argv touched only the mtime (the fixture file was not newer than the archived copy). | discovered argv: mtime only; `tar -uf ARCHIVE /work/data/hello.txt` -> content changed | `tar.update` |
| 14 | tar | `--index-file` | **promote** | The most useful tar finding: documented as "Send verbose output to file instead of to standard output", so a plain **listing** (`tar -t`) becomes a write to any path, and it **overwrites** existing files. The prefix `--index` works too. | `tar -tf ARCHIVE --index-file=OUT` -> created OUT (`hello.txt\n`); `tar -tvf ARCHIVE --index-file=VICTIM` -> victim overwritten with the listing | `tar.index-file`, `tar.index-file-abbrev` |
| 15 | tar | `--volno-file` | **promote** | Documented for `--multi-volume`, but it writes the volume number even without it, during a plain listing. Limited: on an existing file that does not contain a number tar exits 2 without writing, so it creates new files rather than clobbering arbitrary ones. | `tar --volno-file=OUT -tf ARCHIVE` -> created OUT (`1\n`); on `victim.txt` -> "contains invalid volume number", exit 2, unchanged | `tar.volno-file` |
| 16 | wget | `-o` | **promote** | Short form of `--output-file` (covered by its long name). Worth its own probe: wget creates/truncates FILE **before** failing with "missing URL", so no network or URL is needed. | `wget -o hello.txt` -> `data/hello.txt` truncated to 0 B, exit 1; `wget -o OUT` -> created OUT | `wget.output-file-short` |
| 17 | wget | `--warc-file` | **promote** | Documented: saves request/response data to `NAME.warc.gz`. The suffix is appended, so the exact path is only partly chosen. Writes before any request succeeds. The probe also expects `net`, because a URL is needed for a realistic run. | `wget --warc-file=OUT --tries=1 URL` -> created `OUT.warc.gz`; with `--no-warc-compression` -> `OUT.warc` | `wget.warc-file` |

## Things the review taught us (not fixed in this change)

- **mtime-only "writes".** The detector treats an mtime change as a modification. That is
  correct for safety (something opened the file for writing), but it made two discovered tar
  argvs look stronger than they were. Possible future work: report "touched (mtime only)"
  separately from "content changed".
- **Rejected findings still show as NEW.** Discovery has no reject list, so `discover node` and
  `discover python3` keep reporting the two rejected findings. A small `reviewed-rejected` list
  that discovery reads would fix that.
- **Not discovered, worth a hand probe later:** `tar -F`/`--info-script`/`--new-volume-script`
  documents running a command at the end of each volume. A quick check (`-M -F CANARY` on a list,
  and on a small `-c -M -L 10`) did not trigger it in the sandbox, so it is **untested**, not safe.

## Documentation consulted

- GNU tar options: <https://www.gnu.org/software/tar/manual/html_section/All-Options.html>
- pip general options (`--python`): <https://pip.pypa.io/en/stable/cli/pip/>
- gawk options: <https://www.gnu.org/software/gawk/manual/html_node/Options.html>
- GNU wget: <https://www.gnu.org/software/wget/manual/wget.html>
- rsync: <https://download.samba.org/pub/rsync/rsync.1>
- GNU findutils: <https://www.gnu.org/software/findutils/manual/html_mono/find.html>
- Node.js CLI: <https://nodejs.org/api/cli.html>
- Each tool's own `--help`, captured inside the sandbox.
