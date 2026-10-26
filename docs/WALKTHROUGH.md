# Walkthrough: reading the code in order

Everything below was produced by real runs on a Linux box (Debian 13, bubblewrap 0.12.0;
milestones 1-2: git 2.47.3, GNU sed 4.9, findutils 4.10.0, tar 1.35, curl 8.14.1;
milestone 3 adds 26 more tools, versions listed in `docs/examples/capabilities.json`). Read
[DESIGN.md](DESIGN.md) first for the "why"; this file is the "what, file by file".

The whole package is about 1,770 lines of Python with **no third-party
dependencies**. Read the files in this order; each builds on the previous one.
Sections 1-8 are milestone 1 (building the database); section 9 is milestone 2
(using the database to audit an allowlist); section 10 is milestone 3 (26 more tools,
"runner tools", and what changed in each file); section 11 is milestone 4 (automatic
flag discovery: two new files, `helpparse.py` and `discover.py`).

```
src/gtfo_probe/
  spec.py       1. what a probe IS
  fixtures.py   2. the fake world probes run in
  sandbox.py    3. the locked box
  detector.py   4. judging what happened
  runner.py     5. the loop that ties 1-4 together
  db.py         6. the output file
  cli.py        7. the command line
  probes/*.json 8. the actual experiments (data)
  allowlist.py  9a. read an allowlist file into entries      (milestone 2)
  checker.py    9b. compare entries with the database         (milestone 2)
  report.py     9c. print the result                          (milestone 2)
  helpparse.py  11a. read a help page into candidate flags    (milestone 4)
  discover.py   11b. test the candidates in the sandbox       (milestone 4)
tests/          one test file per module
```

---

## 1. `spec.py`: what a probe is

A probe is a small JSON object:

```json
{ "id": "find.exec", "tool": "find",
  "argv": [".", "-maxdepth", "0", "-exec", "<<canary_exec>>", "{}", ";"],
  "expect": ["exec"], "flag": "-exec",
  "description": "`-exec CMD ;` runs CMD for each match." }
```

* `tool` + `argv` = the command line. A **list**, never a shell string, so there is
  no shell to trick.
* `expect` = which effects we predict: any of `fs_write`, `exec`, `net`. An empty
  list marks a **control** (should do nothing).
* `<<canary_exec>>` is a placeholder; `<<...>>` was chosen because `{}`, `$` and `;`
  already mean things to find/sed/shells.

The file contains `ProbeSpec` (the dataclass), `validate()` (rejects bad input:
unknown tool, unknown placeholder, bad id, unknown effect...), `load_dir()`
(also rejects duplicate ids) and `substitute()` (fills in placeholders).
`ALLOWED_TOOLS` is a safety valve: a typo can't make us run `rm`.
Tests: `tests/test_spec.py`.

## 2. `fixtures.py`: the fake world

`build_template()` creates this tree once; `fresh_copy()` copies it for every probe:

```
repo/              tiny git repo, 2 commits (the working directory for all probes)
data/hello.txt     harmless text
data/sample.tar    a tar archive
canary/secret.txt  pretend secret (never leaves the sandbox)
canary/victim.txt  file that is safe to delete/modify (in the throwaway copy)
bin/canary-exec    2-line script: appends a line to markers/exec.log
markers/           only canary-exec writes here => "a program ran" evidence
out/               empty; probes write to out/probe-output.txt
home/ tmp/         HOME and /tmp for the tool
--- added in milestone 3 ---
data/Makefile      one target; its recipe runs the canary (for make)
data/hello.py      harmless scripts for python3 / node: they only print
data/hello.js
data/unsorted.txt  three lines out of order (for sort)
data/sample.zip    data/sample.txt.gz   archives for zip / unzip / gzip
npmpkg/            package.json whose scripts ("canary", "preinstall") run the canary
pypkg/             pyproject.toml + a 10-line in-tree build backend that runs the canary
                   (so `pip install DIR` has something to build, with no setuptools needed)
```

`PLACEHOLDERS` maps `<<out>>` to `/work/out/probe-output.txt`, `<<url>>` to
`http://192.0.2.1:9/gtfo-canary` (a documentation-only, non-routable address),
and so on. Inside the sandbox the fixture is always at `/work`.
Tests: `tests/test_fixtures.py`.

## 3. `sandbox.py`: the locked box

Three ideas:

1. **`Sandbox.build_command()`** turns "run `git show`" into a long `bwrap ...`
   command line. Real output for one probe (the temp dir name varies):

```
/usr/bin/bwrap --unshare-net --unshare-pid --unshare-ipc --unshare-uts
  --die-with-parent --new-session
  --symlink usr/bin /bin  --symlink usr/sbin /sbin  --symlink usr/lib /lib  --symlink usr/lib64 /lib64
  --ro-bind /usr /usr  --ro-bind /etc/ld.so.cache /etc/ld.so.cache
  --ro-bind /etc/passwd /etc/passwd  --ro-bind /etc/group /etc/group
  --ro-bind /etc/localtime /etc/localtime  --ro-bind /etc/alternatives /etc/alternatives
  --proc /proc  --dev /dev
  --bind /tmp/gtfo-probe-XXXX/worlds/git.show.output /work
  --bind /tmp/gtfo-probe-XXXX/worlds/git.show.output/tmp /tmp
  --remount-ro /
  --chdir /work/repo  --clearenv
  --setenv PATH /usr/local/bin:/usr/bin:/bin  --setenv HOME /work/home  --setenv TMPDIR /tmp
  --setenv LC_ALL C  --setenv TERM dumb  --setenv GIT_CONFIG_NOSYSTEM 1
  --setenv GIT_CONFIG_GLOBAL /dev/null  --setenv GIT_TERMINAL_PROMPT 0
  --setenv GIT_PAGER cat  --setenv PAGER cat
  -- git show --output=/work/out/probe-output.txt HEAD
```

   Read it as: no network / own process table; the root is an *empty* filesystem
   into which we add `/usr` read-only; only `/work` is writable; empty environment;
   then the command. Everything after `--` is the probe.

2. **`Sandbox.preflight()`** is the self-test. It runs a small shell script *inside*
   the box and checks four facts: only the `lo` network interface exists, writing
   to `/etc` fails, writing to `/work` works, and `/workspace`, `/home`, `/root`
   don't exist. If any is wrong it raises `SandboxUnavailable`.

3. **Refusal.** `Sandbox.run()` raises unless preflight succeeded. Real output when
   `bwrap` is not on PATH:

```
$ env -i PATH=/nonexistent gtfo-probe run --out /tmp/nope.json
refusing to run: bubblewrap (`bwrap`) not found. Install it (e.g. `apt install bubblewrap`). gtfo-probe refuses to run probes without a sandbox.
exit=2        (and /tmp/nope.json was not created)
```

`run()` itself: starts the process in its own process group, sends stdout/stderr to
temp files (so a chatty tool can't fill memory; capped at 64 KB), waits up to the
timeout, and kills the whole group if needed. Tests: `tests/test_sandbox.py`
(includes tests that break the sandbox on purpose and check the preflight notices).

## 4. `detector.py`: judging what happened

Pure functions, no sandbox needed, easy to test.

* `snapshot(dir)` -> `{path: (kind, size, mtime, sha256)}` for every file.
* `diff(before, after)` -> list of `created` / `modified` / `deleted`.
* `find_net_evidence(stdout, stderr)` -> lines that look like failed connections.
* `detect(...)` combines them:
  * `markers/exec.log` non-empty -> **exec** (*confirmed*)
  * any file changed outside `markers/` -> **fs_write** (*confirmed*)
  * failed-connection text -> **net** (*attempted*; weaker, it's text matching; milestone 3
    taught it Node/Python error names such as `EAI_AGAIN` and `ENETUNREACH`)
  * "Read-only file system" text -> **fs_write** (*attempted*, the write was refused)

Tests: `tests/test_detector.py`.

## 5. `runner.py`: the loop

`run_probe()` is five lines of real work: copy world -> snapshot -> `sandbox.run` ->
snapshot -> `detect`. Then `classify()` compares expected vs observed:
`match`, `unexpected_effect`, `expected_effect_missing`, or `mismatch`.
`run_all()` builds the template, asks each tool for its version (`git@2.47.3`),
runs every probe, and cleans up the temp directory. Tests: `tests/test_runner.py`.

Milestone 3 additions: `VERSION_COMMANDS` (tools that spell "version" differently:
`ssh -V`, `zip -v`; `scp` has no version flag and is asked through `ssh -V`), and
**skipping**: if the sandbox cannot even start a tool (bubblewrap prints `execvp NAME: No
such file or directory`), `tool_version` returns `None`, the tool's probes are skipped, and
`run` prints `SKIPPED (not installed on this machine...)`. Before this, a machine without
`rsync` would have reported all its probes as failures.

## 6. `db.py`: the output

`build_database()` groups results by `tool@version`. Each tool gets a quick
`capabilities` summary and the full per-probe `probes` evidence. The real entry for
`find -exec` (from `docs/examples/capabilities.json`):

```json
{
  "id": "find.exec",
  "argv": ["find", ".", "-maxdepth", "0", "-exec", "<<canary_exec>>", "{}", ";"],
  "flag": "-exec",
  "expected": ["exec"],
  "observed": ["exec"],
  "confidence": {"exec": "confirmed"},
  "status": "match",
  "exit_code": 0,
  "evidence": {
    "exec_log": ["canary-exec ran: argv=."],
    "fs_changes": [], "net": [], "blocked_writes": []
  }
}
```

Read it: find ran our canary program, and the canary wrote `argv=.` (the match
`find` passed it) into the log. That log line *is* the proof.
Tests: `tests/test_db.py`.

Milestone 3 adds two fields (additive, `schema_version` stays 1): each tool has
`"category": "runner" | "standard"`, and `capabilities` has a fourth list, `"runner"`
(probes tagged `runner` that really ran the canary). Each probe record also carries its
`tags`. Old databases without these fields still load and are treated as `standard`.

## 7. `cli.py`: the command line

`gtfo-probe doctor` (is the sandbox usable?), `gtfo-probe list` (show probes, run
nothing), `gtfo-probe run [--tool git] [--out FILE] [--timeout S] [--strict]`, and
(milestone 2) `gtfo-probe check` (section 9).
Exit codes of `run`: 0 ok, 1 `--strict` and a probe differed, 2 sandbox unavailable
(refused), 3 bad probe spec. Specs are validated **before** the sandbox is touched.
`check` never touches the sandbox.
Tests: `tests/test_cli.py`.

## 8. `probes/*.json`: the experiments

202 probes over 31 tools (38 for git, sed, find, tar, curl; 164 added in milestone 3,
listed in section 10). About a quarter are **controls** (expect nothing) or negative
results. Counts per tool are in `docs/examples/capabilities.json`.

---

## 9. `check`: auditing an allowlist (milestone 2)

Sections 1-8 produce a *database of facts* ("`tar` with `-I` runs a program"). The
`check` command is where the facts meet *your* allowlist. It is three small files,
read in this order.

### 9a. `allowlist.py`: turn a file into entries

Every allowlist format is reduced to the same small object:

```python
Entry(tool="git", words=("show",), any_args=True)     # from  Bash(git show:*)
Entry(tool="git", words=("show", "HEAD"), any_args=False)   # from  Bash(git show HEAD)  (exact)
```

* `parse_pattern()` handles one command pattern: the `:*` / ` *` / ` $` markers, a `*`
  in the middle, quotes (via `shlex`), `&&`/`;`/`|` (split into several entries),
  `VAR=x` prefixes, and `/usr/bin/git` -> `git`.
* `parse_plain`, `parse_claude`, `parse_codex` read the three file formats. The Codex
  `.rules` file is Python-like; we **only parse it** with `ast` and read literal
  values, we never run it.
* `load()` guesses the format from the file name/content and returns the entries.

Tests: `tests/test_allowlist.py` (19 tests, including "a rules file that tries to
open a file is not executed").

### 9b. `checker.py`: the logic

`check_entry(entry, db)` does four things:

1. **Find the tool** in the DB (`git@2.47.3`). Not there -> `unknown_tool`.
2. **Pick probes in scope** (`probe_in_scope`): for `git show:*` only probes whose git
   subcommand is `show`; for `find:*` every `find` probe; for an exact entry only
   probes whose flag literally appears in it. None in scope -> `unknown_scope`.
3. **Turn effects into findings** with a severity (`SEVERITY` table: exec critical,
   fs_write high, net medium; plain-use writes are low).
4. **Attach abbreviation facts**: if the DB has a `...-abbrev` twin of the probe, the
   finding says whether the shortened flag also works.
5. *(milestone 3)* **Runner tools**: for a tool in `RUNNER_TOOLS` (or a runner-tagged
   subcommand like `npm run`) with arguments allowed, replace all findings by one
   `BY DESIGN` critical finding. See section 10.2 in DESIGN.md and 10c below.

A worked example. The allowlist is three lines:

```
git show $          # exactly `git show`, nothing more
git ls-remote       # `git ls-remote` with any arguments
git branch          # `git branch` with any arguments
```

Real output (`gtfo-probe check mini.txt --db docs/examples/capabilities.json --strict`;
the long `tool versions probed:` line is shortened here):

```
gtfo-probe check: /tmp/mini.txt (format: plain)
capability DB: generated 2026-10-16T17:19:00Z by gtfo-probe 0.1.0
tool versions probed: cat@9.7, cp@9.7, curl@8.14.1, ... (31 tools, one version each)
runner tools (critical by design, they run what you give them): env@9.7, make@4.4.1, node@20.19.2, npx@11.21.1, python3@3.13.5, xargs@4.10.0
Results reflect only the probes that were run, on the tool versions listed above.
"no known risk" means probes saw no effect; "UNKNOWN" means nothing was tested. Neither means safe.
Not modelled: READING files (a `cat` or `grep` entry can still read secrets).

[no known risk] git show $   [git show]
    note: exact entry: only flags literally written in it were checked
    note: probes for this scope showed no effect; that is not a proof of safety

[CRITICAL] git ls-remote   [git ls-remote ...]
    critical exec     via --upload-pack  (probe git.ls-remote.upload-pack, confirmed, git@2.47.3)
             evidence: canary program ran: canary-exec ran: argv=/work/repo
             abbreviation: WORKS in a variant spelling, --upload-pa (probe git.ls-remote.upload-pack-abbrev); deny by capability, not by flag string
    medium   net      in plain use  (probe git.ls-remote.url, attempted, git@2.47.3)
             evidence: network attempt: fatal: unable to access 'http://192.0.2.1:9/gtfo-canary/': Failed to c
    fix: pin the exact command (end the line with ` $` and write the whole command, e.g. `git ls-remote <the exact arguments> $`), or remove this entry.
    note: recommendation: deny by CAPABILITY, not by flag string: ...

[UNKNOWN] git branch   [git branch ...]
    note: no probes cover `git branch`: UNKNOWN (not tested)

summary: 3 entries (1 findings, 1 no_known_risk, 1 unknown_scope); findings by severity: 1 critical, 1 medium
(exit code 1, because of --strict)
```

(The `recommendation` line is shortened here; the real output prints the full sentence.)

Reading it line by line:

* `git show $` is exact, so no extra flag can be appended. We look for known risky
  flags in its text; there are none -> "no known risk" (not "safe").
* `git ls-remote` allows any arguments, and the DB proved `--upload-pack` runs a
  program. The variant-spelling line says `--upload-pa` works too, which is why the advice
  is not "deny that one flag".
* `git branch` has **no probes at all**. The tool refuses to guess: UNKNOWN. With
  `--strict` that alone would fail the CI job, because unknown is not safe.

The same file shows why `git show:*` (a different entry) would **not** list
`--upload-pack`: that probe's subcommand is `ls-remote`, outside the `show` scope.

Tests: `tests/test_checker.py` (23 tests) and `tests/test_milestone3.py` use a tiny hand-made database so every rule
is checked in isolation, plus one test against the real committed database.

### 9c. `report.py`: print it

`render_text` is for people, `render_json` for CI and other programs. Both start
with the DB's tool versions and the "neither means safe" sentence, so the caveat can
never be separated from the results.

### Running it on the four example files

```
gtfo-probe check docs/examples/allowlist.txt          --db docs/examples/capabilities.json
gtfo-probe check docs/examples/claude-settings.json   --db docs/examples/capabilities.json
gtfo-probe check docs/examples/codex-default.rules    --db docs/examples/capabilities.json
gtfo-probe check docs/examples/allowlist-runners.txt  --db docs/examples/capabilities.json
```

The full real outputs are saved next to the inputs as `*.out.txt` (and
`claude-settings.json.out.json` for `--format json`). A test fails if they go stale.
If you change the report wording, regenerate them with the commands above
(`> docs/examples/<name>.out.txt`).

---

## End-to-end example (real output)

```
$ gtfo-probe doctor
sandbox: OK (bubblewrap 0.12.0)
  verified: no network interfaces, read-only root, writable /work only, host dirs hidden

$ gtfo-probe run --tool git --tool sed --tool find --tool tar --tool curl --out /tmp/core.json
match                    curl.version.control                   observed=-
match                    curl.output                            observed=fs_write
match                    curl.remote-name                       observed=fs_write
match                    curl.url                               observed=net
match                    find.name.control                      observed=-
match                    find.exec                              observed=exec
match                    find.execdir                           observed=exec
match                    find.fprint                            observed=fs_write
match                    find.fprintf                           observed=fs_write
match                    find.fls                               observed=fs_write
match                    find.delete                            observed=fs_write
match                    git.log.control                        observed=-
match                    git.show.control                       observed=-
match                    git.status.plain                       observed=fs_write
match                    git.status.no-optional-locks           observed=-
match                    git.show.output                        observed=fs_write
match                    git.log.output                         observed=fs_write
match                    git.diff.output                        observed=fs_write
match                    git.show.output-abbrev                 observed=-
match                    git.ls-remote.upload-pack              observed=exec
match                    git.ls-remote.upload-pack-abbrev       observed=exec
match                    git.grep.open-files-in-pager           observed=exec
match                    git.status.config-fsmonitor            observed=exec,fs_write
match                    git.ls-remote.url                      observed=net
match                    sed.print.control                      observed=-
match                    sed.w-command                          observed=fs_write
match                    sed.s-w-flag                           observed=fs_write
match                    sed.in-place                           observed=fs_write
match                    sed.e-command                          observed=exec
match                    sed.s-e-flag                           observed=exec
match                    sed.sandbox.control                    observed=-
match                    tar.list.control                       observed=-
match                    tar.create                             observed=fs_write
match                    tar.extract                            observed=fs_write
match                    tar.use-compress-program               observed=exec
match                    tar.use-compress-program-abbrev        observed=exec
match                    tar.checkpoint-action-exec             observed=exec
match                    tar.to-command                         observed=exec

38 probes, 38 as expected, 0 differ.
wrote /tmp/core.json
```

(That is the milestone-1 run, reproduced with `--tool` filters. A plain `gtfo-probe run`
now runs all 202 probes; section 10 shows part of that output.)

How to read it:

* `observed=-` rows are controls and mitigations: `git show HEAD`, `sed --sandbox`
  and `git --no-optional-locks status` did nothing, as they should.
* **Surprise 1, `git.status.plain` -> fs_write.** Plain `git status` rewrites
  `.git/index` (refreshing cached file info). "Read-only" is not read-only. The
  `--no-optional-locks` control shows the flag that stops it.
* **Surprise 2, abbreviations.** `git ls-remote --upload-pa=PROG` runs PROG just like
  `--upload-pack`, and so does tar's `--use-compress-prog=`. A deny rule matching the
  exact string `--upload-pack` would miss them. But `git show --outpu=FILE` is
  **rejected** (`fatal: unrecognized argument`): git's diff options do not accept
  prefixes. We recorded that as a negative control.
* The summary the database gives for sed (real output):

```json
"capabilities": {
  "exec":     [{"flag": "e", "probe": "sed.e-command"}, {"flag": "s///e", "probe": "sed.s-e-flag"}],
  "fs_write": [{"flag": "w", "probe": "sed.w-command"}, {"flag": "s///w", "probe": "sed.s-w-flag"}, {"flag": "-i", "probe": "sed.in-place"}],
  "net": []
}
```

(each entry also has `"confidence": "confirmed"`).

Net evidence example (real, from `git ls-remote http://192.0.2.1:9/...`):

```
fatal: unable to access 'http://192.0.2.1:9/gtfo-canary/': Failed to connect to 192.0.2.1 port 9 after 0 ms: Could not connect to server
```

## 10. Milestone 3: what changed, file by file

Read DESIGN.md section 10 for the findings; this is the code tour.

| File | What changed |
|------|--------------|
| `spec.py` | `ALLOWED_TOOLS` grew from 5 to 31; new `RUNNER_TOOLS` and `RUNNER_TAG`. |
| `fixtures.py` | New fake-world files and placeholders (`makefile`, `pyscript`, `jsscript`, `unsorted`, `zipfile`, `gzfile`, `npmpkg`, `pypkg`, `outdir`). |
| `sandbox.py` | One more read-only bind: `/etc/ssl/certs` (CA certificates, so pip can start). |
| `detector.py` | Network patterns for Node/Python errors. |
| `runner.py` | `VERSION_COMMANDS`, `tool_version()` returns `None` for missing tools, `run_all(..., skipped=[...])`, probe `tags` in each record. |
| `db.py` | `category` per tool, `capabilities.runner`. |
| `checker.py` | Runner collapse, `baseline` probes, `TOOL_ALIASES` (`awk`), `SUBCOMMAND_TOOLS` now includes `npm` and `pip`, pager hint. |
| `report.py` | `BY DESIGN` label, "runner tools" header line, and the sentence "Not modelled: READING files". |
| `cli.py` | `run` prints skipped tools and refuses to write an empty DB. |
| `probes/*.json` | 26 new files, 164 probes. |

### 10a. A probe from each family (real JSON)

```json
{ "id": "sort.compress-program", "tool": "sort",
  "argv": ["-m", "--batch-size=2", "--compress-program=<<canary_exec>>", "<<unsorted>>", "<<hello>>", "<<victim>>"],
  "expect": ["exec"], "flag": "--compress-program" }
{ "id": "env.runner", "tool": "env", "argv": ["<<canary_exec>>"],
  "expect": ["exec"], "flag": "", "tags": ["runner"] }
{ "id": "rsync.rsh-abbrev", "tool": "rsync", "argv": ["--rs=<<canary_exec>>", "example.invalid:/x", "<<outdir>>/"],
  "expect": [], "flag": "--rs" }
```

The first needs the odd `-m --batch-size=2` so that sort really makes a temp file (else the
compressor is never started). The second is tagged `runner`. The third is a *negative
control*: the abbreviation is rejected, so nothing happens and `expect` is empty.

### 10b. Real run of three of the new tools

```
$ gtfo-probe run --tool sort --tool env --tool rsync --out /tmp/some.json
match                    env.print.control                      observed=-
match                    env.set-var.control                    observed=-
match                    env.runner                             observed=exec
match                    env.split-string                       observed=exec
match                    env.split-string-abbrev                observed=exec
match                    env.chdir                              observed=exec
match                    rsync.list-only.control                observed=-
match                    rsync.dry-run.control                  observed=-
match                    rsync.rsh                              observed=exec
match                    rsync.rsh-abbrev                       observed=-
match                    rsync.rsh-short                        observed=exec
match                    rsync.copy                             observed=fs_write
match                    rsync.delete                           observed=fs_write
match                    rsync.remove-source-files              observed=fs_write
match                    rsync.log-file                         observed=fs_write
match                    rsync.write-batch                      observed=fs_write
match                    rsync.daemon-url                       observed=net
match                    sort.print.control                     observed=-
match                    sort.unique.control                    observed=-
match                    sort.output                            observed=fs_write
match                    sort.output-abbrev                     observed=fs_write
match                    sort.output-short                      observed=fs_write
match                    sort.merge.control                     observed=-
match                    sort.compress-program                  observed=exec
match                    sort.compress-program-abbrev           observed=exec

25 probes, 25 as expected, 0 differ.
wrote /tmp/some.json
```

(For `sort.compress-program` the saved evidence in the DB shows the canary ran twice:
`canary-exec ran: argv=` and `canary-exec ran: argv=-d`, i.e. once to compress and once
to decompress.)

### 10c. `check` on runner tools (real output, from `allowlist-runners.txt.out.txt`)

```
[CRITICAL] env   [env ...]
    critical exec     BY DESIGN (runs any program you hand it)  (probe env.runner, confirmed, env@9.7)
             evidence: canary program ran: canary-exec ran: argv=
    fix: remove this entry or pin the exact command: end the line with ` $` and write the whole command, e.g. `env <the exact arguments> $`. There is no safe flag list for a runner tool.
```

Compare `sort` in the same file: not a runner, so it keeps its flag list (`--compress-program`
critical, `--output`/`-o` high) with the variant-spelling lines. And `less`:

```
[UNKNOWN] less   [less ...]
    note: `less` is (or starts) a pager: it can run commands (`!cmd`, LESSOPEN) but only on a terminal, and gtfo-probe's sandbox has none, so it cannot be probed. This is a built-in hint, NOT probe data.
```

### 10d. How to add a tool (the whole recipe)

1. `which TOOL`; if it is missing, install it (here: `apt`) or record it as skipped.
2. Try commands by hand in the sandbox first (a scratch script that calls `Sandbox.run` is
   enough) and *read the output*. Several of my first guesses were wrong in useful ways.
3. Add the name to `ALLOWED_TOOLS`; add a version command to `VERSION_COMMANDS` if
   `--version` does not work.
4. Write `probes/TOOL.json`: at least one control, one probe per capability flag, and an
   `-abbrev` twin wherever the tool accepts abbreviations (rejections too).
5. `gtfo-probe run --tool TOOL` and investigate every mismatch before touching an expectation.
6. Regenerate `docs/examples/capabilities.json` and the `.out.txt` files, run `pytest`.

## 11. Milestone 4: automatic flag discovery

Read [DESIGN.md section 11](DESIGN.md) for the why. This is the code, in reading order.
Two new files and one new CLI command; **no existing module's behaviour changed**
(`runner.run_probe`, the sandbox and the detector are reused as they were).

### 11a. `helpparse.py` (180 lines): help text in, candidate flags out

Pure text processing, so it is the easiest file to test and the first to read.

* `Candidate` is one *option*: `names` (all aliases, e.g. `["-I", "--use-compress-program"]`),
  whether it takes a value (`arg`: none/optional/required), the placeholder name (`metavar`,
  e.g. `PROG`), the description text, and `hints`.
* `parse_help(text)` goes line by line. A line that starts with `-` is an "option line":
  the flags come first, then two or more spaces, then the description (plus any more-indented
  continuation lines). Any other line is "prose" (find's help is prose) and is still scanned for
  flags, but only an UPPERCASE or `<angle>` word after a flag counts as a value placeholder, so
  ordinary words are not mistaken for arguments.
  The regular expression `_FLAG` finds `-x`, `--long`, `--[no-]long` and find-style `-longname`;
  its look-behind keeps it from starting inside a word (`non-existent`).
* `_parse_option_part` merges aliases: `-I, --use-compress-program=PROG` is *one* option
  because only `, ` or ` | ` sits between the two flags.
* `classify(c)` fills `hints` from the placeholder (`PROG` -> exec, `FILE` -> fs_write,
  `URL` -> net) and from words (`_EXEC_WORDS`, `_WRITE_WORDS`, `_NET_WORDS`). The last word of
  the placeholder wins: `script-file` is a *file*, not a program. Hints are guesses; the file says so.

### 11b. `discover.py` (about 480 lines, mostly comments): test the candidates

Top to bottom:

1. **The tables**: `SKIP_FLAGS` (`--help` and friends are never tested), `VALUE` (the three
   harmless canaries), `BASES` (the scaffold each tool needs, e.g. `tar FLAG -tf archive`), `SEEDS`
   (3 hand-written patterns help pages cannot show). The `BASES` and `SEEDS` tables are the only
   hand-written knowledge in discovery; both are short and commented.
2. **`Finding` and `DiscoveryReport`**: the results. A `Finding` is `confirmed` only when its
   status is `effect`, it **reproduced** in a second fresh world, and at least one effect is
   `confirmed` rather than `attempted`.
3. **Coverage** (`probe_flags`, `coverage_map`, `covered_by`): reads the existing hand-written
   probes and records which flags they test (for git, per subcommand). `-cf` counts as `-c` and
   `-f` (except for find, which has one-dash long options); an existing `--outp` counts as
   covering `--output` (abbreviation). This is the dedup.
4. **`capture_help`**: runs `tool --help`, `-h`, `help` through `sandbox.run` and decides which
   outputs look like real help pages.
5. **`_Lab`**: a small helper that runs one throw-away probe (built with `spec.validate`, run with
   `runner.run_probe`) and remembers each scaffold's baseline.
6. **`flag_argv`, `_spellings`, `_values`**: how a candidate becomes an argv: `--flag=VALUE`,
   falling back to `--flag VALUE`; which canary values to try.
7. **`probe_candidate`**: the heart. For each scaffold and value: run, subtract the baseline,
   ignore "attempted" effects from a run where the tool rejected its command line, and if a new
   effect remains run it once more to see if it reproduces. Fake-lab unit tests pin each rule.
8. **`select`** (which candidates, with the cap) and **`discover_tool`** (the whole pipeline for
   one tool: help, parse, classify, seeds, select, test, coverage, with the time budget).
9. **`render_text`**: the report. **`build_probe_dicts` / `write_discovered`**: `--apply`
   (only NEW + confirmed; refuses to overwrite files that are not its own).

`cli.py` gets `cmd_discover` (about 50 lines): argument checks, load existing probes, verify the
sandbox (refuse with exit 2 if it fails), loop over tools, print, optionally apply.

### 11c. Real runs

All produced on this machine (tar 1.35, sed 4.9, findutils 4.10.0, coreutils sort 9.7) with
`gtfo-probe discover TOOL --show-all`; the complete outputs are in
`docs/examples/discover-*.txt.out`.

| Tool | options parsed from help | tested | confirmed | already covered by hand probes | NEW |
|------|---:|---:|---:|---:|---:|
| tar  | 161 | 73 | 11 | 5 | 6 |
| sed  | 15  | 11 | 3  | 3 | 0 |
| find | 81  | 17 | 6  | 5 | 1 |
| sort | 30  | 7  | 2  | 2 | 0 |

Excerpt for `tar` (the full file lists everything):

```
== tar  (tar@1.35) ==
  help: tar --help                   used (16662 chars)
  help: tar -h                       ignored: does not look like a help page
  help: tar help                     ignored: tool rejected it
  parsed 161 options from help; tested 73; not tested (no hint) 86; over the cap 0
  CONFIRMED effects (detector saw them, twice):
    -I, --use-compress-program
        exec=confirmed; reproduced=True; known: tar.use-compress-program
        argv: tar --use-compress-program=<<canary_exec>> -tf <<archive>>
    --delete
        fs_write=confirmed; reproduced=True; NEW
        argv: tar --delete -f <<archive>> hello.txt
    --index-file
        fs_write=confirmed; reproduced=True; NEW
        argv: tar --index-file=<<out>> -tf <<archive>>
  ...
  summary: 11 confirmed (5 already covered by hand probes, 6 new), 0 unconfirmed, 62 no effect/rejected/timeout
```

**What this shows, honestly, against the hand-written probes**

* **tar.** All five hand-written effect probes (create, extract, `-I`, `--to-command`,
  `--checkpoint-action`) were re-found. `-I` was found by *parsing the help page*; the
  `--checkpoint-action` finding comes from the **seed** (the same flag taken from the help page
  alone shows nothing, because it needs `--checkpoint=1` and an `exec=` prefix). Six writers
  that had **no** probe were new: `--delete`, `--append`/`-r`, `--update`/`-u`, `--catenate`/`-A`
  (all modify an archive) and `--index-file`, `--volno-file` (write a small file *while merely
  listing* an archive). I re-ran the last three by hand in the sandbox to be sure it was not the detector
  being fooled: `--index-file` really wrote `hello.txt\n` and `--volno-file` wrote `1\n`. Tested with no effect under our scaffolds: 62
  flags, including some that can matter in other combinations (`-g` needs a create operation).
* **sed.** Only `-i` came from the help page. `w` and `e` are script commands, so they were found
  only because they are **seeds**. The hand probes `s///w` and `s///e` (script *flags*) were **not**
  found: nothing teaches discovery about them.
* **find.** Re-found `-exec`, `-execdir`, `-fprint`, `-fls`, `-delete`; new: `-fprint0` (a
  variant of `-fprint`). **Missed:** `-fprintf` (it needs two values, FILE and FORMAT, and we pass one).
  `-ok` and `-okdir` ran without effect: they ask "y/n" on a terminal and stdin is empty. That is
  probably the true answer in this sandbox, but it is a case where the sandbox cannot tell us
  what a terminal would do.
* **sort.** Re-found `--output` and `--compress-program`; **nothing new**. The second one is only
  found because `BASES["sort"]` contains a merge scaffold (`-m --batch-size=2` plus three files); a
  test removes the scaffold and shows the flag going unnoticed.
* **git** (not asked for, but informative): discovery re-found `--upload-pack` and
  `--open-files-in-pager` but **missed `--output`** on `show`/`log`/`diff`, because `git show -h`
  prints only a short option list that leaves it out. That is "help text is incomplete" in its purest form.
* **False leads and false positives met on the way.** (1) curl's error message echoed our canary
  URL and the net heuristic called it a network attempt: fixed (rejected command lines no longer
  count as attempts) and covered by tests. (2) With `--all-flags`, `tar`'s help page example
  `tar -cf archive.tar foo bar` parses as a flag called `-cf`. (3) Before curl got a `file://`
  scaffold, discovery found *no* write for `curl -o`, which the hand probe proves; after the
  scaffold it does. Whenever a scaffold is wrong, discovery says "no effect", not "safe".

`gtfo-probe discover --all` runs the whole allowlist report-only in about 90 seconds
(`docs/examples/discover-all.txt.out`): 17 new confirmed findings across 8 tools (tar 6, find 1,
gawk 3, node 2, wget 2, pip 1, python3 1, rsync 1), many of them profile/log/dump writers
(`gawk -o`, `node --cpu-prof`, `rsync --log-file`, `wget -o`). Four tools (`ssh`, `scp`, `npm`,
`npx`) tested 0 flags because their help is not a flag list. **None of these new findings has
been reviewed or added to the bundled probes**; they are what the tool *proposes*.

> **Update (2026-10-20):** all 17 have since been reviewed by hand: 15 promoted to bundled
> probes (tagged `discovered`, `reviewed`), 2 rejected. See [REVIEW-discovered.md](REVIEW-discovered.md).
> The `discover-*.txt.out` files are kept as the milestone-4 snapshot, so they still say NEW.

### 11d. Using it

```
gtfo-probe discover tar                      # report only: nothing written
gtfo-probe discover tar --show-all           # list every no-effect flag too
gtfo-probe discover git --sub show --sub log # git needs subcommands
gtfo-probe discover tar --apply              # write NEW confirmed ones to probes/tar.discovered.json
gtfo-probe discover tar --apply --out my.discovered.json
gtfo-probe discover --all                    # every allowlisted tool (report only unless --apply)
gtfo-probe run --probes probes --out caps.json   # replay what was saved
```

Exit codes: 0 ok, 2 sandbox unavailable / bad arguments / tool not installed / refused to overwrite
a file, 3 unknown tool.

## Running the tests

```
$ pytest -q
.........................................................................
219 passed in 26s
```

Per file: spec 15, sandbox 10, runner 11, detector 10, cli 12, fixtures 4, db 4,
allowlist 19, checker 23, packaging 5, milestone3 49, helpparse 20, discover 37.
(The run takes about 26 s because several tests run real probes and real discovery.)
Tests marked `sandbox` need working bubblewrap and **skip** (don't fail) without it.

## Mistakes made while building this (and why they're instructive)

1. The first run reported 3 probes as differing from expectation. Investigating, none
   was a tool bug: one was a wrong assumption of mine (git does not accept
   `--outpu`), one was an sed delimiter clash (`s/hello/<path-with-slashes>/e`), and
   one was a real extra effect (`git status` writes the index). The
   expected-vs-observed design exists to surface exactly this.
2. The first sandbox draft left `/` as a writable tmpfs: a write to `/etc/y` silently
   "worked" (and vanished). Adding `--remount-ro /` plus a preflight check for it
   fixed that; a test now breaks the flag deliberately to prove the check fires.

3. (Milestone 3) A `<<out>>` placeholder typed unquoted on a bash command line is a
   here-document, not a placeholder, and it left a stray file in the working tree.
   Lesson: quote placeholders when you try a probe by hand.
4. (Milestone 3) The first `pip` probes failed with a Python traceback, not a result:
   pip's bundled `requests` needs a CA bundle that the sandbox did not provide. The
   traceback was a sandbox gap, not a pip behaviour, so the sandbox got read-only
   `/etc/ssl/certs`. A probe that errors before doing anything must be read as "the
   experiment failed", not "the tool is safe".

## Ideas for where to go next (not done yet)

Discovery from richer sources than `--help` (`--git-completion-helper`, man pages, shell
completion files) and discovery of *abbreviations*; strace-based
network evidence (would fix the `wget -o` blind spot); an `fs_read` effect; a
pseudo-terminal for pagers (`less`, `man`); a tested Docker image for the 31-tool list;
a prebuilt shared database; more tools (`docker`, `gh`, `perl`, `ruby`, `busybox`);
subcommand alias tables (`npm run-script` = `npm run`); signed database releases.
