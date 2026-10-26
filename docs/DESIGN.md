# gtfo-probe: design, in plain language

This document explains **why** gtfo-probe is built the way it is. If you read only
one file before touching the code, read this one. The companion file,
[WALKTHROUGH.md](WALKTHROUGH.md), walks through the code in reading order with a
real run.

---

## 1. The problem

AI coding agents (Claude Code, Codex, Cursor, ...) can run shell commands for you.
To avoid asking "may I run this?" fifty times a session, they let you **pre-approve
commands**: "always allow `git show`", "always allow `find`", "always allow `sed`".

Those rules usually match the **command name**. But what a command can *do* depends
on its **flags**:

| Looks like...      | ...but with a flag it can...                                  |
|--------------------|---------------------------------------------------------------|
| `git show`         | `--output=FILE`: **write a file**                             |
| `find`             | `-exec PROG ;`: **run a program**, `-fprint FILE`: write a file |
| `sed`              | `w FILE`: write a file, `e CMD`: run a command                |
| `tar -t`           | `-I PROG`: run a program                                      |
| `curl`             | `-o FILE`: write a file; any URL: network access              |

If an attacker can put text in front of the AI (a web page, a README, an issue,
a code comment: "prompt injection"), the AI may emit one of these flag
combinations. The approval engine sees an "allowed" command name and lets it
through. Several real vulnerabilities in agent tools have been exactly this.

A hand-written list of dangerous flags is how people defend today
(GTFOBins documents such tricks for humans). Lists go stale, miss
abbreviations, and differ per version.

## 2. The idea

> Don't *guess* what a flag does. **Run it, safely, and watch.**

gtfo-probe runs tiny experiments ("probes"), each one a single command line, inside
a sandbox with no network, against fake files, and records what really happened.
The result is a machine-readable database (`capabilities.json`):
"for `git 2.47.3`, the flag `--output` gives *fs_write*".

Milestone 1 built the foundation: probes, sandbox, detector, database, `run`.
Milestone 2 added the `check` command (section 9): it reads an agent's allowlist and
says "entry X still permits capability Y via flag Z, proven by probe P". Milestone 4
added automatic discovery of flags (section 11), so humans don't have to write every probe.

## 3. How it works, step by step

```
 probes/*.json          (1) humans describe experiments as data
      |
      v
 spec.py                (2) validate them; refuse anything odd
      |
      v   for each probe:
 fixtures.py            (3) copy a pristine fake world (git repo, canary files, canary program)
      |
 detector.snapshot      (4) record every file BEFORE
      |
 sandbox.py             (5) run the one command in the locked box (no network, read-only root)
      |
 detector.snapshot      (6) record every file AFTER
      |
 detector.detect        (7) decide: files changed? canary program ran? network attempted?
      |
      v
 db.py                  (8) collect results into capabilities.json
```

`cli.py` is the front door; `runner.py` is the loop that connects 3-7.

## 4. What each module does (one job each)

| Module        | Job                                                                         |
|---------------|-----------------------------------------------------------------------------|
| `spec.py`     | Defines a probe (`id`, `tool`, `argv`, expected effects, tags), validates JSON, and holds the two tool lists: `ALLOWED_TOOLS` (what we may run) and `RUNNER_TOOLS` (tools that run programs by design). |
| `fixtures.py` | Builds the fake world and defines the `<<placeholders>>` probes can use.     |
| `sandbox.py`  | Builds the `bwrap` command, runs it with a timeout, **self-tests** the box, refuses if unsafe. |
| `detector.py` | Pure functions that turn "before/after files + output" into a list of effects. |
| `runner.py`   | Runs one probe or all probes; compares expectation with reality.             |
| `db.py`       | Writes/reads the JSON database (records each tool's `category` and the "runner" probes). |
| `allowlist.py`| Reads an allowlist file (plain / Claude Code / Codex) into `Entry` objects.   |
| `checker.py`  | Compares each `Entry` with the DB and produces findings. Pure logic.          |
| `report.py`   | Prints check results as text or JSON.                                         |
| `cli.py`      | `gtfo-probe doctor`, `list`, `run`, `check`.                                  |

## 5. Design choices and why

### 5.1 Probes are data (JSON), not code
A reviewer can read `["show", "--output=<<out>>", "HEAD"]` and know exactly what
will run. Adding a probe needs no Python. The runner validates before running
anything: unknown tool, unknown placeholder, or argv as a shell string are all
rejected. argv is always a **list**, never passed through a shell, so there is no
quoting trick that could run something extra.

JSON rather than YAML: Python's standard library reads JSON, so there is **zero
third-party dependency**. For a security tool, fewer dependencies = smaller supply
chain to trust.

### 5.2 Why "single-flag" probes
Each probe changes **one** thing relative to a harmless baseline. If
`git show HEAD` does nothing and `git show --output=FILE HEAD` writes a file, the
flag *is* the cause. Combinations make results ambiguous ("which part did it?") and
explode in number. Single flags also match the question allowlists really ask:
"I approved `git show`; which *one extra flag* breaks that promise?"

Honest nuance: some features need a companion to trigger. `tar
--checkpoint-action=exec=...` only fires with `--checkpoint=1`; `tar -c` needs
`-f FILE`. The rule is "one *capability-bearing* flag, plus the minimum companions
needed to make it observable". Multi-step attack chains are explicitly out of scope.

**Controls** are probes that should do nothing (`git log --oneline`). They make
sure our detector doesn't cry wolf; if a control ever shows an effect, we have a
bug or a surprising "read-only" command (this happened: see `git status`, below).

### 5.3 Why a sandbox with no network
Probing means executing flags that might write files, delete files, run programs
or connect out. We must be able to do that without any risk to the machine we run
on. So:

* **No network** (`--unshare-net`): the tool gets an empty network namespace. A
  network attempt fails instantly. Nothing can leave, even by accident.
  The probe URL uses `192.0.2.1`, an address *reserved for documentation* (RFC 5737)
  that is never routable. Two independent layers, so one mistake can't hurt.
* **Read-only root**: only `/usr` (read-only) and a few `/etc` files are visible.
  Your home directory, SSH keys, this source tree: not visible at all.
* **Writable only in `/work`** (a throwaway copy of fixtures). Every possible write
  lands somewhere the detector can inspect, and is deleted afterwards.
* **Empty environment** (`--clearenv`): no tokens or API keys leak into the tool.
* **Timeout** (5 s): hangs are killed; `--unshare-pid` makes sure children die too.

### 5.4 Why bubblewrap, and why we *refuse* instead of falling back
`bwrap` (bubblewrap) is a small, widely used rootless sandbox (Flatpak uses it).
`unshare -n` only removes the network and leaves the filesystem writable, which is
the exact thing we test. On the development machine it also failed outright
(`Operation not permitted`). So the policy is:

1. Find `bwrap`. If missing: **stop**, tell the user how to install it.
2. Run a **preflight self-test inside the sandbox** and *measure*: only a loopback
   interface? root not writable? `/work` writable? host dirs invisible? If any
   answer is wrong: **stop**.
3. `Sandbox.run()` refuses to run until the preflight passed. There is no
   `--unsafe` switch, and no fallback.

We test the refusal itself in the test suite (removing `--unshare-net` from the
command makes the preflight fail), because a safety check you never saw fail is
a safety check you can't trust.

### 5.5 Why canary files and observation from the *outside*
We never believe what a tool says it did. We look at the world.

* **fs_write**: hash every file before and after (`snapshot` / `diff`). A created,
  changed or deleted file is a fact. The probe tells the tool to write to
  `out/probe-output.txt`, a canary path nobody else touches, so the change is
  unambiguous. Victim files (`canary/victim.txt`) exist so `-delete` and `-i`
  have something to destroy, safely, in a throwaway copy.
* **exec**: the fixture contains `canary-exec`, a 2-line script that appends a line
  to `markers/exec.log`. Probes pass its path wherever a program is expected
  (`find -exec`, `tar -I`, `sed e`). If the log has a line, a program **was
  definitely executed**, no guessing from output text. The canary does nothing
  else, so even if a probe were wrong, the worst case is one line in a log.
* **net**: a no-network sandbox cannot *succeed* at connecting, so we detect the
  **attempt** from the tool's error text ("Failed to connect", "Network is
  unreachable", the canary IP). This is the weakest of the three (it relies on
  wording), so the database labels it `attempted` instead of `confirmed`.

Why not trust `--help`, man pages or source? They describe intent; probes show
behaviour in *this version on this platform*, including surprises.

Why a before/after file diff instead of tracing syscalls (`strace`)? Simplicity
and portability: it needs no extra privileges or tools (strace isn't even
installed on the development machine). The price is that it can only see effects that leave a
trace. Syscall tracing is a possible later addition for stronger `net` evidence.

### 5.6 Why one fresh world per probe
A probe that deletes a file must not change the next probe's result. We build a
pristine template once and copy it per probe. This costs a few milliseconds and
buys reproducibility.

### 5.7 Why expectations live in the spec
Each probe states what we *expect*. The runner reports `match`, `unexpected_effect`,
`expected_effect_missing` or `mismatch`. That gives free **regression testing**:
when a new git release changes a flag's behaviour, the next run shows a diff, and
negative results are recorded too (e.g. `git show --outpu=...` is *not* accepted,
so it's a control with no expected effect).

## 6. Threat model

**Who are we protecting?** Someone who runs an AI coding agent with an allowlist.

**Attacker:** controls text the AI reads (web page, repo file, issue). Can make the
AI emit shell commands, but cannot run code on the host directly and cannot change
the approval rules.

**What gtfo-probe provides:** knowledge. It tells defenders which flags change a
command's capability class so they can write rules (or refuse commands) accordingly.
It does not itself enforce anything.

**What we protect while running probes (safety goals):**
1. The host filesystem is not modified. (read-only root, only throwaway `/work` writable)
2. Nothing leaves the machine. (no network namespace + non-routable canary address)
3. No secrets leak into probes. (cleared environment, host directories invisible)
4. Runaway processes are contained. (timeout, PID namespace)

**Trusted:** the host kernel and bubblewrap; the Python code; the probe files
(which is why they are validated and reviewed as data).
**Not defended against:** a kernel/bubblewrap escape vulnerability (a sandbox is
not a virtual machine), a malicious probe file added by someone with write access to
your checkout (but the tool allowlist and canary-only placeholders limit what a
probe *can* name), and malicious *tool binaries* on the host.

## 7. Limitations (honest list)

* **31 tools, 202 hand-written probes** (38 for the original five, 164 added in
  milestone 3, section 10). Automatic flag discovery (section 11) can propose more, but
  it is a helper with its own limits, not a replacement for review. Anything not in the
  database is reported by `check` as UNKNOWN (section 9).
* **`net` is a text heuristic**, not a syscall observation (see 5.5). Milestone 3 found
  two concrete blind spots: a tool that sends its error text into a file (`wget -o FILE`,
  `ssh -E FILE`) or hides it (`wget -q`) shows no network evidence, and a message that merely
  *mentions* the canary address can be a false positive (see 10.4).
* **Reading is not modelled.** The effect list is `fs_write`, `exec`, `net`. A `cat`, `grep`
  or `head` entry that reads your secrets is "no known risk" here. Reading is a separate
  capability (`fs_read`) that a future milestone should add.
* **Terminal-only behaviour is invisible.** `less`, `man` and other pagers do their
  dangerous things (`!command` escapes, `LESSOPEN`) only when attached to a terminal. The
  sandbox has none, so those tools are not probed at all (see 10.5).
* **`exec` proves "our canary ran"**, so it detects flags that run a program *of the
  caller's choosing*. A flag that runs a fixed program (e.g. a hard-coded
  pager) is not proven by this.
* **Results depend on version and environment.** The DB is keyed by `tool@version`,
  and fixture-dependent effects exist: `git status` rewrites `.git/index` here partly
  because copying the fixture made file timestamps stale. Treat such results as
  "can happen", not "always happens".
* **Exit codes aren't judged.** A probe that errors *after* its effect (e.g. `git
  ls-remote --upload-pa=...` exits 128) still counts; a probe that errors *before*
  doing anything shows as `expected_effect_missing`. That's why every probe records
  `exit_code` and evidence.
* **No multi-step chains** (write a file, then execute it) and no shell-syntax
  tricks (`;`, `$()`, redirection). Those belong to the shell-parsing layer of an
  approval engine, a different problem.
* **Probing is Linux only** (bubblewrap). `check` runs anywhere. See the README for
  Docker / WSL2 (the milestone-2 Dockerfile was verified; the enlarged milestone-3 image is not rebuilt yet).
* **Observation is of the filesystem under `/work`.** Writes elsewhere fail because
  the root is read-only; we then only see the error text ("Read-only file system"),
  which we record as an `attempted` write.

## 8. Responsible use

* Defensive purpose: it helps people tighten allowlists; it contains **no exploit
  code, no payloads**. Probes launch a canary that appends a line to a log.
* Run it only on machines you own or are authorised to test. It never contacts
  any network, and must stay that way. A change that adds network access to the
  sandbox should be rejected in review.
* Keep the output at "GTFOBins level": *which flag gives which capability*, not
  turnkey attack chains.
* If you find that a specific product's allowlist is bypassable, follow that
  vendor's coordinated-disclosure process before publishing details.
* Do not weaken the refusal behaviour (sandbox unavailable => no run).

---

## 9. The `check` command (milestone 2)

### 9.1 What it answers

You give it your agent's allowlist. For every allowed entry it answers:

> "If an attacker controls the arguments, which of the capabilities we measured
> (run a program, write a file, use the network) can this entry still reach?"

It does **not** run any command and needs **no sandbox**, so it works on any OS as
long as you have a `capabilities.json` (made by `run` on Linux, or downloaded).

### 9.2 Input formats, and what each was verified against

All three were checked against public documentation on 2026-10-16.

| Format | Looks like | Verified against |
|--------|------------|------------------|
| **plain** (our own) | one pattern per line: `git show`, `tar`, `git status $` | n/a: our own format, defined in `allowlist.py` |
| **claude** | `.claude/settings.json`: `{"permissions": {"allow": ["Bash(git show:*)"]}}` | Claude Code docs, "Configure permissions": https://code.claude.com/docs/en/permissions |
| **codex** | `~/.codex/rules/default.rules`: `prefix_rule(pattern=["git","show"], decision="allow")` | Codex docs, "Rules": https://learn.chatgpt.com/docs/agent-configuration/rules |

Facts we rely on, quoted in spirit from those pages:

* **Claude Code:** rules are `Tool(specifier)`; `Bash(ls:*)` means the same as
  `Bash(ls *)`; a rule with **no** `*` matches **one exact command**; a `*` may appear
  anywhere and "Claude Code matches everything before the first `*` as written";
  compound commands (`&&`, `;`, `|` ...) are checked part by part; deny rules are
  "not a security boundary" because other spellings (`/usr/bin/curl`, `sh -c ...`,
  `git -C . push`) slip past. Non-Bash rules (`Read(...)`, `WebFetch(...)`) exist and
  we skip them.
* **Codex:** `prefix_rule(pattern=[...])` matches when the command's argument list
  *starts with* the pattern; an element can be a list of alternatives; `decision`
  defaults to `"allow"` ("run the command outside the sandbox without prompting");
  other decisions are `prompt` and `forbidden`. The file is Starlark (Python-like).
  The docs mark rules as **experimental and may change**.

Not verified / not done: Codex's `config.toml` has no per-command allowlist in the
pages we read (only `approval_policy` and `sandbox_mode`), so only `.rules` files are
supported. We did not test against a real Claude Code or Codex install.

**Safety of parsing:** Claude files go through `json.loads`. Codex files go through
Python's `ast.parse` and only literal arguments are read with `ast.literal_eval`. The
file is never executed (a test proves a file that tries to open a file is not run).

### 9.3 How an entry is matched (the heart of it)

Every entry is reduced to three things:

```
Bash(git show:*)   ->  tool = git   pinned words = (show)   extra arguments allowed = yes
Bash(git show HEAD)->  tool = git   pinned words = (show, HEAD)   extra arguments allowed = NO (exact)
tar                ->  tool = tar   pinned words = ()       extra arguments allowed = yes (plain format)
git status $       ->  exact (the trailing ` $` means "exactly this")
Bash(git log * main) -> pinned = (log), extra allowed (everything after the first * is assumed allowed)
```

Then we pick which probes are **in scope** for that entry:

| Entry | Probes that count |
|-------|-------------------|
| `git show:*` | only git probes whose subcommand is `show` (so `git ls-remote --upload-pack` does **not** count against it) |
| `git:*` | every git probe, including the global `git -c ...` one |
| `find:*`, `tar:*`, `sed:*` | every probe of that tool (these tools have no subcommands) |
| exact entry, e.g. `find build -delete $` | only probes whose flag literally appears in the text (`-delete`) |

Why `git show:*` does not include `git -c core.fsmonitor=... status`: both agents match
the words **as written, from the start**, so a command beginning `git -c` is not a
`git show` command. (If you wrote `Bash(git *)`, it would be, and `git:*` counts it.)

Every in-scope probe that showed an effect becomes a **finding**:
severity, the effect, the exact flag, the evidence probe id and one evidence line from
the DB (for example "canary program ran" or "file created: out/probe-output.txt").

### 9.4 Severity

| Effect | Severity | Why |
|--------|----------|-----|
| `exec` (a flag makes the tool run a program) | **critical** | arbitrary code execution |
| `fs_write` through a flag | **high** | can overwrite/delete files |
| `fs_write` in plain use (no flag), e.g. `git status` refreshing `.git/index` | low | the tool's normal behaviour |
| `net` | medium | only `attempted` confidence (text heuristic, see 5.5) |
| runner tool / runner subcommand with arguments (`env`, `xargs`, `python3`, `node`, `make`, `npx`, `npm run`...) | **critical, "by design"** | the entry lets the agent run any program; one finding, no flag list (see 10.2) |
| `Bash` / `Bash(*)` / `*` (allow everything) | critical | nothing to narrow |

The tool cannot know what you *meant* an entry to be for. `tar` is a legitimate
file writer; the report still lists it, because an entry you thought was
"read-only listing" reaches it. You decide.

### 9.5 "Unknown" is not "safe"

Four honest outcomes besides findings:

* **no known risk**: probes for this scope ran and showed nothing. It does *not* say
  safe: only the bundled probes exist (221 after the 2026-10-20 review), and they only test what someone thought of.
* **UNKNOWN (tool)**: the program is not in the DB (`gh`, `docker`, `less`, ...). Not tested.
  For well-known command runners that are *not* in the DB (`bash`, `sudo`, `docker`, `perl`
  ...) the report adds a hint that they can run other programs, and for pagers (`less`,
  `man`) a hint that they can escape to a shell on a terminal. Those hints are hard-coded
  lists, **not** probe data, and say so. (Tools that WERE probed, like `env` or `python3`,
  are reported from probe data instead.)
* **UNKNOWN (scope)**: the tool is in the DB but nothing covers that subcommand
  (`git branch`).
* **skipped**: rules that are not shell commands, or Codex rules whose decision is
  not `allow`.

Every report starts by listing the exact tool versions the DB was made with. A
result for `tar@1.35` says nothing about another `tar`.

### 9.6 Abbreviations, and why the advice is "deny by capability"

Some tools accept shortened long flags: `git ls-remote --upload-pa=PROG` runs a
program exactly like `--upload-pack`, and `tar --use-compress-prog` works like
`--use-compress-program`. Others reject them (`git show --outpu` fails). The DB has
paired probes (`...-abbrev`) and `check` attaches the answer to the finding: "WORKS
abbreviated as `--upload-pa`" or "was rejected by this version". Only abbreviations
that were actually probed are reported; other long flags may work abbreviated too.

The consequence: a deny rule on the string `--upload-pack` misses `--upload-pa`,
`git -c` config tricks, wrappers, and full paths. So the advice is to remove or
**pin** risky wildcard entries (exact commands) and to enforce capabilities where
string matching cannot be dodged: an OS sandbox with no network and a read-only
filesystem, or a hook that inspects the whole argument list. `check` does **not**
subtract your deny rules from its findings, for the same reason.

### 9.7 Exit codes (for CI)

| Code | When |
|------|------|
| 0 | the check ran. Without `--strict` this is always the result, whatever was found. |
| 1 | only with `--strict`: some entry has findings, allows everything, or is UNKNOWN |
| 2 | the allowlist or the DB could not be read or parsed |

`--strict --ignore-unknown` fails only on findings (use it when you accept that tools
outside the DB are untested). The JSON output (`--format json`) has the same
information plus a `disclaimer` field, for scripts.

### 9.8 Limits of `check`

* It cannot see **agent-side protections**. Example: Claude Code's docs say a `find`
  prefix rule will not auto-approve `find` with `-exec`, `-delete` or `-fprint` (it
  still asks). `check` still lists those flags and adds a note for Claude `find`
  entries, but it does not model that behaviour; verify on your agent version.
* Words pinned **after** the subcommand (`git log --oneline:*`) are not analysed: all
  probes for the subcommand count, so a finding may be a false positive (for example
  `tar -tf:*` is flagged for `tar -cf`, which tar itself would reject together with `-t`).
  Over-reporting is the safe direction; under-reporting would not be.
* Exact entries are checked by looking for known flags in the text. Tools whose
  "flags" are script text (`sed` commands like `w file`) cannot be recognised that way.
* Environment variables, shell redirections and expansions inside entries are not
  modelled (`FOO=bar cmd` prefixes are skipped with a note).
* Only the tools and flags in the DB are known. `discover` (section 11) can add more.
* Codex rules are experimental and the format may change; Claude's grammar is
  documented but could change too.

---

## 10. Milestone 3: more tools, runner tools, and what the new probes taught us

### 10.1 What was added

26 tools, 164 probes (202 in total, every one matched its expectation on the final run;
see 10.6 for the one expectation I changed while writing them):

| Group | Tools | What the probes look for |
|-------|-------|--------------------------|
| awk | `gawk`, `mawk` (`awk` in an allowlist is checked as both) | `system()`, pipes, `getline` from a command, `>` redirection, gawk's `-i inplace`, `--profile=`, `/inet`; `--sandbox` as the control |
| runners | `env`, `xargs`, `python3`, `node`, `make`, `npx`, `npm` (subcommands `run`, `exec`, `x`, `install`, `rebuild`) | "does it run the canary program?" |
| write/deletes | `sort`, `cp`, `mv`, `gzip`, `zip`, `unzip`, `rsync` | `sort -o`, `rsync --delete`, `zip -m`, `gzip` replacing files... |
| exec through a flag | `sort --compress-program`, `zip -TT`, `rsync -e`, `ssh -o ProxyCommand`, `scp -S`, `wget --use-askpass`, `pip` (builds) | |
| network | `wget`, `ssh`, `scp`, `rsync`, `pip`, `npm view`, `python3`/`node` code | |
| read-only controls | `diff`, `cat`, `head`, `tail`, `ls`, `grep` | prove that "no known risk" is a measured result, not a guess |

`less` and `man` are **not** here (10.5). Not installed on the development machine at first and
installed with `apt` for this milestone: `gawk less make zip rsync openssh-client man-db`
(`less` and `man-db` were then only used for the pager experiment).

### 10.2 "Runner tools": critical by design

For some programs listing flags is the wrong question. `env X`, `xargs X`, `python3 -c X`,
`node -e X`, `make -f X`, `npx X` and `npm run X` all just run X. Reporting
"`env` can exec via ..., via ..., via ..." would suggest that a deny rule on one flag helps.

How it is modelled (data first, then logic):

* A probe may carry the tag `"runner"`: "this invocation runs arbitrary programs *by design*,
  not through an obscure flag". Tagged probes are the **evidence**.
* `spec.RUNNER_TOOLS` lists the tools that are runners as a whole (`env xargs python3 node
  make npx`). A test requires each of them to have a runner-tagged probe that really ran
  the canary, so the list cannot become a bare opinion.
* `npm` is *not* a runner as a whole (`npm ls` is harmless), so only its runner
  *subcommands* carry the tag. `pip` likewise: only the subcommands that build a local project.
* In the database each tool gets `"category": "runner" | "standard"`, and
  `capabilities` gets a fourth list, `"runner"`.
* `check` then does this for an entry that allows extra arguments (`env`, `python3:*`,
  `npm run`): it prints **one** finding, severity critical, labelled `BY DESIGN`, with the
  plainest proof probe (e.g. `env.runner`), and it drops that tool's other findings
  because they are subsumed. The fix says there is no safe flag list for a runner tool.
* An **exact** entry (`env FOO=1 ls $`) is not collapsed: it runs exactly what it pins, so
  judge that command. The report says so in a note.
* Databases made before milestone 3 have no `category`; `check` treats them as `standard`.

Real output (`gtfo-probe check` on `env`, `npm run`, `npm ls $`):

```
[CRITICAL] env   [env ...]
    critical exec     BY DESIGN (runs any program you hand it)  (probe env.runner, confirmed, env@9.7)
             evidence: canary program ran: canary-exec ran: argv=
    fix: remove this entry or pin the exact command: ... There is no safe flag list for a runner tool.

[CRITICAL] npm run   [npm run ...]
    critical exec     BY DESIGN (runs any program you hand it)  (probe npm.run, confirmed, npm@11.21.1)
    low      fs_write in plain use  (probe npm.ls.baseline, confirmed, npm@11.21.1)

[LOW] npm ls $   [npm ls]
    low      fs_write in plain use  (probe npm.ls.baseline, confirmed, npm@11.21.1)
             evidence: file created: home/.npm
```

(The `npm ls $` line comes from a "baseline" probe, see 10.3.)

### 10.3 Surprising findings, in plain language

All of these are in `docs/examples/capabilities.json` with the evidence.

* **`sort` can run a program.** `sort --compress-program=PROG` runs PROG to compress its
  temporary files. With tiny input sort never makes a temp file, so the first probe did
  nothing; the working probe merges 3 files with `--batch-size=2` to force one. The log
  shows the canary was started twice: once with no arguments (compress) and once with `-d`
  (decompress). The prefix `--compress=` works too.
* **`pip download` runs code.** It sounds like "fetch only", but given a local source
  directory pip must *build* it to learn its metadata, and building runs the project's
  build backend (arbitrary Python). Same for `pip install DIR` and `pip wheel DIR`.
  (A plain `pip install DIR` was refused on this Debian box by the PEP 668 "externally
  managed" marker; the probe `pip.install-plain.control` records that protection and says
  it is machine specific.)
* **`npm run --ignore-scripts` still runs the script.** `--ignore-scripts` only turns off
  the *automatic* lifecycle scripts of `install`/`rebuild`. The npm docs say so, and the
  probe confirms it. `npm install` without the flag runs `preinstall`.
* **npm is never read-only.** Even a plain `npm ls` creates `~/.npm/_logs` (npm 9 and 11).
  That probe, `npm.ls.baseline`, is tagged `baseline` ("every command of this tool does
  this"), and `check` applies it to every npm entry (that is why `npm ls $` is `LOW`, not
  "no known risk"). `npm --version` and `npx --version` are plain controls: npm 9 wrote a
  debug log for them too, but npm 10 and later write nothing, so they are not a reliable
  baseline across versions.
* **Aliases are separate spellings.** `npm run-script` and `npm x` do the same as `npm run`
  and `npm exec`, but a rule written for one spelling does not cover the other (there is no
  alias table; a test documents this limit).
* **`ssh` option names are case-insensitive.** `ssh -oproxycommand=PROG host` runs PROG
  just like `-o ProxyCommand=PROG`. A deny rule matching the text `ProxyCommand` misses it.
  With `ssh -G` (print configuration) the ProxyCommand is only printed, never run: a control.
* **Abbreviations differ per tool**, so each was measured:

  | Tool | Abbreviated long option | Result |
  |------|-------------------------|--------|
  | `sort` | `--outp=`, `--compress=` | works |
  | `gawk` | `--prof=`, `--sandb` | works (also for the *protective* `--sandbox`) |
  | `make` | `--ev=` (for `--eval`) | works |
  | `xargs`, `env` | `--ar=`, `--split=` | works |
  | `cp`, `mv` | `--target-d=` | works |
  | `gzip` | `--decomp` | works |
  | `pip` | `--index=` | works |
  | `wget` | `--output-doc=`, `--use-ask=` | works |
  | `wget` | `--ex=` | **rejected, ambiguous** (`--exclude-directories`, `--exclude-domains`, `--execute`) |
  | `rsync` | `--rs=` | **rejected** (`unknown option`) |
  | `node` | `--ev=` | **rejected** (`bad option`) |

  Rejections are recorded as negative controls, like `git show --outpu=` in milestone 1.
* **`gawk --sandbox` really works**: `system()`, every `>`/`|` redirection and `-i inplace`
  become fatal errors (four controls). But it still reads files.
* **`zip -T -TT PROG` runs PROG** (it replaces the archive tester). `scp -S PROG` and
  `rsync -e PROG` replace the transport program. `wget --use-askpass=PROG` runs PROG when
  a server asks for credentials.
* **Destructive "plain use"**: `gzip FILE` *replaces* FILE, `zip -m` and `rsync
  --remove-source-files` delete the sources, `rsync --delete -r` emptied the `data/`
  directory in the probe, `mv`/`cp` overwrite. These are `fs_write`.
* **`make -t` creates files** (it "touches" targets) and `make -n`/`-q` run nothing
  (controls). `node --cpu-prof-dir=DIR` writes a profile; `python3 -m py_compile` writes
  `.pyc` files.

### 10.4 Problems found in the tool itself (and what was done)

1. **Missing tools produced bogus failures.** On a machine without `rsync`, all its probes
   would report `expected_effect_missing`. Now `run` asks each tool for its version first;
   if the sandbox cannot start it, the tool is **skipped** with a message
   (`SKIPPED (not installed on this machine...)`) and left out of the database.
   `run` refuses to write an empty database.
2. **Different tools print versions differently.** `ssh -V`, `zip -v`, `unzip -v`, and
   `scp` has no version flag at all (it is asked via `ssh -V`: same OpenSSH package). The
   table `runner.VERSION_COMMANDS` holds the exceptions, and the first six lines of
   output are searched, not just the first.
3. **The network heuristic did not know Node/Python errors.** `npm view` failed with
   `EAI_AGAIN` and `node` with `ENETUNREACH`, which none of the patterns matched. Added
   `EAI_AGAIN ENOTFOUND ECONNREFUSED ENETUNREACH EHOSTUNREACH getaddrinfo [Errno 101]`.
4. **Blind spots left as they are, on purpose** (documented in section 7): `wget -o FILE`
   and `ssh -E FILE` send the failure text into the file, so only `fs_write` is seen
   (the probes expect exactly that, with a comment); `wget -q -O -` prints nothing, so its
   network attempt is invisible (no probe written, it would assert a lie). And a
   *false positive*: `pip download --index-url=http://192.0.2.1:9/...` without
   `--trusted-host` prints "The repository located at 192.0.2.1 is not a trusted or secure
   host and is being ignored". That sentence contains our canary address, so the heuristic
   called it `net` although pip never connected. The probe therefore adds
   `--trusted-host=192.0.2.1`, which makes pip really try (and fail) to connect.
5. **pip could not start in the sandbox**: its bundled `requests` needs a CA bundle and
   crashed at import. The sandbox now also binds `/etc/ssl/certs` read-only (public
   certificates, not secrets; `/etc/ssl/private` is not bound). A test checks both.
6. **pip needs no third-party build tool.** The fake Python project uses a 10-line
   in-tree build backend (`pypkg/backend.py`) that runs the canary, because setuptools
   is not installed here and a fixture must not depend on the machine.

### 10.5 Why `less` and `man` are not probed

I tried them in the sandbox. Without a terminal, `less FILE` just prints the file like `cat`;
`less '+!PROG' FILE` and `less -o FILE` did nothing; `man -P PROG -l FILE` printed the page
directly and never started PROG (man only uses a pager when stdout is a terminal). So a
probe would say "no effect", and `check` would then say "no known risk" for the very tools
people know are risky. That is worse than saying nothing, so they are not in
`ALLOWED_TOOLS`, and `check` answers `UNKNOWN` plus a hint labelled "NOT probe data". A
future milestone could give the sandbox a pseudo-terminal.

### 10.6 One expectation changed while writing the probes

`ssh -E FILE` first expected `fs_write` **and** `net`. It showed only `fs_write`: the error
text had gone into the log file (see 10.4 item 4). The expectation was changed to
`fs_write`, with a comment in the probe saying why. Every other expectation was written
after trying the command by hand, so "202 as expected" mostly says the runner reproduces
what I had already seen, not that I predicted it. The value is in the evidence and in the
controls, not in the match count.

### 10.7 Limits of milestone 3

* Linux only, and results are per tool *version* (see the versions at the top of every report).
* GNU tools: BSD/macOS `sort`, `sed`, `tar`, `cp` have different flags; none were probed.
* `diff -l` runs the fixed program `pr`; we cannot observe that (it is not our canary), so
  its probe is only a control for *our* effect types.
* No `fs_read` effect (10.1, section 7), so `cat`, `head`, `tail`, `ls`, `grep` are
  controls only.
* Subcommand scoping covers `git`, `npm`, `pip`. Other tools with subcommands
  (`docker`, `gh`) are not probed.
* The `exec` proof is still "our canary ran". `diff -l` (a fixed program) is the reminder.
* The Docker image for the enlarged tool list is untested.
* npm's own docs say it expands unambiguous abbreviations of config flags (`--par` for
  `--parseable`); only the abbreviations listed in 10.3 were probed, not npm's.

---

## 11. Milestone 4: automatic flag discovery (`gtfo-probe discover`)

### 11.1 What problem it solves

Until now every probe was written by hand: someone had to know that `tar -I` runs a program,
then type the probe. That does not scale to hundreds of flags, and humans miss things.
`discover` automates the boring part: **read the tool's own help page, list its options,
and test the interesting ones in the sandbox.** The result is a list of "this flag really did
something" findings, each backed by the same detector evidence as a hand-written probe.

The one sentence to remember: **the help page suggests, the sandbox decides.**

### 11.2 How it works, step by step

```
tool name
  1. run `tool --help`, `tool -h`, `tool help` INSIDE the sandbox   (discover.capture_help)
  2. read the text, list every option it mentions                    (helpparse.parse_help)
  3. guess which options might be interesting, from their words      (helpparse.classify)
  4. keep the interesting ones, up to a cap                          (discover.select)
  5. for each: build a one-flag probe and run it through the SAME
     sandbox + detector as every other probe                         (discover.probe_candidate)
  6. compare with the hand-written probes: already covered?          (discover.coverage_map)
  7. print a report; with --apply, save the NEW confirmed ones       (discover.write_discovered)
```

**Step 1: the help is run in the sandbox.** Running an unknown tool's `--help` outside a
sandbox would be the very mistake this project warns about, so it goes through
`Sandbox.run`, which refuses unless the preflight self-test passed. Three spellings are tried
because tools disagree (`--help` for GNU tools, `-h` for git subcommands). An answer that is an
error ("invalid option") or does not look like a help page is ignored and shown as ignored
in the report; nothing is guessed from it. For `git`, help is asked per subcommand
(`git show -h`); by default the subcommands are the ones the hand-written probes already use,
or pick your own with `--sub`.

**Step 2: parsing.** Help pages have three common shapes (GNU: `-I, --use-compress-program=PROG`;
git: `-L <range:file>`; and `find`'s run-together prose: `-fprintf FILE FORMAT -print`).
`helpparse.py` recognises flags, their aliases (`-I` and `--use-compress-program` are one
option), whether they take a value, and the value's placeholder name (`PROG`, `FILE`).
It is plain text processing with a few regular expressions; it never runs anything.

**Step 3: hints.** Two cheap clues say what a flag *might* do:
* the **placeholder**: `PROG`/`COMMAND`/`SCRIPT` suggest *runs a program*; `FILE`/`DIR`/`OUTPUT`
  suggest *writes a file*; `URL`/`HOST` suggest *network*;
* **words** in the name or description: `exec`, `program`, `compress`, `pager`, `askpass`,
  `proxy`, `script`, `shell`, `eval`, `open` (exec); `output`, `write`, `delete`, `append`,
  `extract`, `in-place` (fs_write); `upload`, `url`, `remote`, `download` (net).

**Hints are guesses.** A help page that says "execute" proves nothing: the description can be
misleading, and plenty of harmless flags mention files. Hints only decide **what is worth
testing**; they never appear as findings. (`--all-flags` skips the guessing and tests everything,
which is slower and noisier; it is useful to measure what the hints missed, section 11.7.)

**Step 5: testing a candidate.** For each chosen flag the tool builds one ordinary probe
and runs it with the existing `runner.run_probe`: fresh fake world, snapshot, sandboxed run,
snapshot, detector. Details that matter:
* **Values are the harmless canaries**: the canary program for program-like arguments, a file
  inside the fake world for file-like ones, the never-routable `192.0.2.1` URL for network-like
  ones. Nothing real can be named.
* **Minimum companions** (the same rule as hand probes, 5.2): the flag is placed in a
  small scaffold, e.g. `tar FLAG -tf archive`, `find victim FLAG`, `git show FLAG HEAD`
  (`--no-optional-locks` is always added for git so `git status` cannot rewrite the index).
  Some tools have two or three scaffolds, tried in order: `tar -c/-x/--delete` conflict with `-t`,
  so they get their own; `sort --compress-program` only does anything while *merging*, so
  it gets a merge scaffold. **This scaffold table is hand-written knowledge about how to use
  each tool** (`discover.BASES`). Without it discovery silently misses such flags; a test
  shows `sort --compress-program` going unnoticed when the merge scaffold is removed.
* **Spellings**: long options are tried as `--flag=VALUE`, and if the tool refuses that
  (curl does), as `--flag VALUE`.
* **Baseline**: the scaffold is first run *without* the flag. An effect that was already there
  (for example `tar -xf` writes files by itself) is never blamed on the flag.
* **Reproduction**: an effect must show up again in a second fresh world before it counts.
* **Rejected command lines**: if the tool says "unknown option", it did not do anything, so a
  text-heuristic "network attempt" in that run is thrown away. This was added after a real
  false positive: curl's error `option --data=http://192.0.2.1:9/...: is unknown` echoed our
  canary URL back and the net heuristic read it as a connection attempt.
* **Caps**: at most `--max-candidates` flags (default 100), `--timeout` seconds per run
  (default 3), `--max-seconds` per tool (default 120). A runaway help page, a hanging flag or
  a parser bug cannot make discovery run forever; the report says when a cap was hit.

**Seeds.** Some dangerous things are not flags at all, so no help page lists them: `sed`'s
script commands `w FILE` and `e CMD`, or `tar --checkpoint-action` that only works together with
`--checkpoint=1`. A tiny table of **seeds** (`discover.SEEDS`, GTFOBins-style patterns,
3 entries) supplies those as complete probes. They go through the same test and are labelled
`[seed]` in the report and a `seed` tag in saved files.

### 11.3 Reading the report

```
CONFIRMED effects (detector saw them, twice):      <- fs_write / exec, reproduced
    -I, --use-compress-program
        exec=confirmed; reproduced=True; known: tar.use-compress-program
NOT confirmed (text clue only, or did not reproduce):   <- e.g. net=attempted; never saved
ran, no effect observed: 62                         <- tried, nothing happened
rejected by the tool (false leads from the help text)   <- the help mentioned it, the tool refused
```

`known: <probe id>` means a hand-written probe already covers the flag (same flag, an alias,
or a long-flag abbreviation, and for git the same subcommand): the discovery **re-found** it.
`NEW` means no probe covers it yet. Re-finding is good news: it is how we know the pipeline
works on flags we already trust.

### 11.4 `--apply`: what gets saved, and what never does

Without `--apply` nothing is written. With it, `discover` writes probe JSON, in the normal
probe format, for findings that are **NEW, confirmed (fs_write or exec) and reproduced**:
* Net findings are never saved: they rest on a text heuristic (5.5).
* Every saved probe has id `<tool>.disc.<flag>`, a `discovered` tag and a description starting
  with `[discovered]`. They cannot collide with hand-written ids, and a `check`/`run` user can see
  at a glance which probes were machine-found. The file also carries a `discovery` header with
  the tool version and time.
* **Hand-written probes are never touched.** The output file (default
  `probes/<tool>.discovered.json`) is only created or extended if it is one of ours (it has
  the `discovery` header). Any other existing file is refused with an error. Running `--apply`
  again adds only what is still new, so it is safe to repeat.
* The saved file is **not** merged into the bundled probes automatically. To use it,
  run `gtfo-probe run --probes DIR` on a directory holding it (and copy hand-written probes
  you want alongside) or copy it into `src/gtfo_probe/probes/` after reviewing it.
  Discovered probes should be **reviewed by a human** before they back a published database.

With `--all`, `--out` is a directory and one `<tool>.discovered.json` per tool is written.

### 11.5 Safety rules, and how they are enforced

| Rule | How |
|------|-----|
| Nothing runs outside the sandbox, including `--help` | Every execution goes through `Sandbox.run`, which raises unless `preflight()` passed. The CLI refuses (exit 2) if the sandbox is unavailable. A test makes an unverified sandbox try and expects the refusal. |
| Only allowlisted tools | `discover` rejects a tool not in `spec.ALLOWED_TOOLS` before starting anything (exit 3). Every synthesized probe is built with `spec.validate`, so unknown placeholders or non-string argv also fail. |
| Help text is data | It is parsed with regular expressions and never executed or used as a command. Only the *values* we choose (canaries) are put on a command line. |
| No network | Same sandbox as always (`--unshare-net`). Discovery adds no network code. |
| Bounded | Caps on candidates, seconds per run, seconds per tool, help pages (3000 lines, 500 options, 64 KB). |
| Claims need evidence | Only the detector's observation of the fake world creates a finding; the report separates *confirmed* from *not confirmed*. |

### 11.6 Honest limits

* **Help text is incomplete.** Options can be undocumented, hidden, only in the man page, or
  spelled in a way the parser does not recognise. Tools whose help page is not a flag list give almost nothing:
  in the real `--all` run `ssh` (usage is only printed as an *error*, which we deliberately ignore),
  `scp`, `npm` and `npx` tested **0** flags. Absence of a finding is **not** evidence of safety.
* **Keyword gate.** By default only flags with a hint are tested, so a dangerous flag with a boring
  name and description is skipped. `--all-flags` removes the gate (slower, noisier).
* **Companions.** A flag that needs a partner (a merge for `sort --compress-program`, `--checkpoint=1`
  for `tar --checkpoint-action`, a terminal for pagers) is missed unless the scaffold table or a seed
  supplies the partner. Flags needing a *second argument* (`find -fprintf FILE FORMAT`)
  are missed because we pass one value.
* **Abbreviations.** Discovery tests the full flag spelling. It does not probe whether
  `--upload-pa` also works (it does for git); the hand-written `-abbrev` probes remain the
  place for that (9.6). Coverage matching *does* treat an existing `--outp` probe as
  covering `--output`.
* **Script-language tools.** What a `sed` script or an `awk` program can do is not a flag; only seeds cover it.
* **Interactive flags.** There is no terminal and stdin is empty, so things that ask a
  question (`find -ok`) or need a pager do nothing. This is the same blind spot as 10.5.
* **Value kinds are guessed too.** A flag taking a *name* or *number* is not tested with a canary
  at all, and `--flag=VALUE` for one that expects something else just shows "no effect".
* **Net effects stay heuristics.** They are reported, never saved.
* **A flag's effect may need a particular value.** E.g. `-g FILE` (tar's incremental snapshot) only
  creates its file when archiving; with the listing scaffold it shows nothing.
* **Prose examples can look like flags.** `tar -cf archive.tar foo` in a help page's examples
  parses as a flag `-cf` (only visible with `--all-flags`; it was already covered).
* Linux/GNU only, like everything else. The Docker image contains the new code (it ships
  `src/`), but running `discover` inside the container has not been tried.

### 11.7 What it found on real tools

See the end of [WALKTHROUGH.md section 11](WALKTHROUGH.md) for the real output of `tar`, `sed`,
`find` and `sort`. In short: the five tar flags that already had hand probes were all
re-found; six unprobed tar writers, the `find -fprint0` variant and more were new;
`sed` and `sort` found nothing new; and each tool had concrete misses.


## 12. Checked against a real Claude Code install (2026-10-19)

### 12.1 What was done
- Installed Claude Code with the official native installer (`curl -fsSL https://claude.ai/install.sh | bash`,
  from https://code.claude.com/docs/en/setup). `claude --version` → `2.1.303 (Claude Code)`.
- Not signed in (`claude auth status` → `"loggedIn": false`). No API key was used. So Claude Code was
  never asked to run a command; everything below is from its docs and its offline `claude doctor`.
- Fresh install creates `~/.claude.json` and `~/.claude/{backups,downloads,sessions}`, but **no**
  `settings.json` and no default allow rules. Settings files: `~/.claude/settings.json` (user),
  `.claude/settings.json` (project, shared), `.claude/settings.local.json` (local; "don't ask again"
  approvals are saved here, at the git repo root).
- `claude doctor` validates settings offline. A realistic file (`docs/examples/claude-realistic-settings.json`)
  passed; a broken one (`"ask": "oops"`) was reported as
  `permissions.ask: Expected array, but received string`. It did **not** print the documented warning
  for `Bash(git * main)` offline (that warning is shown at session start).

### 12.2 Format details re-read from https://code.claude.com/docs/en/permissions, and parser changes
| Docs say | gtfo-probe now |
|---|---|
| `*` matches any text and may appear anywhere; `Bash(x *)` = `Bash(x:*)`; no `*` = exact | unchanged (already right) |
| Leading `*`: `Bash(* --version)` matches any program (e.g. `bash -c '…' --version`) | reported as allow-all with that explanation |
| `:*` is only special at the end; `Bash(git:* push)` is a literal colon | reported as skipped: matches nothing |
| `Bash(ls*)` (no space) also matches `lsof` | unchanged note |
| Wrappers `timeout time nice nohup stdbuf command builtin noglob` and flag-less `xargs` are stripped before matching | stripped for Claude rules, with a note; `command -v` and `xargs -n1` are not |
| Rules are evaluated deny → ask → allow | `deny`/`ask` Bash rules are read; overlapping ones are shown as a note on the allow entry, findings are **not** reduced (the docs say these rules miss `/usr/bin/curl`, `sh -c`, `git -C .`) |

### 12.3 What Claude Code already protects vs. what gtfo-probe adds
Claude Code (per its docs, not verified live):
- prompts for `find` with `-exec`/`-delete`/`-fprint`… or `-files0-from`, even under `Bash(find *)`;
- never auto-approves exec wrappers `watch`, `setsid`, `ionice`, `flock` via a prefix rule;
- splits compound commands (`&&`, `;`, `|`…) and checks each part;
- prompts on unquoted globs for `find`, `sort`, `sed`, `git`;
- checks `>`, `>>`, `<` and `tee` targets against Read/Edit rules;
- auto-allows a built-in read-only set (`ls cat echo pwd head tail grep find wc which diff stat du cd`,
  read-only `git`) **with no rule at all**.

gtfo-probe adds: measured evidence that flags such as `sort --compress-program`, `tar -I`/`--to-command`,
`sed e`, `git diff/log/show --output`, `sort -o`, `curl -o` run programs or write files. The docs list no
check for files written **by a flag** (only redirects and `tee`), so an Edit deny rule does not cover them,
and `Bash(sort *)`, `Bash(tar *)`, `Bash(sed *)`, `Bash(git log *)` allow them silently. These points are
now printed as "agent note" lines on Claude entries, each marked as documented behaviour, not probe data.

## 13. Reviewing discovered findings (2026-10-20)

Discovery proposes; a person decides. The 17 findings from `discover --all` were each re-run by
hand in the sandbox (with content hashes, not just mtimes), checked against the tool's own
documentation, and given a verdict: 15 promoted, 2 rejected. Promoted findings are ordinary
hand probes in `probes/<tool>.json` that keep their provenance in `tags: ["discovered",
"reviewed"]`. Where the discovered argv was a scaffold artifact (for example `gawk -d FILE`, where
FILE became the program text, or a `tar --catenate` that only touched the archive's mtime), the
probe uses a corrected argv. The full table with evidence is in
[REVIEW-discovered.md](REVIEW-discovered.md), and `tests/test_review.py` keeps the probes and that
table in sync.

