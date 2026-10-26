# gtfo-probe

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

**Find the flags that turn an AI agent's "read-only" commands into file writers, program runners and network clients.**

If you allow your coding agent to run `pip list`, you have also allowed `pip --python=PROG list`,
and that runs PROG. `gtfo-probe` tests flags like that one in a locked-down sandbox, records what
really happened, and then checks your agent's allowlist against that evidence.

It is for anyone who writes or reviews command allowlists for Claude Code, Codex or a similar
agent: developers, security engineers and platform teams.

> Status: early release (0.1.0). Probing runs on Linux. `check` runs anywhere Python does.
> Read [Limitations](#limitations) before relying on it.

## The problem

AI coding agents such as Claude Code and Codex let you pre-approve shell commands so the agent
can run them without asking each time. People approve commands that *look* read-only: `git log`,
`git show`, `sort`, `find`, `tar`.

But approving a command usually means approving **every flag it accepts**, and many "read-only"
tools have flags that are not read-only at all:

| Approved command looks like | One flag later | What actually happens |
|---|---|---|
| `git log` | `git log --output=FILE` | writes a file |
| `sort` | `sort --compress-program=PROG` | runs a program |
| `tar -tf archive.tar` | `tar -tf archive.tar -I PROG` | runs a program |
| `tar -tf archive.tar` | `tar -tf archive.tar --index-file=FILE` | overwrites a file |
| `pip list` | `pip --python=PROG list` | runs a program |
| `find .` | `find . -exec PROG ;` | runs a program |

If an attacker can get text in front of the agent (a README, an issue, a web page, a code
comment), a prompt injection can steer the agent to an approved command with one of these flags.
This has happened in practice. For example, in CVE-2025-66032
([GHSA-xq4m-mc3c-vvg3](https://github.com/anthropics/claude-code/security/advisories/GHSA-xq4m-mc3c-vvg3),
fixed in Claude Code 1.0.93), one of the bypasses used `git ls-remote --upload-pa=...`. Git
accepts abbreviated options, so that slipped past a filter for `--upload-pack` and ran a command
([write-up by RyotaK, GMO Flatt Security](https://flatt.tech/research/posts/pwning-claude-code-in-8-different-ways/)).

## What it does

`gtfo-probe` has three commands that do the work:

- **`run`** runs the bundled probes. Each probe is one tool plus one flag, executed in a sandbox
  with no network, against throwaway canary files. The results go into `capabilities.json`, a
  database of what each `tool@version` can really do, with evidence.
- **`check`** reads an agent allowlist (plain text, Claude Code `settings.json`, or Codex
  `.rules`) and reports which approved entries can write files, run programs or reach the network,
  with the exact flag and the probe that proved it.
- **`discover`** reads a tool's `--help` inside the sandbox, guesses which flags might matter,
  and tests them. It only reports effects that the detector saw twice. Its findings are leads for
  a human to review, not verdicts (see [docs/REVIEW-discovered.md](docs/REVIEW-discovered.md)).

There is also `doctor`, which checks that the sandbox works, and `list`, which shows the probes.

Today the bundled set is **221 probes over 31 tools**: git, sed, find, tar, curl, gawk, mawk,
xargs, env, sort, diff, cat, head, tail, ls, grep, cp, mv, python3, node, npm, npx, pip, make,
wget, ssh, scp, rsync, zip, unzip and gzip. 71 of the probes are **controls** that must show
*no* effect, which keeps the detector honest.

## Quickstart

You need Git and Python 3.11 or newer. There are no other dependencies.

```bash
git clone https://github.com/Dfleisch/gtfo-probe
cd gtfo-probe
python3 -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

### Check an allowlist (any OS)

`check` runs nothing. It only reads a capability database. The repository includes one, made on
Debian 13 with GNU tools, at `docs/examples/capabilities.json`. Try it on the bundled example first:

```bash
gtfo-probe check docs/examples/claude-realistic-settings.json --db docs/examples/capabilities.json
```

Then point it at your own allowlist. It reads Claude Code settings (`~/.claude/settings.json`,
or `.claude/settings.json` and `.claude/settings.local.json` in a project), Codex `.rules` files
(such as `~/.codex/rules/default.rules`), or a plain text file with one command per line:

```bash
gtfo-probe check ~/.claude/settings.json --db docs/examples/capabilities.json
gtfo-probe check my-allowlist.txt --db docs/examples/capabilities.json --strict   # exits 1 on findings, for CI
```

### Probe your own tools (Linux)

Probing needs [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`):

```bash
sudo apt install bubblewrap        # Debian/Ubuntu; use your distribution's package manager otherwise
gtfo-probe doctor                  # checks the sandbox; refuses to continue if it is not safe
gtfo-probe run --out capabilities.json
gtfo-probe check my-allowlist.txt --db capabilities.json
gtfo-probe discover tar            # report-only flag discovery for one tool
```

`run` only probes tools that are installed, and it lists the ones it skipped. A full run takes
well under a minute. Use `--tool NAME` to probe just one tool, and `gtfo-probe list` to see every
probe without running anything.

Run this on a disposable machine or VM. See [Threat model](#threat-model).

### Probe with Docker (experimental)

For macOS, Windows, or Linux without bubblewrap. On Windows, WSL2 is plain Linux, so the native
steps above also work there.

```bash
docker build -t gtfo-probe .
# check needs nothing special:
docker run --rm -v "$PWD:/data:ro" gtfo-probe check /data/docs/examples/allowlist.txt --db /data/docs/examples/capabilities.json
# probing needs user namespaces and a fresh /proc, so both flags are required:
FLAGS="--security-opt seccomp=unconfined --security-opt systempaths=unconfined"
docker run --rm $FLAGS gtfo-probe doctor
docker run --rm $FLAGS -v "$PWD:/out" gtfo-probe run --out /out/capabilities.json
```

Tested on Debian 13 with Docker Engine 26.1, with an earlier, smaller probe set. Docker's
defaults fail `doctor`, and so does either flag on its own. Keep the image's default non-root
`probe` user. Docker Desktop, Podman and Ubuntu hosts (which may also need
`--security-opt apparmor=unconfined`) are not tested yet, so run `doctor` and `run --strict` first.

## Example output

A realistic Claude Code `settings.json` with 20 rules
([input](docs/examples/claude-realistic-settings.json),
[full output](docs/examples/claude-realistic-settings.json.out.txt)). Trimmed:

```text
[HIGH] Bash(git log *)   [git log ...]
    high     fs_write via --output  (probe git.log.output, confirmed, git@2.47.3)
             evidence: file created: out/probe-output.txt
    fix: pin the exact command (write the whole command with no `*`/`:*`, e.g. `Bash(git log <the exact arguments>)`), or remove this entry.

[CRITICAL] Bash(sort *)   [sort ...]
    critical exec     via --compress-program  (probe sort.compress-program, confirmed, sort@9.7)
             evidence: canary program ran: canary-exec ran: argv=
             abbreviation: WORKS in a variant spelling, --compress (probe sort.compress-program-abbrev); deny by capability, not by flag string

[CRITICAL] Bash(tar *)   [tar ...]
    critical exec     via -I  (probe tar.use-compress-program, confirmed, tar@1.35)
             evidence: canary program ran: canary-exec ran: argv=-d
    high     fs_write via --index-file  (probe tar.index-file, confirmed, tar@1.35)
             evidence: file created: out/probe-output.txt

[CRITICAL] Bash(* --version)
    note: a leading `*` stands in for the PROGRAM, so any program matches (Claude Code docs: `Bash(* --version)` matches `bash -c 'echo hi' --version`)

[CRITICAL] Bash(timeout 30 make *)   [make ...]
    critical exec     BY DESIGN (runs any program you hand it)  (probe make.directory, confirmed, make@4.4.1)
    note: Claude Code strips the wrapper `timeout` before matching; analysed as `make`

[UNKNOWN] Bash(git branch:*)   [git branch ...]
    note: no probes cover `git branch`: UNKNOWN (not tested)

[no known risk] Bash(ls *)   [ls ...]
    note: probes for this scope showed no effect; that is not a proof of safety

summary: 20 entries (1 allow_all, 13 findings, 3 no_known_risk, 2 skipped, 1 unknown_scope); findings by severity: 12 critical, 23 high, 3 low, 1 medium
```

Statuses are **CRITICAL** (can run programs), **HIGH** (can write files), **no known risk**, or
**UNKNOWN**. The tool never says "safe". Where the agent has its own documented protections (for
example, Claude Code still prompts for some `find` flags), the report labels them as **agent
notes**, kept apart from probe evidence.

## How it works

1. **Probe cards.** Each probe is a small JSON object: the tool, an argument list (never a shell
   string), and the effect it expects. Only tools on a fixed list can be probed.
2. **Fake world.** Every probe gets a fresh copy of a tiny world: a git repo, a tar archive,
   text files, a fake "secret", and a **canary program** whose only job is to write one line to
   a log when it runs.
3. **Sandbox.** Probes run under bubblewrap: no network, read-only system, an empty environment,
   and only the fake world writable. Your home directory and keys do not exist inside it. Before
   anything runs, a self-test *measures* that the sandbox is locked, and the tool refuses to run if it
   is not. There is no unsafe fallback.
4. **Detector.** Before and after snapshots of the fake world show file writes. A line in the
   canary log proves a program ran. Network attempts are inferred from error text.
5. **Database.** Results go to `capabilities.json`, grouped by `tool@version`, with the evidence
   for each finding.

The design, with the reasons behind each choice, is in [docs/DESIGN.md](docs/DESIGN.md). A guided
tour of the code in reading order is in [docs/WALKTHROUGH.md](docs/WALKTHROUGH.md).

## Supported allowlist formats

| Format | What is read |
|---|---|
| Plain text | One command prefix per line. |
| Claude Code `settings.json` | `Bash(...)` rules in `permissions.allow`, including `:*`, `*`, a leading `*`, and wrappers such as `timeout`. `ask` and `deny` rules are noted. |
| Codex `.rules` | `prefix_rule(pattern=[...])` entries. |

Both agent formats were checked in October 2026 (Claude Code 2.1.303) against the
[Claude Code permissions docs](https://code.claude.com/docs/en/permissions) and the
[Codex rules docs](https://learn.chatgpt.com/docs/agent-configuration/rules). If an agent changes
its matching rules, `check` may read them differently. Please open an issue if you spot one.

## Threat model

**What it is for.** An AI agent may be steered by untrusted text (prompt injection) into running
an approved command with attacker-chosen arguments. `gtfo-probe` answers this question: *with the
arguments an attacker could choose, what can each approved command actually do?*

**It models** three effects of single flags on a tool: writing files, running programs and
opening network connections. It also covers spelling tricks the tool accepts, such as
abbreviated long options (`--upload-pa` for `--upload-pack`) and case-insensitive options.

**It does not model:**
- reading files. An approved `cat` or `grep` can still read secrets.
- combinations of several flags beyond those written into a probe.
- shell features such as pipes, redirection and substitution. The agent's own parser handles
  those.
- configuration the tool reads from the project, such as `.git/config`, `.npmrc` or `Makefile`.
- other operating systems and tool builds.

**The probe runner itself** deliberately executes dangerous flags. Its safety rests on the
sandbox. The sandbox shares the host kernel, so a kernel or bubblewrap bug could let a probe
escape. In Docker, the two `--security-opt` flags also weaken the container. Run `run` and
`discover` on a disposable machine, VM or container that holds no secrets. `check` executes
nothing and is safe to run anywhere.

## Limitations

- **Unknown is not safe.** "No known risk" only means the probes that exist saw nothing. Tools
  and subcommands without probes are reported as UNKNOWN.
- **Linux and GNU only.** The bundled database describes Debian 13 builds (GNU tar, sed, find
  and others). macOS and BSD tools take different flags. Results are labelled `tool@version`, so
  use a database made on the same kind of system as your agent.
- **Expectations follow one set of versions.** Each probe says what it expected on the tools
  in the bundled database (Debian 13, npm 11). A different version can behave differently,
  and `run` reports that instead of hiding it. Example: npm 9 writes a debug log even for
  `npm --version`, so on npm 9 `run --strict` reports `npm.version.control` and
  `npx.version.control` as "unexpected effect".
- **Network detection is a heuristic.** It relies on error text from a sandbox without network,
  so network findings are marked "attempted", and tools that hide their errors can be missed.
- **Help text has gaps.** `discover` only tests what the help page mentions. For example,
  `git show -h` omits `--output`. Flags that need a companion flag, a second argument or a
  terminal are missed. `less` and `man` are not probed at all, because pager escapes need a
  terminal.
- **Sandbox shares the kernel.** See [Threat model](#threat-model).
- **Agent protections are documented, not tested.** Agent notes come from vendor documentation,
  not from running the agent.

## Responsible use

This is a defensive tool. It exists to help people tighten the permissions they give AI agents.
Use it on your own systems and allowlists.

- Probes run only inside the verified sandbox, against canary files and a reserved documentation
  IP range (192.0.2.0/24, RFC 5737). Keep it that way when you add probes.
- Do not use it, or its findings, against systems you do not own or have permission to test.
- If you find a way to bypass an agent vendor's own protections, report it through that vendor's
  security or disclosure program before publishing details.

## Prior art and credit

[GTFOBins](https://gtfobins.github.io/) is the reference, hand-curated list of how Unix binaries
can be abused to break out of restricted environments, and the inspiration for this project's
name. `gtfo-probe` does not copy its data. It takes a complementary approach: it **measures**
behaviour on a specific tool version in a sandbox, records the evidence, and applies the result to
agent allowlists. If you want to understand a technique in depth, GTFOBins is the place to start.

The agent-allowlist angle owes a lot to public research on this bug class, especially RyotaK's
[Pwning Claude Code in 8 Different Ways](https://flatt.tech/research/posts/pwning-claude-code-in-8-different-ways/)
(CVE-2025-66032). Niki A. Niyikiza's
[follow-up](https://niyikiza.com/posts/cve-2025-66032/) makes the same point this tool is built on:
allowlists are policies over names, but security needs policies over effects.

## Contributing

Probes are plain JSON, so you don't need to know the internals to add one. Roughly:

1. Try the command by hand in the sandbox first and read what it actually does.
2. Add it to `src/gtfo_probe/probes/<tool>.json`. Include at least one control per tool, and an
   abbreviation twin where the tool accepts abbreviated options.
3. Run `gtfo-probe run --tool <tool> --strict` and investigate every mismatch before you change
   an expectation.
4. Regenerate `docs/examples/capabilities.json` and the example outputs, then run `pytest`.

Findings from `discover` need a human review before they become probes. Follow the process in
[docs/REVIEW-discovered.md](docs/REVIEW-discovered.md). The full checklist is in
[docs/WALKTHROUGH.md](docs/WALKTHROUGH.md).

Development setup: `pip install -e '.[dev]' && pytest`. Tests that need the sandbox are skipped
when bubblewrap is unavailable.

## Reporting security issues

If you find a bug in gtfo-probe itself, especially one that weakens the sandbox, please report it
privately with **Report a vulnerability** on the repository's [Security tab](https://github.com/Dfleisch/gtfo-probe/security)
rather than in a public issue.

## License

MIT. See [LICENSE](LICENSE).
