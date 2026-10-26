# gtfo-probe in a Linux container, for macOS / Windows users (Docker Desktop runs Linux containers).
#
# Debian 13 ("trixie") is used because it is what the bundled example database was
# produced on, so tool versions match (git 2.47, tar 1.35, sed 4.9, find 4.10, curl 8.14).
#
# STATUS: built and run on Debian 13 + Docker Engine 26.1 (docker.io package, cgroup v2).
# The first image (git/sed/find/tar/curl only) passed `doctor` and all 38 probes. The image
# with the packages below for 26 more tools passed `doctor` and all 202 probes of that time.
# The current 221-probe set has NOT yet been run in Docker; re-verify with `doctor` and
# `run --strict` before relying on it.
#
# Build:   docker build -t gtfo-probe .
# Check:   docker run --rm -v "$PWD:/data:ro" gtfo-probe check /data/allowlist.txt --db /data/capabilities.json
# Doctor:  docker run --rm --security-opt seccomp=unconfined --security-opt systempaths=unconfined gtfo-probe doctor
# Probe:   docker run --rm --security-opt seccomp=unconfined --security-opt systempaths=unconfined \
#              -v "$PWD:/out" gtfo-probe run --out /out/capabilities.json
#
# Why BOTH flags (verified): bubblewrap needs Linux user namespaces AND a fresh /proc mount.
#   - default Docker settings:                 doctor FAILS ("No permissions to create a new namespace")
#   - seccomp=unconfined only:                 doctor FAILS ("Can't mount proc on /proc")
#   - systempaths=unconfined only:             doctor FAILS (namespace creation blocked by seccomp)
#   - seccomp=unconfined + systempaths=unconfined: doctor OK
# Do not run the container as root (-u 0): with both flags bwrap still failed in testing
# ("Creating new namespace failed").  The image's default non-root `probe` user works.
# On Ubuntu hosts you may additionally need `--security-opt apparmor=unconfined` (not tested).
# The `check` command needs none of this.
#
# WARNING: the sandbox shares the host kernel.  Weakening Docker's seccomp and masked
# paths makes the container itself less isolated.  Run probes on a disposable machine/VM,
# never on one holding secrets.
FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        bubblewrap git sed findutils tar curl ca-certificates python3 python3-venv python3-pip \
        gawk mawk coreutils diffutils grep gzip unzip zip make wget rsync openssh-client nodejs npm \
 && rm -rf /var/lib/apt/lists/*

# Install gtfo-probe into its own virtualenv (no root-owned system Python changes).
COPY pyproject.toml README.md LICENSE /src/
COPY src /src/src
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir /src
ENV PATH="/opt/venv/bin:$PATH"

# Probes must never run as root.
RUN useradd --create-home --shell /usr/sbin/nologin probe
USER probe
WORKDIR /home/probe

ENTRYPOINT ["gtfo-probe"]
CMD ["doctor"]
