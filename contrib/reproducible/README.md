# Reproducible builds

`build.sh` builds the gateway for Ubuntu 22.04 (`jammy`) or Ubuntu 24.04 (`noble`) in a way that
gives everyone the same bytes: the same executable and the same archive, whenever and wherever
the build runs.

## Use

```
git clone https://github.com/alphaminetech/datum_gateway.git && cd datum_gateway
git checkout <commit>                      # the full commit hash you want to build
contrib/reproducible/build.sh jammy out    # Ubuntu 22.04
contrib/reproducible/build.sh noble out    # Ubuntu 24.04
```

You need an x86-64 machine with Docker (or Podman: `DOCKER=podman`) and network access to
Docker Hub and `snapshot.ubuntu.com`. A build takes a few minutes. The source comes only from
the repository you build from: the commit and everything it is based on are in its history, and
nothing is fetched from another repository. To build a commit that is not checked out, or from a
repository URL instead of a local clone, name them:

```
COMMIT=<40-character hash> contrib/reproducible/build.sh noble out
SOURCE=https://github.com/alphaminetech/datum_gateway.git COMMIT=<40-character hash> contrib/reproducible/build.sh noble out
```

Each run writes to the output directory:

| File | Content |
|---|---|
| `datum_gateway-<label>-g<commit12>-<jammy\|noble>.tar.gz` | `datum_gateway`, `BUILDINFO`, `LICENSE` |
| `….BUILDINFO` | the commit, the version string the gateway sends, the executable's sha256, and what it was built with |
| `….packages.txt` | every package in the build container, with its version |
| `….selftest.log` | output of `datum_gateway --test`; the build fails if a test fails |

and prints the commit, the version string, and the sha256 of the executable and of the archive.

## What is fixed

| Input | How |
|---|---|
| Container image | `ubuntu:22.04` / `ubuntu:24.04` by digest (see `build.sh`) |
| Compiler, C library, CMake, libraries | every package comes from the Ubuntu archive as it was at one time stamp (`APT_SNAPSHOT` in `build.sh`), served by `snapshot.ubuntu.com` and checked by APT against the archive keys in the image |
| Source | one commit, by full hash, fetched without tags |
| Build directory | `/build/datum_gateway` (the path is compiled into the test code's messages) |
| Build commands | `cmake -S . -B . && make`, the project's defaults |
| Time | `SOURCE_DATE_EPOCH` and the archive's file times are the commit's time; time zone UTC |
| Archive | sorted names, owner and group 0, `gzip -n` |

Building on your own system instead (`cmake . && make`) gives a working gateway with the same
version string, but not the same bytes: another compiler, other library versions or another
directory change the executable.

## The version a build reports

The gateway sends its version to the pool in the DATUM handshake as
`<protocol version>/<commit>`, for example `v0.4.1-beta/0123…cdef`, where `<commit>` is the full
hash of the commit it was built from. The build system adds a `+` when tracked files were
modified, and `(<tag>)` when the commit carries an annotated tag. This recipe fetches the commit
without tags and stops if the result is not exactly the commit hash, so a build made with it
always reports the plain commit.

## Checking a published build

```
sha256sum out/datum_gateway-*.tar.gz                              # the archive
tar -xzOf out/datum_gateway-*-noble.tar.gz --wildcards '*/datum_gateway' | sha256sum   # the executable
```

Compare both with the published values. `BUILDINFO` inside the archive names the commit, so
anyone can repeat the build from it.
