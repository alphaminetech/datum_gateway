# DATUM Gateway, AlphaPool release 3.1

This branch (`alphapool`) is the source code of AlphaPool's DATUM gateway, release 3.1: the gateway
build that AlphaPool tests with its pool and that its node installer installs by default. It is the
DATUM Gateway for BLAKE2b work plus the changes listed below. Everything the release is built from
is in this repository. The upstream project's own README is kept unchanged in
[`README.upstream.md`](README.upstream.md).

You do not need this build to mine with AlphaPool. You can run any DATUM gateway you choose.

## What is different from upstream

The release is commit `90f01b76625f5936febdc2389759c462467a750a`. Its base is commit
`7491a5099dd5d887a027c812f71de63e0d5986a3`, which is part of this branch's history. On top of the
base, in this order:

### Upstream pull requests, carried unchanged

Each is its author's own commit, cherry-picked onto the base as it stands in the pull request.

| Commit | Pull request | Author | Change |
|---|---|---|---|
| [`e23df65b`](https://github.com/alphaminetech/datum_gateway/commit/e23df65bde78436b0324c8184d4366d98ff05b97) | [CONVOYMining/datum_gateway#9](https://github.com/CONVOYMining/datum_gateway/pull/9) | Jason Sopko | protocol: Take the coinbaser lock before sending the request. A reply that arrived between the request and the wait for it is no longer lost. |
| [`cfd127b7`](https://github.com/alphaminetech/datum_gateway/commit/cfd127b743dbb8c5100e415099dc440b02c551aa) | [CONVOYMining/datum_gateway#18](https://github.com/CONVOYMining/datum_gateway/pull/18) | Paul Lamb | Bugfix: stratum: Keep the dupe index valid across a table cleanup. With its tests. |

### AlphaPool's changes

| Commit | Change |
|---|---|
| [`2e783c43`](https://github.com/alphaminetech/datum_gateway/commit/2e783c43444f180bd48deab74cde4c5484da5008) | **A gateway identity that survives restarts.** New optional setting `datum.identity_key_path`: the gateway's signing and encryption keys are kept in that file (mode 0600), so the pool sees the same gateway after a restart. Without the setting nothing changes. |
| [`c24fb32e`](https://github.com/alphaminetech/datum_gateway/commit/c24fb32e7ac94c8bc128fd49cbd4c04797458885) | **Pooled-only mode serves only work that carries the pool's payout assignment.** Details below. |
| [`90f01b76`](https://github.com/alphaminetech/datum_gateway/commit/90f01b76625f5936febdc2389759c462467a750a) | **Reproducible build recipe** in `contrib/reproducible/`. No change to the gateway's code. |

All five as one diff:
<https://github.com/alphaminetech/datum_gateway/compare/7491a5099dd5d887a027c812f71de63e0d5986a3...90f01b76625f5936febdc2389759c462467a750a>

### Pooled-only mode

With `datum.pooled_mining_only` set to `true`:

- A miner is sent a job only after the pool's coinbaser for that job has arrived, the coinbase has
  been built from it, and the result has been checked. No placeholder work is sent in the meantime;
  miners keep the work they have.
- Before a job is published, the coinbase that miners will be served is decoded and compared, output
  by output, with the assignment it was built from. A job that fails the check is withheld and
  requested again.
- An assignment belongs to the DATUM session it was requested on. If that session ended before the
  job was published, the assignment is discarded and requested again.
- If no usable coinbaser arrives for 60 seconds, the gateway disconnects its miners once, so that
  they can fail over, and refuses new connections until a coinbaser is published again.
- Shares are accepted only for work the gateway served in this mode.

In every mode that uses a pool:

- The pool's coinbaser reply is used whole or not at all. A reply with an output past the job's
  coinbase value, more than 512 outputs, a bad script length or trailing bytes is rejected.
- The coinbaser fetch waits for the reply to its own request. Waiting for the reply that carries the
  job's coinbase value is pull request 9 above; this release adds that the reply must have arrived on
  the same DATUM session and, if the pool echoes the request's token, must carry that token.
- A pool id that fits in 32 bits is written in the 7-byte form of the coinbase id push.

Solo mining is unchanged.

## The release build

| | Ubuntu 22.04 | Ubuntu 24.04 |
|---|---|---|
| Archive | `datum_gateway-r3.1-g90f01b76625f-jammy.tar.gz` | `datum_gateway-r3.1-g90f01b76625f-noble.tar.gz` |
| sha256 of the archive | `93fe865c5ecedb30886e16ce9ae8943b3a88218f362af078608a9f6caa19d15c` | `85e5131c272418bf1c12a59802aaea58a902f020c6e9a25bbb46c1ff8b3d14ed` |
| sha256 of `datum_gateway` | `52367405588d48138a972f871624fe9da88df350bec6ebc03d4d83e954f3b043` | `02ca5e7b78c4bd89b97ab385932a6f7baecb0c77bc023f5a57d06d956a336792` |
| Needs | glibc 2.34 or newer | glibc 2.38 or newer |

The version this build sends to the pool in the DATUM handshake is

```
v0.4.1-beta/90f01b76625f5936febdc2389759c462467a750a
```

that is, the protocol version and the full hash of the commit it was built from.

## Rebuild it and get the same bytes

```
git clone https://github.com/alphaminetech/datum_gateway.git && cd datum_gateway
git checkout 90f01b76625f5936febdc2389759c462467a750a
contrib/reproducible/build.sh jammy out    # Ubuntu 22.04
contrib/reproducible/build.sh noble out    # Ubuntu 24.04
sha256sum out/*.tar.gz
```

You need Docker on an x86-64 machine. The recipe pins the container image by digest, takes every
package from the Ubuntu archive at one fixed time stamp, builds in a fixed directory and packs a
deterministic archive, so the two sha256 values above come out again. How it works and what
exactly is fixed: [`contrib/reproducible/README.md`](contrib/reproducible/README.md).

## Build it your own way

```
sudo apt install build-essential cmake pkg-config git libcurl4-openssl-dev libjansson-dev libmicrohttpd-dev libsodium-dev
git clone --no-tags https://github.com/alphaminetech/datum_gateway.git && cd datum_gateway
git checkout 90f01b76625f5936febdc2389759c462467a750a
cmake . && make
./datum_gateway --test        # the gateway's own test suite
```

Such a build sends the same version string. Its bytes differ from the release build when the
compiler, the libraries or the directory differ. (`--no-tags` matters: the build system adds
`(<tag>)` to the version when an annotated tag points at the commit that is built.)

Later commits on this branch change documentation only. The release stays the commit named above.

## Licence

MIT, see [`LICENSE`](LICENSE). The DATUM Gateway is the work of its upstream authors and
contributors; AlphaPool's changes are published under the same licence.
