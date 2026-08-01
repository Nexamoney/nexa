Nexa Hard Fork 2 feature overview
=================================

This document gives an overview of the consensus and protocol changes that
activate with Nexa Hard Fork 2 (also called "fork2"; the source code calls
it "Upgrade 2" since !782 renamed the fork symbols).  It is based on the
changes merged into `dev` since the Nexa 2.1.0.0 release, the
[Hard Fork (Minor) Features](https://gitlab.com/nexa/nexa/-/issues/37)
tracking issue, and [doc/scripts2026.md](scripts2026.md).

Hard Fork 2 is still under active development.  Feature scope and activation
times may change before release.

Please report bugs using the issue tracker at gitlab:

  <https://gitlab.com/nexa/nexa/-/issues>

Activation
==========

Hard Fork 2 uses the same 2 phase activation as Fork 1 (see
[doc/fork1.md](fork1.md)).  When the MTP (median time past) of a block
reaches the activation time the fork is "pending": the txpool is
re-admitted under the new rules, but blocks still follow the old ruleset.
The next block and all subsequent blocks are evaluated under the Hard Fork 2
rules.

The activation time is held in the `consensus.fork2Time` tweak
(`miningForkTime`), which defaults to `consensus.nextForkActivationTime` per
network:

* mainnet and testnet: `1793495471` (Nov 1, 2026).  !835 moved this out
  from June 21, 2026, "we can pull it in later", so the final date is not
  yet decided.
* regtest: `1789948805` (Sept 21, 2026)
* stormtest: pending at height 2 and active from height 3, regardless of
  time

Feature summary
===============

### Tailstorm

The headline Hard Fork 2 feature.  Tailstorm replaces single 2 minute
blocks with a DAG of `k` subblocks (mainnet `TAILSTORM_K = 120`) that are
tied together by a summary block, giving ~1 second commitment intervals
while keeping the 2 minute settlement cadence.  Merged in !754 with many
follow-up fixes, and described in detail in
[doc/tailstorm.md](tailstorm.md).

Key points:

* Subblocks form a DAG ("grove").  Every subblock links to one or more
  previous subblocks via extra prev hashes in its `minerData` field, so
  branch tips cannot be silently pruned or swapped for double spend
  subblocks (!754).
* Summary blocks aggregate the subblock DAG.  Uncle subblocks are included,
  with a `k-1` subblock cap per grove enforced when scoring reorgs (!858).
  Uncles must precede summary blocks in the `minerData` field.
* Emergent consensus "snap to chain" lets nodes converge on the majority
  subblock chain (!770).
* Reorgs operate both between summary blocks and between competing subblock
  trees, and the DAG data is regenerated after a reorg completes.
* Difficulty: summary block work adjustment integrated with ASERT (!809),
  with distinct nBits/chainWork handling for subblocks and summary blocks
  (see [doc/tailstorm.md](tailstorm.md)).
* Blocks containing subblocks are only accepted once Hard Fork 2 is pending
  or activated.  At fork time a `GET_DAG` message recovers subblocks that
  arrived before the last legacy block was processed.
* The next-max-block-size floor becomes `tailstorm_k * 100KB` (12MB at
  `k = 120`) so a subblock can always hold the largest possible transaction.
* New `gettailstorminfo` RPC and a block/DAG viewer in the RPC console.

### Script and VM changes

Described in [doc/scripts2026.md](scripts2026.md), gated by the
`SCRIPT_UPGRADE2_OPCODES` verify flag:

* Bignum operation argument order is aligned with the integer operation
  order.
* `OP_PARSE` pushes the authority bits as an 8 byte bitfield rather than a
  script number, so they can be masked directly with `AND`/`OR`/`XOR`.
* `OP_JUMP` bug fix: it was executed even inside not-taken `if`/`else`
  branches; after Hard Fork 2 only `OP_IF`, `OP_NOTIF`, `OP_ELSE` and
  `OP_ENDIF` are evaluated in unexecuted branches.
* Retargetable (ranged outputs) sighash type: sighashes covering an output
  range become valid (!793).

### Other consensus changes

* Consensus sigop (sigcheck) counting is removed; block-level sigop limits
  are no longer enforced after activation.
* Transaction input types beyond the Fork 1 set (UTXO and read-only) are
  rejected until Hard Fork 2 activates, reserving space for new input
  types.
* Txpool admission switches to the post-fork mandatory script verify flags
  (`POST_UPGRADE2_MANDATORY_SCRIPT_VERIFY_FLAGS`) as soon as the fork is
  pending.

References
==========

* [Hard Fork (Minor) Features tracking issue #37](https://gitlab.com/nexa/nexa/-/issues/37)
* [doc/tailstorm.md](tailstorm.md), [doc/scripts2026.md](scripts2026.md), [doc/fork1.md](fork1.md)
* Major merge requests: !754 (Tailstorm), !770 (EC snap to chain),
  !782 (Upgrade2 flags), !793 (retargetable sighash), !809 (summary block
  work adjustment)
