Release Notes for Nexa 2.2.0.1
======================================================

Nexa version 2.2.0.1 is now available from:

  <https://gitlab.com/nexa/nexa/-/releases>

Please report bugs using the issue tracker at gitlab:

  <https://gitlab.com/nexa/nexa/-/issues>

This is a security and bug fix release of Nexa. Full node operators and users of
libnexa should upgrade. For more information about Nexa see:

- https://spec.nexa.org/
- https://nexa.org

This release does not activate Hard Fork 2. Changes for Tailstorm and other
Hard Fork 2 features remain gated on activation. The Main changes section
covers behavior that takes effect with this release; the commit list also
includes preparation and tests for Hard Fork 2. See doc/hf2.md for that upgrade.

Main changes in 2.2.0.1
-----------------------

- Upgrade the bundled Rostrum Electrum server to [15.0.0](https://gitlab.com/nexa/rostrum/-/blob/v15.0.0/RELEASE-NOTES.md).
  Builds and CI tests use the same source revision, pinned to the release tag and exact commit.
- Bound P2P request queues, transaction request shares, header requests and Graphene decoding work.
  Disconnect peers that exceed GETDATA queue limits, and time out incomplete handshakes.
- Reject GETBLOCKTXN requests with repeated or unordered indexes and EXTGETDATA ids whose length
  does not fit their type. Select the end block of a GETHEADERPATH request from its stop hash.
- Release thin-type block reconstruction state before validation and reject repeated reconstruction,
  preventing duplicate compact-block messages from modifying a block already handed to validation.
- Improve recovery when a received block body may have been altered, and prevent affected transaction
  rejects from suppressing valid copies. Preserve deserialization of valid template spends.
- Improve concurrency safety in parallel validation, block index header access and the deferred
  GETDATA queues. Wait for block validation threads that have only just started before shutting down.
- Fix Graphene, fast filter, Merkle proof and script parsing bounds and undefined behavior.
- Fix fixed-size cashaddr destination decoding and libnexa Merkle-result buffer handling.
- Harden token description parsing, update token indexes only when blocks connect, and correct
  token mint and melt accounting in the indexes.
- Improve double spend proof creation and relay, including template addresses. Bound orphan proof
  storage and avoid penalizing honest peers for proofs whose validity is not yet known or that expire.
- Correct CAPD message priority and eviction ordering, refuse future-dated messages and invalid nonce
  sizes, limit notifications, and reduce memory use when answering repeated message requests.
  Messages created with `capd send` get enough extra priority to stay relayable while they propagate.
  Count pending CAPD replies in a peer's send backlog, so they are sent as its send buffer drains
  instead of exceeding the buffer limit, and keep each CAPD message within the network message limit.
- Fail scripts whose OP_NUM2BIN size does not fit in 32 bits instead of truncating the size, which
  could make the result depend on the node's available memory. Track script stack use with signed
  64-bit counts.
- Require group creation transactions to spend their first input for mempool admission.
  Consensus enforcement of that rule remains gated on Hard Fork 2.
- Add the `hashAncestor` and `chainWork` fields to `getblocktemplate` results.
- Serialize ZMQ publishing, add sequence numbers for each topic, and disable publishers after send
  failures. Reuse block data rather than reading it again for each notification.
- Bind Docker RPC to loopback by default unless a password is supplied.
- Fix Windows libnexa loading, reduce Qt DAG viewer resource use, and improve handling of debug-log failures.
- Extend regression coverage and CI checks, including sanitizer checks and Rostrum functional tests.

Upgrade notes
-------------

Rostrum 15.0.0 changes its database format and automatically rebuilds the index
on the first start after upgrading. Allow time for the rebuild and ensure that
the connected full node retains the blocks needed to complete it. Rostrum RPC
is unavailable during the rebuild; the Nexa node does not require a chain
reindex solely for this Rostrum upgrade.

Script discovery is off by default in Rostrum. Changing `--index-scripts` in
either direction triggers another full index rebuild, so choose the setting
before the first 15.0.0 start. Rostrum also changes limits and pagination for
large queries and removes some height filters. Electrum API integrators should
review the [Rostrum 15.0.0 upgrade notes](https://gitlab.com/nexa/rostrum/-/blob/v15.0.0/RELEASE-NOTES.md)
for the affected methods and restart requirements.

ZMQ notifications now include a third multipart frame containing a 32-bit
little-endian sequence number for each topic. Subscribers should accept this
frame and can use sequence gaps to detect missed notifications. If a publisher
is disabled after a send failure, restart the node to restore it.

Scripts that use OP_NUM2BIN with a size that does not fit in 32 bits now
always fail. Older nodes could evaluate such scripts differently depending on
available memory, so all nodes should upgrade.

The minimum accepted P2P protocol version remains 80003 for compatibility with
existing light clients.

Commit details
--------------

- `c870db3968` Wait for validation threads that have not registered yet (Andrea Suisani)
- `f2c4912486` Test that the validation wait covers unregistered workers (Andrea Suisani)
- `c739c7dbeb` Count pending CAPD replies separately in the receive gate (Andrea Suisani)
- `65b5ad0f71` Queue every CAPD reply and send it as the buffer drains (Andrea Suisani)
- `09ac5cde3f` Wait for send budget instead of disconnecting CAPD peers (Andrea Suisani)
- `28c12bddd6` Bound CAPD responses by peer send budget (Andrea Suisani)
- `a79a590535` fix intermittent test due to message priority time reduction (Andrew Stone)
- `364a70f7a1` Connect the test no-UI handler once (Andrea Suisani)
- `4373f9e508` Collect CI cores from both migration paths (Andrea Suisani)
- `7ad9aed3ee` Use distinct CAPD messages in persistence test (Andrea Suisani)
- `80e63a0551` fix unrelated test flakiness (Andrew Stone)
- `7523dd4540` fix another unrelated intermittent issue (Andrew Stone)
- `4036dc6c99` make a more extensive test of NUM2BIN possibilities, log what unit test is running in case of crashes (Andrew Stone)
- `91b2d46b6b` fix an unrelated capd test timing issue, except that it triggered on this MR (Andrew Stone)
- `c0a2d37924` add checks for stack shrinking and for op_exec resource totals (Andrew Stone)
- `e25c30e415` fix size counting to use int64_t (Andrew Stone)
- `3153eb6dea` script: reject OP_NUM2BIN sizes above 32 bits instead of truncating them (Jørgen S. Notland)
- `c1c91f4fed` Reject EXTGETDATA ids whose length does not fit their type (Andrea Suisani)
- `48538c17e9` Test that EXTGETDATA rejects ids of the wrong length (Andrea Suisani)
- `a2f01bc387` Read the deferred getdata queues only under their lock (Andrea Suisani)
- `7ca2fa8a3a` Wait for compact-block validation worker in test (Andrea Suisani)
- `1d6c99070a` net: GETHEADERPATH must test toHash, not fromHash, when selecting the end block (Jørgen S. Notland)
- `6f4c6ec7b2` Reject repeated or unordered GETBLOCKTXN indexes (Jørgen S. Notland)
- `8ff4f5cdd2` Pin Rostrum builds and CI tests to v15.0.0 (Andrea Suisani)
- `8683664220` Test compact-block replay after reconstruction (Andrea Suisani)
- `f36afccf22` Clean up thinblock data right after the block is successfully reconstructed (Peter Tschipper)
- `5a11bcdadb` Do not allow a second thintype block reconstruction to take place (Peter Tschipper)
- `373fa9d2b3` put min client back until light client update their proto version] (Andrew Stone)
- `4a58e0e5b8` fix unlimited nonce size and capd message request repeats (Andrew Stone)
- `9759c35918` Keep the misbehaviour score as a double in capd_notification_limit (Andrea Suisani)
- `cd3506d2ae` Validate fixed-size cashaddr destination hashes (Andrea Suisani)
- `7aa2525e5e` Allow valid template spends to deserialize (Andrea Suisani)
- `575b3b2b53` Bump Nexa version to 2.2.0.1 (Andrea Suisani)
- `ea43d5f5e0` Add a regression test for dsproof orphan expiry and mark the ban reason unused (Steven van den Meiracker)
- `5d20b9214e` Do not penalize peers for dsproof orphans that expire (Steven van den Meiracker)
- `2ab71aa3ff` Test the header fields returned by getblocktemplate (Andrea Suisani)
- `eac2086b2a` Add hashAncestor and chainWork to getblocktemplate results (Andrea Suisani)
- `bf2d437ed2` Stop parsing token descriptions after the 5th field (Andrea Suisani)
- `688e75c8f6` Test the GETDATA queue limit through regtest P2P (Andrea Suisani)
- `641f9533f9` Test GETDATA admission and requeue limits (Andrea Suisani)
- `002721cfd3` Test bidirectional GETDATA progress after queue limiting (Andrea Suisani)
- `27f54d98c9` Test that token descriptions stop at the 5th field (Andrea Suisani)
- `0ce12140a3` Bound peer time offsets without abs64 (Andrea Suisani)
- `6a50801555` Test that an INT64_MIN time offset cannot pass the adjustment bound (Andrea Suisani)
- `bda60f5bde` Keep Docker RPC on loopback unless a password is set (Andrea Suisani)
- `09b6b1e2b2` Check the result buffer before each hash in extractFromMerkleBlock (Andrea Suisani)
- `a5385775fe` Test that extractFromMerkleBlock stays within its result buffer (Andrea Suisani)
- `00aec7baac` Limit CAPD notifications per peer (Andrea Suisani)
- `afb78a6b02` Test that a CAPD peer cannot install unlimited notifications (Andrea Suisani)
- `99429ac3b6` Keep orphan dsproofs whose validity is not known yet (Andrea Suisani)
- `fbb3e0a0a9` Test rescuing an orphan dsproof that cannot be validated yet (Andrea Suisani)
- `f09f0efbd7` When processing getdata in ProcessMessages() check if WithinBudget() (Peter Tschipper)
- `cafadaf4e0` fix underflow of mantissa in calculating capd priority (Andrew Stone)
- `56e5e2a3e5` After reaquiring the lock check again if we're within budget (Peter Tschipper)
- `faaeb27cf1` Remove the gate on MAX_QUEUED_SEND_MSGS (Peter Tschipper)
- `b73909d8ce` Do not call ProcessGetData() if we exceed our budget (Peter Tschipper)
- `bc6c3d43e1` Limit the getdata request queues to 1 Million (Peter Tschipper)
- `e9dca38942` Refuse CAPD messages created in the future (Andrea Suisani)
- `8f451aa15d` Test that CAPD messages from the future are refused (Andrea Suisani)
- `8eb76fb8f0` Allow a negative age in CAPD message priority (Andrea Suisani)
- `403df5c8e3` Test CAPD messages created ahead of the node's clock (Andrea Suisani)
- `8a3026bef8` refactor to move the socket and its lock into its own object and pull in helper functions (Andrew Stone)
- `6919fe55df` fix formatting.  Add a small check before receiving new data to discover if the other side is reading our responses.  If not, we want to push back on the TCP connection to slow down their sending (so that the memory consumed by servicing the messages from this node is limited). (Andrew Stone)
- `9a4aa11e05` Test GETDATA backpressure through message dispatch (Andrea Suisani)
- `73b4512281` Retain and resume deferred INV header requests (Andrea Suisani)
- `1501b75b5d` Test INV header request bounds with empty GETDATA queues (Andrea Suisani)
- `55349d886b` Test recovery after delayed block announcement bursts (Andrea Suisani)
- `023f5a92e6` Log ZMQ publish failures only with -debug=zmq (Andrea Suisani)
- `54dbf36147` Test that a disabled ZMQ endpoint is logged once (Andrea Suisani)
- `3f96f000fa` Disable ZMQ endpoints after multipart send failures (Andrea Suisani)
- `594bac3e7b` Wait for P2P handshakes before advancing mock time (Andrea Suisani)
- `593fe7b53e` Serialize ZMQ publishing, reuse blocks, and add per-topic sequences (Andrew Stone)
- `3019932abc` Drop INV header requests beyond the limit instead of deferring them (Andrea Suisani)
- `f314e402ef` Test that INV header requests beyond the limit are dropped (Andrea Suisani)
- `583d5854f5` Free an INV header request only once its header is known (Andrea Suisani)
- `623cbcd91e` Test that only the announced header frees an INV header request (Andrea Suisani)
- `b98f19ca34` Limit outstanding INV header requests per peer (Andrea Suisani)
- `5f06dc180b` Send one GETHEADERS per INV of unknown blocks (Andrea Suisani)
- `aab3549a3f` Add tests for GETHEADERS sent per unknown block INV (Andrea Suisani)
- `502607af43` Count only full nodes for transaction request shares (Andrea Suisani)
- `f0e4f934fe` Test transaction request shares with light clients (Andrea Suisani)
- `f49066d18c` Count transaction request peers in the request manager (Andrea Suisani)
- `b4f49f31ec` Format the transaction request limit update (Andrea Suisani)
- `bcb72b6268` Adapt transaction request shares to connected peers (Andrea Suisani)
- `8e7cc5a4e6` Count a peer's tx requests in 32 bits (Andrea Suisani)
- `3aee34ea8a` Hide net.txRequestPeerShare from the default help (Andrea Suisani)
- `371c2db436` Limit each peer's share of the tx request map (Andrea Suisani)
- `58295425ab` Add tests for one peer filling the tx request map (Andrea Suisani)
- `4b2f310f39` Remove unused electrum block notification (David Thibodeau)
- `4d643c16ab` Process deferred EXTGETDATA requests (NX-29) (Andrea Suisani)
- `4e08875ab1` Do not index an empty vector in GetHex (Andrea Suisani)
- `75eb8c5c94` Report every UBSan finding in the CI unit test job (Andrea Suisani)
- `c5941221b4` Give MerkleRootAlg a fixed uint8_t underlying type (Andrea Suisani)
- `75c500dbe8` Test OP_MERKLEROOT with unknown hash algorithms (Andrea Suisani)
- `0ba18b7cda` Declare tweaks with the types they are defined with (Andrea Suisani)
- `3f92ee9fb0` Check the long term CAPD priority drop directly (Andrea Suisani)
- `7d74745e6c` Keep fork headers within a deeper reorg limit (Andrea Suisani)
- `f91d0055e2` Test that a deeper reorg limit keeps fork headers within it (Andrea Suisani)
- `9c4815b017` Parenthesize the low-work header comparison (Andrea Suisani)
- `0a4677e1e8` Add a test for ASERT difficulty on a fork from an old block (Andrea Suisani)
- `895544fafd` Do not store headers far behind the active chain's work (Andrea Suisani)
- `09073c7fa2` Add a test for storing low-work fork headers (Andrea Suisani)
- `419359e8ec` Fill the CAPD priority cache when loading the message pool (Andrea Suisani)
- `6b883acc23` Test the CAPD pool thresholds and eviction as messages age (Andrea Suisani)
- `5ed0e952a1` Format the CAPD order test (Andrea Suisani)
- `9e0f8f80ee` add a test to verify that message ordering is elapsed time invariant (Andrew Stone)
- `f2880848aa` set CAPD priority to be an exponential decay so that message priority decay never causes a priority order change in already-received messages.  Use the log of exponential decay to make the actual priority number mean that each decrement by 1 is half priority.  This allows us to more efficiently calculate the priority change due to age, which needs to be recalculated often (Andrew Stone)
- `372e822f91` keep block candidates sorted when swapping sequence IDs (David Thibodeau)
- `76b0ee8541` test parallel validation cleanup keeps block candidates sorted (David Thibodeau)
- `75a9cb245f` skip orphan DSproofs evicted during rescue instead of penalizing peer (David Thibodeau)
- `a4e7609553` Limit orphan dsproofs size, track btye and per-peer count totals (David Thibodeau)
- `c30dbd25a7` apply clang formatting (David Thibodeau)
- `86354a30fe` Cap orphan double spend proof storage at ~1MB total and 20 per-peer. Evict oldest. Adds tests for both limits and for rejection of over-sized proofs (David Thibodeau)
- `b78dd5d952` Compare sighashes to decide that dsproof spenders sign the same data (Andrea Suisani)
- `bdaf7cf7db` Test that a dsproof from a re-encoded signature is rejected (Andrea Suisani)
- `10550a1dfe` fix debug mode lock order problem (Andrew Stone)
- `4d55703433` tolerate outSequence (Andrew Stone)
- `feb6962478` fix doublespend proofs and add them for p2pkt (Andrew Stone)
- `65d828047c` Update summary request tests for strict proof counts (Andrea Suisani)
- `d7ca710a5a` Remove unnecessary main locks from summary requests (Andrea Suisani)
- `2e6a796f1d` Clarify summary sub-block request checks (Andrea Suisani)
- `b54cc52d73` Format MakeRequestTestSummary (Andrea Suisani)
- `6de2e1ab12` Check summary headers before requesting their sub-blocks (Andrea Suisani)
- `1de6e7128a` Time out peers that do not finish the handshake (Andrea Suisani)
- `81240e52cb` Add tests for peers that never finish the handshake (Andrea Suisani)
- `164d7f598c` Return on a CheckBlock failure where it is logged (Andrea Suisani)
- `fc4dbada90` Add a functional test for re-requesting a bad block body (Andrea Suisani)
- `80655bb85e` Re-request blocks whose body fails CheckBlock (Andrea Suisani)
- `f28720c15a` Use a fresh validation state for each tx in an admission round (Andrea Suisani)
- `afb382045c` Use the wallet-free group id helper in the genesis input test (Andrea Suisani)
- `520905bb06` Fix the read-only input test build after the token index change (Andrea Suisani)
- `244856d9e2` Penalise any Graphene deserialization failure with 20 points (Andrea Suisani)
- `d4176011bb` Test that any Graphene deserialization failure costs 20 points (Andrea Suisani)
- `513dfb7bb7` Keep the OP_PARSE selector as an integer (Andrea Suisani)
- `62a6e492f2` Require a group creation to spend its first input (Andrea Suisani)
- `692bf347c5` Ban peers that send fast filters outside the receive limits (Andrea Suisani)
- `f534d93768` Test that out-of-limit fast filters get the sender banned (Andrea Suisani)
- `60ca4185af` Ban peers that send Graphene sets outside the receive limits (Andrea Suisani)
- `9ff7ca101d` Test that out-of-limit Graphene sets get the sender banned (Andrea Suisani)
- `964986595d` Store a suspect block body only from a peer we asked (Andrea Suisani)
- `bb19cfe882` Test that a suspect body is stored only from a requested peer (Andrea Suisani)
- `d4766763aa` Run branch pipelines on the security release branches (Andrea Suisani)
- `a0a29d90cc` Snapshot pure IBLT entries before peeling (Andrea Suisani)
- `b89a8990ce` test: Drop fork CSV checks that overflow (Andrea Suisani)
- `004c8b8f79` Drop rate limiting of tx requests (Andrea Suisani)
- `458612eec0` Port extended recut recovery tests (Andrea Suisani)
- `da8ad71622` Always read read-only inputs from the snapshot (Andrea Suisani)
- `d21817e812` Drop the unused peer parameter of ActivateBestChain (Andrew Stone)
- `3234bec2d2` Keep OP_RETURN satisfier rejects out of the reject cache (Andrea Suisani)
- `412a3eb8ef` Add helpers to detect OP_RETURN in satisfier scripts (Andrew Stone)
- `88c1127bac` Check that getblock returns the honest body, also after a restart (Andrea Suisani)
- `0b57f8dea7` Add recut scenarios for the gaps left in the recovery (Andrea Suisani)
- `bb6796be6d` Ignore bodies from a bad source even while the block is requested (Andrea Suisani)
- `b8cc9983e5` Add a functional test for recut block-body recovery (Andrea Suisani)
- `b181f513bd` Test that a recut splitting a push does not deserialize (Andrea Suisani)
- `573bf77d15` Log malformed scriptSig parse errors instead of printing to stderr (Andrea Suisani)
- `7023c6173d` Reject transactions whose scriptSig does not parse (Andrew Stone)
- `e571f88437` Feed the recut test bodies directly instead of through the wire (Andrea Suisani)
- `2a967c317a` Fix locking and peer cleanup in the header sweep test (Andrea Suisani)
- `7146296faf` Load and store the block index header pointer atomically (Andrea Suisani)
- `d260709c7e` Mark a suspect body and blame its sender under one lock (Andrea Suisani)
- `65a891765a` Parenthesize the download cursor rewind condition (Andrea Suisani)
- `9346379db0` Flag satisfier dependent standardness failures instead of matching reasons (Andrea Suisani)
- `c5e8fa06e4` Only handle Graphene recovery responses that were requested (Andrea Suisani)
- `6611fcfa48` Bound peer-chosen IBLT and Graphene filter decoding work (Andrea Suisani)
- `361197a7b2` Check unconnected headers before caching them (Andrea Suisani)
- `985790afbf` Keep the suspect block body state in a class (Andrea Suisani)
- `4a96a5a564` Answer get_dag in the mininode with the last two epochs only (Andrea Suisani)
- `e8b484aec8` Snapshot read-only inputs before parallel validation releases cs_main (Andrea Suisani)
- `dba4cd27f2` Check sub-blocks from mining RPCs like those from peers (Andrea Suisani)
- `695e7f5934` Answer empty-locator getheaders with the stop hash (Andrea Suisani)
- `612076c04d` Use CScript::size_type for the satisfier cut (Andrea Suisani)
- `29ae79fadb` Ignore unrequested bodies from peers that sent a bad one (Andrea Suisani)
- `164e625f8a` Do not ask a peer again for a body it sent altered (Andrea Suisani)
- `6a39e32320` Keep satisfier policy failures out of the reject cache (Andrea Suisani)
- `4bdbc1a432` Rewind download cursors for suspect block bodies (Andrea Suisani)
- `67fc18ca8c` Keep suspect block bodies from invalidating headers (Andrea Suisani)
- `73c6982165` Do not cache rejects of possibly altered transactions (Andrea Suisani)
- `7220490048` Blame the peer whose block body is validated (Andrea Suisani)
- `44d1396b26` Fetch a block again when its body may have been altered (Andrea Suisani)
- `deb5436187` Stop REJECT messages from pinning tx requests (Andrea Suisani)
- `1de40d1918` Reject repeated EXTVERSION messages (Andrea Suisani)
- `dcf46a7e80` Fix orphan double spend proof cleanup (Andrea Suisani)
- `a16142a2d4` Reject fast filters whose bit count does not fit their data (Andrea Suisani)
- `757663fe13` Stop the Graphene brute force search once no larger value can win (Andrea Suisani)
- `63c5f38c52` Cap peer mempool counts in Graphene and mempool sync requests (Andrea Suisani)
- `fa7870e2d1` Stop truncating peer counts to int in Graphene set optimisation (Andrea Suisani)
- `4017610bf5` Accumulate exact token mint and melt totals (Andrea Suisani)
- `4845273b77` Keep token indexing tests independent of the wallet (Andrea Suisani)
- `b3b39b48e7` Write token descriptions to the index only for connected blocks (Andrea Suisani)
- `782e6e92e3` Saturate block mint totals and check empty scripts before indexing (Andrea Suisani)
- `09fb2605eb` Guard token indexing against malformed block transactions (Andrea Suisani)
- `5414101311` Stop the token description parser from throwing or over-reading (Andrea Suisani)
- `925f4ba0fd` Zero the padding bits of Graphene encoded ranks (Andrea Suisani)
- `c1e79f7def` Keep variable fast filter reads inside the hash (Andrea Suisani)
- `4c4c5ff059` Load fast filter hash words with memcpy (Andrea Suisani)
- `434cf7c0ee` Mask the OP_MERKLEROOT index shift to 64 bits (Andrea Suisani)
- `353f6d7a93` ci: run unit tests with UBSan (Andrea Suisani)
- `4e87ee631d` Reject Graphene sets that reconcile to no transactions (Andrea Suisani)
- `a7db708242` Reject sub-blocks before the Tailstorm fork is pending (Andrea Suisani)
- `7a32805c8a` Reject merkle proofs truncated inside a sibling hash (Andrea Suisani)
- `c10be70d22` Report internal block reject codes as invalid to peers (Andrea Suisani)
- `a502ff00fe` Reject out-of-range input amounts during tx admission (Andrea Suisani)
- `7dcf6cb1b2` Do not mark a missing index for invalid sub-blocks (Andrea Suisani)
- `48cbca49e6` Reject malformed Graphene item ranks (Andrea Suisani)
- `089471f2c7` Bound CAPD query ranges (Andrea Suisani)
- `8261b08850` Evict non-final txns from the non-final map (Andrea Suisani)
- `c5e8b04370` Require exact sub-block proof counts in Tailstorm summaries (Andrea Suisani)
- `be30c2a75b` libnexa: don't abort on a malformed script-template address (Jørgen S. Notland)
- `3f5e409a3e` test: ClearByHeight frees pruned subblocks (Jørgen S. Notland)
- `68a2590a53` Update the min protocol version to that of nexa 2.0.0.0 (Peter Tschipper)
- `d7cf6c3038` [Initial Sync] Push uncles to the descendant epoch when needed. (Peter Tschipper)
- `8b4e21fa2e` Make the second thinblock bloom check deterministic (Andrea Suisani)
- `44a8ce3aab` CI: keep Windows native job running across pushes to dev (Jørgen S. Notland)
- `163d6ac907` test: cover Tailstorm uncle availability after initial sync (Andrea Suisani)
- `1b2626da8a` Fix tweak declarations, shift widths and empty-vector access (Andrea Suisani)
- `bfc41c2d4e` fix rebase issues (Peter Tschipper)
- `37cc37c201` Regenerate the dag data if the dag + pushed uncles >= tailstorm_k (Peter Tschipper)
- `f4efc06e30` Simplify GetUncles (Peter Tschipper)
- `df87515e1d` When pushing new uncles use the GetUncles() method to find the uncles (Peter Tschipper)
- `f59bc3411a` Allow ProcessOrphans() to accept and insert subblocks to tailstormEnforceDepth (Peter Tschipper)
- `65fc24a4d8` Fix issue with uncles that have two link lines drawn instead of one. (Peter Tschipper)
- `68d2a5188a` Notify the dagviewer of pushed uncles (Peter Tschipper)
- `c86119321c` Push uncles to the descendant epoch when needed. (Peter Tschipper)
- `d077d546b9` Wait for the sent tx in all pools in grapheneblocks.py (Andrea Suisani)
- `8fbf753fc6` Check that the new summary block does not use old hashes as uncles (Peter Tschipper)
- `c5c2f040c1` rework comment based on MR review (Andrew Stone)
- `9a9a01c08b` Build and test Rostrum master in CI (Andrea Suisani)
- `c0ae81279d` fix MR feedback (Andrew Stone)
- `63c913becc` CI: trim comments on Windows job (Jørgen S. Notland)
- `e1119df126` CI: build and test natively on Windows runner on default branch only (jQrgen)
- `fa69c6a5e2` Remove Andrew Stone gpg key finger print from SECURITY.md (Andrea Suisani)
- `446d09b350` test: expect canonical DAG order after regeneration (Andrea Suisani)
- `236ea8bc2f` test: restore cross-branch regeneration tests (Andrea Suisani)
- `5f66f411bc` reorder subblock dags to collapse into a sort by dependency then score then hash.  This ordering is then used in many places in the code instead of passing the dag as a set, and is taken as the transaction doublespend evaluation order.  This simplifies some aspects of the code (Andrew Stone)
- `4f6df97a58` convert windows paths to native wchar strings or utf-8 strings depending on need (Griffith)
- `4051b9212a` Change QLabels to QGraphicsTextItem (Peter Tschipper)
- `fb1451970c` CI: build-win-64-libnexa-jvm builds the JNI libnexa.dll (with a symbol copy) on every pipeline (Jørgen S. Notland)
- `df7903a2d2` chainparams: do not mine the stormtest genesis in a static initializer (Jørgen S. Notland)
- `1db7317ced` test: clarify cross-branch transaction scenarios (Andrea Suisani)
- `c3f583642d` test: cover cross-branch spends with unequal branch lengths (Andrea Suisani)
- `4095ea884e` test: cover chained spends across longer DAG branches (Andrea Suisani)
- `5aebe1e21f` test: cover cross-branch spends during DAG regeneration (Andrea Suisani)
- `254df15b53` Test Tailstorm convergence with opposite subblock arrival orders (Andrea Suisani)
- `ed44e62a45` Test Tailstorm summary proof validation (Andrea Suisani)
- `96ae219879` Test double-spend winner changes after a new sub-block references both competing branches (Andrea Suisani)
- `985c85245b` Create GetDagForReorg() and use it (Peter Tschipper)
- `b306477b0f` Reorg: Add a test to check that fork blocks receive all their subblocks and uncles (Peter Tschipper)
- `3194b84d31` Make sure to destroy the gdi object when the dialog closes (Peter Tschipper)
- `4273b2d7b3` Check for duplicate mininghashes in CheckTailstormSummaryBlockProofOfWork() (Peter Tschipper)
- `1872531ac4` only create ItemInfo labels when they are to be stored and always remove every item from the scene (Griffith)
- `7e73b7aad4` Check relay requests before allocating reconstruction state (Andrea Suisani)
- `42debd7cbc` test: replace flaky CAPD conversion checks with dedicated arithmetic coverage (Andrea Suisani)
- `51486d6b1d` Make Tailstorm snap-back boundary CI test deterministic (Andrea Suisani)
- `26b96b55d8` Remove thinblock download timeouts entirely (Peter Tschipper)
- `3ad6905e31` Move expedited relay files into the blockrelay folder (Peter Tschipper)
- `d0211de7d2` test: use the configured fork activation time (Andrea Suisani)
- `d2c333240d` test: cover epoch height during Tailstorm retries (Andrea Suisani)
- `76d068f575` Read Only Inputs and block height interaction with subblocks (Andrew Stone)
- `ad6912259e` Re-enable emergent consensus py testing (Peter Tschipper)
- `564a9b6ad7` Change the return value of GetNextDagVeiwerHight() to a bool (Peter Tschipper)
- `398e17d17d` Tidy up indentations (Peter Tschipper)
- `36152060c9` Remove bans for unrequested thinblocks (Peter Tschipper)
- `90300bb0a5` logging: survive a debug log that cannot be opened (Andrea Suisani)
- `6b3ec8e0e8` Feature: resolve double spends through a live excluded-transaction view (VDM)
- `90a8db4795` Consider uncles when checking for dag size (Peter Tschipper)
- `16d9b10bb3` Simplify setting the best grove for summary tip and add a check test (Peter Tschipper)
- `85fd9c6958` Refine the steps needed to get the singned macos binaries (Andrea Suisani)

Credits
-------

Thanks to everyone who directly contributed to this release:

- Andrea Suisani
- Andrew Stone
- David Thibodeau
- Griffith
- Jørgen Svennevik Notland
- Peter Tschipper
- Steven van den Meiracker
