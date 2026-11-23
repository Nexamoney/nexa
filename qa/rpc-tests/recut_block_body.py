#!/usr/bin/env python3
# Copyright (c) 2015-2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
import traceback

# The transaction id hashes the input satisfier scripts joined by a 0xff
# separator, with no length prefix. Two different sets of scriptSigs that
# produce the same joined byte stream therefore share a txid (and the idem,
# which ignores satisfiers), so they share the block header. This test forges
# that collision four ways and, each time, delivers the forged body and checks
# the node recovers the honest one. Scenario 5 checks who is blamed for it.
#
# Scenario 1 (pushdata-recut, a regression test): move the bytes after an
# interior 0xff from the first scriptSig onto the second. The byte stream is
# unchanged, but the move splits a data push, so the altered scriptSigs no
# longer decode. CScript::IsWellFormed() must reject the body at
# deserialization (REJECT_MALFORMED).
#
# Scenario 2 (bare-opcode): 0xff is also OP_INVALIDOPCODE, a valid bare opcode,
# so a scriptSig may legitimately end in one. A trailing 0xff on the first
# input is indistinguishable, in the txid preimage, from the separator that
# follows it, and can be donated to the front of the second input without
# changing a preimage byte. Both halves stay well-formed, so the deserializer
# cannot reject the body; it fails later in script validation instead. This is
# the same underlying problem the regression above no longer exercises.
#
# Scenario 3 (interior-opcode): the same collision, but the donated 0xff is
# placed in the middle of a scriptSig rather than at its start, so neither
# altered scriptSig begins with 0xff. It too stays well-formed and is rejected
# only in script validation.
#
# Scenario 4 (op-return-led): the second altered scriptSig starts with
# OP_RETURN, so both altered scriptSigs are push-only by the same rule as
# CScript::IsPushOnly(). Even a deserializer that required push-only scriptSigs
# would admit the body, so it can only be rejected in script validation.
#
# Scenario 5 (blame-honest-peer): A's altered body for C is stored while its
# parent P is still missing, then B delivers the honest C. When P arrives the
# stored altered body fails, and only A may be penalized: the node must still
# fetch C from B. A node that blames the last peer to deliver a body bans B.
#
# Scenario 6 (bad-source): after A's altered body fails, A pushes it again.
# The node must ignore it and fetch the body from B.
#
# Scenario 7 (stored-descendant): A delivers the altered body of C and the
# honest child D before their parent P. Once C is fetched again from B, D must
# connect too.
#
# Scenarios 8 and 9 (reject-cache): A relays the altered transaction, then B
# relays the honest one. The honest transaction must still enter the txpool.
# The altered transaction is not push-only in 8 and push-only in 9; both fail
# script validation, since regtest accepts nonstandard transactions.
#
# Finally, every block whose altered body was stored and then replaced must
# return the honest bytes from getblock, also after a restart, when the body
# is read from disk instead of the block cache.
#
# Scenarios 10 to 13 check invalid-chain bookkeeping, source attribution for
# an uncached body, repeated bodies from a whitelisted peer, and policy-only bans.
#
# Every scenario runs even if an earlier one fails, and the test reports all
# failures at the end.
#
# In scenarios 1 to 4 peer A delivers the forged body. Peer B has already
# advertised the same header, and must be asked for it again. B then delivers
# the honest body. The block has to become the tip, and a child delivered by B
# has to connect, without reconsiderblock, submitblock, or a restart.
#
# Run this before Upgrade2. A satisfier root commits to the exact transaction
# bytes, so this is the pre-commitment recovery path: a suspect body is fetched
# again and the header stays valid. A node that marks the header invalid from
# the altered body never asks B, and this test fails there.

import sys
import time
import pdb
from decimal import Decimal
from io import BytesIO
from test_framework.util import *

from test_framework.blocktools import ancestorHeight, create_block, create_coinbase, getAncHash
from test_framework.mininode import NetworkThread, NodeConn, NodeConnCB, mininode_lock
from test_framework.nodemessages import (
    CBlock,
    CBlockHeader,
    CInv,
    COutPoint,
    CScript,
    CTransaction,
    msg_block,
    msg_extversion,
    msg_headers,
    msg_ping,
    msg_reject,
    msg_tx,
)
from test_framework.script import OP_1, OP_16, OP_INVALIDOPCODE, OP_RETURN, CScriptInvalidError
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, enable_mocktime, p2p_port, start_node, stop_node, uint256ToRpcHex, waitFor

SEPARATOR = b"\xff"
# blockLookAheadInterval defaults to 5s after a body starts arriving.
GETDATA_RETRY_TIMEOUT = 45


class BodyPeer(NodeConnCB):
    def __init__(self):
        NodeConnCB.__init__(self)
        self.connection = None
        self.getdata = []
        self.rejects = []
        self.last_pong = None
        self.ping_counter = 1

    def add_connection(self, conn):
        self.connection = conn

    def send_message(self, message, pushbuf=False):
        self.connection.send_message(message, pushbuf)

    # The base handler answers inv with getdata. This peer only serves what the test sends.
    def on_inv(self, conn, message):
        pass

    def on_getdata(self, conn, message):
        self.getdata.append(message)

    def on_reject(self, conn, message):
        self.rejects.append(message)

    def on_pong(self, conn, message):
        self.last_pong = message

    def on_close(self, conn):
        self.disconnected = True

    def sync_with_ping(self, timeout=30):
        nonce = self.ping_counter
        self.ping_counter += 1
        self.send_message(msg_ping(nonce))

        def got_pong():
            with mininode_lock:
                return self.last_pong is not None and self.last_pong.nonce == nonce

        waitFor(timeout, got_pong, "ping timeout", sleepAmt=0.05)

    def announce(self, block):
        self.send_message(msg_headers([CBlockHeader(block)]))


def getdata_count(peer, block_hash):
    with mininode_lock:
        count = 0
        for message in peer.getdata:
            for inv in message.inv:
                if inv.type == CInv.MSG_BLOCK and inv.hash == block_hash:
                    count += 1
        return count


def block_reject(peer, block_hash):
    with mininode_lock:
        for reject in peer.rejects:
            if reject.message == b"block" and reject.data == block_hash:
                return reject
    return None


def malformed_block_reject(peer):
    # A body that fails deserialization is rejected as REJECT_MALFORMED, which carries no block hash.
    with mininode_lock:
        for reject in peer.rejects:
            if reject.message == b"block" and reject.code == msg_reject.REJECT_MALFORMED:
                return reject
    return None


def block_reject_count(peer, block_hash):
    with mininode_lock:
        return sum(1 for r in peer.rejects if r.message == b"block" and r.data == block_hash)


def connection_dropped(peer):
    with mininode_lock:
        return bool(getattr(peer, "disconnected", False))


def ban_reasons(node):
    # The test peers all connect from 127.0.0.1, so a ban of any of them is listed under that address
    return [b["ban_reason"] for b in node.listbanned() if b["address"].startswith("127.0.0.1")]


def create_cache_coinbase(height):
    coinbase = create_coinbase(height)
    coinbase.vout[0].scriptPubKey += CScript([OP_RETURN, b"\x00" * 90000])
    coinbase.rehash()
    return coinbase


def recut_transaction(tx, cut):
    sig0 = bytes(tx.vin[0].scriptSig)
    sig1 = bytes(tx.vin[1].scriptSig)
    altered = CTransaction(tx)
    altered.vin[0].scriptSig = sig0[:cut]
    altered.vin[1].scriptSig = sig0[cut + 1:] + SEPARATOR + sig1
    altered.rehash()
    return altered


def find_recut_pair(node):
    utxos = [u for u in node.listunspent(100) if u.get("spendable", True)]
    utxos.sort(key=lambda u: u["confirmations"], reverse=True)
    assert len(utxos) >= 2, "need two mature wallet outputs"
    inputs = []
    for utxo in utxos[:2]:
        outpoint = COutPoint().fromIdemAndIdx(utxo["txidem"], utxo["vout"]).rpcHex()
        inputs.append({"outpoint": outpoint, "amount": utxo["amount"]})
    address = node.getnewaddress()
    # One satoshi changes the signature. Stay far below the input sum.
    amount = Decimal("1000.00")
    for _ in range(500):
        raw = node.createrawtransaction(inputs, {address: amount})
        signed = node.signrawtransaction(raw)
        assert signed["complete"], "wallet did not sign the two-input transaction"
        tx = CTransaction(signed["hex"])
        sig0 = bytes(tx.vin[0].scriptSig)
        for cut in range(1, len(sig0) - 1):
            if sig0[cut] != SEPARATOR[0]:
                continue
            altered = recut_transaction(tx, cut)
            if tx.serialize() == altered.serialize():
                continue
            if len(tx.serialize()) != len(altered.serialize()):
                continue
            assert_equal(tx.GetId(), altered.GetId())
            assert_equal(tx.GetIdem(), altered.GetIdem())
            return tx, altered
        amount += Decimal("0.01")
    raise AssertionError("no interior 0xff kept the transaction serialization the same size")


def make_parseable_pair(node):
    # A second way to forge a duplicate txid, one the deserializer cannot reject.
    #
    # GetTxId() hashes the input scriptSigs concatenated with a 0xff separator
    # (OP_INVALIDOPCODE) after each one, with no length prefix. 0xff is also a
    # valid *bare* opcode, so a scriptSig may legitimately end in one. A trailing
    # 0xff on input 0 is therefore indistinguishable, in the txid preimage, from
    # the separator that follows input 0 -- it can be moved to the front of
    # input 1 without changing a single preimage byte, so the txid and idem are
    # unchanged. Unlike recut_transaction(), which splits a data push and leaves
    # an unparsable fragment, both halves here are complete, well-formed scripts
    # and both transactions deserialize.
    #
    # Input 0 is anchored with a trailing "OP_RETURN 0xff": a satisfier may carry
    # OP_RETURN (fork1, always active on regtest) and everything after it is
    # ignored, so the honest transaction still validates. In the altered twin the
    # 0xff leads input 1's scriptSig, where OP_INVALIDOPCODE fails the script, so
    # the altered body is rejected by validation rather than at deserialization.
    utxos = [u for u in node.listunspent(100) if u.get("spendable", True)]
    utxos.sort(key=lambda u: u["confirmations"], reverse=True)
    assert len(utxos) >= 2, "need two mature wallet outputs"
    inputs = []
    for utxo in utxos[:2]:
        outpoint = COutPoint().fromIdemAndIdx(utxo["txidem"], utxo["vout"]).rpcHex()
        inputs.append({"outpoint": outpoint, "amount": utxo["amount"]})
    address = node.getnewaddress()
    raw = node.createrawtransaction(inputs, {address: Decimal("1000.00")})
    signed = node.signrawtransaction(raw)
    assert signed["complete"], "wallet did not sign the two-input transaction"
    base = CTransaction(signed["hex"])

    sig0 = bytes(base.vin[0].scriptSig)
    sig1 = bytes(base.vin[1].scriptSig)

    honest = CTransaction(base)
    honest.vin[0].scriptSig = CScript(sig0 + bytes([OP_RETURN, OP_INVALIDOPCODE]))
    honest.vin[1].scriptSig = CScript(sig1)
    honest.rehash()

    altered = CTransaction(base)
    altered.vin[0].scriptSig = CScript(sig0 + bytes([OP_RETURN]))
    altered.vin[1].scriptSig = CScript(bytes([OP_INVALIDOPCODE]) + sig1)
    altered.rehash()

    # Same change to the ledger (idem), same merkle commitment (id), different bytes.
    assert_equal(honest.GetIdem(), altered.GetIdem())
    assert_equal(honest.GetId(), altered.GetId())
    assert honest.serialize() != altered.serialize()
    assert_equal(len(honest.serialize()), len(altered.serialize()))
    return honest, altered


def make_interior_opcode_pair(node):
    # A third way to forge the same duplicate txid. Here the donated 0xff lands in
    # the *middle* of a scriptSig instead of at its start, so neither altered
    # scriptSig begins with 0xff -- the collision does not need that tell.
    #
    # Here are two formulations of the transaction inputs that have the same hashed bytes. (0xff) means the separator:
    # A OP_RETURN 0xff <anything>
    # (0xff)
    # B
    #
    # A OP_RETURN
    # (0xff)
    # <anything> 0xff B

    # hashed bytes:
    # A OP_RETURN 0xff <anything> 0xff B
    # Both halves decode, so the deserializer admits the altered body; it fails in
    # script validation instead (altered sig0 hits OP_INVALIDOPCODE mid-script).
    # Unlike make_parseable_pair(), altered sig1 == T begins with an ordinary
    # opcode, not 0xff.
    utxos = [u for u in node.listunspent(100) if u.get("spendable", True)]
    utxos.sort(key=lambda u: u["confirmations"], reverse=True)
    assert len(utxos) >= 2, "need two mature wallet outputs"
    inputs = []
    for utxo in utxos[:2]:
        outpoint = COutPoint().fromIdemAndIdx(utxo["txidem"], utxo["vout"]).rpcHex()
        inputs.append({"outpoint": outpoint, "amount": utxo["amount"]})
    address = node.getnewaddress()
    raw = node.createrawtransaction(inputs, {address: Decimal("1000.00")})
    signed = node.signrawtransaction(raw)
    assert signed["complete"], "wallet did not sign the two-input transaction"
    base = CTransaction(signed["hex"])

    sig0 = bytes(base.vin[0].scriptSig)
    sig1 = bytes(base.vin[1].scriptSig)
    tail = bytes([OP_1])  # ignored after OP_RETURN in the honest tx; a lone, well-formed opcode in the altered tx

    honest = CTransaction(base)
    honest.vin[0].scriptSig = CScript(sig0)
    honest.vin[1].scriptSig = CScript(sig1 + bytes([OP_RETURN, OP_INVALIDOPCODE]) + tail)
    honest.rehash()

    altered = CTransaction(base)
    altered.vin[0].scriptSig = CScript(sig0 + bytes([OP_INVALIDOPCODE]) + sig1 + bytes([OP_RETURN]))
    altered.vin[1].scriptSig = CScript(tail)
    altered.rehash()

    # Same change to the ledger (idem), same merkle commitment (id), different bytes.
    assert_equal(honest.GetIdem(), altered.GetIdem())
    assert_equal(honest.GetId(), altered.GetId())
    assert honest.serialize() != altered.serialize()
    assert_equal(len(honest.serialize()), len(altered.serialize()))
    # The point of this variant: neither altered scriptSig starts with the 0xff opcode.
    assert bytes(altered.vin[0].scriptSig)[0] != OP_INVALIDOPCODE
    assert bytes(altered.vin[1].scriptSig)[0] != OP_INVALIDOPCODE
    return honest, altered


def is_push_only(script):
    # Same rule as CScript::IsPushOnly(): nothing after OP_RETURN is checked
    try:
        for opcode, _, _ in CScript(script).raw_iter():
            if opcode == OP_RETURN:
                return True
            if opcode > OP_16:
                return False
    except CScriptInvalidError:
        return False
    return True


def make_op_return_led_pair(node):
    # The same collision as make_parseable_pair(), with the moved bytes chosen so
    # that both altered scriptSigs are push-only:
    #
    # honest:  sig0 OP_RETURN 0xff OP_RETURN | sig1
    # altered: sig0 OP_RETURN | OP_RETURN 0xff sig1
    #
    # hashed bytes: sig0 OP_RETURN 0xff OP_RETURN 0xff sig1 0xff
    # Everything after OP_RETURN is ignored, so the honest transaction still
    # validates. Altered input 1 stops at its leading OP_RETURN with an empty
    # stack and fails script validation.
    utxos = [u for u in node.listunspent(100) if u.get("spendable", True)]
    utxos.sort(key=lambda u: u["confirmations"], reverse=True)
    assert len(utxos) >= 2, "need two mature wallet outputs"
    inputs = []
    for utxo in utxos[:2]:
        outpoint = COutPoint().fromIdemAndIdx(utxo["txidem"], utxo["vout"]).rpcHex()
        inputs.append({"outpoint": outpoint, "amount": utxo["amount"]})
    address = node.getnewaddress()
    raw = node.createrawtransaction(inputs, {address: Decimal("1000.00")})
    signed = node.signrawtransaction(raw)
    assert signed["complete"], "wallet did not sign the two-input transaction"
    base = CTransaction(signed["hex"])

    sig0 = bytes(base.vin[0].scriptSig)
    sig1 = bytes(base.vin[1].scriptSig)

    honest = CTransaction(base)
    honest.vin[0].scriptSig = CScript(sig0 + bytes([OP_RETURN, OP_INVALIDOPCODE, OP_RETURN]))
    honest.vin[1].scriptSig = CScript(sig1)
    honest.rehash()

    altered = CTransaction(base)
    altered.vin[0].scriptSig = CScript(sig0 + bytes([OP_RETURN]))
    altered.vin[1].scriptSig = CScript(bytes([OP_RETURN, OP_INVALIDOPCODE]) + sig1)
    altered.rehash()

    assert_equal(honest.GetIdem(), altered.GetIdem())
    assert_equal(honest.GetId(), altered.GetId())
    assert honest.serialize() != altered.serialize()
    assert_equal(len(honest.serialize()), len(altered.serialize()))
    # The point of this variant: a push-only check at deserialization admits it
    for txin in altered.vin:
        assert is_push_only(bytes(txin.scriptSig))
    return honest, altered


class RecutBlockBodyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = False
        # The cached chain is stamped in the past. Start near its tip so header
        # announcements are direct-fetched instead of treated as ancient.
        enable_mocktime()
        # Full-block GETDATA only. One message thread keeps B's announcement
        # ordered ahead of A's body. The test peers connect from localhost, which
        # is normally never banned; test.banLocalPeers bans them so the checks can
        # see which peer is dropped. Bans are cleared between scenarios.
        self.extra_args = [[
            "-debug=validation",
            "-debug=net",
            "-debug=req",
            "-debug=mempool",
            "-debug=blk",
            "-logtimemicros=1",
            "-test.parallel=0",
            "-use-thinblocks=0",
            "-use-grapheneblocks=0",
            "-use-compactblocks=0",
            "-net.msgHandlerThreads=1",
            "-net.txAdmissionThreads=1",
            "-test.banLocalPeers=1",
        ]]

    def make_block(self, txns):
        node = self.nodes[0]
        tip = node.getblock(node.getbestblockhash())
        height = tip["height"] + 1
        return create_block(
            int(tip["hash"], 16),
            height,
            int(tip["chainwork"], 16) + 2,
            create_coinbase(height),
            getAncHash(height, node),
            tip["time"] + 1,
            txns=txns,
        )

    def wait_getdata(self, peer, block_hash, previous, timeout, what):
        def arrived():
            return getdata_count(peer, block_hash) > previous

        waitFor(timeout, arrived, what, sleepAmt=0.5)

    def run_recovery(self, node, peer_a, peer_b, honest_tx, altered_tx, malformed, label):
        """Drive the body-recovery scenario once.

        A delivers a body around `altered_tx`; B holds the same header built
        around `honest_tx`. The two transactions share a txid, so the block
        header is identical and the node must refetch the suspect body from B.

        `malformed` selects how A's body is expected to fail: True when the
        altered scriptSigs no longer decode (rejected at deserialization -- the
        block never enters the index, so success is A's connection being dropped
        or a parse-error reject), False when they decode but fail script
        validation (a hash-carrying block reject, or A banned as "Invalid block":
        the ban can close A's connection before the reject reaches it).
        """
        print("[%s] honest tx\n" % label, honest_tx)
        print("[%s] altered tx\n" % label, altered_tx)
        # Rejects carried over from an earlier scenario would confuse the
        # hashless REJECT_MALFORMED lookup below.
        with mininode_lock:
            peer_a.rejects = []
        assert_equal(node.getrawtxpool(), [])

        # 2. Honest block H, then the same header around the recut transaction.
        honest = self.make_block([honest_tx])
        honest.solve()
        print("[%s] honest block\n" % label, honest)
        altered = CBlock()
        altered.deserialize(BytesIO(honest.serialize()))
        altered.vtx[1] = altered_tx
        block_hash = honest.gethash()
        assert honest.serialize() != altered.serialize()
        assert_equal(honest_tx.serialize() == altered_tx.serialize(), False)
        assert_equal(altered.gethash(), block_hash)
        assert_equal(altered.hashMerkleRoot, honest.hashMerkleRoot)
        assert_equal(altered.calc_merkle_root(), honest.hashMerkleRoot)
        assert_equal(CBlockHeader(altered).serialize(), CBlockHeader(honest).serialize())
        assert_equal(len(altered.serialize()), len(honest.serialize()))
        assert_equal(honest.size, len(honest.serialize()) - (len(honest.nonce) + 1))

        start_tip = node.getbestblockhash()

        # 3. A announces H. While that GETDATA is outstanding, B advertises the same header.
        asked_a = getdata_count(peer_a, block_hash)
        peer_a.announce(honest)
        self.wait_getdata(peer_a, block_hash, asked_a, 15, "[%s] peer A was not asked for H" % label)
        asked_b = getdata_count(peer_b, block_hash)
        peer_b.announce(honest)
        peer_b.sync_with_ping()
        assert_equal(getdata_count(peer_b, block_hash), asked_b)
        peer_a.send_message(msg_block(altered))

        # 4. The altered body is rejected and the tip stays put.
        def altered_failed():
            if node.getbestblockhash() != start_tip:
                raise AssertionError("[%s] active tip changed after the altered body" % label)
            if malformed:
                # The altered body does not decode. It never enters the block index, so getchaintips
                # shows nothing to key off of. The node either drops the sending connection or returns a
                # parse-error (REJECT_MALFORMED) reject; accept either as proof the body was rejected.
                if block_reject(peer_a, block_hash) is not None:
                    raise AssertionError(
                        "[%s] altered body was deserialized and rejected by validation" % label)
                return connection_dropped(peer_a) or malformed_block_reject(peer_a) is not None
            reject = block_reject(peer_a, block_hash)
            if reject is None:
                # test.banLocalPeers: the DoS(100) for the invalid body bans A, and the disconnect can win
                # the race with the reject. The ban reason still shows it failed validation, not parsing.
                if connection_dropped(peer_a) and "Invalid block" in ban_reasons(node):
                    return True
                return False
            reason = reject.reason.decode("utf-8", "replace")
            # The script queue reports this failure as bad-blk-signatures.
            if reason != "bad-blk-signatures" and "script" not in reason:
                raise AssertionError("[%s] altered body rejected as %s" % (label, reason))
            return True

        def reject_timeout():
            with mininode_lock:
                rejects = list(peer_a.rejects)
            if malformed:
                return "[%s] sender not dropped and no parse-error reject for H\ntip=%s\ndropped=%s\nrejects=%s" % (
                    label, node.getbestblockhash(), connection_dropped(peer_a), rejects)
            return "[%s] no block reject or invalid-block ban for H\ntip=%s\ntips=%s\nrejects=%s\ndropped=%s\nbans=%s" % (
                label, node.getbestblockhash(), node.getchaintips(), rejects, connection_dropped(peer_a),
                ban_reasons(node))

        waitFor(30, altered_failed, reject_timeout, sleepAmt=1)
        assert_equal(node.getbestblockhash(), start_tip)

        # 5. The downloader asks B. B answers that request with the honest body.
        def refetch_timeout():
            tips = node.getchaintips()
            return "[%s] node did not request H from peer B after the altered body\ntip=%s\ntips=%s" % (
                label, node.getbestblockhash(), tips)

        self.wait_getdata(peer_b, block_hash, asked_b, GETDATA_RETRY_TIMEOUT, refetch_timeout)
        peer_b.send_message(msg_block(honest))

        # 6. H is the tip, a child from B connects, and B is not penalized.
        honest_rpc = uint256ToRpcHex(block_hash)
        waitFor(30, lambda: node.getbestblockhash() == honest_rpc,
                "[%s] honest body did not become the tip" % label, sleepAmt=0.05)
        connected = node.getblock(honest_rpc)
        assert honest_tx.GetRpcHexId() in connected["txid"]
        if not malformed:
            self.replaced.append((label, honest))

        child = self.make_block([])
        child.solve()
        child_hash = child.gethash()
        asked_child = getdata_count(peer_b, child_hash)
        peer_b.announce(child)
        self.wait_getdata(peer_b, child_hash, asked_child, 15, "[%s] peer B was not asked for the child" % label)
        peer_b.send_message(msg_block(child))
        child_rpc = uint256ToRpcHex(child_hash)
        waitFor(30, lambda: node.getbestblockhash() == child_rpc,
                "[%s] child of H did not connect" % label, sleepAmt=0.05)

        assert_equal(connection_dropped(peer_b), False)
        assert_equal(block_reject(peer_b, block_hash), None)
        assert_equal(node.getrawtxpool(), [])

    def run_blame(self, node, peer_a, peer_b, honest_tx, altered_tx, label, uncached=False):
        """A's altered body for C is stored before its parent P; B then delivers the honest C.

        The node must blame A, not the last peer to deliver C, and recover C from B.
        """
        with mininode_lock:
            peer_a.rejects = []
            peer_b.rejects = []
        assert_equal(node.getrawtxpool(), [])

        tip = node.getblock(node.getbestblockhash())
        start_tip = tip["hash"]
        parent = create_block(int(tip["hash"], 16), tip["height"] + 1, int(tip["chainwork"], 16) + 2,
                              create_coinbase(tip["height"] + 1), getAncHash(tip["height"] + 1, node),
                              tip["time"] + 1, txns=[])
        parent.solve()
        honest = create_block(parent.gethash(), tip["height"] + 2, int(tip["chainwork"], 16) + 4,
                              create_cache_coinbase(tip["height"] + 2) if uncached else create_coinbase(tip["height"] + 2),
                              getAncHash(tip["height"] + 2, node),
                              tip["time"] + 2, txns=[honest_tx])
        honest.solve()
        altered = CBlock()
        altered.deserialize(BytesIO(honest.serialize()))
        altered.vtx[1] = altered_tx
        block_hash = honest.gethash()
        assert honest.serialize() != altered.serialize()
        assert_equal(altered.gethash(), block_hash)

        # 1. Store the altered C before P; the disk-read case requests C from B.
        if uncached:
            # Exercise disk loading even when the body comes from a peer that was not asked for it.
            peer_a.announce(parent)
            asked_b = getdata_count(peer_b, block_hash)
            peer_b.send_message(msg_headers([CBlockHeader(parent), CBlockHeader(honest)]))
            self.wait_getdata(peer_b, block_hash, asked_b, 15, "[%s] peer B was not asked for C" % label)
        else:
            asked_a = getdata_count(peer_a, block_hash)
            peer_a.send_message(msg_headers([CBlockHeader(parent), CBlockHeader(honest)]))
            self.wait_getdata(peer_a, block_hash, asked_a, 15, "[%s] peer A was not asked for C" % label)
            peer_b.send_message(msg_headers([CBlockHeader(parent), CBlockHeader(honest)]))
            peer_b.sync_with_ping()
        peer_a.send_message(msg_block(altered))
        peer_a.sync_with_ping()
        if uncached:
            with node.assert_debug_log(expected_msgs=[], unexpected_msgs=[
                    "Retrieved block from memory cache: " + uint256ToRpcHex(block_hash)]):
                assert_equal(node.getblock(uint256ToRpcHex(block_hash), 0), altered.serialize().hex())

        # 2. B delivers the honest C, which the node already has a body for.
        peer_b.send_message(msg_block(honest))
        peer_b.sync_with_ping()
        assert_equal(node.getbestblockhash(), start_tip)
        asked_b = getdata_count(peer_b, block_hash)

        # 3. A delivers P. P connects, the stored altered C fails.
        peer_a.send_message(msg_block(parent))
        parent_rpc = uint256ToRpcHex(parent.gethash())
        waitFor(30, lambda: node.getbestblockhash() == parent_rpc,
                "[%s] parent P did not connect" % label, sleepAmt=0.05)

        def altered_failed():
            return (block_reject(peer_a, block_hash) is not None or block_reject(peer_b, block_hash) is not None or
                    connection_dropped(peer_a) or connection_dropped(peer_b))

        waitFor(30, altered_failed, "[%s] no peer was blamed for the stored altered body of C" % label, sleepAmt=0.5)
        # The reject goes to the peer the node blames, together with DoS(100), which bans it (test.banLocalPeers)
        waitFor(30, lambda: connection_dropped(peer_a) or connection_dropped(peer_b),
                "[%s] no peer was banned for the altered body of C" % label, sleepAmt=0.5)
        if connection_dropped(peer_b):
            raise AssertionError("[%s] honest peer B was dropped for A's altered body (dropped=%s, reject=%s)" % (
                label, connection_dropped(peer_b), block_reject(peer_b, block_hash)))

        if block_reject(peer_b, block_hash) is not None:
            raise AssertionError("[%s] honest peer B was sent a rejection for A's altered body (dropped=%s, reject=%s)" % (
                label, connection_dropped(peer_b), block_reject(peer_b, block_hash)))

        if not connection_dropped(peer_a):
            raise AssertionError("[%s] peer A was not banned for its altered body (reject=%s)" % (
                label, block_reject(peer_a, block_hash)))
        assert_equal(node.getbestblockhash(), parent_rpc)

        # 4. The node asks B for C again and connects the honest body.
        self.wait_getdata(peer_b, block_hash, asked_b, GETDATA_RETRY_TIMEOUT,
                          "[%s] node did not request C from peer B" % label)
        peer_b.send_message(msg_block(honest))
        honest_rpc = uint256ToRpcHex(block_hash)
        waitFor(30, lambda: node.getbestblockhash() == honest_rpc,
                "[%s] honest body of C did not become the tip" % label, sleepAmt=0.05)
        assert_equal(connection_dropped(peer_b), False)
        assert_equal(block_reject(peer_b, block_hash), None)
        self.replaced.append((label, honest))

    def make_block_on(self, prev, height, chainwork, ntime, txns, unknown=None):
        # The consensus ancestor may be one of the new blocks, which the node does not have yet
        ancestor = (unknown or {}).get(ancestorHeight(height))
        if ancestor is None:
            ancestor = getAncHash(height, self.nodes[0])
        block = create_block(prev, height, chainwork, create_coinbase(height), ancestor, ntime, txns=txns)
        block.solve()
        return block

    def make_altered(self, honest, altered_tx):
        altered = CBlock()
        altered.deserialize(BytesIO(honest.serialize()))
        altered.vtx[1] = altered_tx
        assert honest.serialize() != altered.serialize()
        assert_equal(altered.gethash(), honest.gethash())
        return altered

    def run_bad_source(self, node, peer_a, peer_b, honest_tx, altered_tx, label):
        """A's altered body fails and A is banned; A cannot reconnect to push it again, and B supplies the body."""
        with mininode_lock:
            peer_a.rejects = []
            peer_b.rejects = []
        honest = self.make_block([honest_tx])
        honest.solve()
        altered = self.make_altered(honest, altered_tx)
        block_hash = honest.gethash()

        asked_a = getdata_count(peer_a, block_hash)
        peer_a.announce(honest)
        self.wait_getdata(peer_a, block_hash, asked_a, 15, "[%s] peer A was not asked for H" % label)
        peer_b.announce(honest)
        peer_b.sync_with_ping()
        asked_b = getdata_count(peer_b, block_hash)
        peer_a.send_message(msg_block(altered))
        waitFor(30, lambda: block_reject(peer_a, block_hash) is not None or connection_dropped(peer_a),
                "[%s] the altered body was not rejected" % label, sleepAmt=0.5)

        # The altered body costs A DoS(100), so it is disconnected and banned (test.banLocalPeers), and the
        # honest peer B stays connected.
        waitFor(30, lambda: connection_dropped(peer_a), "[%s] peer A was not banned" % label, sleepAmt=0.5)
        assert_equal(connection_dropped(peer_b), False)
        banned = [b["address"] for b in node.listbanned()]
        if not any(addr.startswith("127.0.0.1") for addr in banned):
            raise AssertionError("[%s] A's address is not in the ban list (%s)" % (label, banned))

        # A tries to reconnect to push the same altered body again. The node must refuse the connection.
        peer_retry = BodyPeer()
        conn_retry = NodeConn("127.0.0.1", p2p_port(0), node, peer_retry)
        peer_retry.add_connection(conn_retry)
        try:
            waitFor(15, lambda: connection_dropped(peer_retry),
                    "[%s] banned peer A was allowed to reconnect" % label, sleepAmt=0.2)
        finally:
            if not connection_dropped(peer_retry):
                conn_retry.disconnect_node()

        self.wait_getdata(peer_b, block_hash, asked_b, GETDATA_RETRY_TIMEOUT,
                          "[%s] node did not request H from peer B" % label)
        peer_b.send_message(msg_block(honest))
        honest_rpc = uint256ToRpcHex(block_hash)
        waitFor(30, lambda: node.getbestblockhash() == honest_rpc,
                "[%s] honest body did not become the tip" % label, sleepAmt=0.05)
        assert_equal(block_reject(peer_b, block_hash), None)
        self.replaced.append((label, honest))

    def run_descendant(self, node, peer_a, peer_b, honest_tx, altered_tx, label):
        """The altered C and the honest D are stored before P; D must connect once C is fetched again."""
        with mininode_lock:
            peer_a.rejects = []
            peer_b.rejects = []
        tip = node.getblock(node.getbestblockhash())
        height = tip["height"]
        work = int(tip["chainwork"], 16)
        parent = self.make_block_on(int(tip["hash"], 16), height + 1, work + 2, tip["time"] + 1, [])
        unknown = {height + 1: parent.gethash()}
        honest = self.make_block_on(parent.gethash(), height + 2, work + 4, tip["time"] + 2, [honest_tx], unknown)
        unknown[height + 2] = honest.gethash()
        child = self.make_block_on(honest.gethash(), height + 3, work + 6, tip["time"] + 3, [], unknown)
        altered = self.make_altered(honest, altered_tx)
        block_hash = honest.gethash()
        headers = msg_headers([CBlockHeader(parent), CBlockHeader(honest), CBlockHeader(child)])

        asked_a = getdata_count(peer_a, child.gethash())
        peer_a.send_message(headers)
        self.wait_getdata(peer_a, child.gethash(), asked_a, 15, "[%s] peer A was not asked for D" % label)
        peer_b.send_message(headers)
        peer_b.sync_with_ping()
        peer_a.send_message(msg_block(altered))
        peer_a.send_message(msg_block(child))
        peer_a.sync_with_ping()
        asked_b = getdata_count(peer_b, block_hash)
        peer_a.send_message(msg_block(parent))
        def not_rejected():
            with mininode_lock:
                rejects = list(peer_a.rejects)
            return ("[%s] the stored altered body of C was not rejected\ntip=%s (P=%s C=%s D=%s)\ntips=%s\n"
                    "A rejects=%s\nA dropped=%s B dropped=%s\nbans=%s" % (
                        label, node.getbestblockhash(), uint256ToRpcHex(parent.gethash()),
                        uint256ToRpcHex(block_hash), uint256ToRpcHex(child.gethash()), node.getchaintips(),
                        rejects, connection_dropped(peer_a), connection_dropped(peer_b), ban_reasons(node)))

        # The altered C costs A DoS(100), which bans it (test.banLocalPeers); the disconnect can beat the reject
        waitFor(30, lambda: block_reject(peer_a, block_hash) is not None or connection_dropped(peer_a),
                not_rejected, sleepAmt=0.5)
        waitFor(30, lambda: connection_dropped(peer_a), "[%s] peer A was not banned for its altered C" % label,
                sleepAmt=0.5)
        if connection_dropped(peer_b) or block_reject(peer_b, block_hash) is not None:
            raise AssertionError("[%s] honest peer B was blamed for A's altered C (dropped=%s, reject=%s)" % (
                label, connection_dropped(peer_b), block_reject(peer_b, block_hash)))

        self.wait_getdata(peer_b, block_hash, asked_b, GETDATA_RETRY_TIMEOUT,
                          "[%s] node did not request C from peer B" % label)
        peer_b.send_message(msg_block(honest))
        child_rpc = uint256ToRpcHex(child.gethash())
        honest_rpc = uint256ToRpcHex(block_hash)
        waitFor(30, lambda: node.getbestblockhash() in (honest_rpc, child_rpc),
                "[%s] honest body of C did not connect" % label, sleepAmt=0.05)
        # D's body is already stored; serve it again if the node asks
        if getdata_count(peer_b, child.gethash()) > 0:
            peer_b.send_message(msg_block(child))
        waitFor(30, lambda: node.getbestblockhash() == child_rpc,
                "[%s] stored descendant D did not connect after C was fetched again" % label, sleepAmt=0.05)
        self.replaced.append((label, honest))

    def run_reject_cache(self, node, peer_a, peer_b, honest_tx, altered_tx, label):
        """A relays the altered tx first; the honest tx with the same id must still enter the txpool."""
        assert_equal(node.getrawtxpool(), [])
        peer_a.send_message(msg_tx(altered_tx))
        peer_a.sync_with_ping()
        waitFor(15, lambda: any(r.message == b"tx" for r in peer_a.rejects) or connection_dropped(peer_a),
                "[%s] the altered transaction was not rejected" % label, sleepAmt=0.5)
        peer_b.send_message(msg_tx(honest_tx))
        peer_b.sync_with_ping()
        honest_id = honest_tx.GetRpcHexId()
        try:
            waitFor(15, lambda: honest_id in node.getrawtxpool(False, "id"),
                    "[%s] honest transaction was refused after the altered copy (reject cache)" % label,
                    sleepAmt=0.5)
        finally:
            # Leave an empty txpool for the next scenario
            if node.getrawtxpool():
                node.generate(1)

    def check_stored_bodies(self, failures, when):
        """Each replaced body must come back from getblock as the honest bytes."""
        for label, honest in self.replaced:
            raw = self.nodes[0].getblock(uint256ToRpcHex(honest.gethash()), 0)
            if raw != honest.serialize().hex():
                failures.append("%s: getblock %s returned a body other than the honest one" % (label, when))
                print("%s getblock %s test FAILED" % (label, when))
        print("stored bodies %s checked (%d blocks)" % (when, len(self.replaced)))

    def run_invalid_chain(self, node, peer_a, peer_b, honest_tx, altered_tx):
        with node.assert_debug_log(expected_msgs=["bad-blk-signatures"], unexpected_msgs=[
                "InvalidChainFound: invalid block="]):
            self.run_recovery(node, peer_a, peer_b, honest_tx, altered_tx, False, "invalid-chain")

    def run_uncached_source(self, node, peer_a, peer_b, honest_tx, altered_tx):
        tip = node.getblock(node.getbestblockhash())
        fillers = []
        # 64 bodies of at least 90 KB exceed the fixed 5 MB cache without advancing the tip.
        for i in range(64):
            block = create_block(int(tip["previousblockhash"], 16), tip["height"], int(tip["chainwork"], 16),
                                 create_cache_coinbase(tip["height"]),
                                 getAncHash(tip["height"], node), tip["time"] + i + 1, txns=[])
            block.solve()
            fillers.append(block)
            peer_a.send_message(msg_block(block))
        peer_a.sync_with_ping()
        assert_equal(node.getbestblockhash(), tip["hash"])
        for block in fillers:
            assert_equal(node.getblock(uint256ToRpcHex(block.gethash()), 0), block.serialize().hex())
        self.run_blame(node, peer_a, peer_b, honest_tx, altered_tx, "uncached-source", uncached=True)

    def run_whitelisted_source(self, node, peer_a, peer_b, honest_tx, altered_tx):
        honest = self.make_block([honest_tx])
        honest.solve()
        altered = self.make_altered(honest, altered_tx)
        block_hash = honest.gethash()
        asked_a = getdata_count(peer_a, block_hash)
        peer_a.announce(honest)
        self.wait_getdata(peer_a, block_hash, asked_a, 15, "peer A was not asked for H")
        peer_b.announce(honest)
        peer_b.sync_with_ping()
        asked_b = getdata_count(peer_b, block_hash)
        peer_a.send_message(msg_block(altered))
        peer_a.sync_with_ping()
        assert_equal(block_reject_count(peer_a, block_hash), 1)
        assert_equal(connection_dropped(peer_a), False)

        peer_a.send_message(msg_block(altered))
        peer_a.sync_with_ping()
        rejects = block_reject_count(peer_a, block_hash)
        assert rejects == 1, "whitelisted peer: repeated bad body was validated again (%d rejects)" % rejects

        self.wait_getdata(peer_b, block_hash, asked_b, GETDATA_RETRY_TIMEOUT,
                          "node did not request H from peer B after the repeated bad body")
        peer_b.send_message(msg_block(honest))
        waitFor(30, lambda: node.getbestblockhash() == uint256ToRpcHex(block_hash), "honest H did not connect")
        self.replaced.append(("whitelisted-source", honest))

    def run_policy_reject(self, node, peer_a, honest_tx):
        node.set("relay.dustThreshold=%d" % (honest_tx.vout[0].nValue + 1))
        with node.assert_debug_log(expected_msgs=["Rejected tx: dust(64)"], unexpected_msgs=[
                "BAN THRESHOLD EXCEEDED"]):
            peer_a.send_message(msg_tx(honest_tx))

            def rejected():
                if connection_dropped(peer_a):
                    return True
                with mininode_lock:
                    return any(
                        r.message == b"tx" and r.code == msg_reject.REJECT_NONSTANDARD for r in peer_a.rejects)

            waitFor(15, rejected, "the transaction was not rejected by dust policy", sleepAmt=0.05)
            # Acceptance in a block distinguishes relay policy from a consensus failure.
            block = self.make_block([honest_tx])
            block.solve()
            result = node.submitblock(block.serialize().hex())
            assert_equal(result["result"], None)
            assert_equal(node.getbestblockhash(), uint256ToRpcHex(block.gethash()))
            assert_equal(connection_dropped(peer_a), False)
            assert_equal(node.listbanned(), [])

    def restart_for_scenario(self, extra_args):
        stop_node(self.nodes[0], 0)
        node = start_node(0, self.options.tmpdir, self.extra_args[0] + extra_args)
        self.nodes[0] = node
        node.setmocktime(node.getblock(node.getbestblockhash())["time"] + 1)
        return node

    def run_scenario(self, node, failures, label, run):
        peer_a, peer_b, conn_a, conn_b, nt = self.new_peers(node)
        try:
            run(peer_a, peer_b)
            print("%s test succeeded" % label)
        except Exception as e:
            print("%s test FAILED: %s" % (label, e))
            traceback.print_exc()
            failures.append("%s: %s" % (label, e))
        finally:
            self.drop_peers([conn_a, conn_b], nt)
            # A scenario may ban 127.0.0.1, which would refuse the next scenario's peers
            node.clearbanned()

    def new_peers(self, node):
        """Connect a fresh pair of peers and the network thread that services them.

        Each scenario gets its own peers: a scenario may ban the sender, and a
        banned connection cannot be reused by the next one.  run_scenario() clears
        the ban list after each scenario so these new connections are accepted.
        """
        peer_a = BodyPeer()
        peer_b = BodyPeer()
        conn_a = NodeConn("127.0.0.1", p2p_port(0), node, peer_a)
        conn_b = NodeConn("127.0.0.1", p2p_port(0), node, peer_b)
        peer_a.add_connection(conn_a)
        peer_b.add_connection(conn_b)
        nt = NetworkThread()
        nt.start()
        peer_a.send_message(msg_extversion(), True)
        peer_b.send_message(msg_extversion(), True)
        peer_a.wait_for_verack()
        peer_b.wait_for_verack()
        return peer_a, peer_b, conn_a, conn_b, nt

    def drop_peers(self, conns, nt):
        """Disconnect the scenario's peers and wait for the network thread to end.

        Joining nt (which runs while any mininode socket is open) guarantees the
        sockets are gone before the next scenario starts its own network thread.
        """
        for conn in conns:
            conn.disconnect_node()
        nt.join()

    def run_test(self):
        node = self.nodes[0]
        waitFor(30, lambda: node.getblockcount() == 200, "cached chain did not reach height 200")
        tip_time = node.getblock(node.getbestblockhash())["time"]
        node.setmocktime(tip_time + 1)
        info = node.getblockchaininfo()
        if info.get("upgradeactive") or info.get("upgradeenforcednextblock"):
            raise AssertionError("this test must run before Upgrade2")

        failures = []
        self.replaced = []

        # Scenario 1 (regression): the forged body splits a data push, so the
        # altered scriptSigs no longer decode and the block body is rejected at
        # deserialization. CScript::IsWellFormed() must catch this.
        self.run_scenario(node, failures, "split data push", lambda a, b: self.run_recovery(
            node, a, b, *find_recut_pair(node), malformed=True, label="pushdata-recut"))

        # Scenario 2: the same txid forged a different way, so an invalid opcode appears as the first
        # instruction in the scriptSig
        self.run_scenario(node, failures, "bare opcode", lambda a, b: self.run_recovery(
            node, a, b, *make_parseable_pair(node), malformed=False, label="bare-opcode"))

        # Scenario 3: the same collision again, but the donated 0xff lands in the
        # middle of a scriptSig, so neither altered scriptSig begins with 0xff.
        # Still well-formed, so it reaches validation and fails there.
        self.run_scenario(node, failures, "interior opcode", lambda a, b: self.run_recovery(
            node, a, b, *make_interior_opcode_pair(node), malformed=False, label="interior-opcode"))

        # Scenario 4: both altered scriptSigs are push-only, so no deserialization
        # check that accepts every valid satisfier can reject the block body.
        self.run_scenario(node, failures, "op-return-led", lambda a, b: self.run_recovery(
            node, a, b, *make_op_return_led_pair(node), malformed=False, label="op-return-led"))

        # Scenario 5: the altered block body is stored before its parent and B later delivers
        # the honest one. Only A may be blamed when the stored block body fails.
        self.run_scenario(node, failures, "blame honest peer", lambda a, b: self.run_blame(
            node, a, b, *make_op_return_led_pair(node), label="blame-honest-peer"))

        # Scenario 6: a peer that sent a bad block body is not listened to again for that block.
        self.run_scenario(node, failures, "bad source", lambda a, b: self.run_bad_source(
            node, a, b, *make_op_return_led_pair(node), label="bad-source"))

        # Scenario 7: a stored descendant of the altered block body connects once the block body is replaced.
        self.run_scenario(node, failures, "stored descendant", lambda a, b: self.run_descendant(
            node, a, b, *make_op_return_led_pair(node), label="stored-descendant"))

        # Scenarios 8 and 9: the altered transaction does not keep the honest one out of the txpool.
        self.run_scenario(node, failures, "reject cache not push-only", lambda a, b: self.run_reject_cache(
            node, a, b, *make_interior_opcode_pair(node), label="reject-cache-not-push-only"))
        self.run_scenario(node, failures, "reject cache push-only", lambda a, b: self.run_reject_cache(
            node, a, b, *make_op_return_led_pair(node), label="reject-cache-push-only"))

        self.run_scenario(node, failures, "invalid-chain bookkeeping", lambda a, b: self.run_invalid_chain(
            node, a, b, *make_op_return_led_pair(node)))

        node = self.restart_for_scenario(["-cache.maxTxPool=5"])
        self.run_scenario(node, failures, "uncached body source", lambda a, b: self.run_uncached_source(
            node, a, b, *make_op_return_led_pair(node)))

        node = self.restart_for_scenario(["-whitelist=127.0.0.1"])
        self.run_scenario(node, failures, "whitelisted bad source", lambda a, b: self.run_whitelisted_source(
            node, a, b, *make_op_return_led_pair(node)))

        node = self.restart_for_scenario(["-acceptnonstdtxn=0"])
        self.run_scenario(node, failures, "policy-only rejection", lambda a, b: self.run_policy_reject(
            node, a, make_op_return_led_pair(node)[0]))

        # Replaced bodies are read back from the block cache or disk now, and from disk after a restart
        self.check_stored_bodies(failures, "before restart")
        stop_node(self.nodes[0], 0)
        self.nodes[0] = start_node(0, self.options.tmpdir, self.extra_args[0])
        self.check_stored_bodies(failures, "after restart")

        if failures:
            raise AssertionError("%d scenario(s) failed:\n%s" % (len(failures), "\n".join(failures)))


if __name__ == "__main__":
    # rpc-tests.py treats a zero exit as success. Logging goes to stdout.
    sys.exit(RecutBlockBodyTest().main())

def Test():
    t = RecutBlockBodyTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["rpc","net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }

    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
