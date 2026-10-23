#!/usr/bin/env python3
# Copyright (c) 2015-2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit

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
import pdb
from decimal import Decimal
from io import BytesIO
from test_framework.util import *

from test_framework.blocktools import create_block, create_coinbase, getAncHash
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
)
from test_framework.script import OP_1, OP_16, OP_INVALIDOPCODE, OP_RETURN, CScriptInvalidError
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, enable_mocktime, p2p_port, uint256ToRpcHex, waitFor

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


def connection_dropped(peer):
    with mininode_lock:
        return bool(getattr(peer, "disconnected", False))


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
        # ordered ahead of A's body. A localhost peer is never banned and its
        # ban score is reset to 0, so the checks look at which peer gets the
        # block reject instead.
        self.extra_args = [[
            "-debug=validation",
            "-debug=net",
            "-debug=req",
            "-logtimemicros=1",
            "-test.parallel=0",
            "-use-thinblocks=0",
            "-use-grapheneblocks=0",
            "-use-compactblocks=0",
            "-net.msgHandlerThreads=1",
            "-net.txAdmissionThreads=1",
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
        validation (a hash-carrying block reject).
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
            return "[%s] no block reject for H\ntip=%s\ntips=%s\nrejects=%s" % (
                label, node.getbestblockhash(), node.getchaintips(), rejects)

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

        assert_equal(peer_b.disconnected, False)
        assert_equal(block_reject(peer_b, block_hash), None)
        assert_equal(node.getrawtxpool(), [])

    def run_blame(self, node, peer_a, peer_b, honest_tx, altered_tx, label):
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
                              create_coinbase(tip["height"] + 2), getAncHash(tip["height"] + 2, node),
                              tip["time"] + 2, txns=[honest_tx])
        honest.solve()
        altered = CBlock()
        altered.deserialize(BytesIO(honest.serialize()))
        altered.vtx[1] = altered_tx
        block_hash = honest.gethash()
        assert honest.serialize() != altered.serialize()
        assert_equal(altered.gethash(), block_hash)

        # 1. A announces P and C, then delivers only the altered C. It is stored and waits for P.
        asked_a = getdata_count(peer_a, block_hash)
        peer_a.send_message(msg_headers([CBlockHeader(parent), CBlockHeader(honest)]))
        self.wait_getdata(peer_a, block_hash, asked_a, 15, "[%s] peer A was not asked for C" % label)
        peer_b.send_message(msg_headers([CBlockHeader(parent), CBlockHeader(honest)]))
        peer_b.sync_with_ping()
        peer_a.send_message(msg_block(altered))
        peer_a.sync_with_ping()

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
                    connection_dropped(peer_b))

        waitFor(30, altered_failed, "[%s] the stored altered body of C was not rejected" % label, sleepAmt=0.5)
        # The reject goes to the peer the node blames, together with DoS(100)
        if connection_dropped(peer_b) or block_reject(peer_b, block_hash) is not None:
            raise AssertionError("[%s] honest peer B was blamed for A's altered body (dropped=%s, reject=%s)" % (
                label, connection_dropped(peer_b), block_reject(peer_b, block_hash)))
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

    def new_peers(self, node):
        """Connect a fresh pair of peers and the network thread that services them.

        Each scenario gets its own peers: a scenario may ban the sender (scenarios
        2 and 3 do), and a banned connection cannot be reused by the next one.
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

        # Scenario 1 (regression): the forged body splits a data push, so the
        # altered scriptSigs no longer decode and the body is rejected at
        # deserialization. CScript::IsWellFormed() must catch this.
        peer_a, peer_b, conn_a, conn_b, nt = self.new_peers(node)
        honest_tx, altered_tx = find_recut_pair(node)
        self.run_recovery(node, peer_a, peer_b, honest_tx, altered_tx, malformed=True, label="pushdata-recut")
        self.drop_peers([conn_a, conn_b], nt)
        print("split data push test succeeded")

        # Scenario 2: the same txid forged a different way, so an invalid opcode appears as the first
        # instruction in the scriptSig
        peer_a, peer_b, conn_a, conn_b, nt = self.new_peers(node)
        honest_tx, altered_tx = make_parseable_pair(node)
        self.run_recovery(node, peer_a, peer_b, honest_tx, altered_tx, malformed=True, label="bare-opcode")
        self.drop_peers([conn_a, conn_b], nt)
        print("bare opcode test succeeded")

        # Scenario 3: the same collision again, but the donated 0xff lands in the
        # middle of a scriptSig, so neither altered scriptSig begins with 0xff.
        # Still well-formed, so it reaches validation and fails there.
        peer_a, peer_b, conn_a, conn_b, nt = self.new_peers(node)
        honest_tx, altered_tx = make_interior_opcode_pair(node)
        self.run_recovery(node, peer_a, peer_b, honest_tx, altered_tx, malformed=False, label="interior-opcode")
        self.drop_peers([conn_a, conn_b], nt)
        print("interior opcode test succeeded")

        # Scenario 4: both altered scriptSigs are push-only, so no deserialization
        # check that accepts every valid satisfier can reject the body.
        peer_a, peer_b, conn_a, conn_b, nt = self.new_peers(node)
        honest_tx, altered_tx = make_op_return_led_pair(node)
        self.run_recovery(node, peer_a, peer_b, honest_tx, altered_tx, malformed=False, label="op-return-led")
        self.drop_peers([conn_a, conn_b], nt)
        print("op-return-led test succeeded")

        # Scenario 5: the altered body is stored before its parent and B later delivers
        # the honest one. Only A may be blamed when the stored body fails.
        peer_a, peer_b, conn_a, conn_b, nt = self.new_peers(node)
        honest_tx, altered_tx = make_op_return_led_pair(node)
        self.run_blame(node, peer_a, peer_b, honest_tx, altered_tx, label="blame-honest-peer")
        self.drop_peers([conn_a, conn_b], nt)
        print("blame honest peer test succeeded")


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
