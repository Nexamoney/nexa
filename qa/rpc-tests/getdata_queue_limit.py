#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Fill the real GETDATA queues through P2P while regtest pauses servicing."""
import test_framework.loginit

import logging
import struct
import sys

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (assert_equal, assert_raises_rpc_error, p2p_port,
                                 start_nodes, stop_nodes, wait_bitcoinds, waitFor)
from test_framework.mininode import NodeConn, NodeConnCB, NetworkThread, mininode_lock
from test_framework.nodemessages import (CInv, deser_compact_size,
                                         msg_extversion, msg_ping, ser_compact_size,
                                         ser_uint256)

LIMIT = 1000000
MAX_INV = 50000
TIMEOUT = 180
TX_HASH = 0x12345678
IGNORE_CHECKSUM = 0x0000000200000002
INV2_SUPPORT = 0x0000000200000009


class Request:
    def __init__(self, command, entry, count):
        self.command = command
        self.entry = entry
        self.count = count

    def serialize(self):
        return ser_compact_size(self.count) + self.entry * self.count

    def __repr__(self):
        return "Request(%s, %d)" % (self.command, self.count)


def counted_notfound(entry):
    class NotFound:
        command = b"notfound"

        def deserialize(self, stream):
            self.count = deser_compact_size(stream)
            remaining = self.count
            # Validate every descriptor without allocating a million Python inventory objects.
            while remaining:
                batch = min(remaining, 4096)
                assert_equal(stream.read(batch * len(entry)), entry * batch)
                remaining -= batch
            assert_equal(stream.read(), b"")

        def __repr__(self):
            return "NotFound(%d)" % self.count
    return NotFound


class Peer(NodeConnCB):
    def __init__(self, inv2):
        super().__init__(msg_extversion({IGNORE_CHECKSUM: 1, INV2_SUPPORT: int(inv2)}))
        self.notfound = 0
        self.rejects = 0
        self.pong = 0

    def on_notfound(self, conn, message):
        self.notfound += message.count

    def on_reject(self, conn, message):
        if message.message == b"tokeninfo":
            self.rejects += 1

    def on_pong(self, conn, message):
        self.pong = message.nonce

    def on_inv(self, conn, message):
        pass


class GetDataQueueLimitTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # A pong is a processing barrier only with one message handler.
        self.extra_args = [["-net.msgHandlerThreads=1", "-maxsendbuffer=64000"]]

    def exercise(self, inv2):
        node = self.nodes[0]
        peer = Peer(inv2)
        conn = NodeConn("127.0.0.1", p2p_port(0), node, peer,
                        extversion_service=True)
        entry = struct.pack("<B" if inv2 else "<i", CInv.MSG_TX) + ser_uint256(TX_HASH)
        extended = b"\x64\x20" + b"\x01" * 32
        conn.messagemap = dict(conn.messagemap)
        conn.messagemap[b"notfound"] = counted_notfound(entry)
        network = NetworkThread()
        network.start()
        nonce = 0

        def barrier():
            nonlocal nonce
            nonce += 1
            conn.send_message(msg_ping(nonce))
            waitFor(TIMEOUT, lambda: peer.pong == nonce)
            assert not peer.disconnected
            assert not conn.exceptions

        def send(command, descriptor, count):
            conn.send_message(Request(command, descriptor, count))
            barrier()

        try:
            peer.wait_for_verack()
            barrier()
            peerid = node.getpeerinfo()[0]["id"]
            state = node.setmockgetdata(peerid, True)
            assert_equal(state["limit"], LIMIT)
            assert_equal(state["total"], 0)
            assert state["paused"]
            logging.info("Filling %s queue through P2P", "INV2" if inv2 else "legacy GETDATA")
            queued = 0
            while queued < LIMIT - 2:
                batch = min(MAX_INV, LIMIT - 2 - queued)
                send(b"getdata", entry, batch)
                queued += batch
                assert_equal(node.setmockgetdata(peerid)["total"], queued)

            # The last available slot is in a different queue: the budget is shared.
            send(b"extgetdata", extended, 1)
            expected = LIMIT - 1
            state = node.setmockgetdata(peerid)
            assert_equal(state["getdata2" if inv2 else "getdata"], LIMIT - 2)
            assert_equal(state["extgetdata"], 1)
            assert_equal(state["total"], expected)
            for command, descriptor, count in [(b"getdata", entry, 1),
                                                (b"extgetdata", extended, 1),
                                                (b"extgetdata", extended, 2)]:
                send(command, descriptor, count)
                assert_equal(node.setmockgetdata(peerid)["total"], expected)
            assert_equal(peer.notfound, 0)
            assert_equal(peer.rejects, 0)
            assert_equal(node.getpeerinfo()[0]["banscore"], 0)

            logging.info("Boundary checked at %d; resuming and draining retained requests", expected)
            assert not node.setmockgetdata(peerid, False)["paused"]
            waitFor(TIMEOUT, lambda: peer.notfound == LIMIT - 2 and peer.rejects == 1)
            barrier()
            assert_equal(node.setmockgetdata(peerid)["total"], 0)
            assert_equal(peer.notfound, LIMIT - 2)
            assert_equal(peer.rejects, 1)

            # Requests dropped at capacity must not prevent later requests from succeeding.
            send(b"getdata", entry, 1)
            send(b"extgetdata", extended, 1)
            assert_equal(peer.notfound, LIMIT - 1)
            assert_equal(peer.rejects, 2)
            assert_equal(node.getpeerinfo()[0]["id"], peerid)
            assert_equal(node.getpeerinfo()[0]["banscore"], 0)
            logging.info("%s boundary and recovery passed", "INV2" if inv2 else "legacy GETDATA")
        finally:
            with mininode_lock:
                conn.disconnect = True
            network.join(TIMEOUT)
            assert not network.is_alive()
        waitFor(TIMEOUT, lambda: not node.getpeerinfo())

    def run_test(self):
        for inv2 in (False, True):
            self.exercise(inv2)

        # The control must be rejected before looking up a peer on other networks.
        for testnet in (True, False):
            stop_nodes(self.nodes)
            wait_bitcoinds()
            # No wallet: on mainnet nexad warns on stderr about an unencrypted one, which fails the test
            args = ["-regtest=0", "-testnet=%d" % testnet, "-disablewallet", "-listen=0", "-connect=0",
                    "-dnsseed=0", "-discover=0", "-upnp=0"]
            self.nodes = start_nodes(1, self.options.tmpdir, [args])
            assert self.nodes[0].getblockchaininfo()["chain"] != "regtest"
            assert_raises_rpc_error(-32601, "not found", self.nodes[0].setmockgetdata, 0, True)


if __name__ == '__main__':
    sys.exit(GetDataQueueLimitTest().main())
