#!/usr/bin/env python3
# Copyright (c) 2015-2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit

# A block whose body does not match its header fails CheckBlock. The node must
# not stop asking for that block (NX-17).
#
# Peer A announces block H and is asked for it. Peer B advertises the same
# header while that request is outstanding. A answers with H's header and a
# body whose merkle root does not match. The node must then ask B, and B's
# honest body must become the tip.

import sys
from io import BytesIO

from test_framework.blocktools import create_block, create_coinbase, getAncHash
from test_framework.mininode import NetworkThread, NodeConn, NodeConnCB, mininode_lock
from test_framework.nodemessages import CBlock, CBlockHeader, CInv, msg_block, msg_extversion, msg_headers, msg_ping
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, enable_mocktime, p2p_port, uint256ToRpcHex, waitFor

# blockLookAheadInterval defaults to 5s after a body starts arriving.
GETDATA_RETRY_TIMEOUT = 45


class BodyPeer(NodeConnCB):
    def __init__(self):
        NodeConnCB.__init__(self)
        self.connection = None
        self.getdata = []
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

    def on_pong(self, conn, message):
        self.last_pong = message

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


class RerequestBadBlockBodyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = False
        # The cached chain is stamped in the past. Start near its tip so header
        # announcements are direct-fetched instead of treated as ancient.
        enable_mocktime()
        # Full-block GETDATA only. One message thread keeps B's announcement
        # ordered ahead of A's body.
        self.extra_args = [[
            "-debug=net",
            "-debug=req",
            "-debug=blk",
            "-logtimemicros=1",
            "-test.parallel=0",
            "-use-thinblocks=0",
            "-use-grapheneblocks=0",
            "-use-compactblocks=0",
            "-net.msgHandlerThreads=1",
        ]]

    def make_block(self):
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
        )

    def wait_getdata(self, peer, block_hash, previous, timeout, what):
        waitFor(timeout, lambda: getdata_count(peer, block_hash) > previous, what, sleepAmt=0.05)

    def run_test(self):
        node = self.nodes[0]
        waitFor(30, lambda: node.getblockcount() == 200, "cached chain did not reach height 200")
        node.setmocktime(node.getblock(node.getbestblockhash())["time"] + 1)

        peer_a = BodyPeer()
        peer_b = BodyPeer()
        conn_a = NodeConn("127.0.0.1", p2p_port(0), node, peer_a)
        conn_b = NodeConn("127.0.0.1", p2p_port(0), node, peer_b)
        peer_a.add_connection(conn_a)
        peer_b.add_connection(conn_b)
        NetworkThread().start()
        peer_a.send_message(msg_extversion(), True)
        peer_b.send_message(msg_extversion(), True)
        peer_a.wait_for_verack()
        peer_b.wait_for_verack()

        # H, and a body for H's header with a different coinbase
        honest = self.make_block()
        honest.solve()
        bad = CBlock()
        bad.deserialize(BytesIO(honest.serialize()))
        bad.vtx[0].vout[0].nValue += 1
        bad.vtx[0].rehash()
        block_hash = honest.gethash()
        assert_equal(bad.gethash(), block_hash)
        assert bad.calc_merkle_root() != bad.hashMerkleRoot

        start_tip = node.getbestblockhash()

        # A announces H and is asked for it. B advertises the same header while that request is outstanding.
        peer_a.announce(honest)
        self.wait_getdata(peer_a, block_hash, 0, 15, "peer A was not asked for H")
        asked_b = getdata_count(peer_b, block_hash)
        peer_b.announce(honest)
        peer_b.sync_with_ping()
        assert_equal(getdata_count(peer_b, block_hash), asked_b)

        # A sends the bad body. It fails CheckBlock and the tip stays put.
        peer_a.send_message(msg_block(bad))
        peer_a.sync_with_ping()
        assert_equal(node.getbestblockhash(), start_tip)

        # The node asks B for H, and B's honest body becomes the tip.
        self.wait_getdata(peer_b, block_hash, asked_b, GETDATA_RETRY_TIMEOUT,
                          "node did not request H from peer B after the bad body")
        peer_b.send_message(msg_block(honest))
        waitFor(30, lambda: node.getbestblockhash() == uint256ToRpcHex(block_hash),
                "honest body did not become the tip", sleepAmt=0.05)


if __name__ == "__main__":
    # rpc-tests.py treats a zero exit as success. Logging goes to stdout.
    sys.exit(RerequestBadBlockBodyTest().main())
