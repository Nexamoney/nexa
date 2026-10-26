#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
An INV of unknown block hashes must not make the node send one GETHEADERS,
with a full locator, per hash.
"""
import test_framework.loginit

import logging
import random
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.mininode import *
from test_framework.nodemessages import *

NUM_BLOCKS = 5000


class GetHeadersCounter(SingleNodeConnCB):
    def __init__(self):
        SingleNodeConnCB.__init__(self)
        self.numGetHeaders = 0
        self.getHeadersBytes = 0

    def on_getheaders(self, conn, message):
        self.numGetHeaders += 1
        self.getHeadersBytes += len(message.serialize())


class InvBlockGetHeadersTest(BitcoinTestFramework):
    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir)
        self.is_network_split = False
        self.peer = GetHeadersCounter()
        self.peer.add_connection(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.peer))
        NetworkThread().start()

    def run_test(self):
        peer = self.peer
        peer.wait_for_verack()
        peer.sync_with_ping()
        # Leave out the GETHEADERS the node sends on connect
        with mininode_lock:
            peer.numGetHeaders = 0
            peer.getHeadersBytes = 0

        invs = [CInv(CInv.MSG_BLOCK, random.getrandbits(256)) for _ in range(NUM_BLOCKS)]
        peer.send_message(msg_inv(invs))
        peer.sync_with_ping()
        # GETHEADERS can still arrive after the pong, so wait until the count settles
        count = -1
        while True:
            time.sleep(2)
            with mininode_lock:
                if peer.numGetHeaders == count:
                    break
                count, size = peer.numGetHeaders, peer.getHeadersBytes
        logging.info("INV of %d unknown blocks: %d GETHEADERS, %d bytes" % (NUM_BLOCKS, count, size))
        assert_equal(count, 1)


if __name__ == '__main__':
    InvBlockGetHeadersTest().main()
