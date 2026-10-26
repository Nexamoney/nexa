#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Peers that do not finish the handshake within VERACK_TIMEOUT are disconnected,
whether they send nothing or only messages the node does not process yet.
"""
import test_framework.loginit

import logging
import random
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.mininode import *
from test_framework.nodemessages import *

VERACK_TIMEOUT = 60  # main.h


class SilentPeer(NodeConnCB):
    pass


class NoVerackPeer(NodeConnCB):
    def __init__(self):
        NodeConnCB.__init__(self)
        self.version_received = False

    def on_version(self, conn, message):
        # never answer, so the handshake does not complete
        self.version_received = True


class HandshakeTimeoutTest(BitcoinTestFramework):
    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir)
        self.is_network_split = False

    def run_test(self):
        node = self.nodes[0]
        silent = SilentPeer()
        NodeConn('127.0.0.1', p2p_port(0), node, silent, send_initial_version=False)
        noverack = NoVerackPeer()
        noverack_conn = NodeConn('127.0.0.1', p2p_port(0), node, noverack)
        NetworkThread().start()

        waitFor(30, lambda: noverack.version_received)
        waitFor(30, lambda: len(node.getpeerinfo()) == 2)

        # These are queued until the handshake completes, so they are never processed
        for _ in range(100):
            invs = [CInv(CInv.MSG_TX, random.getrandbits(256)) for _ in range(1000)]
            noverack_conn.send_message(msg_inv(invs))
        waitFor(30, lambda: sum(p["bytesrecv"] for p in node.getpeerinfo()) > 3500000)

        start = time.time()
        waitFor(VERACK_TIMEOUT + 30, lambda: len(node.getpeerinfo()) == 0,
                lambda: "after %d s still connected: %s" % (time.time() - start,
                    ["%s bytesrecv=%d" % (p["addr"], p["bytesrecv"]) for p in node.getpeerinfo()]))


if __name__ == '__main__':
    HandshakeTimeoutTest().main()
