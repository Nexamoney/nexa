#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
One peer announcing more unknown transactions than the request manager's
global cap must not stop the node from requesting other peers' transactions.
"""
import test_framework.loginit

import logging
import random
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.mininode import *
from test_framework.nodemessages import *

MAX_IN_FLIGHT_REQS = 100000  # requestManager.h
NUM_FAKE = MAX_IN_FLIGHT_REQS + 2000


class TxRequestCounter(SingleNodeConnCB):
    def __init__(self):
        SingleNodeConnCB.__init__(self)
        self.requested = set()

    def on_getdata(self, conn, message):
        for inv in message.inv:
            if inv.type == CInv.MSG_TX:
                self.requested.add(inv.hash)


class TxnRequestCapTest(BitcoinTestFramework):
    def setup_network(self, split=False):
        # Keep unanswered requests in flight for 60 s instead of 5 s, so one burst of announcements fills
        # the map without racing the retry interval.
        self.nodes = start_nodes(1, self.options.tmpdir, [["-net.txRetryInterval=60000000"]])
        self.is_network_split = False
        self.attacker = TxRequestCounter()
        self.attacker.add_connection(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.attacker))
        self.honest = TxRequestCounter()
        self.honest.add_connection(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.honest))
        NetworkThread().start()

    def run_test(self):
        attacker, honest = self.attacker, self.honest
        attacker.wait_for_verack()
        honest.wait_for_verack()

        for i in range(0, NUM_FAKE, 25000):
            fake = [CInv(CInv.MSG_TX, random.getrandbits(256)) for _ in range(min(25000, NUM_FAKE - i))]
            attacker.send_message(msg_inv(fake))
        # Wait until the node stops requesting them
        waitFor(60, lambda: len(attacker.requested) > 0)
        count = -1
        while True:
            time.sleep(3)
            with mininode_lock:
                if len(attacker.requested) == count:
                    break
                count = len(attacker.requested)
        logging.info("attacker's transactions requested: %d, requester.mapTxnInfo: %d" %
                     (count, self.nodes[0].getstructuresizes()["requester.mapTxnInfo"]))

        txhash = random.getrandbits(256)
        honest.send_message(msg_inv([CInv(CInv.MSG_TX, txhash)]))
        waitFor(15, lambda: txhash in honest.requested, "the honest peer's transaction was never requested")


if __name__ == '__main__':
    TxnRequestCapTest().main()
