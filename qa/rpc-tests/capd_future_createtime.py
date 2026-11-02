#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
A CAPD message created ahead of the node's clock is dropped, since a later creation time would buy priority.  The peer
that relayed it is only penalised beyond clock skew.  Messages sent with "capd send" are backdated a few seconds, so
peers whose clocks are slightly behind do not drop them.
"""
import test_framework.loginit

import logging
import sys

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.bunode import BasicBUCashNode, BUProtocolHandler
from test_framework.mininode import NetworkThread
from test_framework.nodemessages import *
from test_framework.bumessages import *

CAPD_XVERSION_STR = '000000020000000e'
TIMEOUT = 30


def hashToHex(x):
    return x[::-1].hex()


class CapdHandler(BUProtocolHandler):
    def __init__(self):
        BUProtocolHandler.__init__(self, extversion=True)

    def on_version(self, conn, message):
        BUProtocolHandler.on_version(self, conn, message)
        conn.send_message(msg_extversion({int(CAPD_XVERSION_STR, 16): 1}))

    def on_capdinv(self, conn, message):
        pass

    def on_capdinfo(self, conn, message):
        pass


class CapdFutureCreateTimeTest(BitcoinTestFramework):
    def setup_chain(self, bitcoinConfDict=None, wallets=None):
        logging.info("Initializing test directory " + self.options.tmpdir)
        bitcoinConfDict.update({"cache.maxCapdPool": 100000})
        initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir)
        self.is_network_split = False

    def banscore(self):
        peers = self.nodes[0].getpeerinfo()
        assert_equal(len(peers), 1)
        return peers[0]["banscore"]

    def run_test(self):
        # leave IBD
        self.nodes[0].generate(1)

        pynode = BasicBUCashNode()
        pynode.connect(0, '127.0.0.1', p2p_port(0), self.nodes[0], protohandler=CapdHandler(),
                       send_initial_version=True, extversion_service=True)
        NetworkThread().start()
        hdlr = pynode.cnxns[0]
        hdlr.wait_for_verack()

        now = int(time.time())
        self.nodes[0].setmocktime(now)

        # Messages are handled in order, so once a later message is in, the ones before it have been handled
        def handled(msg, n):
            marker = CapdMsg(b"marker %d after the test message" % n)
            marker.solve(2, now)
            hdlr.send_message(msg_capdmsg([msg, marker]))
            waitFor(TIMEOUT, lambda: hashToHex(marker.calcHash()) in self.nodes[0].capd("list"))

        ahead = CapdMsg(b"created 5 s ahead")
        ahead.solve(2, now + 5)
        handled(ahead, 0)
        assert hashToHex(ahead.calcHash()) not in self.nodes[0].capd("list")
        assert_equal(self.banscore(), 0)

        far = CapdMsg(b"created 1 h ahead")
        far.solve(2, now + 3600)
        handled(far, 1)
        assert hashToHex(far.calcHash()) not in self.nodes[0].capd("list")
        assert_equal(self.banscore(), 1)

        sent = self.nodes[0].capd("send", "sent by rpc")
        assert self.nodes[0].capd("get", sent)["created"] < now


if __name__ == '__main__':
    sys.exit(CapdFutureCreateTimeTest().main())

def Test():
    flags = standardFlags()
    # install ctrl-c handler
    import signal, pdb
    signal.signal(signal.SIGINT, lambda sig, stk: pdb.Pdb().set_trace(stk))

    t = CapdFutureCreateTimeTest()
    t.drop_to_pdb = True
    t.main(flags)
