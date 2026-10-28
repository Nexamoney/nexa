#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
EXTGETDATA requests deferred because the send buffer is full must be
answered once there is room again, like GETDATA requests (see rejectReply).
"""
import test_framework.loginit

import logging

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.bunode import *
from test_framework.mininode import *
from test_framework.nodemessages import *

MSG_TOKENINFO = 100
IGNORE_CHECKSUM_STR = '0000000200000002'
NUM_REQUESTS = 2000
TIMEOUT = 60


class CExtInv(object):
    def __init__(self, t, h):
        self.type = t
        self.hash = h

    def serialize(self, stype=SER_DEFAULT):
        return struct.pack("<B", self.type) + ser_string(self.hash)


class msg_extgetdata(object):
    command = b"extgetdata"

    def __init__(self, invs):
        self.inv = invs

    def serialize(self, stype=SER_DEFAULT):
        return ser_vector(self.inv, stype)

    def __repr__(self):
        return "msg_extgetdata(%d invs)" % len(self.inv)


class TokenInfoRejectHandler(BUProtocolHandler):
    def __init__(self):
        BUProtocolHandler.__init__(self, extversion=True)
        self.numRejects = 0

    def on_version(self, conn, message):
        BUProtocolHandler.on_version(self, conn, message)
        conn.send_message(msg_extversion({int(IGNORE_CHECKSUM_STR, 16): 1}))

    def on_reject(self, conn, message):
        if message.message == b"tokeninfo":
            self.numRejects += 1


class ExtGetDataDeferredTest(BitcoinTestFramework):
    def setup_chain(self, bitcoinConfDict=None, wallets=None):
        logging.info("Initializing test directory " + self.options.tmpdir)
        # 2 KB, so the replies to one EXTGETDATA overflow the send buffer
        bitcoinConfDict.update({"maxsendbuffer": 2})
        initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir)
        self.is_network_split = False
        self.hdlr = TokenInfoRejectHandler()
        self.conn = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], self.hdlr,
                             services=NODE_NETWORK | NODE_EXTVERSION,
                             send_initial_version=True, extversion_service=True)
        self.hdlr.add_connection(self.conn)
        self.nt = NetworkThread()
        self.nt.start()

    def run_test(self):
        # leave IBD
        self.nodes[0].generate(1)

        hdlr = self.hdlr
        self.conn.handle_write()
        hdlr.wait_for_verack()

        # Unknown token ids: the node answers each one with a reject
        invs = [CExtInv(MSG_TOKENINFO, i.to_bytes(32, "little")) for i in range(1, NUM_REQUESTS + 1)]
        self.conn.send_message(msg_extgetdata(invs))

        waitFor(TIMEOUT, lambda: hdlr.numRejects == NUM_REQUESTS,
                lambda: "got %d of %d tokeninfo replies" % (hdlr.numRejects, NUM_REQUESTS))
        assert_equal(len(self.nodes[0].getpeerinfo()), 1)


if __name__ == '__main__':
    ExtGetDataDeferredTest().main()
