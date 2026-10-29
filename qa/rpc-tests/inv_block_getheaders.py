#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Bound INV-triggered GETHEADERS across both large and separate INV messages.
Retain excess announcements and resume them without another INV.
"""
import test_framework.loginit

import logging
import random
import sys

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.mininode import *
from test_framework.nodemessages import *
from test_framework.blocktools import create_block, create_coinbase, getAncHash

NUM_BLOCKS = 5000
MAX_INV_HEADER_REQUESTS = 16  # net.h
INV_HEADER_REQUEST_TIMEOUT = 30  # net.h, in seconds
IGNORE_CHECKSUM = 0x0000000200000002


class GetHeadersCounter(SingleNodeConnCB):
    def __init__(self, cookies=True):
        SingleNodeConnCB.__init__(self)
        if cookies:
            self.extversion = msg_extversion({IGNORE_CHECKSUM: 1})
        self.cookies = cookies
        self.announced = set()
        self.requests = []
        self.numGetHeaders = 0
        self.getHeadersBytes = 0

    def on_getheaders(self, conn, message):
        if message.hashstop in self.announced:
            self.requests.append((message.hashstop, self.cookie))
            self.numGetHeaders += 1
            self.getHeadersBytes += len(message.serialize())

    def announce(self, hashes, separate=False):
        with mininode_lock:
            self.announced.update(hashes)
        if separate:
            for h in hashes:
                self.send_message(msg_inv([CInv(CInv.MSG_BLOCK, h)]))
        else:
            self.send_message(msg_inv([CInv(CInv.MSG_BLOCK, h) for h in hashes]))

    def reply(self, cookie):
        self.connection.send_message_with_cookie(msg_headers(), cookie | 0xFFFF)


class InvBlockGetHeadersTest(BitcoinTestFramework):
    def setup_chain(self):
        config = dict(self.confDict or {})
        # Keep admission order deterministic for the deferred FIFO check.
        config['net.msgHandlerThreads'] = 1
        for option in ('usecashaddr', 'wallet.payTxFee', 'wallet.instant'):
            config[option] = NoConfigValue()
        initialize_chain_clean(self.options.tmpdir, 1, config)

    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir)
        self.is_network_split = False
        self.peers = [GetHeadersCounter(), GetHeadersCounter(), GetHeadersCounter(cookies=False)]
        for peer in self.peers:
            peer.add_connection(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], peer,
                                         extversion_service=peer.cookies))
        NetworkThread().start()

    def wait_count(self, peer, count, timeout=10):
        waitFor(timeout, lambda: peer.numGetHeaders >= count)
        peer.sync_with_ping()
        with mininode_lock:
            assert_equal(peer.numGetHeaders, count)

    def run_test(self):
        for peer in self.peers:
            peer.wait_for_verack()
            peer.sync_with_ping()

        batch, cookie_peer, checksum_peer = self.peers
        hashes = [random.getrandbits(256) for _ in range(NUM_BLOCKS)]
        batch.announce(hashes)
        self.wait_count(batch, 1)
        assert_equal(batch.requests[0][0], hashes[-1])
        logging.info("One large INV: one GETHEADERS, %d bytes", batch.getHeadersBytes)

        # A header the cookie peer can deliver later for its first announcement.
        node = self.nodes[0]
        genesis = node.getblock(node.getbestblockhash())
        block = create_block(int(genesis["hash"], 16), 1, int(genesis["chainwork"], 16) + 2, create_coinbase(1),
                             getAncHash(1, node), genesis["time"] + 1)
        block.solve()

        # Each connection gets its own window, including peers without cookie support.
        announced = []
        for peer in (cookie_peer, checksum_peer):
            targets = [random.getrandbits(256) for _ in range(2 * MAX_INV_HEADER_REQUESTS)]
            if peer is cookie_peer:
                targets[0] = block.gethash()
            announced.append(targets)
            peer.announce(targets[:1])
            self.wait_count(peer, 1)
            peer.announce(targets[1:], separate=True)
            self.wait_count(peer, MAX_INV_HEADER_REQUESTS)

        # Replies without the announced header release no slot, whatever cookie the peer guesses.
        for cookie in [0] + [i << 16 for i in range(1, MAX_INV_HEADER_REQUESTS + 1)]:
            cookie_peer.reply(cookie)
        checksum_peer.reply(0)
        for peer in (cookie_peer, checksum_peer):
            peer.sync_with_ping()
            assert_equal(peer.numGetHeaders, MAX_INV_HEADER_REQUESTS)

        # Delivering the header resumes the first deferred request without another INV.
        cookie_peer.send_message(msg_headers([CBlockHeader(block)]))
        cookie_peer.sync_with_ping()
        self.wait_count(cookie_peer, MAX_INV_HEADER_REQUESTS + 1)
        assert_equal(cookie_peer.requests[-1][0], announced[0][MAX_INV_HEADER_REQUESTS])

        # Expiry also resumes retained announcements without further messages from the peer.
        for peer, targets in zip((cookie_peer, checksum_peer), announced):
            self.wait_count(peer, 2 * MAX_INV_HEADER_REQUESTS, timeout=INV_HEADER_REQUEST_TIMEOUT + 3)
            assert_equal({h for h, _ in peer.requests}, set(targets))
        logging.info("Separate INV windows, release on the header and automatic deferred recovery passed")


if __name__ == '__main__':
    sys.exit(InvBlockGetHeadersTest().main())
