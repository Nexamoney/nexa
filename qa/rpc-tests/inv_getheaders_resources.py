#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bound unanswered INV header requests even when a peer keeps reading them."""

import logging
import random
import sys
import time

import test_framework.loginit
from test_framework import cashaddr
from test_framework.mininode import NetworkThread, NodeConn, SingleNodeConnCB, mininode_lock
from test_framework.nodemessages import CInv, msg_extversion, msg_inv
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import NoConfigValue, assert_equal, initialize_chain_clean, p2p_port, start_nodes

REQUEST_LIMIT = 16  # net.h
P2P_HEADER_BYTES = 24
IGNORE_CHECKSUM = 0x0000000200000002


class HeadersReader(SingleNodeConnCB):
    def __init__(self, cookies=True):
        super().__init__()
        if cookies:
            self.extversion = msg_extversion({IGNORE_CHECKSUM: 1})
        self.cookies = cookies
        self.announced = set()
        self.requests = 0
        self.request_bytes = 0
        self.inv_bytes = 0
        self.locator_entries = 0

    def on_getheaders(self, conn, message):
        if message.hashstop in self.announced:
            self.requests += 1
            self.request_bytes += P2P_HEADER_BYTES + len(message.serialize())
            self.locator_entries = len(message.locator.vHave)

    def on_inv(self, conn, message):
        # This peer sends no GETDATA; incoming service queues are irrelevant here.
        pass

    def announce(self, count, separate):
        inventory = [CInv(CInv.MSG_BLOCK, random.getrandbits(256)) for _ in range(count)]
        with mininode_lock:
            self.announced.update(inv.hash for inv in inventory)
            messages = [msg_inv([inv]) for inv in inventory] if separate else [msg_inv(inventory)]
            for message in messages:
                self.inv_bytes += P2P_HEADER_BYTES + len(message.serialize())
                self.send_message(message)


class InvGetHeadersResourcesTest(BitcoinTestFramework):
    def setup_chain(self):
        config = dict(self.confDict or {})
        config['consensus.fork2Time'] = int(time.time()) + 86400
        # One handler makes each pong a barrier for preceding INV processing.
        config['net.msgHandlerThreads'] = 1
        for option in ('usecashaddr', 'wallet.payTxFee', 'wallet.instant'):
            config[option] = NoConfigValue()
        initialize_chain_clean(self.options.tmpdir, 1, config)

    def setup_network(self):
        self.nodes = start_nodes(1, self.options.tmpdir)

    def run_test(self):
        node = self.nodes[0]
        address = cashaddr.encode_full('nexareg', cashaddr.PUBKEY_TYPE, bytes(20))
        assert_equal(len(node.generatetoaddress(128, address, 100000000)), 128)
        peers = [HeadersReader(), HeadersReader(), HeadersReader(cookies=False)]
        for peer in peers:
            peer.add_connection(NodeConn('127.0.0.1', p2p_port(0), node, peer,
                                         extversion_service=peer.cookies))
        network = NetworkThread()
        network.start()
        try:
            for peer in peers:
                peer.wait_for_verack()
                assert peer.sync_with_ping()

            batch, *readers = peers
            batch.announce(512, separate=False)
            assert batch.sync_with_ping()
            with mininode_lock:
                logging.info("Batched INV: 512 hashes, %d GETHEADERS, %d INV wire bytes, %d reply wire bytes",
                             batch.requests, batch.inv_bytes, batch.request_bytes)
                assert_equal(batch.requests, 1)
                assert batch.locator_entries > 1

            counts = []
            for peer in readers:
                peer.announce(4 * REQUEST_LIMIT, separate=True)
                assert peer.sync_with_ping()
                with mininode_lock:
                    first = peer.requests
                # All first-wave requests have been read; no HEADERS are returned.
                peer.announce(4 * REQUEST_LIMIT, separate=True)
                assert peer.sync_with_ping()
                with mininode_lock:
                    counts.append((first, peer.requests))
                    logging.info("cookies=%s: 128 separate INVs, GETHEADERS by wave=%s, "
                                 "%d INV wire bytes, %d reply wire bytes, %d locator entries",
                                 peer.cookies, counts[-1], peer.inv_bytes, peer.request_bytes, peer.locator_entries)
                    assert peer.locator_entries > 1
            for first, second in counts:
                assert_equal(first, REQUEST_LIMIT)
                assert_equal(second, REQUEST_LIMIT)
            logging.info("GETHEADERS stayed bounded while readers drained every wave without GETDATA or HEADERS")
        finally:
            for peer in peers:
                peer.connection.disconnect_node()
            network.join(timeout=10)


if __name__ == '__main__':
    sys.exit(InvGetHeadersResourcesTest().main())
