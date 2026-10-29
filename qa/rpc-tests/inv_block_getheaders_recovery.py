#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Recover a valid block burst after delayed header replies, without another INV."""

import logging
import sys
import time

import test_framework.loginit
from test_framework import cashaddr
from test_framework.mininode import NetworkThread, NodeConn, P2PDataStore, mininode_lock
from test_framework.nodemessages import CBlock, CBlockHeader, CInv, FromHex, msg_extversion, msg_headers, msg_inv
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import NoConfigValue, assert_equal, initialize_chain_clean, p2p_port, start_nodes, waitFor

BURST_BLOCKS = 32  # Exceed the 16 outstanding INV header requests in net.h.
HEADER_REPLY_DELAY = 31  # Exceed the 30-second deadline in net.h using real time.
IGNORE_CHECKSUM = 0x0000000200000002


class DelayedHeadersPeer(P2PDataStore):
    def __init__(self, genesis, cookies, separate):
        super().__init__()
        if cookies:
            self.extversion = msg_extversion({IGNORE_CHECKSUM: 1})
        self.cookies = cookies
        self.separate = separate
        self.chain = [genesis]
        self.block_store[genesis.gethash()] = genesis
        self.requests = []
        self.pending = []
        self.delay_headers = False

    def on_getheaders(self, conn, message):
        self.requests.append(message.hashstop)
        if self.delay_headers:
            self.pending.append((message, self.cookie))
        else:
            self.reply_headers(message, self.cookie)

    def reply_headers(self, message, cookie):
        if not message.locator.vHave:
            block = self.block_store.get(message.hashstop)
            headers = [CBlockHeader(block)] if block is not None else []
        else:
            heights = {block.gethash(): i for i, block in enumerate(self.chain)}
            start = next((heights[h] + 1 for h in message.locator.vHave if h in heights), 1)
            headers = []
            # Match a real peer: stop at hashstop, rather than returning the whole burst.
            for block in self.chain[start:start + 2000]:
                headers.append(CBlockHeader(block))
                if block.gethash() == message.hashstop:
                    break
        self.connection.send_message_with_cookie(msg_headers(headers), cookie | 0xFFFF)

    def announce_burst(self, blocks):
        with mininode_lock:
            self.chain.extend(blocks)
            self.block_store.update((block.gethash(), block) for block in blocks)
            self.delay_headers = True
            inventory = [CInv(CInv.MSG_BLOCK, block.gethash()) for block in blocks]
            if self.separate:
                for inv in inventory:
                    self.send_message(msg_inv([inv]))
            else:
                self.send_message(msg_inv(inventory))

    def release_headers(self):
        with mininode_lock:
            self.delay_headers = False
            for message, cookie in self.pending:
                self.reply_headers(message, cookie)
            self.pending.clear()


class InvBlockGetHeadersRecoveryTest(BitcoinTestFramework):
    def setup_chain(self):
        config = dict(self.confDict or {})
        config['consensus.fork2Time'] = int(time.time()) + 86400
        for option in ('usecashaddr', 'wallet.payTxFee', 'wallet.instant'):
            config[option] = NoConfigValue()
        initialize_chain_clean(self.options.tmpdir, 4, config)

    def setup_network(self):
        # The builder remains isolated; each receiver has only its delayed peer.
        self.nodes = start_nodes(4, self.options.tmpdir, [['-debug=net']] * 4)

    def run_test(self):
        builder = self.nodes[0]
        genesis = FromHex(CBlock(), builder.getblock(builder.getbestblockhash(), 0))
        peers = [DelayedHeadersPeer(genesis, cookies, separate)
                 for cookies, separate in ((True, False), (True, True), (False, True))]
        for i, peer in enumerate(peers, 1):
            peer.add_connection(NodeConn('127.0.0.1', p2p_port(i), self.nodes[i], peer,
                                         extversion_service=peer.cookies))
        network = NetworkThread()
        network.start()
        try:
            for peer in peers:
                peer.wait_for_verack()
                # Answer the initial availability query while both peers are at genesis.
                waitFor(10, lambda: bool(peer.requests))
                assert peer.sync_with_ping()

            address = cashaddr.encode_full('nexareg', cashaddr.PUBKEY_TYPE, bytes(20))
            hashes = builder.generatetoaddress(BURST_BLOCKS, address, 100000000)
            assert_equal(len(hashes), BURST_BLOCKS)
            raw_blocks = [builder.getblock(h, 0) for h in hashes]
            blocks = [FromHex(CBlock(), raw) for raw in raw_blocks]
            for peer in peers:
                peer.announce_burst(blocks)
                assert peer.sync_with_ping()
                with mininode_lock:
                    assert peer.pending
                    logging.info("cookies=%s separate=%s: %d header requests for %d blocks",
                                 peer.cookies, peer.separate, len(peer.pending), BURST_BLOCKS)
            for node in self.nodes[1:]:
                assert_equal(node.getblockcount(), 0)

            logging.info("Holding header replies for %d seconds while continuing to read requests",
                         HEADER_REPLY_DELAY)
            time.sleep(HEADER_REPLY_DELAY)
            for peer in peers:
                assert peer.sync_with_ping()
                peer.release_headers()

            # The same delayed replies must recover the whole chain for one batched INV.
            waitFor(30, lambda: self.nodes[1].getbestblockhash() == hashes[-1],
                    "The batched INV control did not recover the valid chain")
            logging.info("Batched INV control recovered all %d blocks", BURST_BLOCKS)

            def stalled():
                state = [(peer.cookies, peer.separate, node.getblockcount(), node.getblockchaininfo()['headers'],
                          len(peer.getdata_requests)) for peer, node in zip(peers, self.nodes[1:])]
                return ("Delayed honest-peer burst did not recover: "
                        "(cookies, separate, blocks, headers, GETDATA)=" + str(state))

            waitFor(60, lambda: all(node.getbestblockhash() == hashes[-1] for node in self.nodes[1:]), stalled)
            for peer, node in zip(peers, self.nodes[1:]):
                assert peer.sync_with_ping()
                assert_equal(node.getblockcount(), BURST_BLOCKS)
                assert_equal([node.getblock(h, 0) for h in hashes], raw_blocks)
            logging.info("All receivers recovered all %d block bodies without another INV", BURST_BLOCKS)
        finally:
            for peer in peers:
                peer.connection.disconnect_node()
            network.join(timeout=10)


if __name__ == '__main__':
    sys.exit(InvBlockGetHeadersRecoveryTest().main())
