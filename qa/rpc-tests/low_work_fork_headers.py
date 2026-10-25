#!/usr/bin/env python3
# Copyright (c) 2015-2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit

# Headers with less chain work than the active chain had LOW_WORK_HEADER_DEPTH
# blocks below its tip must not be stored (NX-19). On mainnet ASERT lets a fork
# from an old block run at minimum difficulty after its first header, so every
# stored header would be nearly free for a peer and the block index never
# shrinks. Forks within that depth are still stored.

from test_framework.blocktools import create_block, create_coinbase, getAncHash, ancestorHeight
from test_framework.mininode import NetworkThread, NodeConn, SingleNodeConnCB
from test_framework.nodemessages import CBlockHeader, msg_headers
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import JSONRPCException, assert_equal, p2p_port, start_nodes, uint256ToRpcHex

CHAIN_LENGTH = 1000
LOW_WORK_HEADER_DEPTH = 720  # validation.h


class LowWorkForkHeadersTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir)
        self.is_network_split = False

    def build_fork(self, fork_height, count):
        node = self.nodes[0]
        fork = node.getblockheader(fork_height)
        prev = fork["hash"]
        height = fork_height + 1
        work = int(fork["chainwork"], 16) + 2
        block_time = fork["time"] + 1
        headers = []
        for _ in range(count):
            anc_height = ancestorHeight(height)
            if anc_height > fork_height:
                anc_hash = headers[anc_height - fork_height - 1].gethash()
            else:
                anc_hash = getAncHash(height, node)
            block = create_block(prev, height, work, create_coinbase(height), anc_hash, block_time)
            block.solve()
            headers.append(block)
            prev = block.gethash()
            height += 1
            work += 2
            block_time += 1
        return headers

    def count_stored(self, headers):
        stored = 0
        for b in headers:
            try:
                self.nodes[0].getblockheader(uint256ToRpcHex(b.gethash()))
                stored += 1
            except JSONRPCException:
                pass
        return stored

    def run_test(self):
        node = self.nodes[0]
        node.generate(CHAIN_LENGTH)

        peer = SingleNodeConnCB()
        peer.add_connection(NodeConn('127.0.0.1', p2p_port(0), node, peer))
        NetworkThread().start()
        peer.wait_for_verack()
        tips_before = len(node.getchaintips())

        # A fork from height 50 whose work stays below the active chain at height 280 is not stored
        deep = self.build_fork(50, 200)
        assert deep[-1].chainWork < int(node.getblockheader(CHAIN_LENGTH - LOW_WORK_HEADER_DEPTH)["chainwork"], 16)
        peer.send_message(msg_headers([CBlockHeader(b) for b in deep]))
        peer.sync_with_ping()
        assert_equal(self.count_stored(deep), 0)
        assert_equal(len(node.getchaintips()), tips_before)

        # A fork from 10 blocks below the tip is stored as before
        shallow = self.build_fork(CHAIN_LENGTH - 10, 5)
        peer.send_message(msg_headers([CBlockHeader(b) for b in shallow]))
        peer.sync_with_ping()
        assert_equal(self.count_stored(shallow), len(shallow))
        assert_equal(len(node.getchaintips()), tips_before + 1)


if __name__ == '__main__':
    LowWorkForkHeadersTest().main()
