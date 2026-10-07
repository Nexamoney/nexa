#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Check that a spend across sibling subblocks survives opposite arrival orders.
# The spender-first node mines a summary and relays it to the other node.
# Both must confirm the same outputs and converge again when the other node mines.

import copy
import logging
import time

import test_framework.loginit
from test_framework.blocktools import create_block, create_coinbase, create_transaction
from test_framework.mininode import NetworkThread, NodeConn, P2PDataStore
from test_framework.nodemessages import CBlock, CBlockHeader, FromHex, msg_headers
from test_framework.script import spendAnyoneCanSpend
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (assert_equal, connect_nodes_bi, disconnect_all,
                                 initialize_chain_clean, p2p_port, rpcHexToUint256,
                                 start_node, sync_blocks, uint256ToRpcHex, waitFor)


class CrossBranchTest(BitcoinTestFramework):
    def setup_chain(self):
        config = dict(self.confDict or {})
        config['consensus.fork2Time'] = int(time.time()) + 86400
        initialize_chain_clean(self.options.tmpdir, 3, config)

    def setup_network(self):
        self.nodes = []
        for i in range(3):
            self.nodes.append(start_node(i, self.options.tmpdir, ["-debug=dag", "-debug=net"]))
        connect_nodes_bi(self.nodes, 0, 2)
        connect_nodes_bi(self.nodes, 1, 2)

    def mine(self, node, count):
        hashes = node.generatetoaddress(count, self.mining_address, 100000000)
        assert_equal(len(hashes), count)
        return hashes

    def set_time(self, timestamp):
        for node in self.nodes:
            node.setmocktime(timestamp)

    def run_test(self):
        # Subblock ancestry:       +--> A[C]
        #              Summary ---+--> B[P]
        #                         +--> F (empty filler for K=4)
        # Transactions: P -> C. Node 0 receives A/B, node 1 receives B/A.
        builder = self.nodes[2]
        self.mining_address = builder.getnewaddress()
        now = int(time.time())
        self.set_time(now)
        genesis = builder.getblockheader(builder.getbestblockhash())
        funding = create_coinbase(1)
        first = create_block(genesis['hash'], 1, int(genesis['chainwork'], 16) + 2,
                             funding, rpcHexToUint256(genesis['hash']), now)
        first.solve()
        assert_equal(builder.submitblock(first.serialize().hex())['result'], None)
        self.mine(builder, 100)
        sync_blocks(self.nodes)

        # Activate Tailstorm on a common chain before isolating the receivers.
        for _ in range(10):
            now += 120
            self.set_time(now)
            self.mine(builder, 1)
        sync_blocks(self.nodes)
        for node in self.nodes:
            node.set("consensus.fork2Time=" + str(now + 240))
        for _ in range(20):
            if builder.getblockchaininfo()['upgradeenforcednextblock']:
                break
            now += 120
            self.set_time(now)
            self.mine(builder, 1)
            sync_blocks(self.nodes)
        else:
            raise AssertionError("Tailstorm did not become pending")
        self.mine(builder, 4)
        sync_blocks(self.nodes)
        root = builder.getbestblockhash()
        height = builder.getblockcount()
        for node in self.nodes:
            assert_equal(node.getblockchaininfo()['upgradeactive'], True)
            assert_equal(node.gettailstorminfo()['bestdag'], 0)
            disconnect_all(node)
        for node in self.nodes:
            waitFor(60, lambda: not node.getpeerinfo())

        # Use a mined empty subblock for consensus header fields, but do not
        # give the receivers any template block or transaction through RPC.
        template_hash = self.mine(builder, 1)[0]
        template = FromHex(CBlock(), builder.getsubblock(template_hash, 0))
        assert_equal(template.minerData, b'\x01\x00')
        provider = create_transaction(funding, 0, spendAnyoneCanSpend(), funding.vout[0].nValue - 10000)
        child = create_transaction(provider, 0, spendAnyoneCanSpend(), provider.vout[0].nValue - 10000)

        def make_subblock(txns, nonce):
            block = copy.deepcopy(template)
            block.vtx = [block.vtx[0]] + txns
            block.nonce = bytearray([nonce, 0, 0])
            block.update_fields()
            block.solve(prevhash=block.hashPrevBlock)
            assert_equal(block.hashPrevBlock, rpcHexToUint256(root))
            assert_equal(block.minerData, b'\x01\x00')
            return block

        block_a = make_subblock([child], 1)
        block_b = make_subblock([provider], 2)
        filler = make_subblock([], 3)
        provider_id = uint256ToRpcHex(provider.GetIdem())
        child_id = uint256ToRpcHex(child.GetIdem())
        peers = []
        connections = []
        for i in range(2):
            peer = P2PDataStore()
            connection = NodeConn('127.0.0.1', p2p_port(i), self.nodes[i], peer)
            peer.add_connection(connection)
            peers.append(peer)
            connections.append(connection)
        network = NetworkThread()
        network.start()
        try:
            for peer in peers:
                peer.wait_for_verack()

            def deliver(i, block, expected_size):
                peer = peers[i]
                peer.block_store[block.gethash()] = block
                peer.last_block_hash = block.gethash()
                peer.send_message(msg_headers([CBlockHeader(block)]))
                waitFor(60, lambda: block.gethash() in peer.getdata_requests)
                # Ping alone does not wait for background block validation.
                waitFor(60, lambda: self.nodes[i].gettailstorminfo()['bestdag'] == expected_size)
                assert_equal(self.nodes[i].getsubblock(block.hash, 0), block.serialize().hex())

            deliver(0, block_a, 1)
            deliver(1, block_b, 1)
            deliver(0, block_b, 2)
            deliver(1, block_a, 2)
            for i in range(2):
                deliver(i, filler, 3)
                assert_equal(self.nodes[i].getbestblockhash(), root)
                assert_equal(self.nodes[i].getrawtxpool(), [])

            # Only the spender-first node mines the summary. Its peer must
            # receive and validate it through ordinary node-to-node relay.
            connect_nodes_bi(self.nodes, 0, 1)
            summary_hash = self.mine(self.nodes[0], 1)[0]
            waitFor(60, lambda: all(node.getbestblockhash() == summary_hash for node in self.nodes[:2]))
            for node in self.nodes[:2]:
                assert_equal(node.getblockcount(), height + 1)
                summary = node.getblock(summary_hash)
                assert provider_id in summary['txidem']
                assert child_id in summary['txidem']
                assert_equal(node.gettxout(provider_id, 0, False), None)
                output = node.gettxout(child_id, 0, False)
                assert output is not None
                assert_equal(output['confirmations'], 1)
            assert_equal(self.nodes[0].gettxout(child_id, 0, False),
                         self.nodes[1].gettxout(child_id, 0, False))

            # Continue from the other receiver to show neither node is stranded.
            next_summary = self.mine(self.nodes[1], 4)[-1]
            waitFor(60, lambda: all(node.getbestblockhash() == next_summary for node in self.nodes[:2]))
            for node in self.nodes[:2]:
                assert_equal(node.getblockcount(), height + 2)
                assert_equal(node.gettxout(child_id, 0, False)['confirmations'], 2)
            logging.info("Opposite subblock arrival orders converged through two summaries")
        finally:
            for connection in connections:
                connection.disconnect_node()
            network.join(timeout=10)


if __name__ == '__main__':
    CrossBranchTest().main()
