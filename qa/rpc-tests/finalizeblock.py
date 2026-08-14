#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the maximum reorganization depth."""
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import logging
logging.getLogger().setLevel(logging.INFO)

# Give more time in slow CI machines than for developer's machines.
# $CI env variable is available for all jobs executed in CI/CD.
# Is set to true when available.
# see https://docs.gitlab.com/ci/variables/predefined_variables/
# TODO: evaluate tif it would be better to use NEXA_DBG_NO_PAUSE
# which is something we control directly.
waitTime = 60 if os.getenv("CI") == "true" else 10

class MaxReorgTest(BitcoinTestFramework):
    NUM_NODES = 4

    def set_mock_time(self, mocktime):
        for node in self.nodes:
            node.setmocktime(mocktime)

    def activate_tailstorm(self):
        node = self.nodes[0]
        mocktime = node.getblockheader(node.getbestblockhash())['time']

        # Establish a predictable median time before scheduling Fork2.
        for _ in range(10):
            mocktime += 120
            self.set_mock_time(mocktime)
            node.generate(1)
        self.sync_blocks()

        activation_time = node.getblockheader(node.getbestblockhash())['time'] + 240
        for peer in self.nodes:
            peer.set("consensus.fork2Time=" + str(activation_time))

        for _ in range(20):
            if node.getblockchaininfo()['upgradeenforcednextblock']:
                break
            mocktime += 120
            self.set_mock_time(mocktime)
            node.generate(1)
            self.sync_blocks()
        else:
            raise AssertionError("Fork2 did not become pending")

        self.mine_summary_blocks(node, 1)
        self.sync_blocks()
        for peer in self.nodes:
            assert_equal(peer.getblockchaininfo()['upgradeactive'], True)

    def mine_summary_blocks(self, node, count):
        summary_hashes = []
        for _ in range(count):
            previous_height = node.getblockcount()
            for _ in range(10):
                block_hash = node.generate(1)[0]
                if node.getblockcount() != previous_height:
                    assert_equal(node.getblockcount(), previous_height + 1)
                    summary_hashes.append(block_hash)
                    break
            else:
                raise AssertionError("Failed to mine a Tailstorm summary block")
        return summary_hashes

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        logging.info("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 4, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = []
        self.is_network_split = False
        for i in range(0, self.NUM_NODES):
            self.nodes.append(start_node(i, self.options.tmpdir, []))
        interconnect_nodes(self.nodes)
        self.sync_all()
        self.nodes[1].set("test.maxReorgDepth=3")
        self.nodes[2].set("test.maxReorgDepth=4")
        self.nodes[3].set("test.maxReorgDepth=5")


    def run_test(self):
        node = self.nodes[0]

        logging.info("Test block finalization...")
        node.generate(10)
        waitFor(waitTime, lambda: node.getblockcount() == 10)
        tip = node.getbestblockhash()
        assert_equal(node.getbestblockhash(), tip)
        logging.info(f"node 0 at {node.getblockcount()}")

        self.sync_blocks()
        waitFor(waitTime, lambda: self.nodes[0].getblockcount() == 10)

        # Disconnect the alt_node first before mining and then reconnecting. In other
        # single threaded nodes we wouldn't need to do this however in BU we if we
        # didn't disonnect here we could end up with multiple getdata's from the other
        # peer which would result in a first set of headers which are accepted (and then invalidated)
        # followed by a second set of headers which get rejected; if this happens then this python
        # test will fail, hence the need here to disconnect/reconnect which then results in only one
        # getdata and one set of headers and thus we end up with the correct chaintip.
        logging.info("disconnecting")
        disconnect_all(node)

        logging.info("generating")
        tip = node.generate(5)[4]

        # The rewind depth for these nodes is 4, so nodes 2 and 3 should reorg based on their
        # maxReorgDepths of 4 and 5
        self.nodes[1].generate(4)
        waitFor(waitTime, lambda: self.nodes[1].getblockcount() == 14)
        waitFor(waitTime, lambda: self.nodes[2].getblockcount() == 14)
        waitFor(waitTime, lambda: self.nodes[3].getblockcount() == 14)

        logging.info("sync 0")
        waitFor(waitTime, lambda: node.getblockcount() == 15)
        logging.info("reconnect")
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)
        connect_nodes_bi(self.nodes, 0, 3)

        # Wait for all the nodes to become aware of the other fork
        waitFor(waitTime, lambda: len(self.nodes[1].getchaintips()) == 2)
        waitFor(waitTime, lambda: len(self.nodes[2].getchaintips()) == 2)
        waitFor(waitTime, lambda: len(self.nodes[3].getchaintips()) == 2)

        # Node 1 should not have reorged
        assert_not_equal(self.nodes[1].getbestblockhash(), tip)
        tips = self.nodes[1].getchaintips()
        fork = next((d for d in tips if d["height"] == 15), None)
        assert(fork['status'] == "valid-headers") # not 'active'

        # the other 2 nodes should have reorged to the other fork
        waitFor(waitTime, lambda: self.nodes[2].getbestblockhash() == tip)
        waitFor(waitTime, lambda: self.nodes[3].getbestblockhash() == tip)

        # we change the reorg depth so we can move to the longest fork
        self.nodes[1].set("test.maxReorgDepth=4")
        # to trigger a re-eval and switch over, we need to find a new block on the fork
        tip = node.generate(1)[0]
        waitFor(waitTime, lambda: self.nodes[1].getbestblockhash() == tip)

        logging.info("Test maximum reorganization depth with Tailstorm grove work")
        self.sync_blocks()
        self.activate_tailstorm()

        # Build equal-work forks whose common ancestor is four summary blocks
        # behind their tips. Node 1 permits reorgs of at most three blocks.
        for peer in self.nodes:
            disconnect_all(peer)

        common_height = self.nodes[0].getblockcount()
        protected_tip = self.mine_summary_blocks(self.nodes[1], 4)[-1]
        competing_tip = self.mine_summary_blocks(self.nodes[0], 4)[-1]
        assert_equal(self.nodes[0].getblockcount(), common_height + 4)
        assert_equal(self.nodes[1].getblockcount(), common_height + 4)

        connect_nodes_bi(self.nodes, 0, 1)
        waitFor(waitTime, lambda: any(tip['hash'] == competing_tip
                                      for tip in self.nodes[1].getchaintips()))
        assert_equal(self.nodes[1].getbestblockhash(), protected_tip)

        # A subblock gives the competing grove more total work than node 1's
        # active grove. It must not bypass the summary-chain reorg-depth limit.
        competing_subblock = self.nodes[0].generate(1)[0]
        waitFor(waitTime, lambda: self.nodes[1].getsubblock(competing_subblock))
        assert_equal(self.nodes[1].getbestblockhash(), protected_tip)

if __name__ == '__main__':
    MaxReorgTest().main()


# Create a convenient function for an interactive python debugging session
def Test():
    t = MaxReorgTest()
    t.drop_to_pdb = True
    # install ctrl-c handler
    #import signal, pdb
    #signal.signal(signal.SIGINT, lambda sig, stk: pdb.Pdb().set_trace(stk))
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
