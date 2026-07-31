#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the finalizeblock RPC calls."""
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import logging
logging.getLogger().setLevel(logging.INFO)

RPC_FINALIZE_INVALID_BLOCK_ERROR = 'finalize-invalid-block'
AUTO_FINALIZATION_DEPTH = 10

# Give more time in slow CI machines than for developer's machines.
waitTime = 60 if os.getenv("CI") == "true" else 10

class MaxReorgTest(BitcoinTestFramework):
    NUM_NODES = 4
    # There should only be one chaintip, which is expected_tip
    def only_valid_tip(self, expected_tip, other_tip_status=None):
        node = self.nodes[0]
        assert_equal(node.getbestblockhash(), expected_tip)
        for tip in node.getchaintips():
            if tip["hash"] == expected_tip:
                assert_equal(tip["status"], "active")
            else:
                assert_equal(tip["status"], other_tip_status)

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
