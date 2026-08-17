#!/usr/bin/env python3
# Copyright (c) 2017-2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test getblockstats rpc call
#
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    standardFlags
)
import json
import os
import logging
import decimal

from test_framework.util import *
TESTSDIR = os.path.dirname(os.path.realpath(__file__))

# Give more time in slow CI machines than for developer's machines.
waitTime = 60 if os.getenv("CI") == "true" else 10

def EncodeDecimal(o):
    if isinstance(o, decimal.Decimal):
        # json.load will read a quoted float as a string and not convert it back
        # to decimal, so store the value as unquoted float instead.
        return float(o)
    raise TypeError(repr(o) + " is not JSON serializable")

class GetblockstatsTest(BitcoinTestFramework):

    start_height = 101
    max_stat_pos = 2


    def __init__(self):
        super().__init__()
        self.set_test_params()

    def add_options(self, parser):
        parser.add_option('--gen-test-data', dest='gen_test_data',
                          default=False, action='store_true',
                          help='Generate test data')
        parser.add_option('--test-data', dest='test_data',
                          default='data/rpc_getblockstats.json',
                          action='store', metavar='FILE',
                          help='Test data file')

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-debug=rpc']]

    def get_stats(self):
        stats = [ ]
        for i in range(self.max_stat_pos + 1):
            stats.append(self.nodes[0].getblockstats(self.start_height + i))
        return stats

    def generate_test_data(self, filename):
        mocktime = 1776765080
        self.nodes[0].setmocktime(mocktime)
        self.nodes[0].generate(101)

        subtractfeefromamount = True
        self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 100000, "", "", subtractfeefromamount)
        waitFor(waitTime, lambda: self.nodes[0].gettxpoolinfo()['size'] == 1)
        self.nodes[0].generate(1)

        self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 100000, "", "", subtractfeefromamount)
        subtractfeefromamount = False
        self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 100000, "", "", subtractfeefromamount)
        self.nodes[0].set("wallet.payTxFee=3000")
        subtractfeefromamount = True
        self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 100000.1, "", "", subtractfeefromamount)
        waitFor(waitTime, lambda: self.nodes[0].gettxpoolinfo()['size'] == 3)
        self.nodes[0].generate(1)

        self.expected_stats = self.get_stats()

        blocks = []
        tip = self.nodes[0].getbestblockhash()
        blockhash = None
        height = 0
        while tip != blockhash:
            blockhash = self.nodes[0].getblockhash(height)
            blocks.append(self.nodes[0].getblock(blockhash, 0))
            height += 1

        to_dump = {
            'blocks': blocks,
            'mocktime': int(mocktime),
            'stats': self.expected_stats,
        }
        with open(filename, 'w') as f:
            json.dump(to_dump, f, sort_keys=True, indent=2, default=EncodeDecimal)

    def load_test_data(self, filename):
        logging.info("Loading test data from: %s" % filename)
        with open(filename, 'r') as f:
            d = json.load(f, parse_float=decimal.Decimal)
            blocks = d['blocks']
            mocktime = d['mocktime']
            self.expected_stats = d['stats']

        # Set the timestamps from the file so that the nodes can get out of Initial Block Download
        self.nodes[0].setmocktime(mocktime)
        self.sync_all()

        it = 0
        for b in blocks:
            ret = self.nodes[0].submitblock(b)
            if it == 0: # trying to submit the genesis block
                assert(ret == "duplicate")
            else:
                assert(ret["result"] == None)
            it = it + 1

    def run_test(self):
        test_data = os.path.join(TESTSDIR, self.options.test_data)
        if self.options.gen_test_data:
            self.generate_test_data(test_data)
        else:
            self.load_test_data(test_data)

        self.sync_blocks()
        stats = self.get_stats()

        # Make sure all valid statistics are included but nothing else is
        expected_keys = self.expected_stats[0].keys()
        assert_equal(set(stats[0].keys()), set(expected_keys))

        assert_equal(stats[0]['height'], self.start_height)
        assert_equal(stats[self.max_stat_pos]['height'], self.start_height + self.max_stat_pos)

        for i in range(self.max_stat_pos+1):
            logging.info('Checking block %d\n' % (i))
            assert_equal(stats[i], self.expected_stats[i])

            # Check selecting block by hash too
            blockhash = self.expected_stats[i]['blockhash']
            stats_by_hash = self.nodes[0].getblockstats(blockhash)
            assert_equal(stats_by_hash, self.expected_stats[i])

        # Make sure each stat can be queried on its own
        for stat in expected_keys:
            for i in range(self.max_stat_pos+1):
                result = self.nodes[0].getblockstats(self.start_height + i, [stat])
                assert_equal(list(result.keys()), [stat])
                if result[stat] != self.expected_stats[i][stat]:
                    logging.info('result[%s] (%d) failed, %r != %r' % (
                        stat, i, result[stat], self.expected_stats[i][stat]))
                assert_equal(result[stat], self.expected_stats[i][stat])

        # Make sure only the selected statistics are included (more than one)
        some_stats = {'minfee', 'maxfee'}
        stats = self.nodes[0].getblockstats(1, list(some_stats))
        assert_equal(set(stats.keys()), some_stats)

        # Test invalid parameters raise the proper json exceptions
        tip = self.start_height + self.max_stat_pos
        assert_raises_rpc_error(-8, 'Target block height %d after current tip %d' % (tip+1, tip),
                                self.nodes[0].getblockstats, tip+1)
        assert_raises_rpc_error(-8, 'Target block height %d is negative' % (-1),
                                self.nodes[0].getblockstats, -1)

        # Make sure not valid stats aren't allowed
        inv_sel_stat = 'asdfghjkl'
        inv_stats = [
            [inv_sel_stat],
            ['minfee' , inv_sel_stat],
            [inv_sel_stat, 'minfee'],
            ['minfee', inv_sel_stat, 'maxfee'],
        ]
        for inv_stat in inv_stats:
            assert_raises_rpc_error(-8, 'Invalid selected statistic %s' % inv_sel_stat,
                                    self.nodes[0].getblockstats, 1, inv_stat)

        # Make sure we aren't always returning inv_sel_stat as the culprit stat
        assert_raises_rpc_error(-8, 'Invalid selected statistic aaa%s' % inv_sel_stat,
                self.nodes[0].getblockstats, 1, ['minfee' , 'aaa%s' % inv_sel_stat])

        # Mainchain's genesis block shouldn't be found on regtest
        assert_raises_rpc_error(-5, 'Block not found', self.nodes[0].getblockstats,
                                'edc7144fe1ba4edd0edf35d7eea90f6cb1dba42314aa85da8207e97c5339c801')

        # check genesis block stats
        gb = self.nodes[0].getblock("0")
        gbstats = self.nodes[0].getblockstats(gb["hash"])
        assert_equal(gbstats['blockhash'], 'd71ee431e307d12dfef31a6b21e071f1d5652c0eb6155c04e3222612c9d0b371')
        assert_equal(gbstats['txs'], 1)
        assert_equal(gbstats['utxo_increase'], 1)
        assert_equal(gbstats['utxo_size_inc'], 48)


if __name__ == '__main__':
    GetblockstatsTest().main()

def Test():
    t = GetblockstatsTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["rpc","net", "blk", "thin", "mempool", "req", "bench", "evict"]
    }
    flags = standardFlags()
    # To regenerate the files:
    # flags.append('--gen-test-data')
    t.main(flags, bitcoinConf, None)
