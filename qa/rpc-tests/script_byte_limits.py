#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test the limits on the bytes an input hashes and on the size of a stack item.

Before upgrade2 they are policy: the mempool refuses such a spend, without penalizing the peer and without
running the script any further, and a block that contains it is still valid.
"""
import logging
import time

from test_framework.blocktools import create_block, create_coinbase, create_tx_with_script, getAncHash, \
    make_conform_to_ctor
from test_framework.nodemessages import CBlock, CTransaction, FromHex, ToHex, anySpender
from test_framework.mininode import P2PDataStore, NodeConn, NetworkThread
from test_framework.script import CScript, OP_CAT, OP_DROP, OP_DUP, OP_SHA256, spendAnyoneCanSpend
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import JSONRPCException, p2p_port, waitFor

HASHED_BYTES_REASON = 'non-mandatory-script-verify-flag (Validation resources exceeded (hashed bytes))'
ITEM_SIZE_REASON = 'non-mandatory-script-verify-flag (Push value size limit exceeded)'


def hash_item(count, drop_first=False):
    """Template that hashes a 500 byte item count times"""
    ops = [OP_DROP] if drop_first else []
    ops.append(b'\xa5' * 500)
    for _ in range(count):
        ops += [OP_DUP, OP_SHA256, OP_DROP]
    return CScript(ops + [OP_DROP])


class ScriptByteLimitsTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.block_heights = {}
        self.extra_args = [["-debug=mempoolrej"]]

    def get_best_block(self, node):
        block = FromHex(CBlock(), node.getblock(node.getbestblockhash(), 0))
        block.rehash()
        self.block_heights[block.hashNum] = node.getblockcount()
        return block

    def build_block(self, parent, transactions=()):
        parent.rehash()
        height = self.block_heights[parent.hashNum] + 1
        block = create_block(parent.hashNum, height, parent.chainWork + 2, create_coinbase(height),
            getAncHash(height, self.nodes[0]), parent.nTime + 1)
        block.vtx.extend(transactions)
        block.txCount = len(block.vtx)
        block.nonce = bytearray(12)
        block.size = len(block.serialize()) - (len(block.nonce) + 1)
        make_conform_to_ctor(block)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        block.rehash()
        self.block_heights[block.hashNum] = height
        return block

    def spend(self, fund, template, satisfier=None):
        tx = CTransaction()
        tx.vin.append(fund.SpendTemplate(0, template, None, satisfier))
        tx.vout.append(anySpender(fund.vout[0].nValue - 2 * len(tx.vin[0].scriptSig) - 2000, 100))
        tx.rehash()
        return tx

    def refused(self, tx, reason):
        try:
            self.nodes[0].sendrawtransaction(ToHex(tx))
        except JSONRPCException as e:
            assert reason in e.error['message'], e.error['message']
        else:
            raise AssertionError("accepted a spend that should fail with " + reason)

    def run_test(self):
        node = self.nodes[0]
        self.p2p = P2PDataStore()
        self.p2p.add_connection(NodeConn('127.0.0.1', p2p_port(0), node, self.p2p))
        NetworkThread().start()
        self.p2p.wait_for_verack()

        tip = self.get_best_block(node)
        coinbases = []
        for _ in range(6):
            tip = self.build_block(tip)
            self.p2p.send_blocks_and_test([tip], node)
            coinbases.append(tip.vtx[0])
        node.generate(100)
        tip = self.get_best_block(node)

        # An input may hash 4096 bytes plus twice the length of its scriptSig, here about 540 bytes
        within = hash_item(10)
        over = hash_item(11)
        # the same 5500 bytes are allowed once the scriptSig is 200 bytes longer
        over_padded = hash_item(11, drop_first=True)
        # a 4200 byte item
        long_item = CScript([b'\xa5' * 2100, OP_DUP, OP_CAT, OP_DROP])
        # a 512000 byte item hashed 16000 times, about 8 GB
        slow = CScript([b'\xa5' * 500] + [OP_DUP, OP_CAT] * 10 + [OP_DUP, OP_SHA256, OP_DROP] * 16000 + [OP_DROP])

        templates = [within, over, over_padded, long_item, slow]
        funds = []
        for template in templates:
            coinbase = coinbases.pop()
            fund = create_tx_with_script(coinbase, 0, spendAnyoneCanSpend(), coinbase.vout[0].nValue, template)
            fund.rehash()
            funds.append(fund)
        tip = self.build_block(tip, funds)
        self.p2p.send_blocks_and_test([tip], node)

        spend_within = self.spend(funds[0], within)
        spend_over = self.spend(funds[1], over)
        spend_over_padded = self.spend(funds[2], over_padded, [b'\x00' * 200])
        spend_long_item = self.spend(funds[3], long_item)
        spend_slow = self.spend(funds[4], slow)

        logging.info("The mempool accepts spends within the limits")
        self.p2p.send_txs_and_test([spend_within, spend_over_padded], node)
        waitFor(10, lambda: set(node.getrawtxpool()) ==
            {spend_within.GetRpcHexIdem(), spend_over_padded.GetRpcHexIdem()})

        logging.info("The mempool refuses spends over the limits, without banning the peer")
        self.refused(spend_over, HASHED_BYTES_REASON)
        self.refused(spend_long_item, ITEM_SIZE_REASON)
        self.p2p.send_txs_and_test([spend_over, spend_long_item], node, success=False)

        logging.info("The script is not run again without the limits")
        start = time.time()
        self.refused(spend_slow, ITEM_SIZE_REASON)
        elapsed = time.time() - start
        assert elapsed < 5, "refusing the 8 GB spend took %.1f s" % elapsed

        logging.info("Before upgrade2 a block may contain spends over the limits")
        tip = self.build_block(tip, [spend_within, spend_over_padded, spend_over, spend_long_item])
        self.p2p.send_blocks_and_test([tip], node)


if __name__ == '__main__':
    ScriptByteLimitsTest().main()
