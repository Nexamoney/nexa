#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test the limits on the bytes an input hashes and copies, and on the numbers it converts to a BigNum.

Before upgrade2 they are policy: the mempool refuses such a spend, without penalizing the peer and without
running the script any further, and a block that contains it is still valid. After upgrade2 they are consensus:
a block that contains such a spend is refused.
"""
import copy
import logging
import time

from test_framework.blocktools import create_block, create_coinbase, create_tx_with_script, getAncHash, \
    make_conform_to_ctor
from test_framework.nodemessages import CBlock, CTransaction, FromHex, ToHex, anySpender
from test_framework.mininode import P2PDataStore, NodeConn, NetworkThread
from test_framework.script import CScript, OP_BIN2BIGNUM, OP_CAT, OP_DROP, OP_DUP, OP_SHA256, spendAnyoneCanSpend
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import JSONRPCException, assert_equal, assert_raises_rpc_error, p2p_port, waitFor

HASHED_BYTES_REASON = 'non-mandatory-script-verify-flag (Validation resources exceeded (hashed bytes))'
COPIED_BYTES_REASON = 'non-mandatory-script-verify-flag (Validation resources exceeded (copied bytes))'
BIGNUM_REASON = 'non-mandatory-script-verify-flag (Number too wide to convert to a BigNum)'


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

    def activate_upgrade2(self, node):
        mocktime = node.getblockheader(node.getbestblockhash())['time']
        for _ in range(10):
            mocktime += 120
            node.setmocktime(mocktime)
            node.generate(1)
        node.set("consensus.fork2Time=" + str(node.getblockheader(node.getbestblockhash())['time'] + 240))
        for _ in range(20):
            if node.getblockchaininfo()['upgradeenforcednextblock']:
                break
            mocktime += 120
            node.setmocktime(mocktime)
            node.generate(1)
        else:
            raise AssertionError("upgrade2 did not become pending")
        node.generate(4)
        assert node.getblockchaininfo()['upgradeactive']
        assert_equal(node.gettailstorminfo()['bestdag'], 0)

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
        for _ in range(13):
            tip = self.build_block(tip)
            self.p2p.send_blocks_and_test([tip], node)
            coinbases.append(tip.vtx[0])
        node.generate(100)
        tip = self.get_best_block(node)

        # An input may hash 8192 bytes plus the length of its scriptSig, here about 560 bytes, and of the script
        # of the output it spends
        within = hash_item(17)
        over = hash_item(18)
        # the same 9000 bytes are allowed once the scriptSig is 300 bytes longer
        over_padded = hash_item(18, drop_first=True)
        # An input may copy 2 MiB plus 16 times the length of its scriptSig. Building the 512000 byte item copies
        # 1535000 bytes
        big_item = [b'\xa5' * 500] + [OP_DUP, OP_CAT] * 10
        copy_within = CScript(big_item + [OP_DUP, OP_DROP, OP_DROP])
        copy_over = CScript(big_item + [OP_DUP, OP_DROP] * 2 + [OP_DROP])
        # a 8200 bit number, more than the 8192 bits that convert to a BigNum
        too_wide = CScript([b'\xff' * 1025 + b'\x00', OP_BIN2BIGNUM, OP_DROP])
        # a 512000 byte item hashed 16000 times, about 8 GB
        slow = CScript(big_item + [OP_DUP, OP_SHA256, OP_DROP] * 16000 + [OP_DROP])

        templates = [within, over, over_padded, copy_within, copy_over, too_wide, slow]
        templates += [within, over, copy_over, too_wide, within]  # spent after upgrade2
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
        spend_over_padded = self.spend(funds[2], over_padded, [b'\x00' * 300])
        spend_copy_within = self.spend(funds[3], copy_within)
        spend_copy_over = self.spend(funds[4], copy_over)
        spend_too_wide = self.spend(funds[5], too_wide)
        spend_slow = self.spend(funds[6], slow)

        logging.info("The mempool accepts spends within the limits")
        accepted = [spend_within, spend_over_padded, spend_copy_within]
        self.p2p.send_txs_and_test(accepted, node)
        waitFor(10, lambda: set(node.getrawtxpool()) == {tx.GetRpcHexIdem() for tx in accepted})

        logging.info("The mempool refuses spends over the limits, without banning the peer")
        self.refused(spend_over, HASHED_BYTES_REASON)
        self.refused(spend_copy_over, COPIED_BYTES_REASON)
        self.refused(spend_too_wide, BIGNUM_REASON)
        refused = [spend_over, spend_copy_over, spend_too_wide]
        self.p2p.send_txs_and_test(refused, node, success=False)

        logging.info("The script is not run again without the limits")
        start = time.time()
        self.refused(spend_slow, HASHED_BYTES_REASON)
        elapsed = time.time() - start
        assert elapsed < 5, "refusing the 8 GB spend took %.1f s" % elapsed

        logging.info("Before upgrade2 a block may contain spends over the limits")
        tip = self.build_block(tip, accepted + refused)
        self.p2p.send_blocks_and_test([tip], node)

        logging.info("After upgrade2 a block may not")
        self.activate_upgrade2(node)
        # a mined empty subblock gives the header fields
        template = FromHex(CBlock(), node.getsubblock(node.generate(1)[0], 0))
        in_dag = 1
        refused = []
        valid_spends = [True, False, False, False, True]
        for nonce, (fund, script, valid) in enumerate(zip(funds[7:], templates[7:], valid_spends), 1):
            block = copy.deepcopy(template)
            block.vtx = [block.vtx[0], self.spend(fund, script)]
            block.nonce = bytearray([nonce, 0, 0])
            block.update_fields()
            block.solve(prevhash=block.hashPrevBlock)
            block.rehash()
            node.submitblock(ToHex(block))
            if valid:
                in_dag += 1
                waitFor(10, lambda: node.gettailstorminfo()['bestdag'] == in_dag)
                assert_equal(node.getsubblock(block.hash, 0), ToHex(block))
            else:
                refused.append(block)
        for block in refused:
            assert_raises_rpc_error(None, "Subblock not found in dag", node.getsubblock, block.hash, 0)
        assert_equal(node.gettailstorminfo()['bestdag'], in_dag)


if __name__ == '__main__':
    ScriptByteLimitsTest().main()
