#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# A fresh node must recover previous-epoch subblocks through P2P sync and
# use the same eligible uncle as peers that witnessed the epoch being mined.

import logging
import time
from io import BytesIO

import test_framework.loginit
from test_framework import cashaddr
from test_framework.nodemessages import CBlock, FromHex, deser_compact_size, deser_string
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (NoConfigValue, assert_equal, assert_raises_rpc_error,
                                 connect_nodes_bi, disconnect_all, initialize_chain_clean,
                                 start_node, sync_blocks, waitFor)


def summary_proofs(node, blockhash):
    data = BytesIO(bytes.fromhex(node.getblockheader(blockhash)['minerData']))
    assert_equal(data.read(1), b'\x02')
    data.read(32)  # Previous epoch's summary hash.
    uncles = data.read(1)[0]
    data.read(4)  # Uncle difficulty.
    subblocks = data.read(1)[0]
    data.read(4)  # Current epoch's difficulty.
    count = deser_compact_size(data)
    assert_equal(count, uncles + subblocks)
    proofs = [(data.read(32), deser_string(data)) for _ in range(count)]
    assert_equal(data.read(), b'')
    return proofs[:uncles], proofs[uncles:]


class UncleSyncTest(BitcoinTestFramework):
    def setup_chain(self):
        config = dict(self.confDict or {})
        config['consensus.fork2Time'] = int(time.time()) + 86400
        for option in ('usecashaddr', 'wallet.payTxFee', 'wallet.instant'):
            config[option] = NoConfigValue()
        initialize_chain_clean(self.options.tmpdir, 3, config)

    def setup_network(self):
        self.nodes = [self.start_node(i) for i in range(2)]
        connect_nodes_bi(self.nodes, 0, 1)

    def start_node(self, index):
        return start_node(index, self.options.tmpdir, ['-debug=dag', '-debug=net'])

    def mine(self, node, count):
        address = self.mining_addresses[self.nodes.index(node)]
        hashes = node.generatetoaddress(count, address, 100000000)
        assert_equal(len(hashes), count)
        return hashes

    def set_time(self, timestamp):
        for node in self.nodes:
            node.setmocktime(timestamp)

    def run_test(self):
        # Subblock ancestry: R --> A1 --> A2
        #                    +---> B1 --> B2
        # Summary S commits three of these; the fourth becomes uncle U.
        # R --> S --> F, with U available for the epoch rooted at S.
        source, other = self.nodes
        # Distinct coinbase recipients keep the isolated miners from
        # producing identical empty subblocks. No wallet funds are needed.
        self.mining_addresses = [cashaddr.encode_full('nexareg', cashaddr.PUBKEY_TYPE, bytes([i]) * 20)
                                 for i in range(3)]
        now = int(time.time())
        for _ in range(10):
            now += 120
            self.set_time(now)
            self.mine(source, 1)
        sync_blocks(self.nodes)
        activation = now + 240
        for node in self.nodes:
            node.set('consensus.fork2Time=' + str(activation))
        for _ in range(20):
            if source.getblockchaininfo()['upgradeenforcednextblock']:
                break
            now += 120
            self.set_time(now)
            self.mine(source, 1)
            sync_blocks(self.nodes)
        else:
            raise AssertionError('Tailstorm did not become pending')
        self.mine(source, 4)
        sync_blocks(self.nodes)
        root = source.getbestblockhash()
        for node in self.nodes:
            assert_equal(node.getblockchaininfo()['upgradeactive'], True)
            assert_equal(node.gettailstorminfo()['bestdag'], 0)
            disconnect_all(node)
        for node in self.nodes:
            waitFor(60, lambda: not node.getpeerinfo())

        branches = self.mine(source, 2) + self.mine(other, 2)
        assert_equal(len(set(branches)), 4)
        bodies = {h: node.getsubblock(h, 0)
                  for node, hashes in ((source, branches[:2]), (other, branches[2:]))
                  for h in hashes}
        proofs = {}
        for h, body in bodies.items():
            block = FromHex(CBlock(), body)
            proofs[h] = (block.calc_mining_commitment(), bytes(block.nonce))
        connect_nodes_bi(self.nodes, 0, 1)
        for node in self.nodes:
            waitFor(60, lambda: all(h in node.gettailstorminfo(True)['subblock_to_grove_summaryblock']
                                   for h in branches))
            assert_equal(node.gettailstorminfo()['bestdag'], 3)

        summary = self.mine(source, 1)[0]
        sync_blocks(self.nodes)
        previous_uncles, committed = summary_proofs(source, summary)
        assert_equal(previous_uncles, [])
        omitted = [h for h in branches if proofs[h] not in committed]
        assert_equal(len(omitted), 1)
        uncle = omitted[0]
        self.mine(source, 1)
        grove = str(source.getblockcount()) + ':' + summary
        waitFor(60, lambda: source.gettailstorminfo(True)['uncles_to_grove_summaryblock'].get(uncle) == grove)
        logging.info('Eligible uncle %s from root %s belongs to grove %s', uncle, root, grove)

        # Node 2 has never seen the chain or the uncle. Do not submit any
        # block to it through RPC: downloads must come from the syncing peers.
        fresh = self.start_node(2)
        self.nodes.append(fresh)
        fresh.setmocktime(now)
        fresh.set('consensus.fork2Time=' + str(activation))
        assert_equal(fresh.getblockcount(), 0)
        assert_raises_rpc_error(-5, 'Subblock not found', fresh.getsubblock, uncle, 0)
        connect_nodes_bi(self.nodes, 0, 2)
        connect_nodes_bi(self.nodes, 1, 2)
        sync_blocks(self.nodes)
        waitFor(60, lambda: not fresh.getblockchaininfo()['initialblockdownload'])
        waitFor(60, lambda: fresh.getsubblock(uncle, 0) == bodies[uncle],
                'Fresh node did not download uncle ' + uncle)
        logging.info('Fresh node downloaded the exact body of uncle %s', uncle)
        previous_grove = str(source.getblockcount() - 1) + ':' + root
        waitFor(60, lambda: fresh.gettailstorminfo(True)['subblock_to_grove_summaryblock'].get(uncle) == previous_grove,
                lambda: 'Downloaded uncle was not inserted into its previous-epoch grove: ' +
                str(fresh.gettailstorminfo(True)))
        waitFor(60, lambda: fresh.gettailstorminfo(True)['uncles_to_grove_summaryblock'].get(uncle) == grove,
                'Downloaded uncle was not made available in the current grove')
        waitFor(60, lambda: fresh.gettailstorminfo()['bestdag'] == 2)

        # Stop peer traffic before mining, so a late announcement cannot
        # supply the uncle that the completed sync should already have found.
        disconnect_all(fresh)
        waitFor(60, lambda: not fresh.getpeerinfo())
        # U and F supply two of the three subblocks required by regtest K=4.
        next_summary = self.mine(fresh, 2)[-1]
        assert_equal(fresh.getblockcount(), source.getblockcount() + 1)
        included_uncles, _ = summary_proofs(fresh, next_summary)
        assert_equal(included_uncles, [proofs[uncle]])
        connect_nodes_bi(self.nodes, 0, 2)
        sync_blocks(self.nodes)
        assert_equal(source.getbestblockhash(), next_summary)
        logging.info('Fresh node mined uncle %s and peers accepted its summary', uncle)


if __name__ == '__main__':
    UncleSyncTest().main()
