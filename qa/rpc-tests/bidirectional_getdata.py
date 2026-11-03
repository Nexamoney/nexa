#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Two honest nodes requesting from each other must both make progress.

If each node has many GETDATAs from the other still to answer and a full send buffer, it can only send more once the
other node reads its replies.  A node that stops reading a peer while those requests are pending therefore deadlocks
with a peer doing the same.

Two ways to get there are tested: a node with small send buffers keeps most requests deferred, and a node with
send buffers large enough to queue every reply has many responses queued.  Either must not stop it reading.

The nodes are connected through a relay that only reads from one side as fast as the other side accepts the bytes, so
TCP backpressure passes through it.  The relay injects block GETDATAs in both directions and renames the BLOCK replies
to an unknown command, so the receiving node reads and drops them like any other message.
"""
import test_framework.loginit

import logging
import select
import socket
import struct
import sys
import threading

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.mininode import NodeConn
from test_framework.nodemessages import *

MAGIC = NodeConn.MAGIC_BYTES["regtest"]
HDR_LEN = 4 + 12 + 4 + 4
# The node's own socket buffers can't be shrunk from here, so the replies have to outgrow them (up to 4 MB send and
# 32 MB receive on Linux) in each direction
REPLY_BYTES = 96 * 1024 * 1024
# Requests served one at a time are slow even without a deadlock, so ask for fewer.  On a node that stops reading,
# the link stalls well before this.
DEFERRED_REQUESTS = 4000
# Blocks with one large transaction each: replies of about 9 KB, so thousands of requests and far more than 256
# deferred requests or queued responses when the link stalls
OUTPUTS_PER_TX = 250
BLOCKS = 8
# Each reply nearly fills the send buffer, so requests are served one at a time
DEFERRED_SEND_BUFFER_KB = 10
# Holds every reply at once
RESPONSE_SEND_BUFFER_KB = 2 * REPLY_BYTES // 1000
# Stop reading a side once this much is waiting to be written to the other side
RELAY_BUFFER = 64 * 1024
# A link slower than the node produces replies, so they pile up in its send queue
SLOW_LINK_RATE = 4 * 1024 * 1024
TIMEOUT = 180
MAX_INV_SZ = 50000


def frame(command, data):
    return MAGIC + command + b"\x00" * (12 - len(command)) + struct.pack("<I", len(data)) + b"\x00" * 4 + data


def getdata(hashes):
    """GETDATA for blocks in the CInv2 format that nexad peers negotiate with each other"""
    return frame(b"getdata", ser_compact_size(len(hashes)) +
                 b"".join(struct.pack("<B", CInv.MSG_BLOCK) + ser_uint256(h) for h in hashes))


class Direction(object):
    """Bytes read from src, split into whole messages and queued for dst"""
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst
        self.buf = b""
        self.out = b""
        self.replies = 0
        self.sent = 0
        self.credit = 0
        self.last = time.time()

    def allowance(self, rate):
        """How many queued bytes may be sent now"""
        if rate is None:
            return len(self.out)
        now = time.time()
        self.credit = min(self.credit + (now - self.last) * rate, RELAY_BUFFER)
        self.last = now
        return int(self.credit)

    def feed(self, data, rename):
        self.buf += data
        while len(self.buf) >= HDR_LEN:
            assert self.buf[:4] == MAGIC, "garbage from node: %s" % repr(self.buf[:HDR_LEN])
            msglen = struct.unpack("<I", self.buf[16:20])[0]
            if len(self.buf) < HDR_LEN + msglen:
                return
            msg = self.buf[:HDR_LEN + msglen]
            self.buf = self.buf[HDR_LEN + msglen:]
            if rename and msg[4:16] == b"block" + b"\x00" * 7:
                msg = msg[:4] + b"testdata" + b"\x00" * 4 + msg[16:]
                self.replies += 1
            self.out += msg


class Relay(threading.Thread):
    def __init__(self, port, target, rate=None):
        threading.Thread.__init__(self, daemon=True)
        self.lock = threading.Lock()
        self.rename = False
        self.stopped = False
        self.closed = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Accepted sockets inherit these.  Small buffers keep the relay from hiding backpressure.
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        self.listener.bind(("127.0.0.1", port))
        self.listener.listen(1)
        self.target = target
        # Bytes per second forwarded in each direction, or None for as fast as the nodes accept them
        self.rate = rate

    def run(self):
        a, _ = self.listener.accept()
        self.listener.close()
        b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        b.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        b.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        b.connect(self.target)
        a.setblocking(False)
        b.setblocking(False)
        self.toTarget = Direction(a, b)
        self.fromTarget = Direction(b, a)
        dirs = [self.toTarget, self.fromTarget]
        while not self.stopped and self.closed is None:
            with self.lock:
                readers = [d.src for d in dirs if len(d.out) < RELAY_BUFFER]
                writers = [d.dst for d in dirs if d.out and d.allowance(self.rate) > 0]
            readable, writable, _ = select.select(readers, writers, [], 0.01)
            with self.lock:
                try:
                    for d in dirs:
                        if d.src in readable:
                            data = d.src.recv(65536)
                            if not data:
                                raise ConnectionResetError()
                            d.feed(data, self.rename)
                        if d.dst in writable and d.out:
                            try:
                                n = d.dst.send(d.out[:d.allowance(self.rate)])
                                d.out = d.out[n:]
                                d.sent += n
                                d.credit -= n
                            except BlockingIOError:
                                pass
                except ConnectionError:
                    self.closed = "a node closed the connection"
        a.close()
        b.close()

    def inject(self, toTarget, fromTarget):
        """Queue messages at a message boundary in each direction"""
        with self.lock:
            self.rename = True
            self.toTarget.out += toTarget
            self.fromTarget.out += fromTarget


class BidirectionalGetdataTest(BitcoinTestFramework):
    def setup_network(self, split=False):
        self.start(DEFERRED_SEND_BUFFER_KB)

    def start(self, sendBufferKb):
        args = ["-maxsendbuffer=%d" % sendBufferKb, "-net.msgHandlerThreads=2"]
        self.nodes = start_nodes(2, self.options.tmpdir, [args, args])
        self.is_network_split = False

    def connect(self, port, rate=None):
        relay = Relay(port, ("127.0.0.1", p2p_port(1)), rate)
        relay.start()
        self.nodes[0].addnode("127.0.0.1:%d" % port, "onetry")
        waitFor(TIMEOUT, lambda: all(len(n.getpeerinfo()) == 1 and n.getpeerinfo()[0]["version"] != 0
                                      for n in self.nodes))
        assert_equal(self.nodes[0].getpeerinfo()[0]["addr"], "127.0.0.1:%d" % port)
        return relay

    def mine(self, node):
        """Blocks with a large transaction each, and their average reply size"""
        hashes = []
        for i in range(BLOCKS):
            node.sendmany("", {node.getnewaddress(): 1000 for j in range(OUTPUTS_PER_TX)})
            hashes += node.generate(1)
        sync_blocks(self.nodes)
        return hashes, sum(node.getblock(h)["size"] for h in hashes) // len(hashes) + HDR_LEN

    def exchange(self, relay, hashes, count):
        """Ask each node for count blocks as if by the other node; return why not every reply arrived, if not"""
        logging.info("Requesting %d blocks in each direction" % count)
        requested = [int(hashes[i % len(hashes)], 16) for i in range(count)]
        msgs = b"".join(getdata(requested[i:i + MAX_INV_SZ]) for i in range(0, count, MAX_INV_SZ))
        relay.inject(msgs, msgs)
        deadline = time.time() + TIMEOUT
        last = None
        error = None
        while error is None:
            with relay.lock:
                progress = (relay.toTarget.replies, relay.fromTarget.replies)
                forwarding = relay.toTarget.out or relay.fromTarget.out
                # Bytes the relay has written to node0 and node1
                sent = (relay.fromTarget.sent, relay.toTarget.sent)
            if relay.closed is not None:
                error = "%s, replies %s of %d" % (relay.closed, progress, count)
            elif progress == (count, count) and not forwarding and \
                    all(n.getpeerinfo()[0]["bytesrecv"] >= sent[i] for i, n in enumerate(self.nodes)):
                break
            elif time.time() > deadline:
                error = "replies %s of %d" % (progress, count)
            elif progress != last:
                logging.info("Replies relayed (node0, node1): %s" % (progress,))
                last = progress
            time.sleep(1)
        if error is None and any(len(n.getpeerinfo()) != 1 for n in self.nodes):
            error = "a node dropped the connection"
        relay.stopped = True
        relay.join()
        return error

    def run_test(self):
        errors = []

        # Small send buffers: most requests wait in the deferred GETDATA queue
        relay = self.connect(p2p_port(2))
        hashes, size = self.mine(self.nodes[0])
        error = self.exchange(relay, hashes, DEFERRED_REQUESTS)
        if error:
            errors.append("deferred requests: " + error)

        # Send buffers that take every reply and a slow link: nothing is deferred, but responses pile up
        stop_nodes(self.nodes)
        wait_bitcoinds()
        self.start(RESPONSE_SEND_BUFFER_KB)
        relay = self.connect(p2p_port(3), SLOW_LINK_RATE)
        error = self.exchange(relay, hashes, REPLY_BYTES // size + 1)
        if error:
            errors.append("queued responses: " + error)

        assert not errors, "; ".join(errors)


if __name__ == '__main__':
    sys.exit(BidirectionalGetdataTest().main())

def Test():
    flags = standardFlags()
    # install ctrl-c handler
    import signal, pdb
    signal.signal(signal.SIGINT, lambda sig, stk: pdb.Pdb().set_trace(stk))

    t = BidirectionalGetdataTest()
    t.drop_to_pdb = True
    t.main(flags)
