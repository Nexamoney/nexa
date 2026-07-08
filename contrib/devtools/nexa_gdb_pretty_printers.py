"""
GDB 15 pretty printers for the Nexa blockchain node.

Load in GDB:
    source /path/to/nexa/contrib/devtools/nexa_pretty_printers.py

Or add to ~/.gdbinit:
    source /path/to/nexa/contrib/devtools/nexa_pretty_printers.py

Covered types:
    uint256, uint160, base_blob<N>   - hash types (shown as big-endian hex)
    arith_uint256, base_uint<N>      - arithmetic hash types
    CInv, CInv2                      - inventory messages
    COutPoint                        - transaction output reference
    CTxIn, CTxOut                    - transaction inputs/outputs
    CTransaction, CMutableTransaction
    CScript / prevector<N, T>        - scripts and compact vectors
    CBlockHeader                     - block header fields
    CBlock                           - full block (header + transactions)
    CBlockIndex                      - chain index entry
    CNetAddr, CService, CAddress     - network address types
    CUnknownObj                      - request manager tracking entry
    CRequestManager                  - block/txn download queue summary
    CTxMemPoolEntry                  - mempool entry
    Coin                             - UTXO set entry
"""

import gdb
import gdb.printing

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Block status decoder (mirrors chain.h BlockStatus enum)
# ---------------------------------------------------------------------------

_BLOCK_VALID_NAMES = {
    0: 'UNKNOWN',
    1: 'HEADER',
    2: 'TREE',
    3: 'TRANSACTIONS',
    4: 'CHAIN',
    5: 'SCRIPTS',
}

_BLOCK_FLAG_BITS = [
    (8,   'HAVE_DATA'),
    (16,  'HAVE_UNDO'),
    (64,  'FAILED_VALID'),
    (128, 'FAILED_CHILD'),
    (256, 'PROCESSED'),
    (512, 'LINKED'),
]


def _decode_block_status(status):
    status = int(status)
    valid_level = status & 0x7
    parts = ['VALID_' + _BLOCK_VALID_NAMES.get(valid_level, str(valid_level))]
    for bit, name in _BLOCK_FLAG_BITS:
        if status & bit:
            parts.append(name)
    return ' | '.join(parts)


# ---------------------------------------------------------------------------
# Inventory type names (mirrors protocol.h GetDataMsg enum)
# ---------------------------------------------------------------------------

_INV_TYPE_NAMES = {
    0:   'ERROR',
    1:   'TX',
    2:   'BLOCK',
    3:   'FILTERED_BLOCK',
    4:   'CMPCT_BLOCK',
    5:   'XTHINBLOCK',
    6:   'GRAPHENEBLOCK',
    7:   'DOUBLESPENDPROOF',
    100: 'TOKENINFO',
    101: 'EXT_TX',
}

# ---------------------------------------------------------------------------
# Network type names (mirrors netaddress.h Network enum)
# ---------------------------------------------------------------------------

_NET_NAMES = {
    0: 'UNROUTABLE',
    1: 'IPv4',
    2: 'IPv6',
    3: 'TOR3',
    4: 'I2P',
    5: 'CJDNS',
    6: 'INTERNAL',
}

# ---------------------------------------------------------------------------
# Helper: read base_blob<BITS> as a Bitcoin-convention hex string.
# Bitcoin displays hashes MSB-first, but stores them LSB-first in memory.
# ---------------------------------------------------------------------------

def _blob_to_hex(val, width):
    """Return the big-endian hex string for a base_blob data[] field."""
    try:
        data = val['data']
        return ''.join('%02x' % (int(data[i]) & 0xff)
                       for i in range(width - 1, -1, -1))
    except Exception as exc:
        return '<blob error: {}>'.format(exc)


def _blob_short(val, width):
    """First 8 hex chars + '...' for compact display."""
    h = _blob_to_hex(val, width)
    return h[:16] + '...' if len(h) > 16 else h


# ---------------------------------------------------------------------------
# Helper: read base_uint<BITS> (ArithUint256 style, pn[] is LE word order).
# ---------------------------------------------------------------------------

def _arith_to_hex(val, nwords):
    """Return big-endian hex for base_uint pn[] array (pn[0] = LSW)."""
    try:
        pn = val['pn']
        return ''.join('%08x' % (int(pn[i]) & 0xffffffff)
                       for i in range(nwords - 1, -1, -1))
    except Exception as exc:
        return '<arith error: {}>'.format(exc)


# ---------------------------------------------------------------------------
# Helper: access prevector<N,T> elements.
# Layout (from prevector.h):
#   alignas(char*) direct_or_indirect _union;   // union{char direct[N]; {char* indirect; size_type capacity;}}
#   size_type _size;                             // if <=N: count; else count+N+1
# ---------------------------------------------------------------------------

def _prevector_elems(val):
    """Return (count, element_accessor) for any prevector value.

    element_accessor(i) returns the GDB value of the i-th element.
    Raises on error.
    """
    try:
        N = int(val.type.template_argument(0))
        T = val.type.template_argument(1)
    except Exception:
        # Fallback for CScript (prevector<28, uint8_t>)
        N = 28
        T = gdb.lookup_type('unsigned char')

    size = int(val['_size'])

    if size <= N:
        count = size
        # Direct storage: _union.direct is char[sizeof(T)*N]
        # Cast its address to T* for indexed access
        T_ptr_type = T.pointer()
        elem_ptr = val['_union']['direct'].address.cast(T_ptr_type)
    else:
        # Indirect storage: _union.indirect is char*, actual count = _size - N - 1
        count = size - N - 1
        T_ptr_type = T.pointer()
        elem_ptr = val['_union']['indirect'].cast(T_ptr_type)

    def get_elem(i):
        return elem_ptr[i]

    return count, get_elem


def _script_to_hex(val):
    """Return hex string for a CScript / prevector<28, uint8_t> value."""
    try:
        count, get = _prevector_elems(val)
        return ''.join('%02x' % (int(get(i)) & 0xff) for i in range(count))
    except Exception as exc:
        return '<script error: {}>'.format(exc)


def _vec_size(vec):
    """Return element count of a libstdc++ std::vector."""
    try:
        start = vec['_M_impl']['_M_start']
        finish = vec['_M_impl']['_M_finish']
        return int(finish - start)
    except Exception:
        return -1


# ===========================================================================
# Pretty-printer classes
# ===========================================================================

class _BaseBlobPrinter:
    """base_blob<BITS>, uint256, uint160."""

    def __init__(self, val):
        self.val = val
        try:
            bits = int(val.type.template_argument(0))
            self.width = bits // 8
        except Exception:
            # uint256/uint160 are direct subclasses; derive width from data[]
            try:
                self.width = int(val['data'].type.sizeof)
            except Exception:
                self.width = 32

    def to_string(self):
        return _blob_to_hex(self.val, self.width)

    def display_hint(self):
        return 'string'


class Uint256Printer(_BaseBlobPrinter):
    def __init__(self, val):
        super().__init__(val)
        self.width = 32


class Uint160Printer(_BaseBlobPrinter):
    def __init__(self, val):
        super().__init__(val)
        self.width = 20


class ArithUint256Printer:
    """arith_uint256 / base_uint<BITS>."""

    def __init__(self, val):
        self.val = val
        try:
            bits = int(val.type.template_argument(0))
            self.nwords = bits // 32
        except Exception:
            self.nwords = 8  # 256-bit default

    def to_string(self):
        return _arith_to_hex(self.val, self.nwords)

    def display_hint(self):
        return 'string'


class CInvPrinter:
    """CInv – type + 256-bit hash."""

    def __init__(self, val):
        self.val = val

    def to_string(self):
        try:
            t = int(self.val['type'])
            h = _blob_to_hex(self.val['hash'], 32)
            tname = _INV_TYPE_NAMES.get(t, 'type={}'.format(t))
            return 'CInv({}, {})'.format(tname, h)
        except Exception as exc:
            return '<CInv error: {}>'.format(exc)

    def display_hint(self):
        return 'string'


class CInv2Printer:
    """CInv2 – compact 1-byte type + 256-bit hash."""

    def __init__(self, val):
        self.val = val

    def to_string(self):
        try:
            t = int(self.val['type'])
            h = _blob_to_hex(self.val['hash'], 32)
            tname = _INV_TYPE_NAMES.get(t, 'type={}'.format(t))
            return 'CInv2({}, {})'.format(tname, h)
        except Exception as exc:
            return '<CInv2 error: {}>'.format(exc)

    def display_hint(self):
        return 'string'


class COutPointPrinter:
    """COutPoint – computed hash of (txIdem, outIdx)."""

    def __init__(self, val):
        self.val = val

    def to_string(self):
        try:
            return 'COutPoint({})'.format(_blob_to_hex(self.val['hash'], 32))
        except Exception as exc:
            return '<COutPoint error: {}>'.format(exc)

    def display_hint(self):
        return 'string'


class PrevectorPrinter:
    """prevector<N, T> – compact vector with inline storage for small sizes."""

    def __init__(self, val):
        self.val = val

    def to_string(self):
        try:
            count, _ = _prevector_elems(self.val)
            try:
                N = int(self.val.type.template_argument(0))
                storage = 'direct' if count <= N else 'heap'
            except Exception:
                storage = '?'
            return 'prevector<{}> [{}]'.format(storage, count)
        except Exception as exc:
            return '<prevector error: {}>'.format(exc)

    def children(self):
        try:
            count, get = _prevector_elems(self.val)
            for i in range(count):
                yield ('[{}]'.format(i), get(i))
        except Exception:
            return

    def display_hint(self):
        return 'array'


class CScriptPrinter:
    """CScript – prevector<28, uint8_t> with an attached ScriptType."""

    _TYPE_NAMES = {0: 'SATOSCRIPT', 1: 'PUSH_ONLY', 2: 'TEMPLATE'}

    def __init__(self, val):
        self.val = val

    def to_string(self):
        try:
            stype = int(self.val['type'])
            tname = self._TYPE_NAMES.get(stype, 'type={}'.format(stype))
            hexdata = _script_to_hex(self.val)
            nbytes = len(hexdata) // 2
            return 'CScript({}, {} bytes: {})'.format(tname, nbytes, hexdata)
        except Exception as exc:
            return '<CScript error: {}>'.format(exc)

    def display_hint(self):
        return 'string'


class CTxInPrinter:
    """CTxIn – transaction input."""

    _TYPE_NAMES = {0: 'UTXO', 1: 'READONLY', 2: 'INVALID'}

    def __init__(self, val):
        self.val = val

    def to_string(self):
        try:
            t = int(self.val['type'])
            tname = self._TYPE_NAMES.get(t, 'type={}'.format(t))
            prevout = _blob_short(self.val['prevout']['hash'], 32)
            amount = int(self.val['amount'])
            seq = int(self.val['nSequence'])
            return 'CTxIn({}, prevout={}, amount={} sat, seq=0x{:08x})'.format(
                tname, prevout, amount, seq)
        except Exception as exc:
            return '<CTxIn error: {}>'.format(exc)

    def children(self):
        try:
            yield ('type',      self.val['type'])
            yield ('prevout',   self.val['prevout'])
            yield ('amount',    self.val['amount'])
            yield ('nSequence', self.val['nSequence'])
            yield ('scriptSig', self.val['scriptSig'])
        except Exception:
            return


class CTxOutPrinter:
    """CTxOut – transaction output."""

    _TYPE_NAMES = {0: 'SATOSCRIPT', 1: 'TEMPLATE'}

    def __init__(self, val):
        self.val = val

    def to_string(self):
        try:
            t = int(self.val['type'])
            tname = self._TYPE_NAMES.get(t, 'type={}'.format(t))
            value = int(self.val['nValue'])
            return 'CTxOut({}, {} sat)'.format(tname, value)
        except Exception as exc:
            return '<CTxOut error: {}>'.format(exc)

    def children(self):
        try:
            yield ('type',        self.val['type'])
            yield ('nValue',      self.val['nValue'])
            yield ('scriptPubKey', self.val['scriptPubKey'])
        except Exception:
            return


class CTransactionPrinter:
    """CTransaction – immutable transaction."""

    def __init__(self, val):
        self.val = val

    def to_string(self):
        try:
            txid  = _blob_short(self.val['id'],   32)
            idem  = _blob_short(self.val['idem'],  32)
            nin   = _vec_size(self.val['vin'])
            nout  = _vec_size(self.val['vout'])
            nin_s  = str(nin)  if nin  >= 0 else '?'
            nout_s = str(nout) if nout >= 0 else '?'
            return 'CTransaction(id={}, idem={}, vin={}, vout={})'.format(
                txid, idem, nin_s, nout_s)
        except Exception as exc:
            return '<CTransaction error: {}>'.format(exc)

    def children(self):
        try:
            yield ('id',        self.val['id'])
            yield ('idem',      self.val['idem'])
            yield ('nVersion',  self.val['nVersion'])
            yield ('nLockTime', self.val['nLockTime'])
            yield ('vin',       self.val['vin'])
            yield ('vout',      self.val['vout'])
        except Exception:
            return


class CMutableTransactionPrinter(CTransactionPrinter):
    """CMutableTransaction – mutable variant; same layout as CTransaction."""
    pass


class CBlockIndexPrinter:
    """CBlockIndex – blockchain index entry."""

    def __init__(self, val):
        self.val = val

    def to_string(self):
        try:
            height = int(self.val['nHeight'])
            status = _decode_block_status(self.val['nStatus'])

            phash = self.val['phashBlock']
            hash_str = (_blob_short(phash.dereference(), 32)
                        if int(phash) != 0 else '<null>')

            work = _arith_to_hex(self.val['nChainWork'], 8)
            ntime = int(self.val['nTime'])
            ntx   = int(self.val['nTx'])

            return ('CBlockIndex(h={}, hash={}, work=...{}, '
                    'time={}, tx={}, {})').format(
                height, hash_str, work[-16:], ntime, ntx, status)
        except Exception as exc:
            return '<CBlockIndex error: {}>'.format(exc)

    def children(self):
        try:
            yield ('nHeight',    self.val['nHeight'])
            phash = self.val['phashBlock']
            if int(phash) != 0:
                yield ('hash',   phash.dereference())
            yield ('nChainWork', self.val['nChainWork'])
            yield ('nTime',      self.val['nTime'])
            yield ('nBits',      self.val['nBits'])
            yield ('nStatus',    self.val['nStatus'])
            yield ('nTx',        self.val['nTx'])
            yield ('nChainTx',   self.val['nChainTx'])
            yield ('nFile',      self.val['nFile'])
            yield ('nDataPos',   self.val['nDataPos'])
            yield ('nUndoPos',   self.val['nUndoPos'])
            yield ('pprev',      self.val['pprev'])
        except Exception:
            return


class CNetAddrPrinter:
    """CNetAddr – network address (IP or Tor/I2P/etc.)."""

    def __init__(self, val):
        self.val = val

    def _ip_string(self):
        net_type = int(self.val['_net_type'])
        net_name = _NET_NAMES.get(net_type, 'NET_{}'.format(net_type))

        # ip is std::vector<uint8_t>; pull bytes out of _M_impl
        ip_vec = self.val['ip']
        try:
            start  = ip_vec['_M_impl']['_M_start']
            finish = ip_vec['_M_impl']['_M_finish']
            n = int(finish - start)
            raw = [int(start[i]) & 0xff for i in range(n)]
        except Exception:
            return net_name, '<ip?>'

        if net_type == 1 and n == 4:   # IPv4
            addr = '.'.join(str(b) for b in raw)
        elif net_type == 2 and n == 16:  # IPv6
            groups = ['%02x%02x' % (raw[i*2], raw[i*2+1]) for i in range(8)]
            addr = ':'.join(groups)
        else:
            addr = ''.join('%02x' % b for b in raw)

        return net_name, addr

    def to_string(self):
        try:
            net_name, addr = self._ip_string()
            return 'CNetAddr({}, {})'.format(net_name, addr)
        except Exception as exc:
            return '<CNetAddr error: {}>'.format(exc)

    def display_hint(self):
        return 'string'


class CServicePrinter(CNetAddrPrinter):
    """CService – CNetAddr + port."""

    def to_string(self):
        try:
            net_name, addr = self._ip_string()
            port = int(self.val['port'])
            return 'CService({}, {}:{})'.format(net_name, addr, port)
        except Exception as exc:
            return '<CService error: {}>'.format(exc)


class CAddressPrinter(CNetAddrPrinter):
    """CAddress – CService + nTime + nServices."""

    def to_string(self):
        try:
            net_name, addr = self._ip_string()
            port     = int(self.val['port'])
            services = int(self.val['nServices'])
            ntime    = int(self.val['nTime'])
            return 'CAddress({}, {}:{}, svc=0x{:016x}, t={})'.format(
                net_name, addr, port, services, ntime)
        except Exception as exc:
            return '<CAddress error: {}>'.format(exc)

    def children(self):
        try:
            yield ('nTime',     self.val['nTime'])
            yield ('nServices', self.val['nServices'])
            yield ('port',      self.val['port'])
        except Exception:
            return


class CUnknownObjPrinter:
    """CUnknownObj – request manager per-object tracking entry."""

    def __init__(self, val):
        self.val = val

    def to_string(self):
        try:
            inv_str     = CInvPrinter(self.val['obj']).to_string()
            processing  = bool(self.val['fProcessing'])
            outstanding = int(self.val['outstandingReqs'])
            last_req    = int(self.val['lastRequestTime'])
            entry_time  = int(self.val['nEntryTime'])
            return ('CUnknownObj({}, processing={}, outstanding={}, '
                    'lastReq={}, entryTime={})').format(
                inv_str, processing, outstanding, last_req, entry_time)
        except Exception as exc:
            return '<CUnknownObj error: {}>'.format(exc)

    def children(self):
        try:
            yield ('obj',              self.val['obj'])
            yield ('fProcessing',      self.val['fProcessing'])
            yield ('outstandingReqs',  self.val['outstandingReqs'])
            yield ('lastRequestTime',  self.val['lastRequestTime'])
            yield ('nEntryTime',       self.val['nEntryTime'])
            yield ('nDownloadingSince', self.val['nDownloadingSince'])
            yield ('availableFrom',    self.val['availableFrom'])
            yield ('prevRequestNode',  self.val['prevRequestNode'])
        except Exception:
            return


class CTxMemPoolEntryPrinter:
    """CTxMemPoolEntry – in-memory mempool tracking entry."""

    def __init__(self, val):
        self.val = val

    def to_string(self):
        try:
            fee    = int(self.val['nFee'])
            height = int(self.val['entryHeight'])
            ntime  = int(self.val['nTime'])
            anc_cnt = int(self.val['nCountWithAncestors'])
            return 'CTxMemPoolEntry(fee={} sat, height={}, time={}, ancestors={})'.format(
                fee, height, ntime, anc_cnt)
        except Exception as exc:
            return '<CTxMemPoolEntry error: {}>'.format(exc)

    def children(self):
        try:
            yield ('tx',                      self.val['tx'])
            yield ('nFee',                    self.val['nFee'])
            yield ('entryHeight',             self.val['entryHeight'])
            yield ('nTime',                   self.val['nTime'])
            yield ('inChainInputValue',       self.val['inChainInputValue'])
            yield ('spendsCoinbase',          self.val['spendsCoinbase'])
            yield ('sigOpCount',              self.val['sigOpCount'])
            yield ('feeDelta',                self.val['feeDelta'])
            yield ('nCountWithAncestors',     self.val['nCountWithAncestors'])
            yield ('nSizeWithAncestors',      self.val['nSizeWithAncestors'])
            yield ('nModFeesWithAncestors',   self.val['nModFeesWithAncestors'])
            yield ('nSigOpCountWithAncestors', self.val['nSigOpCountWithAncestors'])
        except Exception:
            return


class CBlockHeaderPrinter:
    """CBlockHeader – wire-format block header."""

    def __init__(self, val):
        self.val = val

    def to_string(self):
        try:
            h      = int(self.val['height'])
            ntime  = int(self.val['nTime'])
            nbits  = int(self.val['nBits'])
            txcnt  = int(self.val['txCount'])
            sz     = int(self.val['size'])
            prev   = _blob_short(self.val['hashPrevBlock'], 32)
            work   = _blob_to_hex(self.val['chainWork'], 32)
            return ('CBlockHeader(h={}, time={}, bits=0x{:08x}, '
                    'txs={}, size={}, prev={}, work=...{})').format(
                h, ntime, nbits, txcnt, sz, prev, work[-16:])
        except Exception as exc:
            return '<CBlockHeader error: {}>'.format(exc)

    def children(self):
        try:
            yield ('height',          self.val['height'])
            yield ('hashPrevBlock',   self.val['hashPrevBlock'])
            yield ('hashAncestor',    self.val['hashAncestor'])
            yield ('hashMerkleRoot',  self.val['hashMerkleRoot'])
            yield ('hashTxFilter',    self.val['hashTxFilter'])
            yield ('chainWork',       self.val['chainWork'])
            yield ('nTime',           self.val['nTime'])
            yield ('nBits',           self.val['nBits'])
            yield ('size',            self.val['size'])
            yield ('txCount',         self.val['txCount'])
            yield ('feePoolAmt',      self.val['feePoolAmt'])
            yield ('nonce',           self.val['nonce'])
            yield ('utxoCommitment',  self.val['utxoCommitment'])
            yield ('minerData',       self.val['minerData'])
        except Exception:
            return


class CBlockPrinter(CBlockHeaderPrinter):
    """CBlock – full block (CBlockHeader + transaction list)."""

    def to_string(self):
        try:
            base = CBlockHeaderPrinter.to_string(self)
            nvtx    = _vec_size(self.val['vtx'])
            fxval   = bool(self.val['fXVal'])
            checked = bool(self.val['fChecked'])
            vtx_s   = str(nvtx) if nvtx >= 0 else '?'
            return 'CBlock({}, vtx={}, xval={}, checked={})'.format(
                base[len('CBlockHeader('):-1], vtx_s, fxval, checked)
        except Exception as exc:
            return '<CBlock error: {}>'.format(exc)

    def children(self):
        # Emit header fields first, then block-specific fields
        yield from CBlockHeaderPrinter.children(self)
        try:
            yield ('fXVal',   self.val['fXVal'])
            yield ('fChecked', self.val['fChecked'])
            yield ('vtx',     self.val['vtx'])
            yield ('setUnVerifiedTxns', self.val['setUnVerifiedTxns'])
        except Exception:
            return


def _map_size(m):
    """Return element count of a libstdc++ std::map or std::set."""
    try:
        return int(m['_M_t']['_M_impl']['_M_node_count'])
    except Exception:
        return -1


def _atomic_int(val):
    """Read the integer value of a std::atomic<integral>."""
    try:
        return int(val['_M_b']['_M_i'])
    except Exception:
        pass
    try:
        return int(val['_M_i'])
    except Exception:
        return -1


class CRequestManagerPrinter:
    """CRequestManager – block and transaction download queue state."""

    def __init__(self, val):
        self.val = val

    def to_string(self):
        try:
            blk_info  = _map_size(self.val['mapBlkInfo'])
            txn_info  = _map_size(self.val['mapTxnInfo'])
            blk_add   = _map_size(self.val['mapBlkToAdd'])
            txn_add   = _map_size(self.val['mapTxnToAdd'])
            in_flight = _map_size(self.val['mapBlocksInFlight'])
            blk_del   = _map_size(self.val['setBlockDeleter'])
            window    = _atomic_int(self.val['BLOCK_DOWNLOAD_WINDOW'])
            asked     = int(self.val['nBlocksAskedFor'])

            def _s(n):
                return str(n) if n >= 0 else '?'

            return ('CRequestManager('
                    'blkInfo={}, txnInfo={}, '
                    'blkToAdd={}, txnToAdd={}, '
                    'inFlight={}, pendingDel={}, '
                    'window={}, askedFor={})').format(
                _s(blk_info), _s(txn_info),
                _s(blk_add),  _s(txn_add),
                _s(in_flight), _s(blk_del),
                _s(window), asked)
        except Exception as exc:
            return '<CRequestManager error: {}>'.format(exc)

    def children(self):
        try:
            yield ('mapBlkInfo',              self.val['mapBlkInfo'])
            yield ('mapTxnInfo',              self.val['mapTxnInfo'])
            yield ('mapBlkToAdd',             self.val['mapBlkToAdd'])
            yield ('mapTxnToAdd',             self.val['mapTxnToAdd'])
            yield ('mapBlocksInFlight',       self.val['mapBlocksInFlight'])
            yield ('mapRequestManagerNodeState',
                   self.val['mapRequestManagerNodeState'])
            yield ('nBlocksAskedFor',         self.val['nBlocksAskedFor'])
            yield ('BLOCK_DOWNLOAD_WINDOW',   self.val['BLOCK_DOWNLOAD_WINDOW'])
            yield ('setBlockDeleter',         self.val['setBlockDeleter'])
            yield ('setDeleter',              self.val['setDeleter'])
            yield ('receivedTxns',            self.val['receivedTxns'])
            yield ('rejectedTxns',            self.val['rejectedTxns'])
            yield ('pendingTxns',             self.val['pendingTxns'])
        except Exception:
            return


class CoinPrinter:
    """Coin – UTXO set entry (CTxOut + coinbase flag + height)."""

    def __init__(self, val):
        self.val = val

    def to_string(self):
        try:
            value    = int(self.val['out']['nValue'])
            height   = int(self.val['nHeight'])
            coinbase = bool(self.val['fCoinBase'])
            return 'Coin({} sat, h={}, coinbase={})'.format(value, height, coinbase)
        except Exception as exc:
            return '<Coin error: {}>'.format(exc)

    def children(self):
        try:
            yield ('out',       self.val['out'])
            yield ('fCoinBase', self.val['fCoinBase'])
            yield ('nHeight',   self.val['nHeight'])
        except Exception:
            return


# ===========================================================================
# Registration
# ===========================================================================

def build_nexa_pretty_printers():
    pp = gdb.printing.RegexpCollectionPrettyPrinter("nexa")

    # Hash blobs
    pp.add_printer('uint256',     r'^uint256$',                Uint256Printer)
    pp.add_printer('uint160',     r'^uint160$',                Uint160Printer)
    pp.add_printer('base_blob',   r'^base_blob<\d+\s*u?>$',    _BaseBlobPrinter)

    # Arithmetic hash
    pp.add_printer('arith_uint256', r'^arith_uint256$',        ArithUint256Printer)
    pp.add_printer('base_uint',   r'^base_uint<\d+\s*u?>$',    ArithUint256Printer)

    # Inventory
    pp.add_printer('CInv',        r'^CInv$',                   CInvPrinter)
    pp.add_printer('CInv2',       r'^CInv2$',                  CInv2Printer)

    # Transaction primitives
    pp.add_printer('COutPoint',   r'^COutPoint$',              COutPointPrinter)
    pp.add_printer('CTxIn',       r'^CTxIn$',                  CTxInPrinter)
    pp.add_printer('CTxOut',      r'^CTxOut$',                 CTxOutPrinter)
    pp.add_printer('CTransaction', r'^CTransaction$',          CTransactionPrinter)
    pp.add_printer('CMutableTransaction', r'^CMutableTransaction$',
                   CMutableTransactionPrinter)

    # Scripts and compact vectors
    pp.add_printer('CScript',     r'^CScript$',                CScriptPrinter)
    pp.add_printer('prevector',   r'^prevector<.*>$',          PrevectorPrinter)

    # Block types
    pp.add_printer('CBlockHeader', r'^CBlockHeader$',          CBlockHeaderPrinter)
    pp.add_printer('CBlock',       r'^CBlock$',                CBlockPrinter)

    # Chain
    pp.add_printer('CBlockIndex',  r'^CBlockIndex$',           CBlockIndexPrinter)

    # Request manager
    pp.add_printer('CRequestManager', r'^CRequestManager$',   CRequestManagerPrinter)

    # Network addresses
    pp.add_printer('CNetAddr',    r'^CNetAddr$',               CNetAddrPrinter)
    pp.add_printer('CService',    r'^CService$',               CServicePrinter)
    pp.add_printer('CAddress',    r'^CAddress$',               CAddressPrinter)

    # Request manager
    pp.add_printer('CUnknownObj', r'^CUnknownObj$',            CUnknownObjPrinter)

    # Mempool / UTXO
    pp.add_printer('CTxMemPoolEntry', r'^CTxMemPoolEntry$',    CTxMemPoolEntryPrinter)
    pp.add_printer('Coin',        r'^Coin$',                   CoinPrinter)

    return pp


def register_nexa_printers(objfile=None):
    """Register the Nexa pretty printers, optionally scoped to an objfile."""
    gdb.printing.register_pretty_printer(objfile, build_nexa_pretty_printers(),
                                         replace=True)


register_nexa_printers(gdb.current_objfile())
gdb.write("Loaded Nexa GDB pretty printers {}.\n".format(VERSION))
