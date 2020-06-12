#!/usr/bin/env python3
from .psbt import CTransaction, CTxIn, CTxOut, CTxInWitness
from .psbt import deser_vector, ser_vector
import struct
from . import base58

MAGIC = b"\x45\x50\x54\x46\xFF\x00"
INPUT_MAGIC = b"\xfe\xff\xff\xff\xff"

class ElectrumInputMeta:
    def __init__(self):
        self.nValue = 0
        self.unknown = b""
        self.xpub = b""

    def deserialize(self, f):
        # magic...
        assert f.read(len(INPUT_MAGIC)) == INPUT_MAGIC
        self.nValue = struct.unpack("<q", f.read(8))[0]
        self.unknown = f.read(7)
        print(self.unknown.hex())
        self.xpub = f.read(78)
        self.derivation = [int.from_bytes(f.read(2),'little') for i in range(2)]

    def serialize(self):
        r = INPUT_MAGIC
        r += struct.pack("<q", self.nValue)
        r += self.unknown
        r += self.xpub
        for der in self.derivation:
            r += der.to_bytes(2, 'little')
        return r

    def __repr__(self):
        return "ElectrumInputMeta(nValue=%d, xpub=%s, derivation=%s)" \
        % (self.nValue, base58.encode_check(self.xpub), repr(self.derivation))


class ElectrumTx(CTransaction):
    def deserialize(self, f):
        prefix = f.read(len(MAGIC))
        assert prefix == MAGIC

        self.nVersion = struct.unpack("<i", f.read(4))[0]
        self.vin = deser_vector(f, CTxIn)
        flags = 0
        if len(self.vin) == 0:
            flags = struct.unpack("<B", f.read(1))[0]
            # Not sure why flags can't be zero, but this
            # matches the implementation in bitcoind
            if (flags != 0):
                self.vin = deser_vector(f, CTxIn)
                self.vout = deser_vector(f, CTxOut)
        else:
            self.vout = deser_vector(f, CTxOut)
        # segwit
        self.flags = flags
        if flags != 0:
            self.inputsMeta = [ElectrumInputMeta() for i in range(len(self.vin))]
            for inp in self.inputsMeta:
                inp.deserialize(f)
        self.nLockTime = struct.unpack("<I", f.read(4))[0]
        self.sha256 = None
        self.hash = None

    def serialize(self):
        r = MAGIC
        r += struct.pack("<i", self.nVersion)
        if self.flags:
            dummy = []
            r += ser_vector(dummy)
            r += struct.pack("<B", self.flags)
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        for inp in self.inputsMeta:
            r += inp.serialize()
        r += struct.pack("<I", self.nLockTime)
        return r


    def __repr__(self):
        return "ElectrumTx(nVersion=%i vin=%s vout=%s wit=%s nLockTime=%i meta=%s)" \
            % (self.nVersion, repr(self.vin), repr(self.vout), repr(self.wit), self.nLockTime, repr(self.inputsMeta))
