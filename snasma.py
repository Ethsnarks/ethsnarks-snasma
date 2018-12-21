# Copyright (c) 2018 HarryR
# License: GPL-3.0+

from __future__ import print_function
import sys
import json
import struct
import bitstring
from copy import copy, deepcopy
from collections import namedtuple

from ethsnarks.eddsa import pureeddsa_sign, eddsa_tobits, eddsa_random_keypair
from ethsnarks.jubjub import Point
from ethsnarks.field import FQ
from ethsnarks.merkletree import MerkleTree
from ethsnarks.longsight import LongsightL12p5_MP


TREE_SIZE = 24
AMOUNT_BITS = 32


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class OnchainTransaction(namedtuple('_OnchainTransaction', ('from_idx', 'to_idx', 'amount'))):
    def message(self, nonce):
        """
        Return an array of bits representing the on-chain transaction details
        that will be included in the signature.

        This is 104 bits long:

        +-----------+---------+---------+---------+
        | from_idx  | to_idx  | amount  | nonce   |
        +-----------+---------+---------+---------+
        | 24 bits   | 24 bits | 32 bits | 24 bits |
        +-----------+---------+---------+---------+

        Each integer is encoded in little-endian form,
        with the least significant bit first.
        """
        assert self.from_idx < (1<<TREE_SIZE)
        assert self.to_idx < (1<<TREE_SIZE)
        assert self.amount < (1<<AMOUNT_BITS)
        assert nonce < (1<<TREE_SIZE)
        msg_parts = [FQ(self.from_idx, 1<<TREE_SIZE), FQ(self.to_idx, 1<<TREE_SIZE),
                     FQ(self.amount, 1<<AMOUNT_BITS), FQ(nonce, 1<<TREE_SIZE)]
        msg_bits = ''.join([eddsa_tobits(_) for _ in msg_parts])
        return bitstring.BitArray('0b' + msg_bits)

    def sign(self, k, nonce):
        msg = self.message(nonce)
        R, s, _ = pureeddsa_sign(msg, k)
        sig = Signature(R, s)
        return SignedTransaction(self, nonce, sig)

    def __str__(self):
        return ' '.join(str(_) for _ in [self.from_idx, self.to_idx, self.amount])


class Signature(namedtuple('_Signature', ('R', 's'))):
    def __str__(self):
        return ' '.join(str(_) for _ in [self.R.x, self.R.y, self.s])


class SignedTransaction(namedtuple('_SignedTransaction', ('tx', 'nonce', 'sig'))):
    def __str__(self):
        return ' '.join(str(_) for _ in [self.tx, self.nonce, self.sig])

    def message(self):
        return self.tx.message(self.nonce)


class AccountState(object):
    def __init__(self, pubkey, balance, nonce, index=None):
        assert isinstance(pubkey, Point)
        self.pubkey = pubkey
        self.balance = balance
        self.nonce = nonce  
        self.index = index

    def leaf_fields(self):
        # TODO: pack balance and nonce into a single field?
        return [self.pubkey.x, self.pubkey.y, self.balance, self.nonce]

    def hash(self):
        """
        Compress data so it can be used as a leaf in the merkle tree
        """
        return LongsightL12p5_MP([int(_) for _ in self.leaf_fields()], 1)

    def __str__(self):
        return ' '.join(str(_) for _ in self.leaf_fields())


def path2str(path):
    return ' '.join([str(_) for _ in path])


class TransactionProof(namedtuple('_TransactionProof', ('merkle_root', 'stx', 'state_from', 'state_to', 'before_from', 'before_to'))):
    def __str__(self):
        subobjs = [str(_) for _ in [self.merkle_root, self.stx, self.state_from, self.state_to]]
        paths = [self.before_from, self.before_to]
        return ' '.join(subobjs + [path2str(_.path) for _ in paths])


class AccountManager(object):
    def __init__(self, tree_size):
        self._accounts = []
        self._key2idx = dict()
        self._tree = MerkleTree(tree_size)

    def lookup_accounts(self, *args):
        return [self.lookup_account(_) for _ in args]

    def lookup_account(self, index):
        if isinstance(index, AccountState):
            assert index.index is not None
            index = index.index
        elif isinstance(index, Point):
            index = self._key2idx[index]
        return self._accounts[index]

    def new_account(self, balance=0):
        secret, pubkey = eddsa_random_keypair()
        return secret, self.add_account(pubkey, balance)

    def add_account(self, pubkey, balance=0, nonce=0):
        assert isinstance(pubkey, Point)
        state = AccountState(pubkey, balance, nonce)
        state.index = self._tree.append(state.hash())
        self._accounts.append(state)
        self._key2idx[pubkey] = state.index
        return state

    def new_transaction(self, from_account, to_account, amount):
        from_account, to_account = self.lookup_accounts(from_account, to_account)
        return OnchainTransaction(from_account.index, to_account.index, amount)

    def apply_transaction(self, stx):
        """
        Records the state transition of the transaction being applied to the tree
        """
        assert isinstance(stx, SignedTransaction)
        tx = stx.tx
        from_account, to_account = self.lookup_accounts(tx.from_idx, tx.to_idx)

        if from_account.balance < tx.amount:
            raise RuntimeError("Balance not sufficient to perform transfer")

        merkle_root = self._tree.root

        # Update `from` leaf, recording its state before modification
        state_from = deepcopy(from_account)
        from_account.nonce += 1
        from_account.balance -= tx.amount
        proof_before_from = self._tree.proof(tx.from_idx)
        self._tree.update(tx.from_idx, from_account.hash())

        # Update `to` leaf, recording its state before modification
        state_to = deepcopy(to_account)
        to_account.balance += tx.amount
        proof_before_to = self._tree.proof(tx.to_idx)
        self._tree.update(tx.to_idx, to_account.hash())

        return TransactionProof(merkle_root, stx, state_from, state_to, proof_before_from, proof_before_to)
