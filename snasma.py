# Copyright (c) 2018 HarryR
# License: GPL-3.0+

import struct
from ethsnarks.eddsa import eddsa_sign, eddsa_verify
from ethsnarks.jubjub import Point, FQ, JUBJUB_L
from ethsnarks.merkletree import MerkleTree
from ethsnarks.longsight import LongsightL12p5_MP


def pack24(n):
	return struct.pack('<I', n)[:3]


def unpack24(s):
	return struct.unpack('<I', x + b'\0')


class OnchainTransaction(object):
	def __init__(self, from_idx, to_idx, amount):
		self.from_idx = from_idx
		self.to_idx = to_idx
		self.amount = amount

	def message(self, nonce):
		return pack24(self.from_idx) + pack24(self.to_idx) + struct.pack('<H', self.amount) + pack24(nonce)

	def sign(self, k, nonce):
		msg = self.message(nonce)
		B = Point.generator()
		R, s, A = eddsa_sign(msg, k, B)
		sig = Signature(R, s)
		return SignedTransaction(sig, self, nonce)


class Signature(object):
	def __init__(self, R, s):
		assert isinstance(R, Point)
		self.R = R
		self.s = s


class SignedTransaction(object):
	def __init__(self, sig, tx, nonce):
		assert isinstance(sig, Signature)
		assert isinstance(tx, OnchainTransaction)
		self.sig = sig
		self.tx = tx
		self.nonce = nonce

	def message(self):
		return self.tx.message(self.nonce)


class TransactionProof(object):
	def __init__(self, before_from, before_to, after_from, after_to):
		self.before_from = before_from
		self.before_to = before_to
		self.after_from = after_from
		self.after_to = after_to


class AccountState(object):
	def __init__(self, pubkey, balance, nonce, index=None):
		assert isinstance(pubkey, Point)
		self.pubkey = pubkey
		self.balance = balance
		self.nonce = nonce	
		self.index = index

	def encode(self):
		"""
		Compress data so it can be used as a leaf in the merkle tree
		"""
		# TODO: pack balance and nonce into a single field
		args = [self.pubkey.x, self.pubkey.y, self.balance, self.nonce]
		return LongsightL12p5_MP([int(_) for _ in args], 0)


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

	def get_pubkey(self, account):
		return self.lookup_account(account).pubkey

	def get_balance(self, account):
		return self.lookup_account(account).balance

	def get_nonce(self, account):
		return self.lookup_account(account).nonce

	def new_account(self, balance=0):
		secret = FQ.random(JUBJUB_L)
		pubkey = Point.generator() * secret
		return secret, self.add_account(pubkey, balance)

	def add_account(self, pubkey, balance=0, nonce=0):
		assert isinstance(pubkey, Point)
		state = AccountState(pubkey, balance, nonce)
		state.index = self._tree.append(state.encode())
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

		proof_before_from = self._tree.proof(tx.from_idx)
		proof_before_to = self._tree.proof(tx.to_idx)

		from_account.nonce += 1
		from_account.balance -= tx.amount
		to_account.balance += tx.amount

		self._tree.update(tx.from_idx, from_account.encode())
		self._tree.update(tx.to_idx, to_account.encode())

		proof_after_from = self._tree.proof(tx.from_idx)
		proof_after_to = self._tree.proof(tx.to_idx)

		return TransactionProof(proof_before_from, proof_before_to, proof_after_from, proof_after_to)
