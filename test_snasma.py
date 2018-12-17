import sys
import random
from snasma import *


def path2str(path):
	return ' '.join([str(_) for _ in path])


def main():
	mgr = AccountManager(0xFF)
	accts = list()
	for _ in range(10):
		accts.append( mgr.new_account(1000) )

	all_transactions = []
	for _ in range(1):
		for (key_a, a) in accts:
			(key_b, b) = random.choice(accts)
			v = random.randint(1, a.balance)
			tx = mgr.new_transaction(a, b, v)
			stx = tx.sign(key_a, a.nonce)
			tx_proof = mgr.apply_transaction(stx)
			print(' '.join([path2str(_.path) for _ in [tx_proof.before_from, tx_proof.before_to, tx_proof.after_from, tx_proof.after_to]]))


if __name__ == "__main__":
	sys.exit(main(*sys.argv[1:]))
