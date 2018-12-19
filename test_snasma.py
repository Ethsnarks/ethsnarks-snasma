import sys
import random
from snasma import *


def main():
	mgr = AccountManager(1<<24)

	accts = list()
	for _ in range(2):
		accts.append(mgr.new_account(random.randint(1, 1000)))

	all_transactions = []
	for _ in range(len(accts)):
		for (key_a, a) in accts:
			(key_b, b) = random.choice(accts)
			v = random.randint(1, a.balance)

			tx = mgr.new_transaction(a, b, v)
			stx = tx.sign(key_a, a.nonce)

			tx_proof = mgr.apply_transaction(stx)
			print(str(tx_proof))


if __name__ == "__main__":
	sys.exit(main(*sys.argv[1:]))
