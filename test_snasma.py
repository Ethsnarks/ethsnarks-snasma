import sys
import random
from snasma import *


def main():
	mgr = AccountManager(1<<24)

	accts = list()
	for _ in range(5):
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
			all_transactions.append(tx_proof)

	with open('transactions.dot', 'w') as handle:
		handle.write("digraph transactions {\n")
		for tx_proof in all_transactions:
			handle.write("\t%d -> %d;\n" % (tx_proof.stx.tx.from_idx, tx_proof.stx.tx.to_idx))
		handle.write("}\n")


if __name__ == "__main__":
	sys.exit(main(*sys.argv[1:]))
