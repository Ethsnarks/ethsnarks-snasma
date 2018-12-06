from __future__ import print_function
import sys
from random import randint

from ethsnarks.eddsa import eddsa_sign
from ethsnarks.jubjub import Point, JUBJUB_L
from ethsnarks.field import FQ


def main(n_sigs):
	B = Point(FQ(6310387441923805963163495340827050724868600896655464356695079365984952295953),
			  FQ(12999349368805111542414555617351208271526681431102644160586079028197231734677))

	for _ in range(int(n_sigs)):
		k = FQ(randint(1, JUBJUB_L), JUBJUB_L)
		msg = b"abc"
		R, s, A = eddsa_sign(msg, k, B)
		print(A.x, A.y, msg.decode('ascii'), R.x, R.y, s)


if __name__ == "__main__":
	sys.exit(main(*sys.argv[1:]))
