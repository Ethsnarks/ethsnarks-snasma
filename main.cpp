// Copyright (c) 2018 HarryR
// License: GPL-3.0+

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "stubs.hpp"
#include "jubjub/point.hpp"
#include "jubjub/eddsa.hpp"

#include "snasma.hpp"

#include <fstream>
#include <sstream>
#include <string>

using std::cerr;
using std::cout;
using std::endl;
using std::ifstream;
using std::string;
using std::istringstream;
using std::vector;

using ethsnarks::ppT;
using ethsnarks::ProtoboardT;



int main( int argc, char **argv )
{
	if( argc < 3 ) {
		cerr << "Usage: " << argv[0] << " <n> <transactions.txt>" << endl;
		return 1;
	}

	ppT::init_public_params();

	const auto arg_n = atoi(argv[1]);
	const auto arg_sigsfile = argv[2];
	ifstream infile(arg_sigsfile);
	if( ! infile.is_open() )
	{
		cerr << "Error: cannot open input file - " << arg_sigsfile << endl;
		return 2; 
	}

	libff::enter_block("Parsing Lines");
	vector<snasma::TransactionProof> proofs;
	string line;
	size_t i = 0;
	while ( i++ < arg_n && std::getline(infile, line) )
	{
		decltype(proofs)::value_type item;
		if( istringstream(line) >> item ) {
			proofs.emplace_back(item);
			continue;
		}
		
		cerr << "Error parsing line " << i << endl;
		cerr << "Line is: " << line << endl;
		return 3;
	}
	libff::leave_block("Parsing Lines");

	for( const auto& p : proofs )
	{
		cout << p.stx.tx.from_idx << " " << p.stx.tx.to_idx << " " << p.stx.tx.amount << endl;
	}

	return 0;
}
