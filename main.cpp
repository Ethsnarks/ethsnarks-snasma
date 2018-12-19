// Copyright (c) 2018 HarryR
// License: GPL-3.0+

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "stubs.hpp"
#include "jubjub/point.hpp"
#include "jubjub/eddsa.hpp"

#include "snasma.hpp"
#include "circuit.hpp"

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

using namespace ethsnarks;


void print_tx( const snasma::TxProof& p )
{
	cout << "Tx:\n\tFrom IDX: " << p.stx.tx.from_idx << "\n\tTo IDX: " << p.stx.tx.to_idx << "\n\tAmount: " << p.stx.tx.amount << endl;

	cout << "Sig:\n\tR.x = "; p.stx.sig.R.x.print();
	cout << "\tR.y = "; p.stx.sig.R.y.print();
	cout << "\ts = "; p.stx.sig.s.print();
	cout << "\tnonce = " << p.stx.nonce << endl;

	cout << "From:" << endl;
	cout << "\tpubkey.x = "; p.state_from.pubkey.x.print();
	cout << "\tpubkey.y = "; p.state_from.pubkey.y.print();
	cout << "\tbalance = "; p.state_from.balance.print();
	cout << "\tnonce = " << p.state_from.nonce << endl;

	cout << "To:" << endl;
	cout << "\tpubkey.x = "; p.state_to.pubkey.x.print();
	cout << "\tpubkey.y = "; p.state_to.pubkey.y.print();
	cout << "\tbalance = "; p.state_to.balance.print();
	cout << "\tnonce = " << p.state_to.nonce << endl;

	cout << "Before From path:" << endl;
	for( size_t i = 0; i < p.before_from.size(); i++ ) {
		cout << "\t" << i << " : "; p.before_from[i].print();
	}

	cout << "Before To path:" << endl;
	for( size_t i = 0; i < p.before_to.size(); i++ ) {
		cout << "\t" << i << " : "; p.before_to[i].print();
	}

	cout << "After To path:" << endl;
	for( size_t i = 0; i < p.after_to.size(); i++ ) {
		cout << "\t" << i << " : "; p.after_to[i].print();
	}
	cout << endl;
}


int main( int argc, char **argv )
{
	if( argc < 3 ) {
		cerr << "Usage: " << argv[0] << " <n> <transactions.txt>" << endl;
		return 1;
	}

	ppT::init_public_params();
	ProtoboardT pb;

	const auto arg_n = atoi(argv[1]);
	const auto arg_sigsfile = argv[2];
	ifstream infile(arg_sigsfile);
	if( ! infile.is_open() )
	{
		cerr << "Error: cannot open input file - " << arg_sigsfile << endl;
		return 2; 
	}

	VariableT merkle_root;
	jubjub::Params params;
	vector<snasma::TxCircuit> tx_gadgets;

	libff::enter_block("Circuit");	

	libff::enter_block("setup");	
	for( size_t j = 0; j < arg_n; j++ )
	{
		tx_gadgets.emplace_back(pb, params, (j == 0) ? merkle_root : tx_gadgets[j-1].result(), FMT("tx", "[%zu]", j));
	}
	libff::leave_block("setup");

	libff::enter_block("constraints");
	for( auto& gadget : tx_gadgets )
	{
		gadget.generate_r1cs_constraints();
	}

	libff::leave_block("constraints");

	libff::leave_block("Circuit");

	cout << pb.num_constraints() << " constraints (" << (pb.num_constraints() / arg_n) << " avg/tx)" << endl;

	libff::enter_block("Parsing Lines");
	vector<snasma::TxProof> proofs;
	string line;
	size_t i = 0;
	while ( i++ < arg_n && std::getline(infile, line) )
	{
		decltype(proofs)::value_type item;
		if( istringstream(line) >> item )
		{
			if( ! item.is_valid() )
			{
				cerr << "is_valid failed " << i << endl;				
			}
			else {
				proofs.emplace_back(item);
				continue;
			}
		}
		else {
			cerr << "Error parsing line " << i << endl;
			print_tx(item);
		}
		
		cerr << "Line is: " << line << endl;
		return 3;
	}
	libff::leave_block("Parsing Lines");

	for( const auto& p : proofs )
	{
		print_tx(p);		
	}

	return 0;
}
