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


/**
* Display all fields in the transaction
*/
void print_tx( const snasma::TxProof& p )
{
	cout << "Tx:" << endl;
	cout << "\tFrom IDX: " << p.stx.tx.from_idx << "\n\tTo IDX: " << p.stx.tx.to_idx << "\n\tAmount: " << p.stx.tx.amount << endl;

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

	cout << endl;
}


void print_tx( ProtoboardT& pb, const snasma::TxCircuit& p )
{
	cout << "Msg bits len: " << p.sig_m.size() << endl;
	auto bits = p.m_sig.m_hash_RAM.m_RAM_bits.get_bits(pb);
	print_bv(" msg bits", bits);

	cout << "tx_from_idx: "; p.tx_from_idx.get_field_element_from_bits(pb).print();
	cout << "tx_to_idx: "; p.tx_to_idx.get_field_element_from_bits(pb).print();

	cout << "from_pubkey.x: "; pb.val(p.from_pubkey.x).print();
	cout << "from_pubkey.y: "; pb.val(p.from_pubkey.y).print();
	cout << "from_balance: "; pb.val(p.from_balance).print();
	cout << "next_nonce: "; pb.val(p.next_nonce).print();

	cout << "to_pubkey.x: "; pb.val(p.to_pubkey.x).print();
	cout << "to_pubkey.y: "; pb.val(p.to_pubkey.y).print();
	cout << "to_balance: "; pb.val(p.to_balance).print();
	cout << "to_nonce: "; pb.val(p.to_nonce).print();

	cout << "sig_R.x: "; pb.val(p.sig_R.x).print();
	cout << "sig_R.y: "; pb.val(p.sig_R.y).print();
	cout << "sig_nonce: "; pb.val(p.sig_nonce.packed).print();
	cout << "sig_s: "; p.sig_s.get_field_element_from_bits(pb).print();

	cout << "balance.A: "; pb.val(p.m_balance.A).print();
	cout << "balance.B: "; pb.val(p.m_balance.B).print();
	cout << "balance.N: "; pb.val(p.m_balance.N).print();
	cout << "balance.X: "; pb.val(p.m_balance.X).print();
	cout << "balance.Y: "; pb.val(p.m_balance.Y).print();

	cout << "balance.N_lt_A: "; pb.val(p.m_balance.N_lt_A).print();
	cout << "balance.N_leq_A: "; pb.val(p.m_balance.N_leq_A).print();
	cout << "balance.Y_overflow_lt: "; pb.val(p.m_balance.Y_overflow_lt).print();
	cout << "balance.Y_overflow_leq: "; pb.val(p.m_balance.Y_overflow_leq).print();

	cout << "m_leaf_before_from: "; pb.val(p.m_leaf_before_from.result()).print();
	cout << "m_leaf_after_from: "; pb.val(p.m_leaf_after_from.result()).print();
	cout << "m_leaf_before_to: "; pb.val(p.m_leaf_before_to.result()).print();
	cout << "m_leaf_after_to: "; pb.val(p.m_leaf_after_to.result()).print();
}


const VariableT setup_circuits( ProtoboardT& pb, jubjub::Params& params, vector<snasma::TxCircuit>& tx_gadgets, int arg_n )
{
	const VariableT merkle_root = make_variable(pb, "merkle_root");

	libff::enter_block("Circuit");	

		libff::enter_block("setup");	
		for( size_t j = 0; j < arg_n; j++ )
		{
			tx_gadgets.emplace_back(pb, params, (j == 0) ? merkle_root : tx_gadgets.back().result(), FMT("tx", "[%zu]", j));
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

	return merkle_root;
}


bool parse_lines( const VariableT& merkle_root, vector<snasma::TxCircuit>& tx_gadgets, int arg_n, ifstream& infile )
{
	libff::enter_block("Parsing Lines");
	string line;
	size_t i = 0;
	while ( std::getline(infile, line) )
	{
		if( '#' == line[0] )
		{
			continue;
		}

		if( i >= arg_n )
		{
			break;
		}

		snasma::TxProof item;
		if( istringstream(line) >> item )
		{
			if( ! item.is_valid() )
			{
				cerr << "is_valid failed " << i << endl;
			}
			else {
				tx_gadgets[i].generate_r1cs_witness(item);
				i += 1;
				continue;
			}
		}
		else {
			cerr << "Error parsing line " << i << endl;
		}
		
		cerr << "Line is: " << line << endl;
		print_tx(item);
		return false;
	}
	libff::leave_block("Parsing Lines");

	if( i != arg_n ) {
		cerr << "Expected " << arg_n << " lines, got " << i << endl;
		return false;
	}

	return true;
}


int main( int argc, char **argv )
{
	if( argc < 3 ) {
		cerr << "Usage: " << argv[0] << " <n> <transactions.txt>" << endl;
		return 1;
	}

	ppT::init_public_params();
	ProtoboardT pb;

	// open inputs file
	const auto arg_n = atoi(argv[1]);
	const auto arg_sigsfile = argv[2];
	ifstream infile(arg_sigsfile);
	if( ! infile.is_open() )
	{
		cerr << "Error: cannot open input file - " << arg_sigsfile << endl;
		return 2; 
	}

	// Setup circuit and parse lines
	jubjub::Params params;
	vector<snasma::TxCircuit> tx_gadgets;
	const auto merkle_root = setup_circuits(pb, params, tx_gadgets, arg_n);
	if ( ! parse_lines(merkle_root, tx_gadgets, arg_n, infile) )
	{
		return 3;
	}

	// Display circuit inputs and necessary intermediates
	/*
	for( const auto& gadget : tx_gadgets )
	{
		print_tx(pb, gadget);
	}
	*/

	if( ! pb.is_satisfied() )
	{
		cerr << "Not valid" << endl;
		return 3;
	}

	if( ! stub_test_proof_verify(pb) ) {
		cerr << "FAIL" << endl;
		return 4;
	}

	return 0;
}
