#include "ethsnarks.hpp"
#include "utils.hpp"
#include "stubs.hpp"
#include "jubjub/eddsa.hpp"

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
using ethsnarks::VariableT;
using ethsnarks::VariableArrayT;
using ethsnarks::FieldT;
using ethsnarks::VariableArray_from_bits;
using ethsnarks::make_variable;
using ethsnarks::make_var_array;
using ethsnarks::bytes_to_bv;
using ethsnarks::stub_test_proof_verify;

using ethsnarks::jubjub::Params;
using ethsnarks::jubjub::VariablePointT;
using ethsnarks::jubjub::EdwardsPoint;
using ethsnarks::jubjub::EdDSA_Verify;


struct Input_Sig {
	string R_x;
	string R_y;
	string A_x;
	string A_y;
	string m;
	string s;
};


int main( int argc, char **argv )
{
	if( argc < 3 ) {
		cerr << "Usage: " << argv[0] << " <n> <signatures.txt>" << endl << endl;
		cerr << "Signatures file format, one row per line, space separated" << endl;
		cerr << "	A.x A.y m R.x R.y s" << endl;
		return 1;
	}

	ppT::init_public_params();

	const auto arg_n = atoi(argv[1]);
	const auto arg_sigsfile = argv[2];

	ProtoboardT pb;
	Params params;
	vector<EdDSA_Verify> gadgets;
	
	ifstream infile(arg_sigsfile);
	if( ! infile.is_open() )
	{
		cerr << "Error: cannot open input file - " << arg_sigsfile << endl;
		return 2; 
	}

	string line;
	size_t i = 0;

	const EdwardsPoint base_point(FieldT("6310387441923805963163495340827050724868600896655464356695079365984952295953"),
								  FieldT("12999349368805111542414555617351208271526681431102644160586079028197231734677"));

	while ( i++ < arg_n && std::getline(infile, line))
	{
		istringstream iss(line);

		Input_Sig sig;

		if (!(iss >> sig.A_x >> sig.A_y >> sig.m >> sig.R_x >> sig.R_y >> sig.s)) {
			cerr << "Error on line " << i << endl;
			cerr << "Line is: " << line << endl << endl;	    	
			return 3;
		}

		VariableT var_A_x = make_variable(pb, FieldT(sig.A_x.c_str()), FMT("sig", "[%zu].A_x", i));
		VariableT var_A_y = make_variable(pb, FieldT(sig.A_y.c_str()), FMT("sig", "[%zu].A_y", i));
		VariablePointT var_A(var_A_x, var_A_y);

		VariableT var_R_x = make_variable(pb, FieldT(sig.R_x.c_str()), FMT("sig", "[%zu].R_x", i));
		VariableT var_R_y = make_variable(pb, FieldT(sig.R_y.c_str()), FMT("sig", "[%zu].R_y", i));
		VariablePointT var_R(var_R_x, var_R_y);

		VariableArrayT var_s = make_var_array(pb, FieldT::size_in_bits(), FMT("sig", "[%zu].s", i));
		var_s.fill_with_bits_of_field_element(pb, FieldT(sig.s.c_str()));

		const auto m_bits = bytes_to_bv((uint8_t*)(sig.m.c_str()), sig.m.size());
		VariableArrayT var_msg = VariableArray_from_bits(pb, m_bits, FMT("sig", "[%zu].m", i));

		gadgets.emplace_back(pb, params, base_point, var_A, var_R, var_s, var_msg, FMT("sig", "[%zu].eddsa", i));
	}

	for( auto& the_gadget : gadgets )
	{
		the_gadget.generate_r1cs_witness();
		the_gadget.generate_r1cs_constraints();
	}

	cout << pb.num_constraints() << " constraints" << endl;

	if( ! pb.is_satisfied() )
	{
		cerr << "Not Satisfied!" << endl;
		return 4;
	}

	if( ! stub_test_proof_verify(pb) ) {
		cerr << "Failed test proof verify" << endl;
		return 5;
	}

	return 0;
}
