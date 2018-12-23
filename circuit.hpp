#ifndef CIRCUIT_HPP_
#define CIRCUIT_HPP_

#include "ethsnarks.hpp"
#include "utils.hpp"
#include "snasma.hpp"
#include "jubjub/point.hpp"
#include "jubjub/eddsa.hpp"
#include "gadgets/longsightl.hpp"
#include "gadgets/subadd.hpp"
#include "gadgets/merkle_tree.hpp"
#include "gadgets/field2bits_strict.hpp"
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

namespace snasma {

using namespace ethsnarks;
using jubjub::VariablePointT;


/**
* Applies a transaction to a merkle tree
*
* This gadget can be instansiated, and then re-used to create multiple
* proofs without re-creating the circuit in-memory.
*
* Transactions are a signature, which instructs the circuit to subtract
* an amount from the signed accounts balance, and give it to another account.
*
* Signed fields:
*
*   From index: 24 bit
*   To index: 24 bit
*   Amount: 16 bit
*   Nonce: 24 bit
*
* Signature consists of:
*
*   EdDSA signature of H(R, A, M)
*
*   Where:
*
*       R = bits(sig.R.x) || bits(sig.R.y)
*       A = bits(leaf.x) || bits(leaf.y)
*       M = bits(tx.from) || bits(tx.to) || bits(tx.amount) || bits(tx.nonce)
*
*   A total of 1104 bits are used as input to H(R,A,M)
*
*   The H() function for EdDSA is the 'Fast ZCash Pedersen Hash for Baby Jubjub'
*
* Supplementary data (provided by the operator) records the states of the
* sender and receiver leaves in the merkle tree before and after applying the
* transaction.
*
* This is the account state of `from` and `to` leaves:
*
*   pubkey  : FieldT[2](x, y)
*   balance : FieldT
*   nonce   : FieldT
*
* The fields of the leaf are hashed using LongsightL+MP or MiMC+MP,
* each field in the account state is passed as an input to the compression
* function one-by-one.
*
*/
class TxCircuit : public GadgetT
{
public:
    typedef markle_path_compute<LongsightL12p5_MP_gadget> MerklePathT;
    typedef merkle_path_authenticator<LongsightL12p5_MP_gadget> MerklePathCheckT;

    const VariableT merkle_root;

    const VariableArrayT tx_from_idx;
    const VariableArrayT tx_to_idx;
    libsnark::dual_variable_gadget<FieldT> tx_amount;

    // Account state `from`
    const VariablePointT from_pubkey;
    const VariableT from_balance;
    const VariableT next_nonce;

    // Account state `to`
    const VariablePointT to_pubkey;
    const VariableT to_balance;
    const VariableT to_nonce;

    // variables for signature
    const VariablePointT sig_R;
    const VariableArrayT sig_s;
    libsnark::dual_variable_gadget<FieldT> sig_nonce;
    const VariableArrayT sig_m;
    // gadgets for signature
    jubjub::PureEdDSA_Verify m_sig;

    // apply transaction balance transfer
    subadd_gadget m_balance;

    // Prove `from` leaf exists in tree
    LongsightL12p5_MP_gadget m_leaf_before_from;
    const VariableArrayT proof_before_from;
    MerklePathCheckT path_before_from;

    // Calculate new leaf for updated `from`, create new merkle-root
    LongsightL12p5_MP_gadget m_leaf_after_from;
    MerklePathT path_after_from;

    // Prove (against merkle root from `path_after_from`) that `to` leaf exists
    LongsightL12p5_MP_gadget m_leaf_before_to;
    const VariableArrayT proof_before_to;
    MerklePathCheckT path_before_to;

    // Calculate new leaf with update `to`, creates resulting merkle-root
    LongsightL12p5_MP_gadget m_leaf_after_to;
    MerklePathT path_after_to;

    TxCircuit(
        ProtoboardT& pb,
        const jubjub::Params& params,
        const VariableT& in_merkle_root,
        const std::string& annotation_prefix
    ) :
        GadgetT(pb, annotation_prefix),

        merkle_root(in_merkle_root),

        // on-chain transaction spec
        tx_from_idx(make_var_array(pb, snasma::TREE_DEPTH, FMT(annotation_prefix, ".from_idx"))),
        tx_to_idx(make_var_array(pb, snasma::TREE_DEPTH, FMT(annotation_prefix, ".to_idx"))),
        tx_amount(pb, AMOUNT_BITS, FMT(annotation_prefix, ".amount")),

        // variables to store from account state
        from_pubkey(pb, FMT(annotation_prefix, ".from_pubkey")),
        from_balance(make_variable(pb, FMT(annotation_prefix, ".from_balance"))),
        next_nonce(make_variable(pb, FMT(annotation_prefix, ".next_nonce"))),

        // variables to store to account state
        to_pubkey(pb, FMT(annotation_prefix, ".to_pubkey")),
        to_balance(make_variable(pb, FMT(annotation_prefix, ".to_balance"))),
        to_nonce(make_variable(pb, FMT(annotation_prefix, ".to_nonce"))),

        // Signature variables
        sig_R(pb, FMT(annotation_prefix, ".R")),
        sig_s(make_var_array(pb, FieldT::size_in_bits(), FMT(annotation_prefix, ".s"))),
        sig_nonce(pb, snasma::TREE_DEPTH, FMT(annotation_prefix, ".nonce")),
        sig_m(flatten({tx_from_idx, tx_to_idx, tx_amount.bits, sig_nonce.bits})),
        //
        // Calculate hash used for signature
        //      M = (from_idx, to_idx, tx_amount, sig_nonce)
        //      A = (from.x, from.y)
        //      PureEdDSA-Verify(A, R, S, BITS(M))
        m_sig(pb, params, jubjub::EdwardsPoint(params.Gx, params.Gy),
            from_pubkey, sig_R, sig_s, sig_m,
            FMT(annotation_prefix, ".sig")),

        // Apply balance transfer
        // first verfies from.balance is >= tx.amount
        //      from.balance -= tx.amount
        //      to.balance += tx.amount;
        m_balance(pb, BALANCE_BITS, from_balance, to_balance, tx_amount.packed, FMT(annotation_prefix, ".subadd")),

        // Verify the from_idx and to_idx exist in the current merkle tree
        m_leaf_before_from(pb, libsnark::ONE, {from_pubkey.x, from_pubkey.y, from_balance, sig_nonce.packed}, FMT(annotation_prefix, ".leaf_before_from")),
        proof_before_from(make_var_array(pb, snasma::TREE_DEPTH, FMT(annotation_prefix, ".proof_before_from"))),
        path_before_from(pb, snasma::TREE_DEPTH, tx_from_idx, merkle_tree_IVs(pb), m_leaf_before_from.result(), merkle_root, proof_before_from, FMT(annotation_prefix, ".path_before_from")),

        // Update the 'from' leaf to create a new merkle root
        //
        //  `path_after_from.result()` is the new root
        m_leaf_after_from(pb, libsnark::ONE, {from_pubkey.x, from_pubkey.y, m_balance.X, next_nonce}, FMT(annotation_prefix, ".leaf_after_from")),
        path_after_from(pb, snasma::TREE_DEPTH, tx_from_idx, merkle_tree_IVs(pb), m_leaf_after_from.result(), proof_before_from, FMT(annotation_prefix, ".path_after_from")),

        // Verify the 'to' leaf exists in the new merkle root and is the expected value
        //
        //  leaf_before_to = H(to_pubkey.x, to_pubkey.y, to_balance, to_nonce)
        //  assert merkle_path(leaf_before_to, path_after_from.result(), proof_before_to)
        m_leaf_before_to(pb, libsnark::ONE, {to_pubkey.x, to_pubkey.y, to_balance, to_nonce}, FMT(annotation_prefix, ".leaf_before_to")),
        proof_before_to(make_var_array(pb, snasma::TREE_DEPTH, FMT(annotation_prefix, ".proof_before_to"))),
        path_before_to(pb, snasma::TREE_DEPTH, tx_to_idx, merkle_tree_IVs(pb), m_leaf_before_to.result(), path_after_from.result(), proof_before_to, FMT(annotation_prefix, ".path_before_to")),

        // Update the 'to' leaf with the new balance
        // this creates the last merkle root
        // to_nonce isn't incremented
        m_leaf_after_to(pb, libsnark::ONE, {to_pubkey.x, to_pubkey.y, m_balance.Y, to_nonce}, FMT(annotation_prefix, ".leaf_after_to")),
        path_after_to(pb, snasma::TREE_DEPTH, tx_to_idx, merkle_tree_IVs(pb), m_leaf_after_to.result(), proof_before_to, FMT(annotation_prefix, ".path_after_to"))
    {

    }


    const VariableT result() const
    {
        return path_after_to.result();
    }


    void generate_r1cs_witness( const snasma::TxProof& proof )
    {
        this->pb.val(merkle_root) = proof.merkle_root;

        tx_from_idx.fill_with_bits_of_ulong(this->pb, (unsigned long)proof.stx.tx.from_idx);
        tx_to_idx.fill_with_bits_of_ulong(this->pb, (unsigned long)proof.stx.tx.to_idx);

        tx_amount.bits.fill_with_bits_of_ulong(this->pb, proof.stx.tx.amount);
        tx_amount.generate_r1cs_witness_from_bits();

        this->pb.val(from_pubkey.x) = proof.state_from.pubkey.x;
        this->pb.val(from_pubkey.y) = proof.state_from.pubkey.y;
        this->pb.val(from_balance) = proof.state_from.balance;
        this->pb.val(next_nonce) = proof.stx.nonce + 1;

        this->pb.val(to_pubkey.x) = proof.state_to.pubkey.x;
        this->pb.val(to_pubkey.y) = proof.state_to.pubkey.y;
        this->pb.val(to_balance) = proof.state_to.balance;
        this->pb.val(to_nonce) = proof.state_to.nonce;

        this->pb.val(sig_R.x) = proof.stx.sig.R.x;
        this->pb.val(sig_R.y) = proof.stx.sig.R.y;
        sig_s.fill_with_bits_of_field_element(this->pb, proof.stx.sig.s);
        this->pb.val(sig_nonce.packed) = proof.stx.nonce;
        sig_nonce.generate_r1cs_witness_from_packed();
        m_sig.generate_r1cs_witness();

        m_balance.generate_r1cs_witness();

        m_leaf_before_from.generate_r1cs_witness();
        proof_before_from.fill_with_field_elements(this->pb, proof.before_from);
        path_before_from.generate_r1cs_witness();

        m_leaf_after_from.generate_r1cs_witness();
        path_after_from.generate_r1cs_witness();

        m_leaf_before_to.generate_r1cs_witness();
        proof_before_to.fill_with_field_elements(this->pb, proof.before_to);
        path_before_to.generate_r1cs_witness();

        m_leaf_after_to.generate_r1cs_witness();
        path_after_to.generate_r1cs_witness();

    }


    void generate_r1cs_constraints()
    {
        tx_amount.generate_r1cs_constraints(true);
        sig_nonce.generate_r1cs_constraints(true);

        this->pb.add_r1cs_constraint(
            ConstraintT(sig_nonce.packed + FieldT::one(), 1, next_nonce),
            "next_nonce = sig_nonce++");

        m_sig.generate_r1cs_constraints();

        m_leaf_before_from.generate_r1cs_constraints();
        m_leaf_before_to.generate_r1cs_constraints();

        m_balance.generate_r1cs_constraints();

        m_leaf_after_from.generate_r1cs_constraints();
        m_leaf_after_to.generate_r1cs_constraints();

        path_before_from.generate_r1cs_constraints();
        path_before_to.generate_r1cs_constraints();
        path_after_from.generate_r1cs_constraints();
        path_after_to.generate_r1cs_constraints();
    }
};

// namespace snasma
}

// CIRCUIT_HPP_
#endif
