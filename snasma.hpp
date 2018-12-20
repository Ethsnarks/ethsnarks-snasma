#ifndef SNASMA_HPP_
#define SNASMA_HPP_

// Copyright (c) 2018 HarryR
// License: GPL-3.0+

#include "ethsnarks.hpp"
#include "jubjub/point.hpp"


namespace snasma {


static const size_t TREE_DEPTH = 24;

using std::endl;


/**
* Contains the only information published on-chain
*
* This specifies the merkle-tree leaf indexes for the to and from addresses,
* and the amount in a compressed form (like floating point, but for integers).
*
* This information is used to create a zero-knowledge proof that the tiny
* amount of information published on-chain has been used for a state transition.
*
* Each on-chain transaction is 8 bytes.
*/
class OnchainTransaction
{
public:
    uint32_t from_idx;    // TREE_DEPTH bits
    uint32_t to_idx;      // TREE_DEPTH bits
    uint16_t amount;      // 16 bits

    OnchainTransaction() {}

    OnchainTransaction(
        const decltype(from_idx) in_from_idx,
        const decltype(to_idx) in_to_idx,
        const decltype(amount) in_amount
    ) :
        from_idx(in_from_idx),
        to_idx(in_to_idx),
        amount(in_amount)
    {
        assert( is_valid() );
    }

    bool is_valid()
    {
        return from_idx < (1<<TREE_DEPTH)
            && to_idx < (1<<TREE_DEPTH)
            && amount != 0;
    }

    friend std::istream& operator>> (std::istream& is, OnchainTransaction& self)
    {
        if( ! (is >> self.from_idx) ) {
            std::cerr << "error read OnchainTransaction.from_idx" << endl;
        }

        if ( ! (is >> self.to_idx) ) {
            std::cerr << "error read OnchainTransaction.to_idx" << endl;
        }

        if ( ! (is >> self.amount) ) {
            std::cerr << "error read OnchainTransaction.amount" << endl;
        }

        return is;
    }
};


class Signature
{
public:
    ethsnarks::jubjub::EdwardsPoint R;
    ethsnarks::FieldT s;

    Signature() {}

    Signature(const decltype(R) in_R, const decltype(s) in_s
    ) :
        R(in_R), s(in_s)
    { }

    friend std::istream& operator>> (std::istream& is, Signature& self)
    {
        if ( ! (is >> self.R) ) {
            std::cerr << "error read R" << endl;
        }

        std::string read_str;
        if ( ! (is >> read_str) ) {        
            std::cerr << "error read s" << endl;
        }
        else {
            self.s = decltype(self.s)(read_str.c_str());
        }

        return is;
    }
};


class AccountState
{
public:
    ethsnarks::jubjub::EdwardsPoint pubkey;

    /**
    * 128-bit balance of account
    */
    ethsnarks::FieldT balance;

    /**
    * Sequentially incrementing, Number used ONCE
    */
    uint32_t nonce;

    AccountState()
    : nonce(0)
    {}

    AccountState(const decltype(pubkey) in_pubkey, const decltype(balance) in_balance
    ) :
        pubkey(in_pubkey), balance(in_balance)
    {
        assert( is_valid() );
    }

    bool is_valid() {
        return nonce < (1<<TREE_DEPTH);
    }

    friend std::istream& operator>> (std::istream& is, AccountState& self)
    {
        if( ! (is >> self.pubkey) ) {
            std::cerr << "error reading AccountState.pubkey" << endl;
        }

        if( ! (is >> self.balance) ) {
            std::cerr << "error reading AccountState.balance" << endl;
        }

        if( ! (is >> self.nonce) ) {
            std::cerr << "error reading AccountState.nonce" << endl;
        }

        return is;
    }
};


/**
* Signed transaction, provided by an account owner
*/
class SignedTransaction
{
public:
    /**
    * Signature authorising the on-chain transaction for a specific nonce
    */
    Signature sig;

    /**
    * The only information published on-chain
    */
    OnchainTransaction tx;

    uint32_t nonce;

    SignedTransaction() {}

    SignedTransaction(const decltype(sig) in_sig, const decltype(tx) in_tx, const decltype(nonce) in_nonce
    ) :
        sig(in_sig), tx(in_tx), nonce(in_nonce)
    {
        assert( is_valid() );
    }

    bool is_valid()
    {
        return tx.is_valid()
            && nonce < (1<<TREE_DEPTH);
    }

    friend std::istream& operator>> (std::istream& is, SignedTransaction& self)
    {
        if ( ! (is >> self.tx) ) {
            std::cerr << "error read SignedTransaction.tx" << endl;
        }

        if ( ! (is >> self.nonce) ) {
            std::cerr << "error read SignedTransaction.nonce" << endl;
        }

        if ( ! (is >> self.sig) ) {
            std::cerr << "error read SignedTransaction.sig" << endl;
        }

        return is;
    }

    /**
    * @return Message to be signed, as a bit vector
    */
    const libff::bit_vector message()
    {       
        return ethsnarks::int_list_to_bits(
            {tx.from_idx, tx.to_idx,  tx.amount, nonce},
            {TREE_DEPTH,  TREE_DEPTH, 16,        TREE_DEPTH});
    }
};


static std::istream& read_tree_path (std::istream& is, std::vector<ethsnarks::FieldT>& ov)
{
    std::string read_str;
    for( size_t i = 0; i < TREE_DEPTH; i++ )
    {            
        if ( ! (is >> read_str) ) {
            std::cerr << "error read path " << i << endl;
            break;
        }
        ov.emplace_back(read_str.c_str());
    }

    return is;
}


/**
* Provided by the operator to supply merkle proofs of the accounts
* before and after the transaction has been applied.
*/
class TxProof
{
public:
    SignedTransaction stx;

    AccountState state_from;
    AccountState state_to;

    std::vector<ethsnarks::FieldT> before_from;
    std::vector<ethsnarks::FieldT> before_to;
    std::vector<ethsnarks::FieldT> after_to;

    bool is_valid()
    {
        return stx.is_valid()
            && state_from.is_valid()
            && state_to.is_valid()
            && before_from.size() == TREE_DEPTH
            && before_to.size() == TREE_DEPTH
            && after_to.size() == TREE_DEPTH;
    }

    friend std::istream& operator>> (std::istream& is, TxProof& self)
    {
        if ( ! (is >> self.stx) ) {
            std::cerr << "error read TxProof.stx" << endl;
        }

        if ( ! (is >> self.state_from) ) {
            std::cerr << "error read TxProof.state_from" << endl;
        }

        if ( ! (is >> self.state_to) ) {
            std::cerr << "error read TxProof.state_to" << endl;
        }

        // Before transaction is applied
        if ( ! read_tree_path(is, self.before_from) ) {
            std::cerr << "error read TxProof.before_from" << endl;
        }

        if( ! read_tree_path(is, self.before_to) ) {
            std::cerr << "error read TxProof.before_to" << endl;
        }

        // After transaction is applied
        if( ! read_tree_path(is, self.after_to) ) {
            std::cerr << "error read TxProof.after_to" << endl;
        }

        return is;
    }
};


// namespace snasma
}

// SNASMA_HPP_
#endif
