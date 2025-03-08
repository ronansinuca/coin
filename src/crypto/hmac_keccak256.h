// Copyright (c) 2014-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_HMAC_KECCAK256_H
#define BITCOIN_CRYPTO_HMAC_KECCAK256_H

#include <crypto/keccak.h>

#include <stdint.h>
#include <stdlib.h>

/** A hasher class for HMAC-SHA-256. */
class CHMAC_KECCAK256
{
private:
    CKeccak256 outer;
    CKeccak256 inner;

public:
    static const size_t OUTPUT_SIZE = 32;

    CHMAC_KECCAK256(const unsigned char* key, size_t keylen);
    CHMAC_KECCAK256& Write(const unsigned char* data, size_t len)
    {
        inner.Write(data, len);
        return *this;
    }
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
};

#endif // BITCOIN_CRYPTO_HMAC_KECCAK256_H
