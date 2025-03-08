#ifndef BITCOIN_CRYPTO_KECCAK_256_H
#define BITCOIN_CRYPTO_KECCAK_256_H

/*
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 *
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>

/*
 * Computes the Keccak-256 hash of a sequence of bytes. The hash value is 32 bytes long.
 * Provides just one static method.
 */
class CKeccak256
{
public:
    static constexpr int OUTPUT_SIZE = 32;

public:
    CKeccak256();
    CKeccak256(const std::uint8_t data[], std::size_t len);
    
    static void getHash(const std::uint8_t data[], std::size_t len, std::uint8_t hashResult[OUTPUT_SIZE]);
    //static void hash(const uint8_t data[], size_t len, uint8_t hashResult[OUTPUT_SIZE]);

    CKeccak256& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CKeccak256& Reset();

private:
    std::vector<uint8_t> mData;
};

/*
    Compute a Keccak256 hash
*/
void Keccak256(const std::uint8_t data[], std::size_t len, std::uint8_t hashResult[CKeccak256::OUTPUT_SIZE]);

/*
    Compute a Keccak256 double hash
*/
void Keccak256D(const std::uint8_t data[], std::size_t len, std::uint8_t hashResult[CKeccak256::OUTPUT_SIZE]);

#endif