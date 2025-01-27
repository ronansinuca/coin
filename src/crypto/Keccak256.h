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
#include <span.h>


/*
 * Computes the Keccak-256 hash of a sequence of bytes. The hash value is 32 bytes long.
 * Provides just one static method.
 */
class Keccak256 final
{
public:
    static constexpr int OUTPUT_SIZE = 32;

public:
    Keccak256();
    
    static void getHash(const std::uint8_t msg[], std::size_t len, std::uint8_t hashResult[OUTPUT_SIZE]);

    Keccak256& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    Keccak256& Reset();

private:
    std::vector<uint8_t> mData;
};

#endif