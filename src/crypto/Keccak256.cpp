/*
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 *
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

#include <cassert>
#include <crypto/Keccak256.h>

using std::size_t;
using std::uint64_t;
using std::uint8_t;


const int BLOCK_SIZE = 200 - Keccak256::OUTPUT_SIZE * 2;
const int NUM_ROUNDS = 24;

// Static initializers
const unsigned char ROTATION[5][5] = {
    {0, 36, 3, 41, 18},
    {1, 44, 10, 45, 2},
    {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39, 8, 14},
};


uint64_t rotl64(uint64_t x, int i)
{
    return ((0U + x) << i) | (x >> ((64 - i) & 63));
}

void absorb(uint64_t state[5][5])
{
    uint64_t(*a)[5] = state;
    uint8_t r = 1; // LFSR
    for (int i = 0; i < NUM_ROUNDS; i++) {
        // Theta step
        uint64_t c[5] = {};
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++)
                c[x] ^= a[x][y];
        }
        for (int x = 0; x < 5; x++) {
            uint64_t d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
            for (int y = 0; y < 5; y++)
                a[x][y] ^= d;
        }

        // Rho and pi steps
        uint64_t b[5][5];
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++)
                b[y][(x * 2 + y * 3) % 5] = rotl64(a[x][y], ROTATION[x][y]);
        }

        // Chi step
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++)
                a[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]);
        }

        // Iota step
        for (int j = 0; j < 7; j++) {
            a[0][0] ^= static_cast<uint64_t>(r & 1) << ((1 << j) - 1);
            r = static_cast<uint8_t>((r << 1) ^ ((r >> 7) * 0x171));
        }
    }
}

Keccak256::Keccak256()
{
    mData.empty();
}

Keccak256& Keccak256::Reset()
{
    mData.empty();
    return *this;
}

Keccak256& Keccak256::Write(const unsigned char* data, size_t len)
{
    mData.insert(mData.end(), data, data + len);
    return *this;
}

void Keccak256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    size_t len = mData.size();
    uint8_t *msg = mData.data();

    assert((msg != nullptr || len == 0) && hash != nullptr);
    uint64_t state[5][5] = {};

    // XOR each message byte into the state, and absorb full blocks
    int blockOff = 0;
    for (size_t i = 0; i < len; i++) {
        int j = blockOff >> 3;
        state[j % 5][j / 5] ^= static_cast<uint64_t>(msg[i]) << ((blockOff & 7) << 3);
        blockOff++;
        if (blockOff == BLOCK_SIZE) {
            absorb(state);
            blockOff = 0;
        }
    }

    // Final block and padding
    {
        int i = blockOff >> 3;
        state[i % 5][i / 5] ^= UINT64_C(0x01) << ((blockOff & 7) << 3);
        blockOff = BLOCK_SIZE - 1;
        int j = blockOff >> 3;
        state[j % 5][j / 5] ^= UINT64_C(0x80) << ((blockOff & 7) << 3);
        absorb(state);
    }

    // Uint64 array to bytes in little endian
    for (int i = 0; i < OUTPUT_SIZE; i++) {
        int j = i >> 3;
        hash[i] = static_cast<uint8_t>(state[j % 5][j / 5] >> ((i & 7) << 3));
    }
}

void Keccak256::getHash(const uint8_t msg[], size_t len, uint8_t hashResult[OUTPUT_SIZE])
{
    Keccak256 kc;
    kc.Write(&msg[0], len);
    kc.Finalize(hashResult);
}

/*void Keccak256::getHash(const uint8_t msg[], size_t len, uint8_t hashResult[OUTPUT_SIZE])
{
    assert((msg != nullptr || len == 0) && hashResult != nullptr);
    uint64_t state[5][5] = {};

    // XOR each message byte into the state, and absorb full blocks
    int blockOff = 0;
    for (size_t i = 0; i < len; i++) {
        int j = blockOff >> 3;
        state[j % 5][j / 5] ^= static_cast<uint64_t>(msg[i]) << ((blockOff & 7) << 3);
        blockOff++;
        if (blockOff == BLOCK_SIZE) {
            absorb(state);
            blockOff = 0;
        }
    }

    // Final block and padding
    {
        int i = blockOff >> 3;
        state[i % 5][i / 5] ^= UINT64_C(0x01) << ((blockOff & 7) << 3);
        blockOff = BLOCK_SIZE - 1;
        int j = blockOff >> 3;
        state[j % 5][j / 5] ^= UINT64_C(0x80) << ((blockOff & 7) << 3);
        absorb(state);
    }

    // Uint64 array to bytes in little endian
    for (int i = 0; i < OUTPUT_SIZE; i++) {
        int j = i >> 3;
        hashResult[i] = static_cast<uint8_t>(state[j % 5][j / 5] >> ((i & 7) << 3));
    }
}*/
