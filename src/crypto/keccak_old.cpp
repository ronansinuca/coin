/*
 * Bitcoin cryptography library
 * Copyright (c) Project Nayuki
 *
 * https://www.nayuki.io/page/bitcoin-cryptography-library
 * https://github.com/nayuki/Bitcoin-Cryptography-Library
 */

 #include <cassert>
 #include <crypto/keccak_old.h>
 
 using std::size_t;
 using std::uint64_t;
 using std::uint8_t;
 
 
 const int BLOCK_SIZE = 200 - CKeccak256::OUTPUT_SIZE * 2;
 const int NUM_ROUNDS = 24;
 const int STATE_SIZE = 5;
 
 // Static initializers
 const unsigned char ROTATION[STATE_SIZE][STATE_SIZE] = {
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
 
 void absorb(uint64_t state[STATE_SIZE][STATE_SIZE])
 {
     uint64_t(*a)[STATE_SIZE] = state;
     uint8_t r = 1; // LFSR
     for (int i = 0; i < NUM_ROUNDS; i++) {
         // Theta step
         uint64_t c[5] = {};
         for (int x = 0; x < STATE_SIZE; x++) {
             for (int y = 0; y < STATE_SIZE; y++)
                 c[x] ^= a[x][y];
         }
         for (int x = 0; x < STATE_SIZE; x++) {
             uint64_t d = c[(x + 4) % STATE_SIZE] ^ rotl64(c[(x + 1) % STATE_SIZE], 1);
             for (int y = 0; y < STATE_SIZE; y++)
                 a[x][y] ^= d;
         }
 
         // Rho and pi steps
         uint64_t b[STATE_SIZE][STATE_SIZE];
         for (int x = 0; x < STATE_SIZE; x++) {
             for (int y = 0; y < STATE_SIZE; y++)
                 b[y][(x * 2 + y * 3) % STATE_SIZE] = rotl64(a[x][y], ROTATION[x][y]);
         }
 
         // Chi step
         for (int x = 0; x < STATE_SIZE; x++) {
             for (int y = 0; y < STATE_SIZE; y++)
                 a[x][y] = b[x][y] ^ (~b[(x + 1) % STATE_SIZE][y] & b[(x + 2) % STATE_SIZE][y]);
         }
 
         // Iota step
         for (int j = 0; j < 7; j++) {
             a[0][0] ^= static_cast<uint64_t>(r & 1) << ((1 << j) - 1);
             r = static_cast<uint8_t>((r << 1) ^ ((r >> 7) * 0x171));
         }
     }
 }
 
 CKeccak256::CKeccak256()
 {
     mData.empty();
 }
 
 
 CKeccak256::CKeccak256(const std::uint8_t data[], std::size_t len){
     mData.insert(mData.end(), data, data + len);
 }
 
 CKeccak256& CKeccak256::Reset()
 {
     mData.empty();
     return *this;
 }
 
 CKeccak256& CKeccak256::Write(const unsigned char* data, size_t len)
 {
     mData.insert(mData.end(), data, data + len);
     return *this;
 }
 
 void CKeccak256::Finalize(unsigned char hash[OUTPUT_SIZE])
 {
     size_t len = mData.size();
     uint8_t *msg = mData.data();
 
     assert((msg != nullptr || len == 0) && hash != nullptr);
     uint64_t state[STATE_SIZE][STATE_SIZE] = {};
 
     // XOR each message byte into the state, and absorb full blocks
     int blockOff = 0;
     for (size_t i = 0; i < len; i++) {
         int j = blockOff >> 3;
         state[j % STATE_SIZE][j / STATE_SIZE] ^= static_cast<uint64_t>(msg[i]) << ((blockOff & 7) << 3);
         blockOff++;
         if (blockOff == BLOCK_SIZE) {
             absorb(state);
             blockOff = 0;
         }
     }
 
     // Final block and padding
     {
         int i = blockOff >> 3;
         state[i % STATE_SIZE][i / STATE_SIZE] ^= UINT64_C(0x01) << ((blockOff & 7) << 3);
         blockOff = BLOCK_SIZE - 1;
         int j = blockOff >> 3;
         state[j % STATE_SIZE][j / STATE_SIZE] ^= UINT64_C(0x80) << ((blockOff & 7) << 3);
         absorb(state);
     }
 
     // Uint64 array to bytes in little endian
     for (int i = 0; i < OUTPUT_SIZE; i++) {
         int j = i >> 3;
         hash[i] = static_cast<uint8_t>(state[j % STATE_SIZE][j / STATE_SIZE] >> ((i & 7) << 3));
     }
 }
 
 void CKeccak256::getHash(const uint8_t msg[], size_t len, uint8_t hashResult[OUTPUT_SIZE])
 {
     CKeccak256 kc;
     kc.Write(&msg[0], len);
     kc.Finalize(hashResult);
 }
 
 void Keccak256(const std::uint8_t msg[], std::size_t len, std::uint8_t hashResult[CKeccak256::OUTPUT_SIZE]){
     CKeccak256 kc;
     kc.Write(&msg[0], len);
     kc.Finalize(hashResult);
 }
 
 void Keccak256D(const std::uint8_t msg[], std::size_t len, std::uint8_t hashResult[CKeccak256::OUTPUT_SIZE]){
     CKeccak256 kc;
     kc.Write(&msg[0], len);
     kc.Finalize(hashResult);
     kc.Reset().Write(hashResult, CKeccak256::OUTPUT_SIZE).Finalize(hashResult);
 }