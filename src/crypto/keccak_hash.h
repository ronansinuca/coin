
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef union 
{
    uint64_t word64s[4];
    uint32_t word32s[8];
    uint8_t bytes[32];
    char str[32];
} keccak_hash256;

typedef union 
{
    uint64_t word64s[8];
    uint32_t word32s[16];
    uint8_t bytes[64];
    char str[64];
} keccak_hash512;


keccak_hash256 hash_keccak256(const uint8_t* data, size_t size);
keccak_hash512 hash_keccak512(const uint8_t* data, size_t size);

#ifdef __cplusplus
}
#endif



