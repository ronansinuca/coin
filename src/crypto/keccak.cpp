// //////////////////////////////////////////////////////////
// keccak.cpp
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#include <crypto/common.h>
#include <crypto/keccak.h>
#include <crypto/keccak_hash.h>
#include <tinyformat.h>

/// return latest hash as 16 hex characters
std::string CKeccak256::getHex()
{
    // convert hash to string
    static const char dec2hex[16 + 1] = "0123456789abcdef";

    // number of significant elements in hash (uint64_t)
    unsigned int hashLength = OUTPUT_SIZE;// hash_len();

    std::vector<unsigned char> hash;
    Finalize(&hash);

    std::string result;
    for (unsigned int i = 0; i < hashLength; i++) {
        // convert a byte to hex
        unsigned char oneByte = (unsigned char)(hash[i]);
        result += dec2hex[oneByte >> 4];
        result += dec2hex[oneByte & 15];
    }

    return result;
}

/* CKeccak256 */
CKeccak256& CKeccak256::Finalize(unsigned char *hash)
{
    keccak_hash256 hash256 = hash_keccak256(m_data.data(), m_data.size());
    for (size_t i = 0; i < CKeccak256::OUTPUT_SIZE; i++)
    {
        hash[i] = hash256.bytes[i];
    }   
    return *this; 
}

CKeccak256& CKeccak256::Finalize(std::vector<unsigned char> *hash)
{
    keccak_hash256 hash256 = hash_keccak256(m_data.data(), m_data.size());
    for (size_t i = 0; i < CKeccak256::OUTPUT_SIZE; i++)
    {
        hash->push_back(hash256.bytes[i]);
    }
    return *this; 
}


/* CKeccak512 */

/// return latest hash as 16 hex characters
std::string CKeccak512::getHex()
{
    // convert hash to string
    static const char dec2hex[16 + 1] = "0123456789abcdef";

    // number of significant elements in hash (uint64_t)
    unsigned int hashLength = OUTPUT_SIZE;// hash_len();

    std::vector<unsigned char> hash;
    Finalize(&hash);

    std::string result;
    for (unsigned int i = 0; i < hashLength; i++) {
        // convert a byte to hex
        unsigned char oneByte = (unsigned char)(hash[i]);
        result += dec2hex[oneByte >> 4];
        result += dec2hex[oneByte & 15];
    }

    return result;
}

CKeccak512& CKeccak512::Finalize(unsigned char *hash)
{
    keccak_hash512 hash512 = hash_keccak512(m_data.data(), m_data.size());
    for (size_t i = 0; i < CKeccak512::OUTPUT_SIZE; i++)
    {
        hash[i] = hash512.bytes[i];
    }  
    return *this;  
}

CKeccak512& CKeccak512::Finalize(std::vector<unsigned char> *hash)
{
    keccak_hash512 hash512 = hash_keccak512(m_data.data(), m_data.size());
    for (size_t i = 0; i < CKeccak512::OUTPUT_SIZE; i++)
    {
        hash->push_back(hash512.bytes[i]);
    } 
    return *this;
}



void Keccak256(const uint8_t msg[], std::size_t len, uint8_t hashResult[CKeccak256::OUTPUT_SIZE])
{
    CKeccak256 kc;
    kc.Write(&msg[0], len);
    kc.Finalize(hashResult);
}

void Keccak256D(const uint8_t msg[], std::size_t len, uint8_t hashResult[CKeccak256::OUTPUT_SIZE])
{
    CKeccak256 kc;
    kc.Write(&msg[0], len);
    kc.Finalize(hashResult);
    kc.Reset();
    kc.Write(hashResult, CKeccak256::OUTPUT_SIZE);
    kc.Finalize(hashResult);
}



void Keccak512(const uint8_t msg[], std::size_t len, uint8_t hashResult[CKeccak512::OUTPUT_SIZE])
{
    CKeccak512 kc;
    kc.Write(&msg[0], len);
    kc.Finalize(hashResult);
}