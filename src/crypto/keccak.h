// //////////////////////////////////////////////////////////
// keccak.h
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#pragma once

// #include "hash.h"
#include <string>
#include <vector>

// define fixed size integer types
#ifdef _MSC_VER
// Windows
typedef unsigned __int8 uint8_t;
typedef unsigned __int64 uint64_t;
#else
// GCC
#include <stdint.h>
#endif

#include <span.h>
#include <uint256.h>

/// compute CKeccak hash (designated SHA3)

class CKeccak //: public Hash
{
public:
    /// same as reset()
    explicit CKeccak();

    /// restart
    CKeccak& Reset();

    /// add arbitrary number of bytes  
    CKeccak& Write(const uint8_t* data, size_t numBytes);

    CKeccak& Write(std::vector<uint8_t> data)
    {
        return Write(data.data(), data.size());
    }

    CKeccak& Write(Span<const uint8_t> data)
    {
        return Write(data.data(), data.size());
    }

    CKeccak& Write(std::string data)
    {
        return Write((uint8_t*)data.c_str(), data.size());
    }

    CKeccak& Write(uint8_t data)
    {
        return Write(&data, sizeof(data));
    }

    CKeccak& Write(uint16_t data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak& Write(uint32_t data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak& Write(uint64_t data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak& Write(float data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak& Write(uint256 data)
    {
        return Write(data.begin(), data.size());
    }

    virtual CKeccak& Finalize(unsigned char *hash) { return *this; }
    virtual CKeccak& Finalize(std::vector<unsigned char> *hash) { return *this; }

    /// return latest hash as hex characters
    std::string getHex();

    ///  return a length of data in bytes
    size_t Size() { return m_data.size(); }
    int hash_len() { return m_bits / 8; }

protected:
    std::vector<u_int8_t> m_data;
    /// variant
    int m_bits;
};


class CKeccak256 : public CKeccak
{
public:
    static constexpr int OUTPUT_SIZE = 32;
    CKeccak256()
    {
        m_bits = 256;
        Reset();
    }
    
    CKeccak& Finalize(unsigned char *hash) override;
    CKeccak& Finalize(std::vector<unsigned char> *hash) override;
};

class CKeccak512 : public CKeccak
{
public:
    static constexpr int OUTPUT_SIZE = 64;
    CKeccak512()
    {
        m_bits = 512;
        Reset();
    }
    
    CKeccak& Finalize(unsigned char *hash) override;
    CKeccak& Finalize(std::vector<unsigned char> *hash) override;
};

/*
    Compute a Keccak256 hash
*/
void Keccak256(const uint8_t data[], std::size_t len, uint8_t hashResult[CKeccak256::OUTPUT_SIZE]);

/*
    Compute a Keccak256 double hash
*/
void Keccak256D(const uint8_t data[], std::size_t len, uint8_t hashResult[CKeccak256::OUTPUT_SIZE]);


void Keccak512(const uint8_t msg[], std::size_t len, uint8_t hashResult[CKeccak512::OUTPUT_SIZE]);