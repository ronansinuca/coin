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

template<unsigned int BITS>
class CKeccak //: public Hash
{
public:
    static constexpr int OUTPUT_SIZE = BITS / 8;
public:
    /// same as reset()
    explicit CKeccak();

    /// restart
    CKeccak<BITS>& Reset();

    /// add arbitrary number of bytes  
    CKeccak<BITS>& Write(const uint8_t* data, size_t numBytes);

    CKeccak<BITS>& Write(std::vector<uint8_t> data)
    {
        return Write(data.data(), data.size());
    }

    CKeccak<BITS>& Write(Span<const uint8_t> data)
    {
        return Write(data.data(), data.size());
    }

    CKeccak<BITS>& Write(std::string data)
    {
        return Write((uint8_t*)data.c_str(), data.size());
    }

    CKeccak<BITS>& Write(uint8_t data)
    {
        return Write(&data, sizeof(data));
    }

    CKeccak<BITS>& Write(uint16_t data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak<BITS>& Write(uint32_t data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak<BITS>& Write(uint64_t data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak<BITS>& Write(float data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak<BITS>& Write(uint256 data)
    {
        return Write(data.begin(), data.size());
    }

    virtual CKeccak<BITS>& Finalize(unsigned char *hash) { return *this; }
    virtual CKeccak<BITS>& Finalize(std::vector<unsigned char> *hash) { return *this; }

    /// return latest hash as hex characters
    std::string getHex();

    ///  return a length of data in bytes
    size_t Size() { return m_data.size(); }
    int hash_len() { return BITS / 8; }

protected:
    std::vector<u_int8_t> m_data;
};


class CKeccak256 : public CKeccak<256>
{
public:
    
    CKeccak<256>& Finalize(unsigned char *hash) override;
    CKeccak<256>& Finalize(std::vector<unsigned char> *hash) override;
};

class CKeccak512 : public CKeccak<512>
{
public:
    
    CKeccak<512>& Finalize(unsigned char *hash) override;
    CKeccak<512>& Finalize(std::vector<unsigned char> *hash) override;
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