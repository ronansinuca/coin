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

class CKeccak256 //: public Hash
{
public:
    static constexpr int OUTPUT_SIZE = 32;
public:
    /// same as reset()
    CKeccak256()
    {
        Reset();
    }

    /// restart
    CKeccak256& Reset()
    {
        m_data.empty();
        return *this;
    }

    /// add arbitrary number of bytes  
    CKeccak256& Write(const uint8_t* data, size_t numBytes)
    {
        m_data.insert(m_data.end(), (unsigned char*)data, (unsigned char*)data + numBytes);
        return *this;
    }

    CKeccak256& Write(std::vector<uint8_t> data)
    {
        return Write(data.data(), data.size());
    }

    CKeccak256& Write(Span<const uint8_t> data)
    {
        return Write(data.data(), data.size());
    }

    CKeccak256& Write(std::string data)
    {
        return Write((uint8_t*)data.c_str(), data.size());
    }

    CKeccak256& Write(uint8_t data)
    {
        return Write(&data, sizeof(data));
    }

    CKeccak256& Write(uint16_t data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak256& Write(uint32_t data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak256& Write(uint64_t data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak256& Write(float data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak256& Write(uint256 data)
    {
        return Write(data.begin(), data.size());
    }

    CKeccak256& Finalize(unsigned char *hash);
    CKeccak256& Finalize(std::vector<unsigned char> *hash);

    /// return latest hash as hex characters
    std::string getHex();

    ///  return a length of data in bytes
    size_t Size() { return m_data.size(); }
    int hash_len() { return OUTPUT_SIZE; }

protected:
    std::vector<u_int8_t> m_data;
};




class CKeccak512 //: public Hash
{
public:
    static constexpr int OUTPUT_SIZE = 64;
public:
    /// same as reset()
    CKeccak512()
    {
        Reset();
    }

    /// restart
    CKeccak512& Reset()
    {
        m_data.empty();
        return *this;
    }

    /// add arbitrary number of bytes  
    CKeccak512& Write(const uint8_t* data, size_t numBytes)
    {
        m_data.insert(m_data.end(), (unsigned char*)data, (unsigned char*)data + numBytes);
        return *this;
    }

    CKeccak512& Write(std::vector<uint8_t> data)
    {
        return Write(data.data(), data.size());
    }

    CKeccak512& Write(Span<const uint8_t> data)
    {
        return Write(data.data(), data.size());
    }

    CKeccak512& Write(std::string data)
    {
        return Write((uint8_t*)data.c_str(), data.size());
    }

    CKeccak512& Write(uint8_t data)
    {
        return Write(&data, sizeof(data));
    }

    CKeccak512& Write(uint16_t data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak512& Write(uint32_t data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak512& Write(uint64_t data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak512& Write(float data)
    {
        return Write((uint8_t*)&data, sizeof(data));
    }

    CKeccak512& Write(uint256 data)
    {
        return Write(data.begin(), data.size());
    }

    CKeccak512& Finalize(unsigned char *hash);
    CKeccak512& Finalize(std::vector<unsigned char> *hash);

    /// return latest hash as hex characters
    std::string getHex();

    ///  return a length of data in bytes
    size_t Size() { return m_data.size(); }
    int hash_len() { return OUTPUT_SIZE; }

protected:
    std::vector<u_int8_t> m_data;
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