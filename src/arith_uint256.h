// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin developers
// Copyright (c) 2015-2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_ARITH_UINT256_H
#define NEXA_ARITH_UINT256_H

#include <assert.h>
#include <cstring>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <vector>

class uint256;

class uint_error : public std::runtime_error
{
public:
    explicit uint_error(const std::string &str) : std::runtime_error(str) {}
};

class ZpcAvoider // Zero pointer case avoider -- so base_uint(0) calls base_uint(uint64_t).
{
public:
    ZpcAvoider(const uint32_t *d) : data(d) {}
    const uint32_t *data;
};

/** Template base class for unsigned big integers. */
template <unsigned int BITS>
class base_uint
{
    // Make every base_uint a friend of every other so we can convert
    template <unsigned int B>
    friend class base_uint;

protected:
    enum
    {
        WIDTH = BITS / 32
    };
    // Note that the least significant word is pn[0]
    uint32_t pn[WIDTH];

    explicit base_uint(const ZpcAvoider &underlyingStorage)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = underlyingStorage.data[i];
    }

public:
    base_uint()
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = 0;
    }

    base_uint(const base_uint &b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = b.pn[i];
    }

    base_uint &operator=(const base_uint &b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = b.pn[i];
        return *this;
    }

    explicit base_uint(uint64_t b)
    {
        pn[0] = (unsigned int)b;
        pn[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < WIDTH; i++)
            pn[i] = 0;
    }

    explicit base_uint(const std::string &str);

    bool operator!() const
    {
        for (int i = 0; i < WIDTH; i++)
            if (pn[i] != 0)
                return false;
        return true;
    }

    const base_uint operator~() const
    {
        base_uint ret;
        for (int i = 0; i < WIDTH; i++)
            ret.pn[i] = ~pn[i];
        return ret;
    }

    const base_uint operator-() const
    {
        base_uint ret;
        for (int i = 0; i < WIDTH; i++)
            ret.pn[i] = ~pn[i];
        ret++;
        return ret;
    }

    double getdouble() const;
    void setdouble(double val);

    base_uint &operator=(uint64_t b)
    {
        pn[0] = (unsigned int)b;
        pn[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < WIDTH; i++)
            pn[i] = 0;
        return *this;
    }

    base_uint &operator^=(const base_uint &b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] ^= b.pn[i];
        return *this;
    }

    base_uint &operator&=(const base_uint &b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] &= b.pn[i];
        return *this;
    }

    base_uint &operator|=(const base_uint &b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] |= b.pn[i];
        return *this;
    }

    base_uint &operator^=(uint64_t b)
    {
        pn[0] ^= (unsigned int)b;
        pn[1] ^= (unsigned int)(b >> 32);
        return *this;
    }

    base_uint &operator|=(uint64_t b)
    {
        pn[0] |= (unsigned int)b;
        pn[1] |= (unsigned int)(b >> 32);
        return *this;
    }

    base_uint &operator<<=(unsigned int shift);
    base_uint &operator>>=(unsigned int shift);

    base_uint &operator+=(const base_uint &b)
    {
        uint64_t carry = 0;
        for (int i = 0; i < WIDTH; i++)
        {
            uint64_t n = carry + pn[i] + b.pn[i];
            pn[i] = n & 0xffffffff;
            carry = n >> 32;
        }
        return *this;
    }

    base_uint &operator-=(const base_uint &b)
    {
        *this += -b;
        return *this;
    }

    base_uint &operator+=(unsigned long long int b64)
    {
        base_uint b;
        b = b64;
        *this += b;
        return *this;
    }

    template <typename T = uint64_t, std::enable_if_t<!std::is_same_v<T, unsigned long long>, int> = 0>
    base_uint &operator+=(uint64_t b64)
    {
        base_uint b;
        b = b64;
        *this += b;
        return *this;
    }
    base_uint &operator+=(uint32_t bn)
    {
        base_uint b;
        b = bn;
        *this += b;
        return *this;
    }
    base_uint &operator+=(int bn)
    {
        if (bn < 0)
            *this -= -bn;
        else
        {
            base_uint b;
            b = bn;
            *this += b;
        }
        return *this;
    }

    base_uint &operator-=(unsigned long long int b64)
    {
        base_uint b;
        b = b64;
        *this += -b;
        return *this;
    }
    template <typename T = uint64_t, std::enable_if_t<!std::is_same_v<T, unsigned long long>, int> = 0>
    base_uint &operator-=(uint64_t b64)
    {
        base_uint b;
        b = b64;
        *this += -b;
        return *this;
    }

    base_uint &operator-=(uint32_t bn)
    {
        base_uint b;
        b = bn;
        *this += -b;
        return *this;
    }
    base_uint &operator-=(int bn)
    {
        if (bn < 0)
            *this += -bn;
        else
        {
            base_uint b;
            b = bn;
            *this += -b;
        }
        return *this;
    }

    base_uint &operator*=(uint32_t b32);
    base_uint &operator*=(const base_uint &b);
    base_uint &operator/=(const base_uint &b);

    base_uint &operator++()
    {
        // prefix operator
        int i = 0;
        while (++pn[i] == 0 && i < WIDTH - 1)
            i++;
        return *this;
    }

    const base_uint operator++(int)
    {
        // postfix operator
        const base_uint ret = *this;
        ++(*this);
        return ret;
    }

    base_uint &operator--()
    {
        // prefix operator
        int i = 0;
        while (--pn[i] == (uint32_t)-1 && i < WIDTH - 1)
            i++;
        return *this;
    }

    const base_uint operator--(int)
    {
        // postfix operator
        const base_uint ret = *this;
        --(*this);
        return ret;
    }

    int CompareTo(const base_uint &b) const;
    bool EqualTo(uint64_t b) const;

    friend inline const base_uint operator+(const base_uint &a, const base_uint &b) { return base_uint(a) += b; }
    friend inline const base_uint operator-(const base_uint &a, const base_uint &b) { return base_uint(a) -= b; }
    friend inline const base_uint operator*(const base_uint &a, const base_uint &b) { return base_uint(a) *= b; }
    friend inline const base_uint operator/(const base_uint &a, const base_uint &b) { return base_uint(a) /= b; }
    friend inline const base_uint operator|(const base_uint &a, const base_uint &b) { return base_uint(a) |= b; }
    friend inline const base_uint operator&(const base_uint &a, const base_uint &b) { return base_uint(a) &= b; }
    friend inline const base_uint operator^(const base_uint &a, const base_uint &b) { return base_uint(a) ^= b; }
    friend inline const base_uint operator>>(const base_uint &a, int shift) { return base_uint(a) >>= shift; }
    friend inline const base_uint operator<<(const base_uint &a, int shift) { return base_uint(a) <<= shift; }
    friend inline const base_uint operator*(const base_uint &a, uint32_t b) { return base_uint(a) *= b; }
    friend inline const base_uint operator*(const base_uint &a, uint64_t b) { return base_uint(a) *= b; }
    friend inline const base_uint operator*(const base_uint &a, int b) { return base_uint(a) *= b; }
    friend inline const base_uint operator+(const base_uint &a, uint32_t b) { return base_uint(a) += b; }
    friend inline const base_uint operator+(const base_uint &a, uint64_t b) { return base_uint(a) += b; }
    template <typename T = uint64_t, std::enable_if_t<!std::is_same_v<T, unsigned long long>, int> = 0>
    friend inline const base_uint operator+(const base_uint &a, unsigned long long int b)
    {
        return base_uint(a) += b;
    }
    friend inline const base_uint operator+(const base_uint &a, int b) { return base_uint(a) += b; }
    friend inline const base_uint operator-(const base_uint &a, uint32_t b) { return base_uint(a) -= b; }
    friend inline const base_uint operator-(const base_uint &a, uint64_t b) { return base_uint(a) -= b; }
    template <typename T = uint64_t, std::enable_if_t<!std::is_same_v<T, unsigned long long>, int> = 0>
    friend inline const base_uint operator-(const base_uint &a, unsigned long long int b)
    {
        return base_uint(a) -= b;
    }
    friend inline const base_uint operator-(const base_uint &a, int b) { return base_uint(a) -= b; }
    friend inline bool operator==(const base_uint &a, const base_uint &b)
    {
        return memcmp(a.pn, b.pn, sizeof(a.pn)) == 0;
    }
    friend inline bool operator!=(const base_uint &a, const base_uint &b)
    {
        return memcmp(a.pn, b.pn, sizeof(a.pn)) != 0;
    }
    friend inline bool operator>(const base_uint &a, const base_uint &b) { return a.CompareTo(b) > 0; }
    friend inline bool operator>(const base_uint &a, unsigned int b) { return a.CompareTo(base_uint(b)) > 0; }
    friend inline bool operator<(const base_uint &a, const base_uint &b) { return a.CompareTo(b) < 0; }
    friend inline bool operator<(const base_uint &a, unsigned int b) { return a.CompareTo(base_uint(b)) < 0; }
    friend inline bool operator>=(const base_uint &a, const base_uint &b) { return a.CompareTo(b) >= 0; }
    friend inline bool operator>=(const base_uint &a, unsigned int b) { return a.CompareTo(base_uint(b)) >= 0; }
    friend inline bool operator<=(const base_uint &a, const base_uint &b) { return a.CompareTo(b) <= 0; }
    friend inline bool operator<=(const base_uint &a, unsigned int b) { return a.CompareTo(base_uint(b)) <= 0; }
    friend inline bool operator==(const base_uint &a, uint64_t b) { return a.EqualTo(b); }
    friend inline bool operator!=(const base_uint &a, uint64_t b) { return !a.EqualTo(b); }
    std::string GetHex() const;
    void SetHex(const char *psz);
    void SetHex(const std::string &str);
    std::string ToString() const;

    unsigned int size() const { return sizeof(pn); }
    /**
     * Returns the position of the highest bit set plus one, or zero if the
     * value is zero.
     */
    unsigned int bits() const;

    uint64_t GetLow64() const
    {
        assert(WIDTH >= 2);
        return pn[0] | (uint64_t)pn[1] << 32;
    }
};

/** 256-bit unsigned big integer. */
class arith_uint256 : public base_uint<256>
{
public:
    arith_uint256() {}
    arith_uint256(const base_uint<256> &b) : base_uint<256>(b) {}
    arith_uint256(uint64_t b) : base_uint<256>(b) {}
    explicit arith_uint256(const std::string &str) : base_uint<256>(str) {}
    explicit arith_uint256(const ZpcAvoider &underlyingStorage) : base_uint<256>(underlyingStorage) {}
    /**
     * The "compact" format is a representation of a whole
     * number N using an unsigned 32bit number similar to a
     * floating point format.
     * The most significant 8 bits are the unsigned exponent of base 256.
     * This exponent can be thought of as "number of bytes of N".
     * The lower 23 bits are the mantissa.
     * Bit number 24 (0x800000) represents the sign of N.
     * N = (-1^sign) * mantissa * 256^(exponent-3)
     *
     * Satoshi's original implementation used BN_bn2mpi() and BN_mpi2bn().
     * MPI uses the most significant bit of the first byte as sign.
     * Thus 0x1234560000 is compact (0x05123456)
     * and  0xc0de000000 is compact (0x0600c0de)
     *
     * Bitcoin only uses this "compact" format for encoding difficulty
     * targets, which are unsigned 256bit quantities.  Thus, all the
     * complexities of the sign bit and using base 256 are probably an
     * implementation accident.
     */
    arith_uint256 &SetCompact(uint32_t nCompact, bool *pfNegative = nullptr, bool *pfOverflow = nullptr);
    uint32_t GetCompact(bool fNegative = false) const;

    friend uint256 ArithToUint256(const arith_uint256 &);
    friend arith_uint256 UintToArith256(const uint256 &);
    friend class arith_uint320;
};

arith_uint256 FromCompact(uint32_t);
uint256 ArithToUint256(const arith_uint256 &);
arith_uint256 UintToArith256(const uint256 &);

// This class is used in the ASERT DAA to avoid overflowing 256 bit numbers
class arith_uint320 : public base_uint<320>
{
public:
    arith_uint320() {}
    arith_uint320(const base_uint<320> &b) : base_uint<320>(b) {}
    arith_uint320(const arith_uint256 &b) : base_uint<320>()
    {
        int i;
        for (i = 0; i < arith_uint256::WIDTH; i++)
            pn[i] = b.pn[i];
        for (; i < WIDTH; i++)
        {
            pn[i] = 0;
        }
    }
    arith_uint256 reduceTo256()
    {
        // This works because the least sig word is index 0, and because this object is larger than 256 bits.
        return arith_uint256(ZpcAvoider(&pn[0]));
    }
};


#endif // NEXA_ARITH_UINT256_H
