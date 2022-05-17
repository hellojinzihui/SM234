#include"SM2.h"
#include"SM3.h"
#include"string.h"
#include"stdlib.h"
#include"time.h"
#include"stdio.h"

#if defined(USE_STDPERIPH_DRIVER)
	#include"stm32f10x.h"
	#include"usart.h"
	#define wrap(s) s"\r\n"
#endif
#if defined(_WIN32)
    #include"stdio.h"
	#define wrap(s) s"\n"
#endif

typedef struct uint128_t
{
    uint64_t m_low;
    uint64_t m_high;
} uint128_t;

#ifdef DEBUG
    #define Curve_P {0x722EDB8B08F1DFC3,0x457283915C45517D,0xE8B92435BF6FF7DE,0x8542D69E4C044F18}
    #define Curve_a {0xEC65228B3937E498,0x2F3C848B6831D7E0,0x2417842E73BBFEFF,0x787968B4FA32C3FD}
    #define Curve_b {0x6E12D1DA27C5249A,0xF61D59A5B16BA06E,0x9CF84241484BFE48,0x63E4C6D3B23B0C84}
    #define Curve_n {0x5AE74EE7C32E79B7,0x297720630485628D,0xE8B92435BF6FF7DD,0x8542D69E4C044F18}
    #define Curve_G {{0x4C4E6C147FEDD43D,0x32220B3BADD50BDC,0x746434EBC3CC315E,0x421DEBD61B62EAB6},\
                    {0xA85841B9E46E09A2,0xE5D7FDFCBFA36EA1,0xD47349D2153B70C4,0x0680512BCBB42C07}}
#else
    #define Curve_P {0xFFFFFFFFFFFFFFFF,0xFFFFFFFF00000000,0xFFFFFFFFFFFFFFFF,0xFFFFFFFEFFFFFFFF}
    #define Curve_a {0xFFFFFFFFFFFFFFFC,0xFFFFFFFF00000000,0xFFFFFFFFFFFFFFFF,0xFFFFFFFEFFFFFFFF}
    #define Curve_b {0xDDBCBD414D940E93,0xF39789F515AB8F92,0x4D5A9E4BCF6509A7,0x28E9FA9E9D9F5E34}
    #define Curve_n {0x53BBF40939D54123,0x7203DF6B21C6052B,0xFFFFFFFFFFFFFFFF,0xFFFFFFFEFFFFFFFF}
    #define Curve_G {{0x715A4589334C74C7,0x8FE30BBFF2660BE1,0x5F9904466A39C994,0x32C4AE2C1F198119},\
                    {0x02DF32E52139F0A0,0xD0A9877CC62A4740,0x59BDCEE36B692153,0xBC3736A2F4F6779C}}
#endif

const static uint64_t curve_p[SM2_256] = Curve_P;
const static uint64_t curve_b[SM2_256] = Curve_b;
const static SM2Point curve_G = Curve_G;
const static uint64_t curve_n[SM2_256] = Curve_n;
const static uint64_t curve_a[SM2_256] = Curve_a;

#define SM2_CopyUint64ToByte(b,l,i)                           \
        do{                                                   \
            (b[(i)    ]) =  ((uint8_t)((l) >> 56) & 0xFF);    \
            (b[(i) + 1]) =  ((uint8_t)((l) >> 48) & 0xFF);    \
            (b[(i) + 2]) =  ((uint8_t)((l) >> 40) & 0xFF);    \
            (b[(i) + 3]) =  ((uint8_t)((l) >> 32) & 0xFF);    \
            (b[(i) + 4]) =  ((uint8_t)((l) >> 24) & 0xFF);    \
            (b[(i) + 5]) =  ((uint8_t)((l) >> 16) & 0xFF);    \
            (b[(i) + 6]) =  ((uint8_t)((l) >> 8 ) & 0xFF);    \
            (b[(i) + 7]) =  ((uint8_t)((l)      ) & 0xFF);    \
          }                                                   \
        while (0)

#define SM2_CopyByteToUint64(l,b,i)                  \
        do{                                          \
            (l) = (( uint64_t )b[(i)    ] << 56)     \
                | (( uint64_t )b[(i) + 1] << 48)     \
                | (( uint64_t )b[(i) + 2] << 40)     \
                | (( uint64_t )b[(i) + 3] << 32)     \
                | (( uint64_t )b[(i) + 4] << 24)     \
                | (( uint64_t )b[(i) + 5] << 16)     \
                | (( uint64_t )b[(i) + 6] << 8 )     \
                | (( uint64_t )b[(i) + 7]      );    \
          }                                          \
        while (0)  

/* Returns nonzero if bit p_bit of p_vli is set. */
static uint64_t vli_testBit(uint64_t *p_vli, uint32_t p_bit)
{
    return (p_vli[p_bit/64] & ((uint64_t)1 << (p_bit % 64)));
}

/* Counts the number of 64-bit "digits" in p_vli. */
static uint32_t vli_numDigits(uint64_t* p_vli)
{
    int i;
    /* Search from the end until we find a non-zero digit.
       We do it in reverse because we expect that most digits will be nonzero. */
    for (i = SM2_256 - 1; i >= 0 && p_vli[i] == 0; --i)
    {
    }

    return (i + 1);
}

/* Counts the number of bits required for p_vli. */
static uint32_t vli_numBits(uint64_t *p_vli)
{
    uint32_t i;
    uint64_t l_digit;
    
    uint32_t l_numDigits = vli_numDigits(p_vli);
    if(l_numDigits == 0)
    {
        return 0;
    }

    l_digit = p_vli[l_numDigits - 1];
    for(i=0; l_digit; ++i)
    {
        l_digit >>= 1;
    }
    
    return ((l_numDigits - 1) * 64 + i);
}

static uint128_t mul_64_64(uint64_t p_left, uint64_t p_right)
{
    uint128_t l_result;

    uint64_t a0 = p_left & 0xffffffffull;
    uint64_t a1 = p_left >> 32;
    uint64_t b0 = p_right & 0xffffffffull;
    uint64_t b1 = p_right >> 32;

    uint64_t m0 = a0 * b0;
    uint64_t m1 = a0 * b1;
    uint64_t m2 = a1 * b0;
    uint64_t m3 = a1 * b1;

    m2 += (m0 >> 32);
    m2 += m1;
    if (m2 < m1)
    { // overflow
        m3 += 0x100000000ull;
    }

    l_result.m_low = (m0 & 0xffffffffull) | (m2 << 32);
    l_result.m_high = m3 + (m2 >> 32);

    return l_result;
}

static uint128_t add_128_128(uint128_t a, uint128_t b)
{
    uint128_t l_result;
    l_result.m_low = a.m_low + b.m_low;
    l_result.m_high = a.m_high + b.m_high + (l_result.m_low < a.m_low);
    return l_result;
}

static void vli_clear(uint64_t *p_vli)
{
    uint32_t i;
    for(i=0; i<SM2_256; ++i)
    {
        p_vli[i] = 0;
    }
}

/* Sets p_dest = p_src. */
static void vli_set(uint64_t *p_dest, uint64_t *p_src)
{
    uint32_t i;
    for(i=0; i<SM2_256; ++i)
    {
        p_dest[i] = p_src[i];
    }
}

/* Returns 1 if p_vli == 0, 0 otherwise. */
static int vli_isZero(uint64_t *p_vli)
{
    uint32_t i;
    for(i = 0; i < SM2_256; ++i)
    {
        if(p_vli[i])
        {
            return 0;
        }
    }
    return 1;
}

/* Computes p_result = p_in << c, returning carry. Can modify in place (if p_result == p_in). 0 < p_shift < 64. */
static uint64_t vli_lshift(uint64_t *p_result, uint64_t *p_in, uint32_t p_shift)
{
    uint64_t l_carry = 0;
    uint32_t i;
    for(i = 0; i < SM2_256; ++i)
    {
        uint64_t l_temp = p_in[i];
        p_result[i] = (l_temp << p_shift) | l_carry;
        l_carry = l_temp >> (64 - p_shift);
    }
    
    return l_carry;
}

/* Computes p_vli = p_vli >> 1. */
static void vli_rshift1(uint64_t *p_vli)
{
    uint64_t *l_end = p_vli;
    uint64_t l_carry = 0;
    
    p_vli += SM2_256;
    while(p_vli-- > l_end)
    {
        uint64_t l_temp = *p_vli;
        *p_vli = (l_temp >> 1) | l_carry;
        l_carry = l_temp << 63;
    }
}

/* Computes p_result = p_left + p_right, returning carry. Can modify in place. */
static uint64_t vli_add(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint64_t l_carry = 0;
    uint32_t i;
    for(i=0; i<SM2_256; ++i)
    {
        uint64_t l_sum = p_left[i] + p_right[i] + l_carry;
        if(l_sum != p_left[i])
        {
            l_carry = (l_sum < p_left[i]);
        }
        p_result[i] = l_sum;
    }
    return l_carry;
}

/* Returns sign of p_left - p_right. */
static int vli_cmp(uint64_t *p_left, uint64_t *p_right)
{
    int i;
    for(i = SM2_256-1; i >= 0; --i)
    {
        if(p_left[i] > p_right[i])
        {
            return 1;
        }
        else if(p_left[i] < p_right[i])
        {
            return -1;
        }
    }
    return 0;
}

/* Computes p_result = p_left - p_right, returning borrow. Can modify in place. */
static uint64_t vli_sub(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint64_t l_borrow = 0;
    uint32_t i;
    for(i=0; i<SM2_256; ++i)
    {
        uint64_t l_diff = p_left[i] - p_right[i] - l_borrow;
        if(l_diff != p_left[i])
        {
            l_borrow = (l_diff > p_left[i]);
        }
        p_result[i] = l_diff;
    }
    return l_borrow;
}

static void vli_mult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right)
{
    uint128_t r01 = {0, 0};
    uint64_t r2 = 0;
    
    uint32_t i, k;
    
    /* Compute each digit of p_result in sequence, maintaining the carries. */
    for(k=0; k < SM2_256*2 - 1; ++k)
    {
        uint32_t l_min = (k < SM2_256 ? 0 : (k + 1) - SM2_256);
        for(i=l_min; i<=k && i<SM2_256; ++i)
        {
            uint128_t l_product = mul_64_64(p_left[i], p_right[k-i]);
            r01 = add_128_128(r01, l_product);
            r2 += (r01.m_high < l_product.m_high);
        }
        p_result[k] = r01.m_low;
        r01.m_low = r01.m_high;
        r01.m_high = r2;
        r2 = 0;
    }
    
    p_result[SM2_256*2 - 1] = r01.m_low;
}

/* Computes p_result = (p_left + p_right) % p_mod.
   Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod. */
static void vli_modAdd(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod)
{
    uint64_t l_carry = vli_add(p_result, p_left, p_right);
    while(l_carry || vli_cmp(p_result, p_mod) >= 0)
    { /* p_result > p_mod (p_result = p_mod + remainder), so subtract p_mod to get remainder. */
        if (l_carry == 1 && vli_cmp(p_mod, p_result) == 1 )
        {
            l_carry = 0;
        }
        vli_sub(p_result, p_result, p_mod);
        
    }
}

/* Computes p_result = (p_left - p_right) % p_mod.
   Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod. */
static void vli_modSub(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod)
{
    uint64_t l_borrow = vli_sub(p_result, p_left, p_right);
    if(l_borrow)
    { /* In this case, p_result == -diff == (max int) - diff.
         Since -x % d == d - x, we can get the correct result from p_result + p_mod (with overflow). */
        vli_add(p_result, p_result, p_mod);
    }
}

static void vli_square(uint64_t *p_result, uint64_t *p_left)
{
    uint128_t r01 = {0, 0};
    uint64_t r2 = 0;
    
    uint32_t i, k;
    for(k=0; k < SM2_256*2 - 1; ++k)
    {
        uint32_t l_min = (k < SM2_256 ? 0 : (k + 1) - SM2_256);
        for(i=l_min; i<=k && i<=k-i; ++i)
        {
            uint128_t l_product = mul_64_64(p_left[i], p_left[k-i]);
            if(i < k-i)
            {
                r2 += l_product.m_high >> 63;
                l_product.m_high = (l_product.m_high << 1) | (l_product.m_low >> 63);
                l_product.m_low <<= 1;
            }
            r01 = add_128_128(r01, l_product);
            r2 += (r01.m_high < l_product.m_high);
        }
        p_result[k] = r01.m_low;
        r01.m_low = r01.m_high;
        r01.m_high = r2;
        r2 = 0;
    }
    
    p_result[SM2_256*2 - 1] = r01.m_low;
}

#define EVEN(vli) (!(vli[0] & 1))
/* Computes p_result = (1 / p_input) % p_mod. All VLIs are the same size.
   See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
   https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf */
static void vli_modInv(uint64_t *p_result, uint64_t *p_input, uint64_t *p_mod)
{
    uint64_t a[SM2_256], b[SM2_256], u[SM2_256], v[SM2_256];
    uint64_t l_carry;
    int l_cmpResult;
    
    if(vli_isZero(p_input))
    {
        vli_clear(p_result);
        return;
    }

    vli_set(a, p_input);
    vli_set(b, p_mod);
    vli_clear(u);
    u[0] = 1;
    vli_clear(v);
    
    while((l_cmpResult = vli_cmp(a, b)) != 0)
    {
        l_carry = 0;
        if(EVEN(a))
        {
            vli_rshift1(a);
            if(!EVEN(u))
            {
                l_carry = vli_add(u, u, p_mod);
            }
            vli_rshift1(u);
            if(l_carry)
            {
                u[SM2_256-1] |= 0x8000000000000000ull;
            }
        }
        else if(EVEN(b))
        {
            vli_rshift1(b);
            if(!EVEN(v))
            {
                l_carry = vli_add(v, v, p_mod);
            }
            vli_rshift1(v);
            if(l_carry)
            {
                v[SM2_256-1] |= 0x8000000000000000ull;
            }
        }
        else if(l_cmpResult > 0)
        {
            vli_sub(a, a, b);
            vli_rshift1(a);
            if(vli_cmp(u, v) < 0)
            {
                vli_add(u, u, p_mod);
            }
            vli_sub(u, u, v);
            if(!EVEN(u))
            {
                l_carry = vli_add(u, u, p_mod);
            }
            vli_rshift1(u);
            if(l_carry)
            {
                u[SM2_256-1] |= 0x8000000000000000ull;
            }
        }
        else
        {
            vli_sub(b, b, a);
            vli_rshift1(b);
            if(vli_cmp(v, u) < 0)
            {
                vli_add(v, v, p_mod);
            }
            vli_sub(v, v, u);
            if(!EVEN(v))
            {
                l_carry = vli_add(v, v, p_mod);
            }
            vli_rshift1(v);
            if(l_carry)
            {
                v[SM2_256-1] |= 0x8000000000000000ull;
            }
        }
    }
    
    vli_set(p_result, u);
}


/* Computes p_result = (p_left * p_right) % p_mod. */
static void vli_modMult(uint64_t* p_result, uint64_t* p_left, uint64_t* p_right, uint64_t* p_mod)
{
    uint64_t l_product[2 * SM2_256];
    uint64_t l_modMultiple[2 * SM2_256];
    uint32_t l_digitShift, l_bitShift;
    uint32_t l_productBits;
    uint32_t l_modBits = vli_numBits(p_mod);
    uint64_t l_carry;

    vli_mult(l_product, p_left, p_right);
    l_productBits = vli_numBits(l_product + SM2_256);
    if (l_productBits)
    {
        l_productBits += SM2_256 * 64;
    }
    else
    {
        l_productBits = vli_numBits(l_product);
    }

    if (l_productBits < l_modBits)
    { /* l_product < p_mod. */
        vli_set(p_result, l_product);
        return;
    }

    /* Shift p_mod by (l_leftBits - l_modBits). This multiplies p_mod by the largest
       power of two possible while still resulting in a number less than p_left. */
    vli_clear(l_modMultiple);
    vli_clear(l_modMultiple + SM2_256);
    l_digitShift = (l_productBits - l_modBits) / 64;
    l_bitShift = (l_productBits - l_modBits) % 64;
    if (l_bitShift)
    {
        l_modMultiple[l_digitShift + SM2_256] = vli_lshift(l_modMultiple + l_digitShift, p_mod, l_bitShift);
    }
    else
    {
        vli_set(l_modMultiple + l_digitShift, p_mod);
    }

    /* Subtract all multiples of p_mod to get the remainder. */
    vli_clear(p_result);
    p_result[0] = 1; /* Use p_result as a temp var to store 1 (for subtraction) */
    while (l_productBits > SM2_256 * 64 || vli_cmp(l_modMultiple, p_mod) >= 0)
    {
        int l_cmp = vli_cmp(l_modMultiple + SM2_256, l_product + SM2_256);
        if (l_cmp < 0 || (l_cmp == 0 && vli_cmp(l_modMultiple, l_product) <= 0))
        {
            if (vli_sub(l_product, l_product, l_modMultiple))
            { /* borrow */
                vli_sub(l_product + SM2_256, l_product + SM2_256, p_result);
            }
            vli_sub(l_product + SM2_256, l_product + SM2_256, l_modMultiple + SM2_256);
        }
        l_carry = (l_modMultiple[SM2_256] & 0x01) << 63;
        vli_rshift1(l_modMultiple + SM2_256);
        vli_rshift1(l_modMultiple);
        l_modMultiple[SM2_256 - 1] |= l_carry;

        --l_productBits;
    }
    vli_set(p_result, l_product);
}

/* p_result = p_left | (1<<n) */
static void vli_bitset1(uint64_t *p_result,uint16_t n)
{
    p_result[n>>6] |= ((uint64_t)0x0000000000000001 << (n%64));
}

/* p_result = p_left & ~( 1<<n ) */
static void vli_bitset0(uint64_t* p_result, uint16_t n)
{
    p_result[n >> 6] &= ~((uint64_t)0x0000000000000001 << (n % 64));
}

/* p_result = sqrt(p_left) */
static void vli_sqrt(uint64_t *p_result,uint64_t *p_left)
{
    uint32_t numbits,bitsmin = 0,bitsmax = 0;
    uint64_t p_cmp[SM2_256]= {0,0,0,0};
    numbits = vli_numBits(p_left);
    bitsmax = numbits - 1;
    for ( ; ; )
    {
        if( (numbits / 2))
        {
            
        }
        
    }
    

}

/**
 * @brief  SM2_GetRandomNumber
 * @note   Get Random Number
 * @param  *RandomNumber: output random
 * @param  MAX: max randnumber is (MAX - 1)
 * @retval None
 */
static void SM2_GetRandomNumber(uint64_t *RandomNumber,uint64_t *MAX)
{
    uint8_t i;
#if defined(WINDOWS)
    srand( clock() );
#elif defined(ARM)
	srand( SysTick->VAL );
#endif
    RandomNumber[0] = \
        (((uint64_t)(rand() & 0xFFFF)) << 48) | \
        (((uint64_t)(rand() & 0xFFFF)) << 32) | \
        (((uint64_t)(rand() & 0xFFFF)) << 16) | \
        ((uint64_t)(rand() & 0xFFFF));
    RandomNumber[1] = \
        (((uint64_t)(rand() & 0xFFFF)) << 48) | \
        (((uint64_t)(rand() & 0xFFFF)) << 32) | \
        (((uint64_t)(rand() & 0xFFFF)) << 16) | \
        ((uint64_t)(rand() & 0xFFFF));
    RandomNumber[2] = \
        (((uint64_t)(rand() & 0xFFFF)) << 48) | \
        (((uint64_t)(rand() & 0xFFFF)) << 32) | \
        (((uint64_t)(rand() & 0xFFFF)) << 16) | \
        ((uint64_t)(rand() & 0xFFFF));
    RandomNumber[3] = \
        (((uint64_t)(rand() & 0xFFFF)) << 48) | \
        (((uint64_t)(rand() & 0xFFFF)) << 32) | \
        (((uint64_t)(rand() & 0xFFFF)) << 16) | \
        ((uint64_t)(rand() & 0xFFFF));
    for ( i = 0; i < SM2_256; i++)
    {
        if (RandomNumber[SM2_256 - 1 - i] > MAX[SM2_256 - 1 - i])
        {
            RandomNumber[SM2_256 - 1 - i] %= MAX[SM2_256 - 1 - i];
            break;
        }
    }
}

/**
 * @brief  SM2_GeneratePrivateKey
 * @note   Generate Private Key
 * @param  *d: Point to private key
 * @retval None
 */
static void SM2_GeneratePrivateKey(uint64_t *d)
{
    uint64_t MAX[4] = Curve_n;
    MAX[0] -= 1;
    SM2_GetRandomNumber(d,MAX);
}
/**
 * @brief  SM2_PointDouble
 * @note   Q(x3,y3) = 2 * P(x,y)
 * @param  *Result: Point Q
 * @param  *Left: Point p
 * @retval None
 */
static void SM2_PointDouble(SM2Point *Result,SM2Point *Left)
{
    uint64_t l[SM2_256] = { 0 }, t[SM2_256] = { 0 }, t1[SM2_256] = { 0 }, _3[SM2_256] = { 3 };

    SM2Point T_Point;

    vli_modMult(l, _3, Left->x,(uint64_t *)curve_p); /* λ = 3*x */
    vli_modMult(l, l, Left->x, (uint64_t *)curve_p);  /* λ = 3*x^2 */
    vli_modAdd(l, l, (uint64_t*)curve_a, (uint64_t *)curve_p);   /* λ = 3*x^2+a */
    vli_modAdd(t,Left->y,Left->y, (uint64_t *)curve_p); /* t = 2y */
    vli_modInv(t, t, (uint64_t *)curve_p); /* t = 1/2y */
    vli_modMult(l, l, t, (uint64_t *)curve_p); /* l =  (3*x^2+a)/2y */

    vli_modAdd(t,Left->x,Left->x, (uint64_t *)curve_p); /* t = 2*x */
    vli_modMult(t1, l, l, (uint64_t *)curve_p); /* t1 = l^2 */
    vli_modSub((&T_Point)->x, t1, t, (uint64_t *)curve_p); /* x3 = l^2 - x - x */
    
    vli_modSub(t,Left->x, (&T_Point)->x, (uint64_t *)curve_p); /*t = x1 - x3*/
    vli_modMult(t, l, t, (uint64_t *)curve_p); /* t = l * (x - x3) */
    vli_modSub((&T_Point)->y,t,Left->y, (uint64_t *)curve_p); /* y3 = l(x - x3) - y */

    vli_set(Result->x, (&T_Point)->x);
    vli_set(Result->y, (&T_Point)->y);
}
/**
 * @brief  SM2_PointDouble
 * @note    Q(x3,y3) = P1(x1,y1) + P2(x2,y2)
 * @param  *Result: Q(x3,y3)
 * @param  *Left: P2(x2,y2)
 * @param  *Right: P1(x1,y1)
 * @retval None
 */
static void SM2_PointAdd(SM2Point *Result,SM2Point *Left,SM2Point *Right)
{
    uint64_t l[SM2_256] = { 0 }, t[SM2_256] = { 0 }, t1[SM2_256] = { 0 };
    
    SM2Point T_Point;

    vli_modSub(l,Left->y,Right->y, (uint64_t *)curve_p); /* l = (y2 - y1)mod p */
    vli_modSub(t,Left->x,Right->x, (uint64_t *)curve_p); /* t = (x2 - x1)mod p */
    vli_modInv(t, t, (uint64_t *)curve_p); /* t = 1/(x2 - x1) mod p */
    vli_modMult(l, l, t, (uint64_t *)curve_p); /* l = (y2 - y1)/(x2 - x1) */

    vli_modAdd(t,Left->x, Right->x, (uint64_t *)curve_p); /* t = x1 + x2 */
    vli_modMult(t1, l, l, (uint64_t *)curve_p); /* t1 = l^2 */
    vli_modSub((&T_Point)->x, t1, t, (uint64_t *)curve_p); /* x3 = l^2 - x1 - x2 */
    
    vli_modSub(t, Right->x, (&T_Point)->x, (uint64_t *)curve_p); /*t = x1 - x3*/
    vli_modMult(t, l, t, (uint64_t *)curve_p); /* t = l * (x1 - x3) */
    vli_modSub((&T_Point)->y, t, Right->y, (uint64_t *)curve_p); /* y3 = l(x1 - x3) - y1 */

    vli_set(Result->x, (&T_Point)->x);
    vli_set(Result->y, (&T_Point)->y);
}

#define EVEN_H(vli) (vli[SM2_256-1] & 0x8000000000000000)
/**
 * @brief  SM2_PointMult
 * @note   Q = k * P
 * @param  *Result: Q
 * @param  Left: P
 * @param  *k: k
 * @retval None
 */
static void SM2_PointMult(SM2Point *Result,const SM2Point Left,const uint64_t *k)
{
    uint16_t i = 0;
    SM2Point T_Point;
    uint64_t T_vli[SM2_256];

    vli_set(T_vli,(uint64_t *)k);
    vli_set((&T_Point)->x, (uint64_t *)(&Left)->x);
    vli_set((&T_Point)->y, (uint64_t *)(&Left)->y);

    for (i = 0; i < Bits; i++)
    {
        if (EVEN_H(T_vli))
        {
            break;
        }
        vli_lshift(T_vli, T_vli, 1);
    }
    
    vli_lshift(T_vli, T_vli, 1);
    i++;
    for (; i < Bits; i++)
    {
        SM2_PointDouble(&T_Point,&T_Point);
        if( EVEN_H(T_vli) )
        {
            SM2_PointAdd(&T_Point,&T_Point, (SM2Point*)&Left);
        }
        vli_lshift(T_vli, T_vli, 1);
    }
    
    vli_set(Result->x, (&T_Point)->x);
    vli_set(Result->y, (&T_Point)->y);
}

/**
 * @brief  SM2_GeneratePublicKey
 * @note   Get Public Key
 * @param  *d: Private Key
 * @param  *P: PublicKey
 * @retval None
 */
static void SM2_GeneratePublicKey(uint64_t *d,SM2Point *P)
{
    SM2_PointMult(P,curve_G,d);
}

/**
 * @brief  SM2DSA_VerifyPoint
 * @note   if Q on the curve,return 0.
 * @param  *Point:  Q
 * @retval 0:Verify OK
 */
static int SM2_VerifyPoint(const SM2Point *Point)
{
    uint64_t t[SM2_256],t1[SM2_256];
    vli_modMult(t, (uint64_t*)Point->x, (uint64_t*)Point->x, (uint64_t *)curve_p);
    vli_modMult(t,t, (uint64_t*)Point->x, (uint64_t *)curve_p);
    vli_modMult(t1, (uint64_t*)curve_a, (uint64_t*)Point->x, (uint64_t *)curve_p);
    vli_modAdd(t,t,t1,(uint64_t *)curve_p);
    vli_modAdd(t,t, (uint64_t*)curve_b,(uint64_t *)curve_p);
    vli_modMult(t1, (uint64_t*)Point->y, (uint64_t*)Point->y, (uint64_t *)curve_p);
    return vli_cmp(t,t1);
}

//#define DEBUG
/**
 * @brief  SM2DSA_Signature
 * @note   SM2 DSA Signature
 * @param  *Message: Message
 * @param  MessageLen: Length Of Message
 * @param  ENTLA: Length Of IDA
 * @param  *IDA: ID
 * @param  *PrivateKey: PrivateKey
 * @param  *Signature: Outpu Of Signature
 * @retval returns 1 if Signature was completed
 */
uint8_t SM2DSA_Signature(   const uint8_t *Message,
                            uint32_t MessageLen,
                            uint16_t ENTLA,
                            const uint8_t *IDA, 
                            const uint64_t *PrivateKey,
                            uint8_t *Signature)
{
    SM2Point PublicKey;
    SM2Point T_Point;
    uint8_t *p_Message,*p_ZA,i;
    uint8_t a[32],b[32],Xg[32],Yg[32],Xa[32],Ya[32];
    uint64_t k[SM2_256],t[SM2_256],r[SM2_256],s[SM2_256]={1};

    if (ENTLA <= 0)
    {
        return 0;
    }
    p_Message = malloc(ENTLA/8 + 2 + 6 * 32);
    p_ZA = malloc(32);
    if (p_ZA == 0 || p_Message == 0)
    {
        free(p_ZA);
        free(p_Message);
        return 0;
    }

    /*Get PublicKey*/
    SM2_GeneratePublicKey((uint64_t *)PrivateKey,&PublicKey);

    /*Get SM2 ZA*/
    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyUint64ToByte(a,curve_a[SM2_256 - 1 - i],i*8);
        SM2_CopyUint64ToByte(b,curve_b[SM2_256 - 1 - i],i*8);
        SM2_CopyUint64ToByte(Xg,curve_G.x[SM2_256 - 1 - i],i*8);
        SM2_CopyUint64ToByte(Yg,curve_G.y[SM2_256 - 1 - i],i*8);
        SM2_CopyUint64ToByte(Xa,PublicKey.x[SM2_256 - 1 - i],i*8);
        SM2_CopyUint64ToByte(Ya,PublicKey.y[SM2_256 - 1 - i],i*8);
    } 

    *p_Message = (ENTLA>>8) & 0xFF;
    *(p_Message+1) = ENTLA & 0XFF;
    memcpy(p_Message + 2, IDA, ENTLA / 8);
    memcpy(p_Message + 2 + ENTLA / 8, a, 32);
    memcpy(p_Message + 34 + ENTLA / 8, b, 32);
    memcpy(p_Message + 66 + ENTLA / 8, Xg, 32);
    memcpy(p_Message + 98 + ENTLA / 8, Yg, 32);
    memcpy(p_Message + 130 + ENTLA / 8, Xa, 32);
    memcpy(p_Message + 162 + ENTLA / 8, Ya, 32);

    SM3_ComputeHash(p_Message, 18 + 2 + 6 * 32, p_ZA);
    free(p_Message);

    /*1 Get M' */
    if (MessageLen <= 0)
    {
        return 0;
    }
    p_Message = malloc(MessageLen + 32);
    if (p_Message == 0)
    {
        return 0;
    }

    memcpy(p_Message,p_ZA,32);
    memcpy(p_Message+32,Message,MessageLen);

    /*2 Get e */
    SM3_ComputeHash(p_Message,MessageLen+32,p_Message);

    for ( ; ; )
    {
        /*3 Get Random Number*/
#ifndef DEBUG
        SM2_GetRandomNumber(k,(uint64_t *)curve_n);
        for ( i = 0; i < SM2_256; i++)
        {
            if (k[SM2_256 - 1 - i] > curve_n[SM2_256 - 1 - i])
            {
                k[SM2_256 - 1 - i] %= curve_n[SM2_256 - 1 - i];
                break;
            }
        }
#else
        k[0] = 0x260DBAAE1FB2F96F;
        k[1] = 0xC176D925DD72B727;
        k[2] = 0x94F94E934817663F;
        k[3] = 0x6CB28D99385C175C;
#endif
        /*4 Compute (x1,y1)=[k]G */
        SM2_PointMult(&T_Point,curve_G,k);

        /*5 Compute r=(e+x1) mod n*/
       for ( i = 0; i < SM2_256; i++)
       {
            SM2_CopyByteToUint64(r[SM2_256 - 1 - i],p_Message,i*8);
       }
        vli_modAdd(r,r,(&T_Point)->x,(uint64_t *)curve_n);

        /*6 Compute s = ((1 + dA)?1 ， (k ? r ， dA)) mod n*/
        s[0] = 1;
        s[1] = 0;
        s[2] = 0;
        s[3] = 0;
        vli_modAdd(s,s, (uint64_t*)PrivateKey, (uint64_t*)curve_n);
        vli_modInv(s,s, (uint64_t*)curve_n);
        vli_modMult(t,r, (uint64_t*)PrivateKey, (uint64_t*)curve_n);
        vli_modSub(t,k,t, (uint64_t*)curve_n);
        vli_modMult(s,s,t, (uint64_t*)curve_n);

        vli_add(t,r,k);
        if ( (!vli_isZero(s)) && (!vli_isZero(r)) && vli_cmp(t, (uint64_t*)curve_n))
        {
            break;
        }
    }

    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyUint64ToByte(Signature,r[SM2_256 - 1 - i],8*i);
        SM2_CopyUint64ToByte(Signature,s[SM2_256 - 1 - i],32 + 8*i);
    }

    free(p_Message);
    free(p_ZA);

    return 1;
}

uint8_t SM2DSA_Verify(  const uint8_t *Message,
                        uint32_t MessageLen,
                        uint16_t ENTLA,
                        const uint8_t *IDA, 
                        SM2Point PublicKey,
                        uint8_t *Signature)
{
    uint16_t i;
    uint64_t r[SM2_256],s[SM2_256],t[SM2_256];
    uint8_t a[32],b[32],Xg[32],Yg[32],Xa[32],Ya[32];
    SM2Point T_Point,T1_Point;
    uint8_t *p_Message,*p_ZA;

    //vli_set((&PublicKey)->x,&PublicKeyX);

    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyByteToUint64(r[SM2_256 - 1 - i],Signature,8*i);
        SM2_CopyByteToUint64(s[SM2_256 - 1 - i],Signature,32 + 8*i);   
    }
    
    /*1,2 if r not（ [1,n-1],s not（ [1,n-1] */
    if ( vli_isZero(r) || \
         vli_isZero(s) || \
         vli_cmp((uint64_t *)curve_n,r) != 1 || \
         vli_cmp((uint64_t *)curve_n,s) != 1)
    {
        return 0;
    }

    /*Get Za*/
    if (ENTLA <= 0)
    {
        return 0;
    }
    p_Message = malloc(ENTLA / 8 + 2 + 6 * 32);
    p_ZA = malloc(32);
    if (p_Message == 0 || p_ZA == 0)
    {
        free(p_Message);
        free(p_ZA);
        return 0;
    }
    
    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyUint64ToByte(a,curve_a[SM2_256 - 1 - i],i*8);
        SM2_CopyUint64ToByte(b,curve_b[SM2_256 - 1 - i],i*8);
        SM2_CopyUint64ToByte(Xg,curve_G.x[SM2_256 - 1 - i],i*8);
        SM2_CopyUint64ToByte(Yg,curve_G.y[SM2_256 - 1 - i],i*8);
        SM2_CopyUint64ToByte(Xa,PublicKey.x[SM2_256 - 1 - i],i*8);
        SM2_CopyUint64ToByte(Ya,PublicKey.y[SM2_256 - 1 - i],i*8);
    }

    *p_Message = (ENTLA>>8) & 0xFF;
    *(p_Message+1) = ENTLA & 0XFF;
    memcpy(p_Message + 2, IDA, ENTLA/8);
    memcpy(p_Message + 2 + ENTLA / 8, a, 32);
    memcpy(p_Message + 34 + ENTLA / 8, b, 32);
    memcpy(p_Message + 66 + ENTLA / 8, Xg, 32);
    memcpy(p_Message + 98 + ENTLA / 8, Yg, 32);
    memcpy(p_Message + 130 + ENTLA / 8, Xa, 32);
    memcpy(p_Message + 162 + ENTLA / 8, Ya, 32);

    SM3_ComputeHash(p_Message, 18 + 2 + 6 * 32, p_ZA);

    /*3 Get M"*/
    memcpy(p_Message,p_ZA,32);
    memcpy(p_Message+32,Message,MessageLen);

    /*4 Get e'*/
    SM3_ComputeHash(p_Message,MessageLen + 32,p_Message);
    
    /*5 Compute t = (r + s) mod n*/
    vli_modAdd(t,r,s, (uint64_t*)curve_n);
    if (vli_isZero(t))
    {
        free(p_Message);
        free(p_ZA);
        return 0;
    }
    
    /*6 T_Point(x1, y1)=[s]G + [t]PA */
    SM2_PointMult(&T_Point,curve_G,s);
    SM2_PointMult(&T1_Point,PublicKey,t);
    SM2_PointAdd(&T_Point,&T_Point,&T1_Point);

    /*7 if r = R = (e＞ + x1) mod n */
    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyByteToUint64(t[SM2_256 - 1 - i],p_Message,8*i);
    }
    vli_modAdd(t,t,(&T_Point)->x, (uint64_t*)curve_n);
    if ( vli_cmp(t,r) )
    {
        free(p_Message);
        free(p_ZA);
        return 0;
    }
    else
    {
        free(p_Message);
        free(p_ZA);
        return 1;
    }
}

/**
 * @brief  SM2_KDF
 * @note   KDF function
 * @param  *Z: input message
 * @param  Zlen: length of z,it is byet of z
 * @param  *k: private key
 * @param  klen: length of private key,it is bits of k
 * @retval returns 1 if complete
 */
static uint8_t SM2_KDF(uint8_t *Z,uint16_t Zlen,uint8_t *k,uint32_t klen)
{
    uint32_t ct = 0x00000001;
    uint32_t i;
    uint8_t *p_H,*p_Ha,*p_t;
    
    p_H = malloc(Zlen + 4);
    if (p_H == 0)
    {
        return 0;
    }
    p_Ha = malloc(32 * ((klen/Bits) + (klen%Bits == 0 ? 0:1)));
    if (p_Ha == 0)
    {
        free(p_H);
        return 0;
    }
    p_t = p_Ha;


    for ( i = 1; i == ((klen/Bits) + (klen%Bits == 0 ? 0:1)); i++)
    {
        memcpy(p_H,Z,Zlen);
        p_H[Zlen] = (ct>>24) & 0xFF;
        p_H[Zlen+1] = (ct>>16) & 0xFF;
        p_H[Zlen+2] = (ct>> 8) & 0xFF;
        p_H[Zlen+3] = (ct    ) & 0xFF;
        SM3_ComputeHash(p_H,Zlen + 4,p_t);
        ct++;
        p_t+=32;
    }
    
    memcpy(k,p_Ha,(klen/8) + (klen%8 == 0 ? 0 : 1));

    free(p_H);
    free(p_Ha);

    return 1;
}

/**
 * @brief  SM2_PointToByteStream
 * @note   Change Point To ByteStream
 * @param  Mode: 0:None Compress,1:Compress,2:Blend Compress
 * @param  Point: input point
 * @param  ByteStream: output bytestream
 * @param  ByteStreamLen*: output length of bytestream l
 * @retval None
 */
static void SM2_PointToByteStream(uint8_t Mode,SM2Point Point,uint8_t* ByteStream,uint8_t *ByteStreamLen)
{
    uint8_t i;
    switch (Mode)
    {
    case 0://None Compress
        ByteStream[0] = 0x04;
        for ( i = 0; i < SM2_256; i++)
        {
            SM2_CopyUint64ToByte(ByteStream,Point.x[SM2_256 - 1 -i ],1+8*i);
            SM2_CopyUint64ToByte(ByteStream,Point.y[SM2_256 - 1 -i ],1+32 + 8*i);
        }
        *ByteStreamLen = 65;
        break;
    case 1://Compress
        ByteStream[0] = 2 + (Point.y[0] & 0x01);
        for (i = 0; i < SM2_256; i++)
        {
            SM2_CopyUint64ToByte(ByteStream, Point.x[SM2_256 - 1 - i], 1 + 8 * i);
        }
        *ByteStreamLen = 33;
        break;
    case 2://Blend Compress
        ByteStream[0] = 6 + (Point.y[0] & 0x01);
        for ( i = 0; i < SM2_256; i++)
        {
            SM2_CopyUint64ToByte(ByteStream,Point.x[SM2_256 - 1 -i ],1+8*i);
            SM2_CopyUint64ToByte(ByteStream,Point.y[SM2_256 - 1 -i ],1+32 + 8*i);
        }
        *ByteStreamLen = 65;
        break;
    default:
        break;
    }
}

/**
 * @brief  SM2_GetEncryptMessageLen
 * @note   Use this function to get EncryptMessage Len
 * @param  MessageLen: Origin Message Len
 * @retval Encrypt Message Len
 */
uint32_t SM2_GetEncryptMessageLen(uint32_t MessageLen)
{
    return MessageLen + 65 + 32;
}

//#define DEBUG
/**
 * @brief  SM2_Encrypt
 * @note   Encrypt
 * @param  *Message: input message 
 * @param  MessageLen: length of input message
 * @param  PublicKey: PublicKey
 * @param  *C: Encrypt Message
 * @retval if encypt ok returns 1
 */
uint8_t SM2_Encrypt(    const uint8_t *Message,
                        uint32_t MessageLen,
                        SM2Point PublicKey,
                        uint8_t *C
                   )
{
    SM2Point T_Point,T1_Point;
    uint64_t k[SM2_256];
    uint8_t *p_tmp,*p_t,i,Hash[32];

    if (MessageLen<=0)
    {
        return 0;
    }
    p_tmp = malloc(64+MessageLen);
    if(p_tmp == 0)
    {
        return 0;
    }
    p_t = malloc(MessageLen + 1);
    if(p_t == 0)
    {
        free(p_tmp);
        return 0;
    }

    for ( ; ; )
    {
        /*1 Get k（[1,n-1]*/
#ifdef DEBUG
        k[0] = 0x18E5388D49DD7B4F;
        k[1] = 0x8AFA17425546D490;
        k[2] = 0x5B92FD6C3D957514;
        k[3] = 0x4C62EEFD6ECFC2B9;
#else
        SM2_GetRandomNumber(k, (uint64_t *)curve_n);
#endif
        /*2 Compute C1 = k[G]*/
        SM2_PointMult(&T_Point,curve_G,k);
        /*3 We dont need*/
        /*4 Compute (x2,y2) = k[PB]*/
        SM2_PointMult(&T1_Point,PublicKey,k);
        /*5 Compute t = KDF (x2 || y2, klen)*/
        for ( i = 0; i < SM2_256; i++)
        {
            SM2_CopyUint64ToByte(p_tmp,T1_Point.x[SM2_256 - 1 - i],8*i);
            SM2_CopyUint64ToByte(p_tmp,T1_Point.y[SM2_256 - 1 - i],32+8*i);
        }
        SM2_KDF(p_tmp,64,p_t,(uint32_t)MessageLen * 8);
        p_t[MessageLen] = 0;
        for ( i = 0; i < MessageLen; i++)
        {
            p_t[MessageLen] |= p_t[i]; 
        }
        if (p_t[MessageLen])
        {
            break;
        }
    }
    /*6 Compute C2 = M ^ t*/
    for ( i = 0; i < MessageLen; i++)
    {
        p_t[i] = p_t[i] ^ Message[i];
    }
    /*7 Compute C3 = Hash(x2 || M || y2)*/
    for ( i = 0; i < 32; i++)/*move y2 to last 32 byte*/
    {
        p_tmp[64 + MessageLen - 1 - i] = p_tmp[64  - 1 - i];
    }
    memcpy(p_tmp+32,Message,MessageLen);/*add M after to x1*/
    SM3_ComputeHash(p_tmp,MessageLen + 64,Hash);
    /*8 C = C1 || C2 || C3*/
    SM2_PointToByteStream(0,T_Point,C,&p_t[MessageLen]); /*use p_t[MessageLen] store bytestream len*/
    memcpy(C + p_t[MessageLen],p_t,MessageLen);
    memcpy(C + p_t[MessageLen] + MessageLen,Hash,32);
    free(p_t);
    free(p_tmp);
    
    return 1;
}

/**
 * @brief  SM2_Decrypt
 * @note   SM2 Decrypt
 * @param  *EncryptMessage: Encrypt Message
 * @param  EMLen: Encrypt Message length,Origin Message + 65 + 32
 * @param  *PrivateKey: PrivateKey
 * @param  *DecryptMessage: Decrypt Message
 * @retval 1:DecryptMessage credible,0 DecryptMessage can not to be use
 */
uint8_t SM2_Decrypt(    const uint8_t *EncryptMessage,
                        uint32_t EMLen,
                        uint64_t *PrivateKey,
                        uint8_t *DecryptMessage
                    )
{
    uint8_t *p_tmp,*p_t,i;
    SM2Point T_Point;

    if (EMLen <= 0)
    {
        return 0;
    }
    p_tmp = malloc(EMLen);
    if (p_tmp == 0)
    {
        return 0;
    }

    if (EMLen - 32 - 65 <= 0)
    {
        free(p_tmp);
        return 0;
    }
    p_t = malloc(EMLen-32-65);
    if (p_t == 0)
    {
        free(p_tmp);
        return 0;
    }
    /*1 Verify C1*/
    //memcpy(p_tmp,EncrryptMessage,65);// C1 Use None Compress ,SO C1 lenth = 65 byte
    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyByteToUint64(T_Point.x[SM2_256 - 1 - i],EncryptMessage,1 + 8*i);
        SM2_CopyByteToUint64(T_Point.y[SM2_256 - 1 - i],EncryptMessage,1 + 32 + 8*i);
    }
    if( SM2_VerifyPoint(&T_Point) )
    {
        free(p_tmp);
        free(p_t);
        return 0;
    }
    /*2 Compute [d]*C1 = (x2,y2)*/
    SM2_PointMult(&T_Point,T_Point,PrivateKey);
    /*3 Compute t=KDF (x2|| y2, klen)*/
    //Message byte number = C number - C1 number - C3number ,So Message bit number = 8*(C number - C1 number - C3number)
    for (i = 0; i < SM2_256; i++)
    {
        SM2_CopyUint64ToByte(p_tmp, T_Point.x[SM2_256 - 1 - i], 8 * i);
        SM2_CopyUint64ToByte(p_tmp, T_Point.y[SM2_256 - 1 - i], 32 + 8 * i);
    }
    SM2_KDF(p_tmp,64,p_t,(uint32_t)(EMLen - 65 - 32)*8);
    p_tmp[EMLen - 1] = 0;
    for ( i = 0; i < (EMLen - 65 - 32); i++)
    {
        p_tmp[EMLen - 1] |= p_t[i];
    }
    if (!p_tmp[EMLen - 1])
    {
        free(p_tmp);
        free(p_t);
        return 0;
    }
    /*4 Compute M' = C2 ^ t*/
    for(i=0;i<(EMLen - 65 - 32);i++)
    {
        p_t[i] = p_t[i]^EncryptMessage[65 + i];
    }
    memcpy(DecryptMessage,p_t,EMLen - 65 - 32);
    /*5 Compute u = Hash(x2 || M ＞|| y2)*/
    for ( i = 0; i < 32; i++)//Move y2 after to M'
    {
        p_tmp[32 + (EMLen - 65 - 32) + 32 -1  - i] = p_tmp[63-i];
    }
    memcpy(p_tmp+32,p_t, EMLen - 65 - 32);
    SM3_ComputeHash(p_tmp,EMLen - 65 - 32 + 2*32,p_tmp);
    /*6 Verify if u = C3 ,it is ok*/
    if (memcmp(p_tmp,EncryptMessage+EMLen-32,32))
    {
        memset(p_tmp,0,32);
        free(p_tmp);
        free(p_t);
        return 0;
    }
    else
    {
        free(p_tmp);
        free(p_t);
        return 1;
    }
}

/**
 * @brief  SM2DH_GenerateKey
 * @note   Generate Key
 * @param  *IDA: input IDA
 * @param  ENTLA: input Length Of IDA
 * @param  *IDB: input IDB
 * @param  ENTLB: input Length Of IDB
 * @param  RA: input RA
 * @param  PublicKeyA: input PublicKey - A
 * @param  PublicKeyB: input PublicKey - B
 * @param  PrivateKeyB: input PrivateKey - B
 * @param  klen: input Length Of Shared key
 * @param  *KB: output Shared key
 * @param  *SB: output Select B
 * @retval  Responder to Initiator KEY OK
 */
uint8_t SM2DH_GenerateKeyResponder( const uint8_t *IDA,
                                    uint16_t ENTLA,
                                    const uint8_t *IDB,
                                    uint16_t ENTLB,
                                    SM2Point RA,
                                    SM2Point *RB,
                                    SM2Point PublicKeyA,
                                    SM2Point PublicKeyB,
                                    const uint64_t* PrivateKeyB,
                                    uint16_t klen,
                                    uint8_t *KB,
                                    uint8_t *SB,
                                    uint8_t *S2)
{
    uint8_t *p_tmp,*p_ZA,*p_ZB;
    uint16_t w = 0,i = 0;
    uint64_t rB[4],tmp[4],tmp1[4];
    SM2Point V;

    /*1 Compute RandomNumber*/
#ifdef DEBUG
	rB[3] = 0x33FE21940342161C;
    rB[2] = 0x55619C4A0C060293;
    rB[1] = 0xD543C80AF19748CE;
    rB[0] = 0x176D83477DE71C80;
#else
	SM2_GetRandomNumber(rB, (uint64_t *)curve_n);
#endif
    /*2 Compute RB = [rB]*G*/
    SM2_PointMult(RB,curve_G,rB);
    /*3 Compute ?x2 = 2^w + (x2&(2^w ? 1))*/
    vli_set(tmp,RB->x);
    for ( i = 0; i < Bits; i++)
    {
        if(vli_testBit((uint64_t *)curve_n,Bits - 1 - i))
        {
            w = Bits - 1 - i;
            break;
        }
    }
    vli_bitset1(tmp, w/2 - (w%2 == 0? 1:0) );
    for ( i = 0; i < Bits - 1 - (w/2 - (w%2 == 0? 1:0)); i++)
    {
        vli_bitset0(tmp,Bits - 1 - i);
    }
    /*4 Compute tB = (dB + ?x2 ， rB) mod n*/
    vli_modMult(tmp,tmp,rB,(uint64_t *)curve_n);
    vli_modAdd(tmp,tmp, (uint64_t*)PrivateKeyB,(uint64_t *)curve_n);
    /*5 Verify RA,if Veirfy OK Compute  ?x1 = 2^w + (x1&(2^w ? 1))*/
    if(SM2_VerifyPoint(&RA))
    {
        return 0;
    }
    vli_set(tmp1,(&RA)->x);
    for ( i = 0; i < Bits; i++)
    {
        if(vli_testBit((uint64_t*)curve_n,Bits - 1 - i))
        {
            w = Bits - 1 - i;
            break;
        }
    }
    vli_bitset1(tmp1, w/2 - (w%2 == 0? 1:0) );
    for ( i = 0; i < Bits - 1 - (w/2 - (w%2 == 0? 1:0)); i++)
    {
        vli_bitset0(tmp1,Bits - 1 - i);
    }
    /*6 Compute V = [h ，tB](PA + [ ?x1]RA) = (xV ,yV ),h = 1*/
    SM2_PointMult(&V,RA,tmp1);
    SM2_PointAdd(&V,&V,&PublicKeyA);
    SM2_PointMult(&V,V,tmp);
    /*Compute KB=KDF(xV || yV || ZA || ZB,klen*/
    if (ENTLA <= 0)
    {
        return 0;
    }
    if (ENTLA > ENTLB)
    {
        p_tmp = malloc( 2 + ENTLA/8 + 6*32 );
    }
    else
    {
        p_tmp = malloc( 2 + ENTLB/8 + 6*32 );
    }
    if (p_tmp == 0)
    {
        return 0;
    }
    p_tmp[0] = (ENTLA >> 8) & 0xFF;
    p_tmp[1] = (ENTLA     ) & 0xFF;
    memcpy(p_tmp + 2,IDA,ENTLA/8);
    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyUint64ToByte(p_tmp,curve_a[SM2_256 - 1 - i],2 + ENTLA/8 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,curve_b[SM2_256 - 1 - i],2 + ENTLA/8 + 32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,curve_G.x[SM2_256 - 1 - i],2 + ENTLA/8 + 2*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,curve_G.y[SM2_256 - 1 - i],2 + ENTLA/8 + 3*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,PublicKeyA.x[SM2_256 - 1 - i],2 + ENTLA/8 + 4*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,PublicKeyA.y[SM2_256 - 1 - i],2 + ENTLA/8 + 5*32 + 8*i);
    }
    p_ZA = malloc(32);
    if (p_ZA == 0)
    {
        free(p_tmp);
        return 0;
    }
    SM3_ComputeHash(p_tmp,2 + ENTLA/8 + 6*32,p_ZA);
    p_tmp[0] = (ENTLB >> 8) & 0xFF;
    p_tmp[1] = (ENTLB     ) & 0xFF;
    memcpy(p_tmp + 2,IDB,ENTLB/8);
    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyUint64ToByte(p_tmp,curve_a[SM2_256 - 1 - i],2 + ENTLB/8 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,curve_b[SM2_256 - 1 - i],2 + ENTLB/8 + 32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,curve_G.x[SM2_256 - 1 - i],2 + ENTLB/8 + 2*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,curve_G.y[SM2_256 - 1 - i],2 + ENTLB/8 + 3*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,PublicKeyB.x[SM2_256 - 1 - i],2 + ENTLB/8 + 4*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,PublicKeyB.y[SM2_256 - 1 - i],2 + ENTLB/8 + 5*32 + 8*i);
    }
    p_ZB = malloc(32);
    if (p_ZB == 0)
    {
        free(p_tmp);
        free(p_ZA);
        return 0;
    }
    SM3_ComputeHash(p_tmp,2 + ENTLB/8 + 6*32,p_ZB);
    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyUint64ToByte(p_tmp,V.x[SM2_256 - 1 - i],8*i);
        SM2_CopyUint64ToByte(p_tmp,V.y[SM2_256 - 1 - i],32 + 8*i);
    }
    memcpy(p_tmp + 2*32,p_ZA,32);
    memcpy(p_tmp + 3*32,p_ZB,32);
    SM2_KDF(p_tmp,4*32,KB,klen);
    free(p_tmp);
    /*8 Compute SB= Hash(0x02 ［ yV ［Hash(xV ［ ZA ［ ZB ［ x1 ［ y1 ［ x2 ［ y2))*/
    p_tmp = malloc(7 * 32);
    if (p_tmp == 0)
    {
        free(p_ZA);
        free(p_ZB);
        return 0;
    }
    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyUint64ToByte(p_tmp,V.x[SM2_256 - 1 - i],8*i);
        SM2_CopyUint64ToByte(p_tmp,RA.x[SM2_256 - 1 - i],3*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,RA.y[SM2_256 - 1 - i],4*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,(*RB).x[SM2_256 - 1 - i],5*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,(*RB).y[SM2_256 - 1 - i],6*32 + 8*i);
    }
    memcpy(p_tmp + 32,p_ZA,32);
    memcpy(p_tmp + 2*32,p_ZB,32);
    SM3_ComputeHash(p_tmp,7*32,p_tmp+33);
    p_tmp[0]= 0x02;
    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyUint64ToByte(p_tmp ,V.y[SM2_256 - 1 - i],1 + 8*i);
    }
    SM3_ComputeHash(p_tmp,65,SB);
    p_tmp[0]= 0x03;
    SM3_ComputeHash(p_tmp,65,S2);
    free(p_tmp);
    free(p_ZA);
    free(p_ZB);
    return 1;
}

/**
 * @brief  SM2DH_GenerateKeyInitiator
 * @note   Generate Key Initiator
 * @param  *IDA: input IDA
 * @param  ENTLA: input ENTLA
 * @param  *IDB: input IDB
 * @param  ENTLB: input ENTLB
 * @param  RA: input RA
 * @param  RB: input RB
 * @param  PublicKeyA: input PublicKeyA
 * @param  PublicKeyB: input PublicKeyB
 * @param  PrivateKeyA: input PrivateKeyA
 * @param  klen:  input Length Of Shared key
 * @param  *KA: output KA
 * @param  *SA: output SA
 * @param  *SB: input SB
 * @retval Initiator to Responder KEY OK
 */
uint8_t SM2DH_GenerateKeyInitiator( const uint8_t *IDA,
                                    uint16_t ENTLA,
                                    const uint8_t *IDB,
                                    uint16_t ENTLB,
                                    const uint64_t *rA,
                                    SM2Point RA,
                                    SM2Point RB,
                                    SM2Point PublicKeyA,
                                    SM2Point PublicKeyB,
                                    const uint64_t* PrivateKeyA,
                                    uint16_t klen,
                                    uint8_t *KA,
                                    uint8_t *SA,
                                    const uint8_t *SB)
{
    uint8_t *p_tmp,*p_ZA,*p_ZB;
    uint16_t w = 0,i = 0;
    uint64_t tmp[4],tmp1[4];
    SM2Point U;

    /*3 Compute x1 = 2^w + (x1&(2^w ? 1))*/
    vli_set(tmp,(&RA)->x);
    for ( i = 0; i < Bits; i++)
    {
        if(vli_testBit((uint64_t *)curve_n,Bits - 1 - i))
        {
            w = Bits - 1 - i;
            break;
        }
    }
    vli_bitset1(tmp, w/2 - (w%2 == 0? 1:0) );
    for ( i = 0; i < Bits - 1 - (w/2 - (w%2 == 0? 1:0)); i++)
    {
        vli_bitset0(tmp,Bits - 1 - i);
    }
    /*4 Compute tA = (dA + ?x1 ， rA) mod n*/
    vli_modMult(tmp,tmp, (uint64_t*)rA,(uint64_t*)curve_n);
    vli_modAdd(tmp,tmp, (uint64_t*)PrivateKeyA,(uint64_t*)curve_n);
    /*5 Verify RB,if Veirfy OK Compute   ?x2 = 2^w + (x2&(2^w ? 1))*/
    if(SM2_VerifyPoint(&RB))
    {
        return 0;
    }
    vli_set(tmp1,(&RB)->x);
    for ( i = 0; i < Bits; i++)
    {
        if(vli_testBit((uint64_t*)curve_n,Bits - 1 - i))
        {
            w = Bits - 1 - i;
            break;
        }
    }
    vli_bitset1(tmp1, w/2 - (w%2 == 0? 1:0) );
    for ( i = 0; i < Bits - 1 - (w/2 - (w%2 == 0? 1:0)); i++)
    {
        vli_bitset0(tmp1,Bits - 1 - i);
    }
    /*6 Compute U = [h ，tA](PB + [ ?x2]RB) = (xU,yU),h = 1*/
    SM2_PointMult(&U,RB,tmp1);
    SM2_PointAdd(&U,&U,&PublicKeyB);
    SM2_PointMult(&U,U,tmp);
    /*Compute KA=KDF(xU ［ yU ［ ZA ［ ZB,klen)*/
    if (ENTLA <= 0)
    {
        return 0;
    }
    if (ENTLA > ENTLB)
    {
        p_tmp = malloc( 2 + ENTLA/8 + 6*32 );
    }
    else
    {
        p_tmp = malloc( 2 + ENTLB/8 + 6*32 );
    }
    if (p_tmp == 0)
    {
        return 0;
    }
    p_tmp[0] = (ENTLA >> 8) & 0xFF;
    p_tmp[1] = (ENTLA     ) & 0xFF;
    memcpy(p_tmp + 2,IDA,ENTLA/8);
    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyUint64ToByte(p_tmp,curve_a[SM2_256 - 1 - i],2 + ENTLA/8 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,curve_b[SM2_256 - 1 - i],2 + ENTLA/8 + 32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,curve_G.x[SM2_256 - 1 - i],2 + ENTLA/8 + 2*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,curve_G.y[SM2_256 - 1 - i],2 + ENTLA/8 + 3*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,PublicKeyA.x[SM2_256 - 1 - i],2 + ENTLA/8 + 4*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,PublicKeyA.y[SM2_256 - 1 - i],2 + ENTLA/8 + 5*32 + 8*i);
    }
    p_ZA = malloc(32);
    if (p_ZA == 0)
    {
        free(p_tmp);
        return 0;
    }
    SM3_ComputeHash(p_tmp,2 + ENTLA/8 + 6*32,p_ZA);
    p_tmp[0] = (ENTLB >> 8) & 0xFF;
    p_tmp[1] = (ENTLB     ) & 0xFF;
    memcpy(p_tmp + 2,IDB,ENTLB/8);
    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyUint64ToByte(p_tmp,curve_a[SM2_256 - 1 - i],2 + ENTLB/8 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,curve_b[SM2_256 - 1 - i],2 + ENTLB/8 + 32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,curve_G.x[SM2_256 - 1 - i],2 + ENTLB/8 + 2*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,curve_G.y[SM2_256 - 1 - i],2 + ENTLB/8 + 3*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,PublicKeyB.x[SM2_256 - 1 - i],2 + ENTLB/8 + 4*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,PublicKeyB.y[SM2_256 - 1 - i],2 + ENTLB/8 + 5*32 + 8*i);
    }
    p_ZB = malloc(32);
    if (p_ZB == 0)
    {
        free(p_tmp);
        free(p_ZA);
        return 0;
    }
    SM3_ComputeHash(p_tmp,2 + ENTLB/8 + 6*32,p_ZB);
    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyUint64ToByte(p_tmp,U.x[SM2_256 - 1 - i],8*i);
        SM2_CopyUint64ToByte(p_tmp,U.y[SM2_256 - 1 - i],32 + 8*i);
    }
    memcpy(p_tmp + 2*32,p_ZA,32);
    memcpy(p_tmp + 3*32,p_ZB,32);
    SM2_KDF(p_tmp,4*32,KA,klen);
    free(p_tmp);
    /*8 Compute S1= Hash(0x02 ［ yU ［Hash(xU ［ ZA ［ ZB ［ x1 ［ y1 ［ x2 ［ y2))*/
    p_tmp = malloc(7 * 32);
    if (p_tmp == 0)
    {
        free(p_ZA);
        free(p_ZB);
        return 0;
    }
    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyUint64ToByte(p_tmp,U.x[SM2_256 - 1 - i],8*i);
        SM2_CopyUint64ToByte(p_tmp,RA.x[SM2_256 - 1 - i],3*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,RA.y[SM2_256 - 1 - i],4*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,RB.x[SM2_256 - 1 - i],5*32 + 8*i);
        SM2_CopyUint64ToByte(p_tmp,RB.y[SM2_256 - 1 - i],6*32 + 8*i);
    }
    memcpy(p_tmp + 32,p_ZA,32);
    memcpy(p_tmp + 2*32,p_ZB,32);
    SM3_ComputeHash(p_tmp,7*32,p_tmp+33);
    p_tmp[0]= 0x02;
    for ( i = 0; i < SM2_256; i++)
    {
        SM2_CopyUint64ToByte(p_tmp ,U.y[SM2_256 - 1 - i],1 + 8*i);
    }
    SM3_ComputeHash(p_tmp,65,SA);
    /*9 Verify S1 == SB */
    if(memcmp(SA,SB,32))
    {
        memset(SA,0,32);
        free(p_tmp);
        free(p_ZA);
        free(p_ZB);
        return 0;
    }
    p_tmp[0]= 0x03;
    SM3_ComputeHash(p_tmp,65,SA);
    free(p_tmp);
    free(p_ZA);
    free(p_ZB);
    return 1;
}

uint8_t SM2_Usage(void)
{
    /*SM2DSA*/
    uint64_t PrivateKey[4];
    SM2Point PublicKey;
    uint8_t SIG[64];
    uint16_t ENTLA = 0x0090;
    char* IDA = "ALICE123@YAHOO.COM";
    char* Message = "message digest";

    /*SM2 Encypt and Decrypt*/
    uint64_t PrivateKey1[4];
    uint8_t EncryptMessage[0x100];
    uint8_t DecryptMessage[0x100];
    SM2Point PublicKey1;
    char* Message1 = "encryption standard";
    uint16_t MessageLen = 19;

    /*SM2DH*/
    uint64_t PrivateKeyA[4];
    SM2Point PublicKeyA;
    uint64_t PrivateKeyB[4];
    SM2Point PublicKeyB;
    uint16_t ENTL_A = 0x0090;
    char* ID_A = "ALICE123@YAHOO.COM";
    uint64_t rA[4];
    SM2Point RA,RB;
    uint16_t ENTL_B = 0x0088;
    char* ID_B = "BILL456@YAHOO.COM";    
    uint8_t KA[16],KB[16],SA[32],SB[32],S2[32];
    uint16_t klen = 128;

    /*User*/
    uint8_t res[3],i,j;
    
    /*SM2DSA*/
    SM2_GeneratePrivateKey(PrivateKey);
    SM2DSA_Signature((uint8_t *)Message,14,ENTLA,(uint8_t *)IDA,PrivateKey,SIG);
    SM2_GeneratePublicKey(PrivateKey,&PublicKey);
    res[0] = SM2DSA_Verify((uint8_t *)Message,14,ENTLA,(uint8_t *)IDA,PublicKey,SIG);

    /*SM2 Encypt and Decrypt*/
    SM2_GeneratePrivateKey(PrivateKey1);
    SM2_GeneratePublicKey(PrivateKey1,&PublicKey1);
    SM2_Encrypt((uint8_t *)Message1,19,PublicKey1,EncryptMessage);
    res[1] = SM2_Decrypt(EncryptMessage,SM2_GetEncryptMessageLen(MessageLen),PrivateKey1,DecryptMessage);

    /*SM2DH*/
    /*Alice action*/
#ifdef DEBUG
    rA[3] = 0x83A2C9C8B96E5AF7;
    rA[2] = 0x0BD480B472409A9A;
    rA[1] = 0x327257F1EBB73F5B;
    rA[0] = 0x073354B248668563;
#else
    SM2_GetRandomNumber(rA,(uint64_t *)curve_n);
#endif
    SM2_PointMult(&RA, curve_G, rA);
    SM2_GeneratePrivateKey(PrivateKeyA);
    SM2_GeneratePublicKey(PrivateKeyA, &PublicKeyA);
    /*Bill action*/
    SM2_GeneratePrivateKey(PrivateKeyB);
    SM2_GeneratePublicKey(PrivateKeyB, &PublicKeyB);
    SM2DH_GenerateKeyResponder((uint8_t *)ID_A,ENTL_A,(uint8_t *)ID_B,ENTL_B,RA,&RB,PublicKeyA,PublicKeyB,PrivateKeyB, klen,KB,SB,S2);
    /*Alice action*/
    SM2DH_GenerateKeyInitiator((uint8_t *)ID_A,ENTL_A,(uint8_t *)ID_B,ENTL_B,rA,RA,RB,PublicKeyA,PublicKeyB,PrivateKeyA, klen,KA,SA,SB);
    if (memcmp(S2,SA,32))
    {
        res[2] = 0;
    }
    else
    {
        res[2] = 1;
    }
    
    /*Show*/
    printf(wrap("SM2DSA:"));
    printf(wrap("Message: %s"),Message);
    printf(wrap("ID: %s"),IDA);
    printf("PrivateKey: 0x");
    for ( i = 0; i < 4; i++)
    {
        for (j = 0; j < 8; j++)
        {
            printf("%02x",(uint8_t)(PrivateKey[SM2_256 - 1 - i] >> (56 - j*8)) & 0xff);
        }
    }
    printf(wrap(" "));
    printf("PublicKey-X: 0x");
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 8; j++)
        {
            printf("%02x", (uint8_t)(PublicKey.x[SM2_256 - 1 - i] >> (56 - j * 8)) & 0xff);
        }
    }
    printf(wrap(" "));
    printf("PublicKey-Y: 0x");
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 8; j++)
        {
            printf("%02x", (uint8_t)(PublicKey.y[SM2_256 - 1 - i] >> (56 - j * 8)) & 0xff);
        }
    }
    printf(wrap(" "));

    printf(wrap("Signature:"));
    for (i = 0;i < 64;i++)
    {
        printf("0x%02x ",SIG[i]);
        if (i % 8 == 7)
        {
            printf(wrap(" "));
        }
    }

    if (res[0] == 1)
    {
        printf(wrap("Verify Pass"));
    }
    else
    {
        printf(wrap("Verify Fail"));
    }
    printf(wrap(" "));
    
    printf(wrap("SM2 Encrypt and Decrypt:"));
    printf(wrap("Message: %s"),Message1);
    printf("PrivateKey: 0x");
    for ( i = 0; i < 4; i++)
    {
        for (j = 0; j < 8; j++)
        {
            printf("%02x",(uint8_t)(PrivateKey1[SM2_256 - 1 - i] >> (56 - j*8)) & 0xff);
        }
    }
    printf(wrap(" "));
    
    printf("PublicKey-X: 0x");
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 8; j++)
        {
            printf("%02x", (uint8_t)(PublicKey1.x[SM2_256 - 1 - i] >> (56 - j * 8)) & 0xff);
        }
    }
    printf(wrap(" "));

    printf("PublicKey-Y: 0x");
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 8; j++)
        {
            printf("%02x", (uint8_t)(PublicKey1.y[SM2_256 - 1 - i] >> (56 - j * 8)) & 0xff);
        }
    }
    printf(wrap(" "));

    printf(wrap("Encypt Message:"));
    for (i = 0;i < SM2_GetEncryptMessageLen(MessageLen);i++)
    {
        printf("0x%02x ",EncryptMessage[i]);
        if (i % 8 == 7)
        {
            printf(wrap(" "));
        }
    }
    printf(wrap(" "));

    DecryptMessage[MessageLen] = '\0';
    printf(wrap("Decrypt Message:%s"),DecryptMessage);

    if (res[1] == 1)
    {
        printf(wrap("Encrypt and Decrypt OK"));
    }
    else
    {
        printf(wrap("Encrypt and Decrypt Fail"));
    }
    printf(wrap(" "));

    printf(wrap("SM2DH:"));
    printf(wrap("Alice:"));
    printf(wrap("ID: %s"), ID_A);
    printf("PrivateKey: 0x");
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 8; j++)
        {
            printf("%02x", (uint8_t)(PrivateKeyA[SM2_256 - 1 - i] >> (56 - j * 8)) & 0xff);
        }
    }
    printf(wrap(" "));
    printf("PublicKey-X: 0x");
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 8; j++)
        {
            printf("%02x", (uint8_t)(PublicKeyA.x[SM2_256 - 1 - i] >> (56 - j * 8)) & 0xff);
        }
    }
    printf(wrap(" "));
    printf("PublicKey-Y: 0x");
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 8; j++)
        {
            printf("%02x", (uint8_t)(PublicKeyA.y[SM2_256 - 1 - i] >> (56 - j * 8)) & 0xff);
        }
    }
    printf(wrap(" "));

    printf(wrap("Bill:"));
    printf(wrap("ID: %s"), ID_B);
    printf("PrivateKey: 0x");
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 8; j++)
        {
            printf("%02x", (uint8_t)(PrivateKeyB[SM2_256 - 1 - i] >> (56 - j * 8)) & 0xff);
        }
    }
    printf(wrap(" "));
    printf("PublicKey-X: 0x");
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 8; j++)
        {
            printf("%02x", (uint8_t)(PublicKeyB.x[SM2_256 - 1 - i] >> (56 - j * 8)) & 0xff);
        }
    }
    printf(wrap(" "));
    printf("PublicKey-Y: 0x");
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 8; j++)
        {
            printf("%02x", (uint8_t)(PublicKeyB.y[SM2_256 - 1 - i] >> (56 - j * 8)) & 0xff);
        }
    }
    printf(wrap(" "));
    printf("ShareKeyA-B: 0x");
    for (i = 0; i < klen/8; i++)
    {
        printf("%02x", KB[i]);
    }
    printf(wrap(" "));
    printf("ShareKeyB-A: 0x");
    for (i = 0; i < klen/8; i++)
    {
        printf("%02x", KA[i]);
    }
    printf(wrap(" "));
    if (res[2] == 1)
    {
        printf(wrap("Share OK"));
    }
    printf(wrap(" "));

    return res[0] & res[1] & res[2];
}