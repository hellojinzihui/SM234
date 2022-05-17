#ifndef __SM2_H
#define __SM2_H

#include<stdint.h>

#ifndef uchar
   typedef unsigned char uchar;
#endif

#ifndef ushort
   typedef unsigned short ushort;
#endif

#ifndef ulong
   typedef unsigned long ulong;
#endif

#define Bits 256
#define SM2_256 4

typedef struct SM2Point
{
    uint64_t x[SM2_256];
    uint64_t y[SM2_256];
} SM2Point;

/*Use this function to Get EncryptMessage Len*/
uint32_t SM2_GetEncryptMessageLen(uint32_t MessageLen);

/*Use this function to sign on*/
uint8_t SM2DSA_Signature(   const uint8_t *Message,
                            uint32_t MessageLen,
                            uint16_t ENTLA,
                            const uint8_t *IDA, 
                            const uint64_t *PrivateKey,
                            uint8_t *Signature);
                            
/*Use this function to varify*/
uint8_t SM2DSA_Verify(  const uint8_t *Message,
                        uint32_t MessageLen,
                        uint16_t ENTLA,
                        const uint8_t *IDA, 
                        SM2Point PublicKey,
                        uint8_t *Signature);

/*Use this function to Encrypt Message*/
uint8_t SM2_Encrypt(    const uint8_t *Message,
                        uint32_t MessageLen,
                        SM2Point PublicKey,
                        uint8_t *C);

/*Use this function to Decrypt Message*/
uint8_t SM2_Decrypt(    const uint8_t *EncryptMessage,
                        uint32_t EMLen,
                        uint64_t *PrivateKey,
                        uint8_t *DecryptMessage);

/*Use this function to Generate Share Key B to A*/
uint8_t SM2DH_GenerateKeyInitiator( const uint8_t* IDA,
                                    uint16_t ENTLA,
                                    const uint8_t* IDB,
                                    uint16_t ENTLB,
                                    const uint64_t* rA,
                                    SM2Point RA,
                                    SM2Point RB,
                                    SM2Point PublicKeyA,
                                    SM2Point PublicKeyB,
                                    const uint64_t* PrivateKeyA,
                                    uint16_t klen,
                                    uint8_t* KA,
                                    uint8_t* SA,
                                    const uint8_t* SB);

/*Use this function to Generate Share Key A to B*/
uint8_t SM2DH_GenerateKeyResponder( const uint8_t* IDA,
                                    uint16_t ENTLA,
                                    const uint8_t* IDB,
                                    uint16_t ENTLB,
                                    SM2Point RA,
                                    SM2Point* RB,
                                    SM2Point PublicKeyA,
                                    SM2Point PublicKeyB,
                                    const uint64_t* PrivateKeyB,
                                    uint16_t klen,
                                    uint8_t* KB,
                                    uint8_t* SB,
                                    uint8_t* S2);

/*Example*/
uint8_t SM2_Usage(void);

#endif