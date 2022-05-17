#include "SM3.h"
#include "string.h"

#if defined(USE_STDPERIPH_DRIVER)
    #include"stm32f10x.h"
    #include"usart.h"
    #define wrap(s) s"\r\n"
#endif
#if defined(_WIN32)
    #include"stdio.h"
    #define wrap(s) s"\n"
#endif

const ulong IV[8] = {0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E};
const ulong T[2] = {0x79CC4519,0x7A879D8A};

/**
 * @brief  SM3_CopyByteToWord
 * @note   Copy Byte To Word
 * @param  w:output word
 * @param  b:input byte
 * @param  i:inout i/offset of array b
 * @retval None
 */
#define SM3_CopyByteToWord(w,b,i)                    \
        do{                                          \
            (w) = ( ulong ) (b[(i)    ] << 24)       \
                | ( ulong ) (b[(i) + 1] << 16)       \
                | ( ulong ) (b[(i) + 2] << 8 )       \
                | ( ulong ) (b[(i) + 3]      );      \
          }                                          \
        while (0)  

/**
 * @brief  SM3_CopyWordToByte
 * @note   Copy Word To Byte
 * @param  b:output byte
 * @param  w:input word
 * @param  i:inout i/offset of array b
 * @retval None
 */
#define SM3_CopyWordToByte(b,w,i)                     \
        do{                                           \
            (b[(i)    ]) =  (((w) >> 24) & 0xFF);     \
            (b[(i) + 1]) =  (((w) >> 16) & 0xFF);     \
            (b[(i) + 2]) =  (((w) >> 8 ) & 0xFF);     \
            (b[(i) + 3]) =  (((w)      ) & 0xFF);     \
          }                                           \
        while (0)   		

/**
 * @brief  SM3_CyclicShift_L
 * @note   Cyclic Shift Left
 * @param  newW:new word after shift
 * @param  oldW:old word before shift
 * @retval None
 */
#define SM3_CyclicShift_L(newW,oldW,n)                            \
        do{                                                       \
            (newW) = ( (oldW) << (n) ) | ((oldW) >> (32 - (n)));  \
          }                                                       \
        while (0)
     
/**
 * @brief  SM3_Permutation1 AND SM3_Permutation0
 * @note   Permutation Function 1 P1
 * @param  X: input word
 * @retval Px: output word
 */
static ulong SM3_Permutation0(ulong X)
{
    ulong Px,X9,X17;
    SM3_CyclicShift_L(X9,X,9);
    SM3_CyclicShift_L(X17,X,17);
    Px = X ^ X9 ^ X17;
    return Px;
}
static ulong SM3_Permutation1(ulong X)
{
    ulong Px,X15,X23;
    SM3_CyclicShift_L(X15,X,15);
    SM3_CyclicShift_L(X23,X,23);
    Px = X ^ X15 ^ X23;
    return Px;
}

/**
 * @brief  SM3_FF AND SM3_GG
 * @note   Bool Function FF AND GG
 * @param  X: input word
 * @param  Y: input word
 * @param  Z: input word
 * @param  j: input word
 * @retval FF OR GG: output word
 */
static ulong SM3_FF(ulong X,ulong Y,ulong Z,uchar j)
{
    return j & 0xF0 ? (X & Y) | (X & Z) | (Y & Z) : X ^ Y ^ Z;
}
static ulong SM3_GG(ulong X,ulong Y,ulong Z,uchar j)
{
    return j & 0xF0 ? (X & Y) | (~X & Z) : X ^ Y ^ Z;
}

/**
 * @brief  SM3_MessageExtension
 * @note   Message Extension
 * @param  MessageBlock: B
 * @param  *MessageWord: W and W'
 * @retval None
 */
static void SM3_MessageExtension(uchar* MessageBlock,ulong *MessageWord)
{
    uchar i;
	ulong MessageWordIi_3,MessageWordIi_13;

    //Step1 Create Message Word
    for( i = 0; i < 16; i++)
    {
        SM3_CopyByteToWord(MessageWord[i],MessageBlock,i*4);
    }
    
    //Step2 Create W
    for(i = 16; i < 68 ; i++)
    {
        SM3_CyclicShift_L(MessageWordIi_3,MessageWord[i - 3],15);
        SM3_CyclicShift_L(MessageWordIi_13,MessageWord[i - 13],7);
        MessageWord[i] = SM3_Permutation1(MessageWord[i - 16] ^ MessageWord[i - 9] ^ MessageWordIi_3) ^
                         MessageWordIi_13 ^ MessageWord[i - 6];
    }

    //Step3 Create W'
    for ( i = 0; i < 64; i++)
    {
        MessageWord[68 + i] = MessageWord[i] ^ MessageWord[i + 4];
    }
}

static void SM3_CF(ulong *Vi ,uchar *Bi)
{
    uchar i;
    ulong temp;
    ulong Ti;
    ulong A,B,C,D,E,F,G,H;
    ulong MessageWord[132];
    ulong SS1 = 0,SS2 = 0,TT1 = 0,TT2 = 0;

    SM3_MessageExtension(Bi,MessageWord);

    A = Vi[0];
    B = Vi[1];
    C = Vi[2];
    D = Vi[3];
    E = Vi[4];
    F = Vi[5];
    G = Vi[6];
    H = Vi[7];

    for ( i = 0; i < 64; i++)
    {
        //SS1 = ((A<<<12) ^ E ^ (Ti<<<(j mod32)))<<<7
        Ti = i>15 ? T[1]:T[0];
        SM3_CyclicShift_L(SS1,A,12);
        SS1 += E;
        SM3_CyclicShift_L(temp,Ti,i%32);
        SS1 += temp;
        SM3_CyclicShift_L(SS1,SS1,7);

        //SS2 = SS1 ^ (A<<<12)
        SM3_CyclicShift_L(SS2,A,12);
        SS2 ^= SS1;

        //TT1 = FF(A,B,C) + D + SS2 + Wi'
        TT1 = SM3_FF(A,B,C,i) + D + SS2 + MessageWord[68 + i];

        //TT2 = GG(A,B,C) + H + SS1 + Wi
        TT2 = SM3_GG(E,F,G,i) + H + SS1 + MessageWord[i];

        //D = C
        D = C;

        //C = B <<< 9
        SM3_CyclicShift_L(C,B,9);

        //B = A
        B = A;

        //A = TT1;
        A = TT1;

        //H = G;
        H = G;

        //G = F <<< 19;
        SM3_CyclicShift_L(G,F,19);

        //F = E;
        F = E;

        //E = P0(TT2)
        E = SM3_Permutation0(TT2);
    }

    Vi[0] =  A ^ Vi[0];
    Vi[1] =  B ^ Vi[1];
    Vi[2] =  C ^ Vi[2];
    Vi[3] =  D ^ Vi[3];
    Vi[4] =  E ^ Vi[4];
    Vi[5] =  F ^ Vi[5];
    Vi[6] =  G ^ Vi[6];
    Vi[7] =  H ^ Vi[7];
}

uchar WorkBuffer[128];
/**
 * @brief  SM3_ComputeHash
 * @note   SM3 ??????????¡¤¡§
 * @param  *Message: input message
 * @param  length: input message length
 * @param  *digest: output hash
 * @retval None
 */
void SM3_ComputeHash(uchar *Message, short length, uchar *digest)
{
    uchar i;
    uchar MessageBlockNums;
    ulong MessageBitNums;
    ulong Hash[8];

    /*Initialization of V(0)*/
    memcpy(Hash,IV,32);

    /*Compute Message bit and block numbers*/
    MessageBitNums = length * 8;
    MessageBlockNums = length / 64 + 1;
    MessageBlockNums += (length % 64 >= 448);

    /*Split Message Block*/
    if(MessageBitNums % 512 >= 448)/*Need add Block*/
    {
        /*Nolmal Block*/
        for ( i = 0; i < MessageBlockNums - 2; i++) 
        {
            memset(WorkBuffer,0,64);
            memcpy(WorkBuffer,Message,64);
            SM3_CF(Hash,WorkBuffer);
            Message += 64;
        }

        /*Padding bit 1 block*/
        memset(WorkBuffer,0,64); 
        memcpy(WorkBuffer,Message,length%64);
        WorkBuffer[length%64] = 0x80;
        SM3_CF(Hash,WorkBuffer);

        /*Padding bitnum block*/
        memset(WorkBuffer,0,64); 
        WorkBuffer[60] = (MessageBitNums >> 24) & 0xFF;
        WorkBuffer[61] = (MessageBitNums >> 16) & 0xFF;
        WorkBuffer[62] = (MessageBitNums >> 8 ) & 0xFF;
        WorkBuffer[63] = (MessageBitNums      ) & 0xFF;
        SM3_CF(Hash,WorkBuffer);
    }
    else/*Dont need add block*/
    {
        /*Nolmal Block*/
        for ( i = 0; i < MessageBlockNums - 1; i++)
        {
            memset(WorkBuffer,0,64);
            memcpy(WorkBuffer,Message,64);
            SM3_CF(Hash,WorkBuffer);
            Message += 64;
        }

        /*Padding bit 1 block and Padding bitnum block*/
        memset(WorkBuffer,0,64);
        memcpy(WorkBuffer,Message,length%64);
        WorkBuffer[length%64] = 0x80;
        WorkBuffer[60] = (MessageBitNums >> 24) & 0xFF;
        WorkBuffer[61] = (MessageBitNums >> 16) & 0xFF;
        WorkBuffer[62] = (MessageBitNums >> 8 ) & 0xFF;
        WorkBuffer[63] = (MessageBitNums      ) & 0xFF;
        SM3_CF(Hash,WorkBuffer);
    }

    /*Output result*/
	for( i = 0; i < 8; i++ )
	{
		SM3_CopyWordToByte(digest,Hash[i],i*4);
	}
}

void SM3_Usage(void)
{
    ushort i;
    uchar SM3ex[64] =
    {
        0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64,
        0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64,
        0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64,
        0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64, 0x61,0x62,0x63,0x64,
    };
    uchar Output[32];
    printf(wrap("SM3 Origin Data :"));
    for (i = 0; i < 64; i++)
    {
        printf("0x%02x ", SM3ex[i]);
        if (i % 8 == 7)
        {
            printf(wrap(" "));
        }
    }

    SM3_ComputeHash(SM3ex, 64, Output);

    printf(wrap("SM3 Hash Data :"));
    for (i = 0; i < 32; i++)
    {
        printf("0x%02x ", Output[i]);
        if (i % 8 == 7)
        {
            printf(wrap(" "));
        }
    }
    printf(wrap(" "));
}