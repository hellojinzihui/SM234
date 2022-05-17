#ifndef __SM3_H
#define __SM3_H

#ifndef uchar
   typedef unsigned char uchar;
#endif

#ifndef ushort
   typedef unsigned short ushort;
#endif

#ifndef ulong
   typedef unsigned long ulong;
#endif

/*Use This Function*/
void SM3_ComputeHash(uchar *Message, short length, uchar *digest);

/*Usage*/
void SM3_Usage(void);

#endif