/*
 **********************************************************************
 ** md5.c                                                            **
 ** RSA Data Security, Inc. MD5 Message Digest Algorithm             **
 ** Created: 2/17/90 RLR                                             **
 ** Revised: 1/91 SRD,AJ,BSK,JT Reference C Version                  **
 **********************************************************************
 */

/*
 **********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
 **                                                                  **
 ** License to copy and use this software is granted provided that   **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message     **
 ** Digest Algorithm" in all material mentioning or referencing this **
 ** software or this function.                                       **
 **                                                                  **
 ** License is also granted to make and use derivative works         **
 ** provided that such works are identified as "derived from the RSA **
 ** Data Security, Inc. MD5 Message Digest Algorithm" in all         **
 ** material mentioning or referencing the derived work.             **
 **                                                                  **
 ** RSA Data Security, Inc. makes no representations concerning      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kind.             **
 **                                                                  **
 ** These notices must be retained in any copies of any part of this **
 ** documentation and/or software.                                   **
 **********************************************************************
 */

/* -- include the following line if the md5.h header file is separate -- */
#include "md5.h"
#include <string.h>

/* forward declaration */
static void Transform ();

static unsigned char PADDING[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* F, G and H are basic MD5 functions: selection, majority, parity */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z))) 

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }

void MD5Init (mdContext)
MD5_CTX *mdContext;
{
  mdContext->i[0] = mdContext->i[1] = (UINT4)0;

  /* Load magic initialization constants.
   */
  mdContext->buf[0] = (UINT4)0x67452301;
  mdContext->buf[1] = (UINT4)0xefcdab89;
  mdContext->buf[2] = (UINT4)0x98badcfe;
  mdContext->buf[3] = (UINT4)0x10325476;
}

void MD5Update (mdContext, inBuf, inLen)
MD5_CTX *mdContext;
unsigned char *inBuf;
unsigned int inLen;
{
  UINT4 in[16];
  int mdi;
  unsigned int i, ii;

  /* compute number of bytes mod 64 */
  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  /* update number of bits */
  if ((mdContext->i[0] + ((UINT4)inLen << 3)) < mdContext->i[0])
    mdContext->i[1]++;
  mdContext->i[0] += ((UINT4)inLen << 3);
  mdContext->i[1] += ((UINT4)inLen >> 29);

  while (inLen--) {
    /* add new character to buffer, increment mdi */
    mdContext->in[mdi++] = *inBuf++;

    /* transform if necessary */
    if (mdi == 0x40) {
      for (i = 0, ii = 0; i < 16; i++, ii += 4)
        in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
                (((UINT4)mdContext->in[ii+2]) << 16) |
                (((UINT4)mdContext->in[ii+1]) << 8) |
                ((UINT4)mdContext->in[ii]);
      Transform (mdContext->buf, in);
      mdi = 0;
    }
  }
}

void MD5Final (md, mdContext)
unsigned char *md;
MD5_CTX *mdContext;
{
  UINT4 in[16];
  int mdi;
  unsigned int i, ii;
  unsigned int padLen;

  /* save number of bits */
  in[14] = mdContext->i[0];
  in[15] = mdContext->i[1];

  /* compute number of bytes mod 64 */
  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  /* pad out to 56 mod 64 */
  padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
  MD5Update (mdContext, PADDING, padLen);

  /* append length in bits and transform */
  for (i = 0, ii = 0; i < 14; i++, ii += 4)
    in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
            (((UINT4)mdContext->in[ii+2]) << 16) |
            (((UINT4)mdContext->in[ii+1]) << 8) |
            ((UINT4)mdContext->in[ii]);
  Transform (mdContext->buf, in);

  /* store buffer in digest */
  for (i = 0, ii = 0; i < 4; i++, ii += 4) {
    mdContext->digest[ii] = (unsigned char)(mdContext->buf[i] & 0xFF);
    mdContext->digest[ii+1] =
      (unsigned char)((mdContext->buf[i] >> 8) & 0xFF);
    mdContext->digest[ii+2] =
      (unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
    mdContext->digest[ii+3] =
      (unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
  }
  /* copy the resulting digest */
  memcpy(md,mdContext->digest,sizeof(mdContext->digest));
}

/* Basic MD5 step. Transform buf based on in.
 */
static void Transform (buf, in)
UINT4 *buf;
UINT4 *in;
{
  UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

  /* Round 1 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
/*  FF ( a, b, c, d, in[ 0], S11, 3614090360); * 1 * */
  FF ( a, b, c, d, in[ 0], S11, 0xD76AA478); /* 1 */
/*  FF ( d, a, b, c, in[ 1], S12, 3905402710); * 2 * */
  FF ( d, a, b, c, in[ 1], S12, 0xE8C7B756); /* 2 */
/*  FF ( c, d, a, b, in[ 2], S13,  606105819); * 3 * */
  FF ( c, d, a, b, in[ 2], S13,  0x242070DB); /* 3 */
/*  FF ( b, c, d, a, in[ 3], S14, 3250441966); * 4 * */
  FF ( b, c, d, a, in[ 3], S14, 0xC1BDCEEE); /* 4 */
/*  FF ( a, b, c, d, in[ 4], S11, 4118548399); * 5 * */
  FF ( a, b, c, d, in[ 4], S11, 0xF57C0FAF); /* 5 */
/*  FF ( d, a, b, c, in[ 5], S12, 1200080426); * 6 * */
  FF ( d, a, b, c, in[ 5], S12, 0x4787C62A); /* 6 */
/*  FF ( c, d, a, b, in[ 6], S13, 2821735955); * 7 * */
  FF ( c, d, a, b, in[ 6], S13, 0xA8304613); /* 7 */
/*  FF ( b, c, d, a, in[ 7], S14, 4249261313); * 8 * */
  FF ( b, c, d, a, in[ 7], S14, 0xFD469501); /* 8 */
/*  FF ( a, b, c, d, in[ 8], S11, 1770035416); * 9 * */
  FF ( a, b, c, d, in[ 8], S11, 0x698098D8); /* 9 */
/*  FF ( d, a, b, c, in[ 9], S12, 2336552879); * 10 * */
  FF ( d, a, b, c, in[ 9], S12, 0x8B44F7AF); /* 10 */
/*  FF ( c, d, a, b, in[10], S13, 4294925233); * 11 * */
  FF ( c, d, a, b, in[10], S13, 0xFFFF5BB1); /* 11 */
/*  FF ( b, c, d, a, in[11], S14, 2304563134); * 12 * */
  FF ( b, c, d, a, in[11], S14, 0x895CD7BE); /* 12 */
/*  FF ( a, b, c, d, in[12], S11, 1804603682); * 13 * */
  FF ( a, b, c, d, in[12], S11, 0x6B901122); /* 13 */
/*  FF ( d, a, b, c, in[13], S12, 4254626195); * 14 * */
  FF ( d, a, b, c, in[13], S12, 0xFD987193); /* 14 */
/*  FF ( c, d, a, b, in[14], S13, 2792965006); * 15 * */
  FF ( c, d, a, b, in[14], S13, 0xA679438E); /* 15 */
/*  FF ( b, c, d, a, in[15], S14, 1236535329); * 16 * */
  FF ( b, c, d, a, in[15], S14, 0x49B40821); /* 16 */

  /* Round 2 */
#define S21 5
#define S22 9
#define S23 14
#define S24 20
/*  GG ( a, b, c, d, in[ 1], S21, 4129170786); * 17 * */
  GG ( a, b, c, d, in[ 1], S21, 0xF61E2562); /* 17 */
/*  GG ( d, a, b, c, in[ 6], S22, 3225465664); * 18 * */
  GG ( d, a, b, c, in[ 6], S22, 0xC040B340); /* 18 */
/*  GG ( c, d, a, b, in[11], S23,  643717713); * 19 * */
  GG ( c, d, a, b, in[11], S23, 0x265E5A51); /* 19 */
/*  GG ( b, c, d, a, in[ 0], S24, 3921069994); * 20 * */
  GG ( b, c, d, a, in[ 0], S24, 0xE9B6C7AA); /* 20 */
/*  GG ( a, b, c, d, in[ 5], S21, 3593408605); * 21 * */
  GG ( a, b, c, d, in[ 5], S21, 0xD62F105D); /* 21 */
/*  GG ( d, a, b, c, in[10], S22,   38016083); * 22 * */
  GG ( d, a, b, c, in[10], S22,   0x2441453); /* 22 */
/*  GG ( c, d, a, b, in[15], S23, 3634488961); * 23 * */
  GG ( c, d, a, b, in[15], S23, 0xD8A1E681); /* 23 */
/*  GG ( b, c, d, a, in[ 4], S24, 3889429448); * 24 * */
  GG ( b, c, d, a, in[ 4], S24, 0xE7D3FBC8); /* 24 */
/*  GG ( a, b, c, d, in[ 9], S21,  568446438); * 25 * */
  GG ( a, b, c, d, in[ 9], S21,  0x21E1CDE6); /* 25 */
/*  GG ( d, a, b, c, in[14], S22, 3275163606); * 26 * */
  GG ( d, a, b, c, in[14], S22, 0xC33707D6); /* 26 */
/*  GG ( c, d, a, b, in[ 3], S23, 4107603335); * 27 * */
  GG ( c, d, a, b, in[ 3], S23, 0xF4D50D87); /* 27 */
/*  GG ( b, c, d, a, in[ 8], S24, 1163531501); * 28 * */
  GG ( b, c, d, a, in[ 8], S24, 0x455A14ED); /* 28 */
/*  GG ( a, b, c, d, in[13], S21, 2850285829); * 29 * */
  GG ( a, b, c, d, in[13], S21, 0xA9E3E905); /* 29 */
/*  GG ( d, a, b, c, in[ 2], S22, 4243563512); * 30 * */
  GG ( d, a, b, c, in[ 2], S22, 0xFCEFA3F8); /* 30 */
/*  GG ( c, d, a, b, in[ 7], S23, 1735328473); * 31 * */
  GG ( c, d, a, b, in[ 7], S23, 0x676F02D9); /* 31 */
/*  GG ( b, c, d, a, in[12], S24, 2368359562); * 32 * */
  GG ( b, c, d, a, in[12], S24, 0x8D2A4C8A); /* 32 */

  /* Round 3 */
#define S31 4
#define S32 11
#define S33 16
#define S34 23
/*  HH ( a, b, c, d, in[ 5], S31, 4294588738); * 33 * */
  HH ( a, b, c, d, in[ 5], S31, 0xFFFA3942); /* 33 */
/*  HH ( d, a, b, c, in[ 8], S32, 2272392833); * 34 * */
  HH ( d, a, b, c, in[ 8], S32, 0x8771F681); /* 34 */
/*  HH ( c, d, a, b, in[11], S33, 1839030562); * 35 * */
  HH ( c, d, a, b, in[11], S33, 0x6D9D6122); /* 35 */
/*  HH ( b, c, d, a, in[14], S34, 4259657740); * 36 * */
  HH ( b, c, d, a, in[14], S34, 0xFDE5380C); /* 36 */
/*  HH ( a, b, c, d, in[ 1], S31, 2763975236); * 37 * */
  HH ( a, b, c, d, in[ 1], S31, 0xA4BEEA44); /* 37 */
/*  HH ( d, a, b, c, in[ 4], S32, 1272893353); * 38 * */
  HH ( d, a, b, c, in[ 4], S32, 0x4BDECFA9); /* 38 */
/*  HH ( c, d, a, b, in[ 7], S33, 4139469664); * 39 * */
  HH ( c, d, a, b, in[ 7], S33, 0xF6BB4B60); /* 39 */
/*  HH ( b, c, d, a, in[10], S34, 3200236656); * 40 * */
  HH ( b, c, d, a, in[10], S34, 0xBEBFBC70); /* 40 */
/*  HH ( a, b, c, d, in[13], S31,  681279174); * 41 * */
  HH ( a, b, c, d, in[13], S31, 0x289B7EC6); /* 41 */
/*  HH ( d, a, b, c, in[ 0], S32, 3936430074); * 42 * */
  HH ( d, a, b, c, in[ 0], S32, 0xEAA127FA); /* 42 */
/*  HH ( c, d, a, b, in[ 3], S33, 3572445317); * 43 * */
  HH ( c, d, a, b, in[ 3], S33, 0xD4EF3085); /* 43 */
/*  HH ( b, c, d, a, in[ 6], S34,   76029189); * 44 * */
  HH ( b, c, d, a, in[ 6], S34,  0x4881D05); /* 44 */
/*  HH ( a, b, c, d, in[ 9], S31, 3654602809); * 45 * */
  HH ( a, b, c, d, in[ 9], S31, 0xD9D4D039); /* 45 */
/*  HH ( d, a, b, c, in[12], S32, 3873151461); * 46 * */
  HH ( d, a, b, c, in[12], S32, 0xE6DB99E5); /* 46 */
/*  HH ( c, d, a, b, in[15], S33,  530742520); * 47 * */
  HH ( c, d, a, b, in[15], S33, 0x1FA27CF8); /* 47 */
/*  HH ( b, c, d, a, in[ 2], S34, 3299628645); * 48 * */
  HH ( b, c, d, a, in[ 2], S34, 0xC4AC5665); /* 48 */

  /* Round 4 */
#define S41 6
#define S42 10
#define S43 15
#define S44 21
/*  II ( a, b, c, d, in[ 0], S41, 4096336452); * 49 * */
  II ( a, b, c, d, in[ 0], S41, 0xF4292244); /* 49 */
/*  II ( d, a, b, c, in[ 7], S42, 1126891415); * 50 * */
  II ( d, a, b, c, in[ 7], S42, 0x432AFF97); /* 50 */
/*  II ( c, d, a, b, in[14], S43, 2878612391); * 51 * */
  II ( c, d, a, b, in[14], S43, 0xAB9423A7); /* 51 */
/*  II ( b, c, d, a, in[ 5], S44, 4237533241); * 52 * */
  II ( b, c, d, a, in[ 5], S44, 0xFC93A039); /* 52 */
/*  II ( a, b, c, d, in[12], S41, 1700485571); * 53 * */
  II ( a, b, c, d, in[12], S41, 0x655B59C3); /* 53 */
/*  II ( d, a, b, c, in[ 3], S42, 2399980690); * 54 * */
  II ( d, a, b, c, in[ 3], S42, 0x8F0CCC92); /* 54 */
/*  II ( c, d, a, b, in[10], S43, 4293915773); * 55 * */
  II ( c, d, a, b, in[10], S43, 0xFFEFF47D); /* 55 */
/*  II ( b, c, d, a, in[ 1], S44, 2240044497); * 56 * */
  II ( b, c, d, a, in[ 1], S44, 0x85845DD1); /* 56 */
/*  II ( a, b, c, d, in[ 8], S41, 1873313359); * 57 * */
  II ( a, b, c, d, in[ 8], S41, 0x6FA87E4F); /* 57 */
/*  II ( d, a, b, c, in[15], S42, 4264355552); * 58 * */
  II ( d, a, b, c, in[15], S42, 0xFE2CE6E0); /* 58 */
/*  II ( c, d, a, b, in[ 6], S43, 2734768916); * 59 * */
  II ( c, d, a, b, in[ 6], S43, 0xA3014314); /* 59 */
/*  II ( b, c, d, a, in[13], S44, 1309151649); * 60 * */
  II ( b, c, d, a, in[13], S44, 0x4E0811A1); /* 60 */
/*  II ( a, b, c, d, in[ 4], S41, 4149444226); * 61 * */
  II ( a, b, c, d, in[ 4], S41, 0xF7537E82); /* 61 */
/*  II ( d, a, b, c, in[11], S42, 3174756917); * 62 * */
  II ( d, a, b, c, in[11], S42, 0xBD3AF235); /* 62 */
/*  II ( c, d, a, b, in[ 2], S43,  718787259); * 63 * */
  II ( c, d, a, b, in[ 2], S43,  0x2AD7D2BB); /* 63 */
/*  II ( b, c, d, a, in[ 9], S44, 3951481745); * 64 * */
  II ( b, c, d, a, in[ 9], S44, 0xEB86D391); /* 64 */

  buf[0] += a;
  buf[1] += b;
  buf[2] += c;
  buf[3] += d;
}

/*
 **********************************************************************
 ** End of md5.c                                                     **
 ******************************* (cut) ********************************
 */
