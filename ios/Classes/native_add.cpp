#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
extern "C"
{
  __attribute__((visibility("default"))) __attribute__((used)) int native_add(int x, int y)
  {
    return x + y +200;
  }


uint8_t* u8List_trans(uint8_t* u8List,int length){
  for (size_t i = 0; i < length; i++)
  {
    u8List[i] = i % 8;
  }

  return u8List;
}

char *reverse(char *str, int length)
{
    char *reversed_str = (char *)malloc((length + 1) * sizeof(char));
    for (int i = 0; i < length; i++)
    {
        reversed_str[length - i - 1] = str[i];
    }
    reversed_str[length] = '\0';
    return reversed_str;
}
/*
 * Copyright (c) 2012, Thingsquare, www.thingsquare.com.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 * Author: Fredrik Osterlind <fredrik@thingsquare.com>
 */

// #include "uip.h"

#include <stdio.h>
#include <string.h>

/**************************************************************
                        AES128 
Author:   Uli Kretzschmar
             MSP430 Systems
             Freising
AES software support for encryption and decryption
ECCN 5D002 TSU - Technology / Software Unrestricted
**************************************************************/

// foreward sbox
static const unsigned char sbox[256] = {
//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,       //0
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,       //1
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,       //2
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,       //3
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,       //4
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,       //5
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,       //6
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,       //7
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,       //8
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,       //9
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,       //A
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,       //B
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,       //C
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,       //D
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,       //E
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16
};                              //F   
// inverse sbox
static const unsigned char rsbox[256] =
  { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4,
0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa,
0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1,
0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90,
0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c,
0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11,
0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22,
0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7,
0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8,
0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69,
0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
// round constant
static const unsigned char Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};


// expand the key
static void
expandKey(unsigned char *expandedKey, const unsigned char *key)
{
  unsigned short ii, buf1;

  for(ii = 0; ii < 16; ii++) {
    expandedKey[ii] = key[ii];
  }
  
  for(ii = 1; ii < 11; ii++) {
    buf1 = expandedKey[ii * 16 - 4];
    expandedKey[ii * 16 + 0] =
      sbox[expandedKey[ii * 16 - 3]] ^ expandedKey[(ii - 1) * 16 +
                                                   0] ^ Rcon[ii];
    expandedKey[ii * 16 + 1] =
      sbox[expandedKey[ii * 16 - 2]] ^ expandedKey[(ii - 1) * 16 + 1];
    expandedKey[ii * 16 + 2] =
      sbox[expandedKey[ii * 16 - 1]] ^ expandedKey[(ii - 1) * 16 + 2];
    expandedKey[ii * 16 + 3] = sbox[buf1] ^ expandedKey[(ii - 1) * 16 + 3];
    expandedKey[ii * 16 + 4] =
      expandedKey[(ii - 1) * 16 + 4] ^ expandedKey[ii * 16 + 0];
    expandedKey[ii * 16 + 5] =
      expandedKey[(ii - 1) * 16 + 5] ^ expandedKey[ii * 16 + 1];
    expandedKey[ii * 16 + 6] =
      expandedKey[(ii - 1) * 16 + 6] ^ expandedKey[ii * 16 + 2];
    expandedKey[ii * 16 + 7] =
      expandedKey[(ii - 1) * 16 + 7] ^ expandedKey[ii * 16 + 3];
    expandedKey[ii * 16 + 8] =
      expandedKey[(ii - 1) * 16 + 8] ^ expandedKey[ii * 16 + 4];
    expandedKey[ii * 16 + 9] =
      expandedKey[(ii - 1) * 16 + 9] ^ expandedKey[ii * 16 + 5];
    expandedKey[ii * 16 + 10] =
      expandedKey[(ii - 1) * 16 + 10] ^ expandedKey[ii * 16 + 6];
    expandedKey[ii * 16 + 11] =
      expandedKey[(ii - 1) * 16 + 11] ^ expandedKey[ii * 16 + 7];
    expandedKey[ii * 16 + 12] =
      expandedKey[(ii - 1) * 16 + 12] ^ expandedKey[ii * 16 + 8];
    expandedKey[ii * 16 + 13] =
      expandedKey[(ii - 1) * 16 + 13] ^ expandedKey[ii * 16 + 9];
    expandedKey[ii * 16 + 14] =
      expandedKey[(ii - 1) * 16 + 14] ^ expandedKey[ii * 16 + 10];
    expandedKey[ii * 16 + 15] =
      expandedKey[(ii - 1) * 16 + 15] ^ expandedKey[ii * 16 + 11];
  }


}

// multiply by 2 in the galois field
static unsigned char
galois_mul2(unsigned char value)
{
  if(value >> 7) {
    value = value << 1;
    return (value ^ 0x1b);
  } else {
    return value << 1;
  }
}

// straight foreward aes encryption implementation
//   first the group of operations
//     - addroundkey
//     - subbytes
//     - shiftrows
//     - mixcolums
//   is executed 9 times, after this addroundkey to finish the 9th round, 
//   after that the 10th round without mixcolums
//   no further subfunctions to save cycles for function calls
//   no structuring with "for (....)" to save cycles
static void
aes_encr(unsigned char *state, unsigned char *expandedKey)
{
  unsigned char buf1, buf2, buf3, round;

  for(round = 0; round < 9; round++) {
    // addroundkey, sbox and shiftrows
    // row 0
    state[0] = sbox[(state[0] ^ expandedKey[(round * 16)])];
    state[4] = sbox[(state[4] ^ expandedKey[(round * 16) + 4])];
    state[8] = sbox[(state[8] ^ expandedKey[(round * 16) + 8])];
    state[12] = sbox[(state[12] ^ expandedKey[(round * 16) + 12])];
    // row 1
    buf1 = state[1] ^ expandedKey[(round * 16) + 1];
    state[1] = sbox[(state[5] ^ expandedKey[(round * 16) + 5])];
    state[5] = sbox[(state[9] ^ expandedKey[(round * 16) + 9])];
    state[9] = sbox[(state[13] ^ expandedKey[(round * 16) + 13])];
    state[13] = sbox[buf1];
    // row 2
    buf1 = state[2] ^ expandedKey[(round * 16) + 2];
    buf2 = state[6] ^ expandedKey[(round * 16) + 6];
    state[2] = sbox[(state[10] ^ expandedKey[(round * 16) + 10])];
    state[6] = sbox[(state[14] ^ expandedKey[(round * 16) + 14])];
    state[10] = sbox[buf1];
    state[14] = sbox[buf2];
    // row 3
    buf1 = state[15] ^ expandedKey[(round * 16) + 15];
    state[15] = sbox[(state[11] ^ expandedKey[(round * 16) + 11])];
    state[11] = sbox[(state[7] ^ expandedKey[(round * 16) + 7])];
    state[7] = sbox[(state[3] ^ expandedKey[(round * 16) + 3])];
    state[3] = sbox[buf1];

    // mixcolums //////////
    // col1
    buf1 = state[0] ^ state[1] ^ state[2] ^ state[3];
    buf2 = state[0];
    buf3 = state[0] ^ state[1];
    buf3 = galois_mul2(buf3);
    state[0] = state[0] ^ buf3 ^ buf1;
    buf3 = state[1] ^ state[2];
    buf3 = galois_mul2(buf3);
    state[1] = state[1] ^ buf3 ^ buf1;
    buf3 = state[2] ^ state[3];
    buf3 = galois_mul2(buf3);
    state[2] = state[2] ^ buf3 ^ buf1;
    buf3 = state[3] ^ buf2;
    buf3 = galois_mul2(buf3);
    state[3] = state[3] ^ buf3 ^ buf1;
    // col2
    buf1 = state[4] ^ state[5] ^ state[6] ^ state[7];
    buf2 = state[4];
    buf3 = state[4] ^ state[5];
    buf3 = galois_mul2(buf3);
    state[4] = state[4] ^ buf3 ^ buf1;
    buf3 = state[5] ^ state[6];
    buf3 = galois_mul2(buf3);
    state[5] = state[5] ^ buf3 ^ buf1;
    buf3 = state[6] ^ state[7];
    buf3 = galois_mul2(buf3);
    state[6] = state[6] ^ buf3 ^ buf1;
    buf3 = state[7] ^ buf2;
    buf3 = galois_mul2(buf3);
    state[7] = state[7] ^ buf3 ^ buf1;
    // col3
    buf1 = state[8] ^ state[9] ^ state[10] ^ state[11];
    buf2 = state[8];
    buf3 = state[8] ^ state[9];
    buf3 = galois_mul2(buf3);
    state[8] = state[8] ^ buf3 ^ buf1;
    buf3 = state[9] ^ state[10];
    buf3 = galois_mul2(buf3);
    state[9] = state[9] ^ buf3 ^ buf1;
    buf3 = state[10] ^ state[11];
    buf3 = galois_mul2(buf3);
    state[10] = state[10] ^ buf3 ^ buf1;
    buf3 = state[11] ^ buf2;
    buf3 = galois_mul2(buf3);
    state[11] = state[11] ^ buf3 ^ buf1;
    // col4
    buf1 = state[12] ^ state[13] ^ state[14] ^ state[15];
    buf2 = state[12];
    buf3 = state[12] ^ state[13];
    buf3 = galois_mul2(buf3);
    state[12] = state[12] ^ buf3 ^ buf1;
    buf3 = state[13] ^ state[14];
    buf3 = galois_mul2(buf3);
    state[13] = state[13] ^ buf3 ^ buf1;
    buf3 = state[14] ^ state[15];
    buf3 = galois_mul2(buf3);
    state[14] = state[14] ^ buf3 ^ buf1;
    buf3 = state[15] ^ buf2;
    buf3 = galois_mul2(buf3);
    state[15] = state[15] ^ buf3 ^ buf1;

  }
  // 10th round without mixcols
  state[0] = sbox[(state[0] ^ expandedKey[(round * 16)])];
  state[4] = sbox[(state[4] ^ expandedKey[(round * 16) + 4])];
  state[8] = sbox[(state[8] ^ expandedKey[(round * 16) + 8])];
  state[12] = sbox[(state[12] ^ expandedKey[(round * 16) + 12])];
  // row 1
  buf1 = state[1] ^ expandedKey[(round * 16) + 1];
  state[1] = sbox[(state[5] ^ expandedKey[(round * 16) + 5])];
  state[5] = sbox[(state[9] ^ expandedKey[(round * 16) + 9])];
  state[9] = sbox[(state[13] ^ expandedKey[(round * 16) + 13])];
  state[13] = sbox[buf1];
  // row 2
  buf1 = state[2] ^ expandedKey[(round * 16) + 2];
  buf2 = state[6] ^ expandedKey[(round * 16) + 6];
  state[2] = sbox[(state[10] ^ expandedKey[(round * 16) + 10])];
  state[6] = sbox[(state[14] ^ expandedKey[(round * 16) + 14])];
  state[10] = sbox[buf1];
  state[14] = sbox[buf2];
  // row 3
  buf1 = state[15] ^ expandedKey[(round * 16) + 15];
  state[15] = sbox[(state[11] ^ expandedKey[(round * 16) + 11])];
  state[11] = sbox[(state[7] ^ expandedKey[(round * 16) + 7])];
  state[7] = sbox[(state[3] ^ expandedKey[(round * 16) + 3])];
  state[3] = sbox[buf1];
  // last addroundkey
  state[0] ^= expandedKey[160];
  state[1] ^= expandedKey[161];
  state[2] ^= expandedKey[162];
  state[3] ^= expandedKey[163];
  state[4] ^= expandedKey[164];
  state[5] ^= expandedKey[165];
  state[6] ^= expandedKey[166];
  state[7] ^= expandedKey[167];
  state[8] ^= expandedKey[168];
  state[9] ^= expandedKey[169];
  state[10] ^= expandedKey[170];
  state[11] ^= expandedKey[171];
  state[12] ^= expandedKey[172];
  state[13] ^= expandedKey[173];
  state[14] ^= expandedKey[174];
  state[15] ^= expandedKey[175];
}

// straight foreward aes decryption implementation
//   the order of substeps is the exact reverse of decryption
//   inverse functions:
//       - addRoundKey is its own inverse
//       - rsbox is inverse of sbox
//       - rightshift instead of leftshift
//       - invMixColumns = barreto + mixColumns
//   no further subfunctions to save cycles for function calls
//   no structuring with "for (....)" to save cycles
static void
aes_decr(unsigned char *state, unsigned char *expandedKey)
{
  unsigned char buf1, buf2, buf3;
  signed char round;

  round = 9;

  // initial addroundkey
  state[0] ^= expandedKey[160];
  state[1] ^= expandedKey[161];
  state[2] ^= expandedKey[162];
  state[3] ^= expandedKey[163];
  state[4] ^= expandedKey[164];
  state[5] ^= expandedKey[165];
  state[6] ^= expandedKey[166];
  state[7] ^= expandedKey[167];
  state[8] ^= expandedKey[168];
  state[9] ^= expandedKey[169];
  state[10] ^= expandedKey[170];
  state[11] ^= expandedKey[171];
  state[12] ^= expandedKey[172];
  state[13] ^= expandedKey[173];
  state[14] ^= expandedKey[174];
  state[15] ^= expandedKey[175];

  // 10th round without mixcols
  state[0] = rsbox[state[0]] ^ expandedKey[(round * 16)];
  state[4] = rsbox[state[4]] ^ expandedKey[(round * 16) + 4];
  state[8] = rsbox[state[8]] ^ expandedKey[(round * 16) + 8];
  state[12] = rsbox[state[12]] ^ expandedKey[(round * 16) + 12];
  // row 1
  buf1 = rsbox[state[13]] ^ expandedKey[(round * 16) + 1];
  state[13] = rsbox[state[9]] ^ expandedKey[(round * 16) + 13];
  state[9] = rsbox[state[5]] ^ expandedKey[(round * 16) + 9];
  state[5] = rsbox[state[1]] ^ expandedKey[(round * 16) + 5];
  state[1] = buf1;
  // row 2
  buf1 = rsbox[state[2]] ^ expandedKey[(round * 16) + 10];
  buf2 = rsbox[state[6]] ^ expandedKey[(round * 16) + 14];
  state[2] = rsbox[state[10]] ^ expandedKey[(round * 16) + 2];
  state[6] = rsbox[state[14]] ^ expandedKey[(round * 16) + 6];
  state[10] = buf1;
  state[14] = buf2;
  // row 3
  buf1 = rsbox[state[3]] ^ expandedKey[(round * 16) + 15];
  state[3] = rsbox[state[7]] ^ expandedKey[(round * 16) + 3];
  state[7] = rsbox[state[11]] ^ expandedKey[(round * 16) + 7];
  state[11] = rsbox[state[15]] ^ expandedKey[(round * 16) + 11];
  state[15] = buf1;

  for(round = 8; round >= 0; round--) {
    // barreto
    //col1
    buf1 = galois_mul2(galois_mul2(state[0] ^ state[2]));
    buf2 = galois_mul2(galois_mul2(state[1] ^ state[3]));
    state[0] ^= buf1;
    state[1] ^= buf2;
    state[2] ^= buf1;
    state[3] ^= buf2;
    //col2
    buf1 = galois_mul2(galois_mul2(state[4] ^ state[6]));
    buf2 = galois_mul2(galois_mul2(state[5] ^ state[7]));
    state[4] ^= buf1;
    state[5] ^= buf2;
    state[6] ^= buf1;
    state[7] ^= buf2;
    //col3
    buf1 = galois_mul2(galois_mul2(state[8] ^ state[10]));
    buf2 = galois_mul2(galois_mul2(state[9] ^ state[11]));
    state[8] ^= buf1;
    state[9] ^= buf2;
    state[10] ^= buf1;
    state[11] ^= buf2;
    //col4
    buf1 = galois_mul2(galois_mul2(state[12] ^ state[14]));
    buf2 = galois_mul2(galois_mul2(state[13] ^ state[15]));
    state[12] ^= buf1;
    state[13] ^= buf2;
    state[14] ^= buf1;
    state[15] ^= buf2;
    // mixcolums //////////
    // col1
    buf1 = state[0] ^ state[1] ^ state[2] ^ state[3];
    buf2 = state[0];
    buf3 = state[0] ^ state[1];
    buf3 = galois_mul2(buf3);
    state[0] = state[0] ^ buf3 ^ buf1;
    buf3 = state[1] ^ state[2];
    buf3 = galois_mul2(buf3);
    state[1] = state[1] ^ buf3 ^ buf1;
    buf3 = state[2] ^ state[3];
    buf3 = galois_mul2(buf3);
    state[2] = state[2] ^ buf3 ^ buf1;
    buf3 = state[3] ^ buf2;
    buf3 = galois_mul2(buf3);
    state[3] = state[3] ^ buf3 ^ buf1;
    // col2
    buf1 = state[4] ^ state[5] ^ state[6] ^ state[7];
    buf2 = state[4];
    buf3 = state[4] ^ state[5];
    buf3 = galois_mul2(buf3);
    state[4] = state[4] ^ buf3 ^ buf1;
    buf3 = state[5] ^ state[6];
    buf3 = galois_mul2(buf3);
    state[5] = state[5] ^ buf3 ^ buf1;
    buf3 = state[6] ^ state[7];
    buf3 = galois_mul2(buf3);
    state[6] = state[6] ^ buf3 ^ buf1;
    buf3 = state[7] ^ buf2;
    buf3 = galois_mul2(buf3);
    state[7] = state[7] ^ buf3 ^ buf1;
    // col3
    buf1 = state[8] ^ state[9] ^ state[10] ^ state[11];
    buf2 = state[8];
    buf3 = state[8] ^ state[9];
    buf3 = galois_mul2(buf3);
    state[8] = state[8] ^ buf3 ^ buf1;
    buf3 = state[9] ^ state[10];
    buf3 = galois_mul2(buf3);
    state[9] = state[9] ^ buf3 ^ buf1;
    buf3 = state[10] ^ state[11];
    buf3 = galois_mul2(buf3);
    state[10] = state[10] ^ buf3 ^ buf1;
    buf3 = state[11] ^ buf2;
    buf3 = galois_mul2(buf3);
    state[11] = state[11] ^ buf3 ^ buf1;
    // col4
    buf1 = state[12] ^ state[13] ^ state[14] ^ state[15];
    buf2 = state[12];
    buf3 = state[12] ^ state[13];
    buf3 = galois_mul2(buf3);
    state[12] = state[12] ^ buf3 ^ buf1;
    buf3 = state[13] ^ state[14];
    buf3 = galois_mul2(buf3);
    state[13] = state[13] ^ buf3 ^ buf1;
    buf3 = state[14] ^ state[15];
    buf3 = galois_mul2(buf3);
    state[14] = state[14] ^ buf3 ^ buf1;
    buf3 = state[15] ^ buf2;
    buf3 = galois_mul2(buf3);
    state[15] = state[15] ^ buf3 ^ buf1;

    // addroundkey, rsbox and shiftrows
    // row 0
    state[0] = rsbox[state[0]] ^ expandedKey[(round * 16)];
    state[4] = rsbox[state[4]] ^ expandedKey[(round * 16) + 4];
    state[8] = rsbox[state[8]] ^ expandedKey[(round * 16) + 8];
    state[12] = rsbox[state[12]] ^ expandedKey[(round * 16) + 12];
    // row 1
    buf1 = rsbox[state[13]] ^ expandedKey[(round * 16) + 1];
    state[13] = rsbox[state[9]] ^ expandedKey[(round * 16) + 13];
    state[9] = rsbox[state[5]] ^ expandedKey[(round * 16) + 9];
    state[5] = rsbox[state[1]] ^ expandedKey[(round * 16) + 5];
    state[1] = buf1;
    // row 2
    buf1 = rsbox[state[2]] ^ expandedKey[(round * 16) + 10];
    buf2 = rsbox[state[6]] ^ expandedKey[(round * 16) + 14];
    state[2] = rsbox[state[10]] ^ expandedKey[(round * 16) + 2];
    state[6] = rsbox[state[14]] ^ expandedKey[(round * 16) + 6];
    state[10] = buf1;
    state[14] = buf2;
    // row 3
    buf1 = rsbox[state[3]] ^ expandedKey[(round * 16) + 15];
    state[3] = rsbox[state[7]] ^ expandedKey[(round * 16) + 3];
    state[7] = rsbox[state[11]] ^ expandedKey[(round * 16) + 7];
    state[11] = rsbox[state[15]] ^ expandedKey[(round * 16) + 11];
    state[15] = buf1;
  }


}

// encrypt
void
aes_encrypt(unsigned char *state, const unsigned char *key)
{
  unsigned char expandedKey[176];

  expandKey(expandedKey, key);  // expand the key into 176 bytes
  aes_encr(state, expandedKey);
}
// decrypt
void
aes_decrypt(unsigned char *state, const unsigned char *key)
{
  unsigned char expandedKey[176];

  expandKey(expandedKey, key);  // expand the key into 176 bytes
  aes_decr(state, expandedKey);
}

/*
 * CCM over AES-128 (RFC3610, http://www.ietf.org/rfc/rfc3610.txt).
 */

#define BLOCK_SIZE 16
#define L_SIZELEN 2 /* Size field length: 2 to 8 bytes  */
#define NONCE_LEN (15-L_SIZELEN) /* Nonce length: fixed to 13 bytes */

/*#define PRINTF(...) printf(__VA_ARGS__)*/
#define PRINTF(...)

/* CBC-MAC */
#define PRINT_CBCMAC_BLOCKS 0
#if PRINT_CBCMAC_BLOCKS
#define CBCMAC_PRINTF(...) PRINTF(__VA_ARGS__)
static int cbcmac_blockcount;
#else /* PRINT_CBCMAC_BLOCKS */
#define CBCMAC_PRINTF(...)
#endif /* PRINT_CBCMAC_BLOCKS */

static unsigned char cbcmac_xor[BLOCK_SIZE];

/* CTR: payload and MIC */
#define PRINT_CTR_BLOCKS 0
#if PRINT_CTR_BLOCKS
#define CTR_PRINTF(...) PRINTF(__VA_ARGS__)
#else /* PRINT_CTR_BLOCKS */
#define CTR_PRINTF(...)
#endif /* PRINT_CTR_BLOCKS */

#define PRINT_CTR_MIC_BLOCKS 0
#if PRINT_CTR_MIC_BLOCKS
#define CTR_MIC_PRINTF(...) PRINTF(__VA_ARGS__)
#else /* PRINT_CTR_MIC_BLOCKS */
#define CTR_MIC_PRINTF(...)
#endif /* PRINT_CTR_MIC_BLOCKS */

void aes_ccm_memcpy(const unsigned char *dest, const unsigned char *from,
                    int len);
#ifndef aes_ccm_memcpy
#define aes_ccm_memcpy memcpy
#endif /* aes_ccm_memcpy */

/*---------------------------------------------------------------------------*/
static void
cbcmac_clear()
{
#if PRINT_CBCMAC_BLOCKS
  cbcmac_blockcount = 0;
#endif /* PRINT_CBCMAC_BLOCKS */
  /* clear last cipher block */
  memset(cbcmac_xor, 0, sizeof(cbcmac_xor));
}
/*---------------------------------------------------------------------------*/
static void
cbcmac_append(const unsigned char *key, unsigned char *block)
{
  int i;

#if PRINT_CBCMAC_BLOCKS
  CBCMAC_PRINTF("B_%d: ", cbcmac_blockcount);
  for(i = 0; i < BLOCK_SIZE; i++) {
    CBCMAC_PRINTF("%02x", block[i]);
  }
  CBCMAC_PRINTF("\n");
#endif /* PRINT_CBCMAC_BLOCKS */

  /* xor with last cipher block */
  for(i = 0; i < BLOCK_SIZE; i++) {
    block[i] ^= cbcmac_xor[i];
  }

#if PRINT_CBCMAC_BLOCKS
  CBCMAC_PRINTF("^_%d: ", cbcmac_blockcount);
  for(i = 0; i < BLOCK_SIZE; i++) {
    CBCMAC_PRINTF("%02x", block[i]);
  }
  CBCMAC_PRINTF("\n");
#endif /* PRINT_CBCMAC_BLOCKS */

  /* encrypt */
  aes_encrypt(block, key);
  memcpy(cbcmac_xor, block, BLOCK_SIZE);

#if PRINT_CBCMAC_BLOCKS
  CBCMAC_PRINTF("X_%d: ", cbcmac_blockcount);
  for(i = 0; i < BLOCK_SIZE; i++) {
    CBCMAC_PRINTF("%02x", block[i]);
  }
  CBCMAC_PRINTF("\n");
  cbcmac_blockcount++;
#endif /* PRINT_CBCMAC_BLOCKS */
}
/*---------------------------------------------------------------------------*/
/**
 * Convert 16-bit quantity from host byte order to network byte order.
 *
 * This macro is primarily used for converting constants from host
 * byte order to network byte order. For converting variables to
 * network byte order, use the uip_htons() function instead.
 *
 * \hideinitializer
 */
#ifndef UIP_HTONS
#   if UIP_BYTE_ORDER == UIP_BIG_ENDIAN
#      define UIP_HTONS(n) (n)
#      define UIP_HTONL(n) (n)
#   else /* UIP_BYTE_ORDER == UIP_BIG_ENDIAN */
#      define UIP_HTONS(n) (uint16_t)((((uint16_t) (n)) << 8) | (((uint16_t) (n)) >> 8))
#      define UIP_HTONL(n) (((uint32_t)UIP_HTONS(n) << 16) | UIP_HTONS((uint32_t)(n) >> 16))
#   endif /* UIP_BYTE_ORDER == UIP_BIG_ENDIAN */
#else
#error "UIP_HTONS already defined!"
#endif /* UIP_HTONS */

static void
ctr_next_ctr_block(const unsigned char *key, const unsigned char *nonce,
                  int counter, unsigned char *outbuf)
{
  int flags;
  int tmp;

  /* Prepare CTR block */
  memset(outbuf, 0, BLOCK_SIZE);

  /* CTR block: Flags field */
  flags = 1 * (L_SIZELEN - 1); /* size. length */
  memcpy(&outbuf[0], &flags, 1);

  /* CTR block: Nonce */
  memcpy(&outbuf[1], nonce, NONCE_LEN);

  /* CTR block: Counter */
  tmp = UIP_HTONS(counter);
  memcpy(&outbuf[BLOCK_SIZE - L_SIZELEN], &tmp, L_SIZELEN); /* MSB. */

#if PRINT_CTR_BLOCKS
  CTR_PRINTF("A_%d: ", counter);
  for(i = 0; i < BLOCK_SIZE; i++) {
    CTR_PRINTF("%02x", outbuf[i]);
  }
  CTR_PRINTF("\n");
#endif /* PRINT_CTR_BLOCKS */

  /* Encrypt CTR block */
  aes_encrypt(outbuf, key);

  CTR_PRINTF("CTR: Counter block encrypted\n");
#if PRINT_CTR_BLOCKS
  CTR_PRINTF("S_%d: ", counter);
  for(i = 0; i < BLOCK_SIZE; i++) {
    CTR_PRINTF("%02x", outbuf[i]);
  }
  CTR_PRINTF("\n");
#endif /* PRINT_CTR_BLOCKS */
}
/*---------------------------------------------------------------------------*/
static int
cbcmac_calc(const unsigned char *key, const unsigned char *nonce,
                       const unsigned char *adata, unsigned long adata_len,
                       const unsigned char *payload, unsigned long payload_len,
                       int mic_len, unsigned char *outbuf)
{
  /*
   * Return value:
   * Number of encrypted bytes at success, negative value at failure.
   */

  unsigned char BUF[BLOCK_SIZE];
  int tmp, tmp2;
  int flags;

  cbcmac_clear();

  /* Block B_0 */
  memset(BUF, 0, sizeof(BUF));

  /* B_0: Flags field */
  flags = 0;
  flags += 64 * (adata_len > 0 ? 1 : 0); /* contains associated data */
  flags += 8 * ((mic_len - 2) / 2); /* auth. length */
  flags += 1 * (L_SIZELEN - 1); /* size. length */
  memcpy(&BUF[0], &flags, 1);

  /* B_0: Nonce */
  memcpy(&BUF[1], nonce, NONCE_LEN);

  /* B_0: Size field */
  tmp2 = (int) payload_len; /* XXX Max size supported is 0xFFFF */
  tmp = UIP_HTONS(tmp2);
  memcpy(&BUF[BLOCK_SIZE - L_SIZELEN], &tmp, L_SIZELEN); /* MSB */
  CBCMAC_PRINTF("CBC-MAC: First block prepared\n");
  cbcmac_append(key, BUF);

  /* B_1..n: auth. blocks */
  if(adata_len > 0) {
    unsigned long left, idx;

    /* 2 bytes data length in first auth. block */
    CBCMAC_PRINTF("CBC-MAC: Have auth. data\n");
    memset(BUF, 0, sizeof(BUF));
    tmp2 = (int) adata_len; /* XXX Max size supported is 0xFFFF */
    tmp = UIP_HTONS(tmp2);
    memcpy(&BUF[0], &tmp, 2);

    /* 14 bytes data in first auth. block */
    left = adata_len;
    idx = 0;
    memcpy(&BUF[2], &adata[idx],
           (left > (BLOCK_SIZE - 2) ? (BLOCK_SIZE - 2) : left));
    idx += (left > (BLOCK_SIZE - 2) ? (BLOCK_SIZE - 2) : left);
    left -= (left > (BLOCK_SIZE - 2) ? (BLOCK_SIZE - 2) : left);

    /* 16 bytes data in subsequent auth. blocks */
    while(left > 0) {
      CBCMAC_PRINTF("CBC-MAC: Auth. block prepared\n");
      cbcmac_append(key, BUF);

      /* Auth data + padding with zeroes */
      memset(BUF, 0, sizeof(BUF));
      memcpy(&BUF[0], &adata[idx], (left > BLOCK_SIZE ? BLOCK_SIZE : left));
      idx += (left > BLOCK_SIZE ? BLOCK_SIZE : left);
      left -= (left > BLOCK_SIZE ? BLOCK_SIZE : left);
    }

    CBCMAC_PRINTF("CBC-MAC: Auth. block prepared (last)\n");
    cbcmac_append(key, BUF);
  }

  /* B_n..m: message blocks */
  if(payload_len > 0) {
    unsigned long left, idx;

    CBCMAC_PRINTF("CBC-MAC: Have payload data\n");
    memset(BUF, 0, sizeof(BUF));

    left = payload_len;
    idx = 0;
    while(left > 0) {
      int i;

      /* Auth data + padding with zeroes */
      memset(BUF, 0, sizeof(BUF));
      memcpy(&BUF[0], &payload[idx], (left > BLOCK_SIZE ? BLOCK_SIZE : left));

      idx += (left > BLOCK_SIZE ? BLOCK_SIZE : left);
      left -= (left > BLOCK_SIZE ? BLOCK_SIZE : left);

      CBCMAC_PRINTF("CBC-MAC: Payload block prepared\n");
      cbcmac_append(key, BUF);
    }
  }

  /* Copy mic_len bytes of CBC-MAC to outbuf */
  memcpy(outbuf, BUF, mic_len);
  return mic_len;
}
/*---------------------------------------------------------------------------*/
static int
cbcmac_verify(const unsigned char *key, const unsigned char *nonce,
                         const unsigned char *adata, unsigned long adata_len,
                         const unsigned char *cipher, unsigned long cipher_len,
                         int mic_len, unsigned char *outbuf)
{
  /*
   * Return value:
   * Number of encrypted bytes at success, negative value at failure.
   */

  unsigned char BUF[BLOCK_SIZE];
  int tmp, tmp2;
  int flags;

  cbcmac_clear();

  /* Block B_0 */
  memset(BUF, 0, sizeof(BUF));

  /* B_0: Flags field */
  flags = 0;
  flags += 64 * (adata_len > 0 ? 1 : 0); /* contains associated data */
  flags += 8 * ((mic_len - 2) / 2); /* auth. length */
  flags += 1 * (L_SIZELEN - 1); /* size. length */
  memcpy(&BUF[0], &flags, 1);

  /* B_0: Nonce */
  memcpy(&BUF[1], nonce, NONCE_LEN);

  /* B_0: Size field */
  tmp2 = (int) cipher_len; /* Note: limits cipher length to 65536 bytes */
  tmp = UIP_HTONS(tmp2);
  memcpy(&BUF[BLOCK_SIZE - L_SIZELEN], &tmp, L_SIZELEN); /* MSB */
  CBCMAC_PRINTF("CBC-MAC: First block prepared\n");
  cbcmac_append(key, BUF);

  /* B_1..n: auth. blocks */
  if(adata_len > 0) {
    unsigned long left, idx;

    /* 2 bytes data length in first auth. block */
    CBCMAC_PRINTF("CBC-MAC: Have auth. data\n");
    memset(BUF, 0, sizeof(BUF));
    tmp2 = (int) adata_len; /* XXX Max size supported is 0xFFFF */
    tmp = UIP_HTONS(tmp2);
    memcpy(&BUF[0], &tmp, 2);

    /* 14 bytes data in first auth. block */
    left = adata_len;
    idx = 0;
    memcpy(&BUF[2], &adata[idx],
           (left > (BLOCK_SIZE - 2) ? (BLOCK_SIZE - 2) : left));
    idx += (left > (BLOCK_SIZE - 2) ? (BLOCK_SIZE - 2) : left);
    left -= (left > (BLOCK_SIZE - 2) ? (BLOCK_SIZE - 2) : left);

    /* 16 bytes data in subsequent auth. blocks */
    while(left > 0) {
      CBCMAC_PRINTF("CBC-MAC: Auth. block prepared\n");
      cbcmac_append(key, BUF);

      /* Auth data + padding with zeroes */
      memset(BUF, 0, sizeof(BUF));
      memcpy(&BUF[0], &adata[idx], (left > BLOCK_SIZE ? BLOCK_SIZE : left));
      idx += (left > BLOCK_SIZE ? BLOCK_SIZE : left);
      left -= (left > BLOCK_SIZE ? BLOCK_SIZE : left);
    }

    CBCMAC_PRINTF("CBC-MAC: Auth. block prepared (last)\n");
    cbcmac_append(key, BUF);
  }

  /* B_n..m: message blocks */
  if(cipher_len > 0) {
    unsigned long left, idx, counter, i;

    CBCMAC_PRINTF("CBC-MAC: Have cipher data\n");
    memset(BUF, 0, sizeof(BUF));

    left = cipher_len;
    idx = 0;
    counter = 1; /* S_1 .. S_n */
    while(left > 0) {

      /* Decrypt block right now */
      ctr_next_ctr_block(key, nonce, counter, BUF);
      /* XOR with payload block */
      for(i = 0; i < BLOCK_SIZE; i++) {
        if(idx + i >= cipher_len) {
          BUF[i] = 0;
        } else {
          BUF[i] ^= cipher[idx + i];
        }
      }
      counter++;

      idx += (left > BLOCK_SIZE ? BLOCK_SIZE : left);
      left -= (left > BLOCK_SIZE ? BLOCK_SIZE : left);

      CBCMAC_PRINTF("CBC-MAC: Payload block prepared\n");
      cbcmac_append(key, BUF);
    }
  }

  /* Copy mic_len bytes of CBC-MAC to outbuf */
  memcpy(outbuf, BUF, mic_len);
  return mic_len;
}
/*---------------------------------------------------------------------------*/
static unsigned long
ctr_payload(const unsigned char *key, const unsigned char *nonce,
            const unsigned char *payload, unsigned long payload_len,
            unsigned char *outbuf)
{
  /*
   * Return value:
   * Number of encrypted bytes at success, negative value at failure.
   */

  unsigned char BUF[BLOCK_SIZE];
  unsigned long left, idx;
  int i;
  int counter;

  /* Encrypt payload */
  left = payload_len;
  idx = 0;
  counter = 1; /* S_1 .. S_n */
  while(left > 0) {
    ctr_next_ctr_block(key, nonce, counter, BUF);

    /* XOR with payload block */
    for(i = 0; i < BLOCK_SIZE; i++) {
      if(idx + i >= payload_len) {
        break;
      }
      BUF[i] ^= payload[idx + i];
    }
    CTR_PRINTF("CTR: Payload XORed with counter block\n");
#if PRINT_CTR_BLOCKS
    CTR_PRINTF("X_%d: ", counter);
    for(i = 0; i < BLOCK_SIZE; i++) {
      if(idx + i >= payload_len) {
        break;
      }
      CTR_PRINTF("%02x", BUF[i]);
    }
    CTR_PRINTF("\n");
#endif /* PRINT_CTR_BLOCKS */

    aes_ccm_memcpy(&outbuf[idx], BUF, (left > BLOCK_SIZE ? BLOCK_SIZE : left));

    idx += (left > BLOCK_SIZE ? BLOCK_SIZE : left);
    left -= (left > BLOCK_SIZE ? BLOCK_SIZE : left);

    counter++;
  }

  return idx;
}
/*---------------------------------------------------------------------------*/
static int
ctr_mic(const unsigned char *key, const unsigned char *nonce,
        const unsigned char *cbcmac, int mic_len, unsigned char *outbuf)
{
  /*
   * Return value:
   * Number of encrypted bytes at success, negative value at failure.
   */

  unsigned char BUF[BLOCK_SIZE];
  int i;
  int tmp;
  int flags;

  /* Prepare CTR block */
  memset(BUF, 0, sizeof(BUF));

  /* CTR block: Flags field */
  flags = 1 * (L_SIZELEN - 1); /* size. length */
  memcpy(&BUF[0], &flags, 1);

  /* CTR block: Nonce */
  memcpy(&BUF[1], nonce, NONCE_LEN);

  /* CTR block: Counter */
  tmp = UIP_HTONS(0); /* S_0: counter is 0 */
  memcpy(&BUF[BLOCK_SIZE - L_SIZELEN], &tmp, L_SIZELEN); /* MSB. */

#if PRINT_CTR_MIC_BLOCKS
  CTR_MIC_PRINTF("A_%d: ", 0);
  for(i = 0; i < BLOCK_SIZE; i++) {
    CTR_MIC_PRINTF("%02x", BUF[i]);
  }
  CTR_MIC_PRINTF("\n");
#endif /* PRINT_CTR_MIC_BLOCKS */

  /* Encrypt CTR block */
  aes_encrypt(BUF, key);
  CTR_MIC_PRINTF("CTRMIC: Counter block encrypted\n");
#if PRINT_CTR_MIC_BLOCKS
  CTR_MIC_PRINTF("S_%d: ", 0);
  for(i = 0; i < BLOCK_SIZE; i++) {
    CTR_MIC_PRINTF("%02x", BUF[i]);
  }
  CTR_MIC_PRINTF("\n");
#endif /* PRINT_CTR_MIC_BLOCKS */

  /* XOR with CBC-MAC */
  for(i = 0; i < mic_len; i++) {
    BUF[i] ^= cbcmac[i];
  }
  CTR_MIC_PRINTF("CTRMIC: CBC-MAC XORed with counter block\n");
#if PRINT_CTR_MIC_BLOCKS
  CTR_MIC_PRINTF("X_%d: ", 0);
  for(i = 0; i < mic_len; i++) {
    CTR_MIC_PRINTF("%02x", BUF[i]);
  }
  CTR_MIC_PRINTF("\n");
#endif /* PRINT_CTR_MIC_BLOCKS */

  memcpy(outbuf, BUF, mic_len);

  return mic_len;
}
/*---------------------------------------------------------------------------*/
long
aes_ccm_encrypt(const unsigned char *key, const unsigned char *nonce,
                const unsigned char *adata, unsigned long adata_len,
                const unsigned char *payload, unsigned long payload_len,
                int mic_len, unsigned char *outbuf)
{
  /*
   * Return value:
   * Number of encrypted bytes at success, negative value at failure.
   */

  int i, cbcmac_len;
  long ctr_len;

  /* MIC length: 4, 6, 8, 10, 12, 14, or 16 bytes */
  unsigned char cbcmac[16];

  /* Copy adata (header) */
  memcpy(&outbuf[0], adata, adata_len);


  /* Authentication: calculate CBC-MAC (MIC) over header and payload */
  cbcmac_len = cbcmac_calc(key, nonce, adata, adata_len, payload, payload_len,
                           mic_len, cbcmac);
  if(cbcmac_len < 0 || cbcmac_len != mic_len) {
    return -1;
  }
  PRINTF("CBCMAC %d bytes:\n", cbcmac_len);
  for(i = 0; i < cbcmac_len; i++) {
    PRINTF("%02x", cbcmac[i]);
  }
  PRINTF("\n");


  /* Encryption: encrypt payload using CTR */
  ctr_len = ctr_payload(key, nonce, payload, payload_len, &outbuf[adata_len]);
  if(ctr_len < 0) {
    return -2;
  }
  PRINTF("CTR payload cipher %d bytes:\n", ctr_len);
  for(i = 0; i < ctr_len; i++) {
    PRINTF("%02x", outbuf[adata_len+i]);
  }
  PRINTF("\n");


  /* Encryption: encrypt MIC */
  mic_len = ctr_mic(key, nonce, cbcmac, mic_len, &outbuf[adata_len + payload_len]);
  if(mic_len < 0) {
    return -3;
  }
  PRINTF("CTR MIC %d bytes:\n", mic_len);
  for(i = 0; i < mic_len; i++) {
    PRINTF("%02x", outbuf[adata_len+payload_len+i]);
  }
  PRINTF("\n");

  return (long)(adata_len + payload_len + mic_len);
}
/*---------------------------------------------------------------------------*/
long
aes_ccm_decrypt(const unsigned char *key, const unsigned char *nonce,
                    const unsigned char *adata, unsigned long adata_len,
                    const unsigned char *ciphermic, unsigned long ciphermic_len,
                    int mic_len, unsigned char *outbuf)
{
  int cbcmac_len, cbcmac_len2;
  unsigned long i, ctr_len;

  /* MIC length: 4, 6, 8, 10, 12, 14, or 16 bytes */
  unsigned char cbcmac[16];
  unsigned char cbcmac2[16]; /* recomputed MIC */

  /*
   * Return value:
   * Number of plaintext bytes at success, negative value at failure.
   */

  /* Santity-check: Cipher + MIC must be equal to or longer than the MIC itself */
  if(ciphermic_len < mic_len) {
    return -6;
  }

  /* Decryption: decrypt MIC */
  cbcmac_len = ctr_mic(key, nonce, &ciphermic[ciphermic_len - mic_len], mic_len,
                       cbcmac);
  if(cbcmac_len < 0 || cbcmac_len != mic_len) {
    return -1;
  }
  PRINTF("CBCMAC %d bytes:\n", mic_len);
  for(i = 0; i < mic_len; i++) {
    PRINTF("%02x", cbcmac[i]);
  }
  PRINTF("\n");


  /* Decryption: decrypt payload using CTR */
  ctr_len = ctr_payload(key, nonce, ciphermic, ciphermic_len - mic_len,
                        &outbuf[0]);
  if(ctr_len == 0) {
    return -2;
  }
  PRINTF("CTR payload plaintext %d bytes:\n", ctr_len);
  for(i = 0; i < ctr_len; i++) {
    PRINTF("%02x", outbuf[i]);
  }
  PRINTF("\n");


  /* Authentication: re-calculate CBC-MAC (MIC) over header and payload */
  cbcmac_len2 = cbcmac_calc(key, nonce, adata, adata_len, outbuf, ctr_len,
                            mic_len, cbcmac2);
  if(cbcmac_len2 < 0 || cbcmac_len2 != mic_len) {
    return -3;
  }
  PRINTF("CBCMAC %d bytes:\n", cbcmac_len2);
  for(i = 0; i < cbcmac_len2; i++) {
    PRINTF("%02x", cbcmac2[i]);
  }
  PRINTF("\n");

  /* Verify that MICs match */
  if(cbcmac_len != cbcmac_len2) {
    return -4;
  }
  for(i = 0; i < cbcmac_len; i++) {
    if(cbcmac[i] != cbcmac2[i]) {
      return -5;
    }
  }

  return (long)ctr_len;
}
/*---------------------------------------------------------------------------*/
int
aes_ccm_verify(const unsigned char *key, const unsigned char *nonce,
                   const unsigned char *adata, unsigned long adata_len,
                   const unsigned char *ciphermic, unsigned long ciphermic_len,
                   int mic_len)
{
  int i;
  int cbcmac_len, cbcmac_len2;

  /* MIC length: 4, 6, 8, 10, 12, 14, or 16 bytes */
  unsigned char cbcmac[16];
  unsigned char cbcmac2[16]; /* recomputed MIC */

  /*
   * Return value:
   * 1 if buffer integrity was verified, 0 otherwise.
   */

  /* Decryption: decrypt MIC */
  cbcmac_len = ctr_mic(key, nonce, &ciphermic[ciphermic_len - mic_len], mic_len,
                       cbcmac);
  if(cbcmac_len < 0 || cbcmac_len != mic_len) {
    return 0;
  }
  PRINTF("CBCMAC %d bytes:\n", mic_len);
  for(i = 0; i < mic_len; i++) {
    PRINTF("%02x", cbcmac[i]);
  }
  PRINTF("\n");

  /* Integrity check: both decrypt and calculate CBC-MAC at the same time.
   * We now decrypt the cipher on-the-fly, without storing the cleartext. */
  cbcmac_len2 = cbcmac_verify(key, nonce, adata, adata_len, ciphermic,
                              ciphermic_len - mic_len, mic_len, cbcmac2);
  if(cbcmac_len2 < 0 || cbcmac_len2 != mic_len) {
    return 0;
  }
  PRINTF("CBCMAC %d bytes:\n", cbcmac_len2);
  for(i = 0; i < cbcmac_len2; i++) {
    PRINTF("%02x", cbcmac2[i]);
  }
  PRINTF("\n");

  /* Verify that MICs match */
  if(cbcmac_len != cbcmac_len2) {
    return 0;
  }
  for(i = 0; i < cbcmac_len; i++) {
    if(cbcmac[i] != cbcmac2[i]) {
      return 0;
    }
  }

  return 1;
}
/*---------------------------------------------------------------------------*/
}