/***

Copyright 2006 bsmith@qq.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/



#include "./aes.h"

void dump(const char * data, int len);


namespace org{ namespace bsmith{ namespace crypto{

AES::AES()
{
}

AES::~AES()
{
}

void AES::init(const char * key, int len, const char * iv)
{
    enc.SetKeyWithIV((const unsigned char *)key, len, (const unsigned char *)iv);
    dec.SetKeyWithIV((const unsigned char *)key, len, (const unsigned char *)iv);
    memcpy(this->iv, iv, 16);
}

int AES::getCipherLen(int len)
{
    // for PKCS#1 v1.5 padding
    // max padding BLOCK_SIZE=16.
    int pad = len%16;
    if (0 == pad)
    {
        return len + 16;
    }
    return len - pad + 16;
}

int AES::encrypt(const char * indata, int inlen, char * outdata)
{
    // resynchronize with an IV 
    enc.Resynchronize((const unsigned char *)iv);

    int pad = inlen%16;
    int prefix = inlen-pad;

    // process normal prefix blocks.
    if (prefix > 0)
    {
        enc.ProcessData((unsigned char *)outdata, (const unsigned char *)indata, prefix);
    }

    // process the last padding block.
    char padding[16];
    if (pad < 16)
    {
        memcpy(padding, indata+prefix, pad);
    }
    memset(padding+pad, 16-pad, 16-pad);
    enc.ProcessLastBlock((unsigned char *)(outdata+prefix), (const unsigned char *)padding, 16);

    return prefix+16;
}

int AES::getPlainLen(int len)
{
    // for PKCS#1 v1.5 padding
    // len always be times of BLOCK_SIZE=16.
    return len;
}

int AES::decrypt(const char * indata, int inlen, char * outdata)
{
    // drop no times of 16 bytes data.
    inlen -= inlen%16;
    if (inlen < 16)
    {
        return 0;
    }

    // resynchronize with an IV 
    dec.Resynchronize((const unsigned char *)iv);

    // process normal prefix blocks.
    int prefix = inlen - 16;
    if (prefix > 0)
    {
        dec.ProcessData((unsigned char *)outdata, (const unsigned char *)indata, prefix);
    }
    
    // process padding block.
    char padding[16];
    dec.ProcessLastBlock((unsigned char *)padding, (const unsigned char *)(indata+prefix), 16);

    int pad = (unsigned char)padding[15];
    if (pad < 16)
    {
        memcpy(outdata+prefix, padding, 16-pad);
    }

    return prefix + 16 - pad;
}


}}}


