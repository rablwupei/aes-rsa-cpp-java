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



#include "./base64.h"


namespace org{ namespace bsmith{ namespace encoding{


CryptoPP::Base64Encoder Base64::enc;
CryptoPP::Base64Decoder Base64::dec;


int Base64::getCipherLen(int len)
{
    // +1 for cryptopp '\n' padding.
    return ((len+3-len%3)*4)/3+1;
    /*
    int pad = len%3;
    if (0 == pad)
    {
        return (len*4)/3+1;
    }
    return ((len+pad+3)*4)/3+1;
    // +1 for cryptopp '\n' padding.
    */
}

int Base64::encode(const char * indata, int inlen, char * outdata)
{
    enc.Put((const unsigned char *)indata, inlen);
    enc.MessageEnd();
    int outlen = (int)enc.TotalBytesRetrievable();
    // enc.Get - 1 for drop the tail '\n' from cryptopp.
    return (int)(enc.Get((unsigned char *)outdata, outlen)-1);
}

int Base64::getPlainLen(int len)
{
    return (len*3)/4;
}

int Base64::decode(const char * indata, int inlen, char * outdata)
{
    dec.Put((const unsigned char *)indata, inlen);
    dec.MessageEnd();
    int outlen = (int)dec.TotalBytesRetrievable();
    return (int)(dec.Get((unsigned char *)outdata, outlen));
}

}}}



