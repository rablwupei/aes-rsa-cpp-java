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



#include "./rsa.h"


namespace org{ namespace bsmith{ namespace crypto{

RSA::RSA()
{
    enc = NULL;
    dec = NULL;
}

RSA::~RSA()
{
    if (NULL != enc)
    {
        delete enc;
    }
    if (NULL != dec)
    {
        delete dec;
    }
}

void RSA::initPublicKey(const char * N, const char * e)
{
    CryptoPP::Integer big_N(N);
    CryptoPP::Integer big_e(e);

    pk.Initialize(big_N, big_e);
    if (NULL != enc)
    {
        delete enc;
    }
    enc = new CryptoPP::RSAES_PKCS1v15_Encryptor(pk);
}

void RSA::initPrivateKey(const char * N, const char * e, const char * d)
{
    CryptoPP::Integer big_N(N);
    CryptoPP::Integer big_e(e);
    CryptoPP::Integer big_d(d);

    sk.Initialize(big_N, big_e, big_d);
    if (NULL != dec)
    {
        delete dec;
    }
    dec = new CryptoPP::RSAES_PKCS1v15_Decryptor(sk);
}

int RSA::getCipherLen(int len)
{
    return (int)enc->CiphertextLength(len);
}


int RSA::encrypt(const char * indata, int len, char * outdata)
{
    enc->Encrypt(rng, (const unsigned char *)indata, len, (unsigned char *)outdata);
    return (int)enc->FixedCiphertextLength();
}

int RSA::getPlainLen(int len)
{
    return (int)dec->MaxPlaintextLength(len);
}

int RSA::decrypt(const char * indata, int len, char * outdata)
{
    const CryptoPP::DecodingResult & res = dec->Decrypt(rng, (const unsigned char *)indata, len, (unsigned char *)outdata);
    return (int)res.messageLength;
}


}}}



