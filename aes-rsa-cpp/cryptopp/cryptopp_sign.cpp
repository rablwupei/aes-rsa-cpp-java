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


#include "./sign.h"

namespace org{ namespace bsmith{ namespace crypto{

Sign::Sign()
{
    ser = NULL;
    ver = NULL;
}

Sign::~Sign()
{
    if (NULL != ser)
    {
        delete ser;
    }

    if (NULL != ver)
    {
        delete ver;
    }
}

void Sign::initPublicKey(const char * N, const char * e)
{
    CryptoPP::Integer big_N(N);
    CryptoPP::Integer big_e(e);

    pk.Initialize(big_N, big_e);
    if (NULL != ver)
    {
        delete ver;
    }
    ver = new CryptoPP::RSASSA_PKCS1v15_SHA_Verifier(pk);
}

void Sign::initPrivateKey(const char * N, const char * e, const char * d)
{
    CryptoPP::Integer big_N(N);
    CryptoPP::Integer big_e(e);
    CryptoPP::Integer big_d(d);

    sk.Initialize(big_N, big_e, big_d);
    if (NULL != ser)
    {
        delete ser;
    }
    ser = new CryptoPP::RSASSA_PKCS1v15_SHA_Signer(sk);
}

int Sign::getCipherLen(int len)
{
    return (int)ser->SignatureLength();
}

int Sign::sign(const char * indata, int inlen, char * outdata)
{
    return (int)ser->SignMessage(rng, (const unsigned char *)indata, inlen, (unsigned char *)outdata);
}

bool Sign::verify(const char * indata, int inlen, const char * signdata, int signlen)
{
    return ver->VerifyMessage((const unsigned char *)indata, inlen, (const unsigned char *)signdata, signlen);
}



}}}


