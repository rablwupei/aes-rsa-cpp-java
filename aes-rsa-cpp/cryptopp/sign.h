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


#pragma once

#include <rsa.h>
#include <osrng.h>


// namespace declare.
namespace org{ namespace bsmith{ namespace crypto{

/**
RSA-SHA1 signer/verifier.
*/
class Sign
{
public: Sign();
public: ~Sign();

/**
init verifier use public key.
@params N N factor in RSA, aslo called the modulus, big integer in string format.
@params e e factor in RSA, aslo called public exponent, big integer in string format.
*/
public: void initPublicKey(const char * N, const char * e);
/**
init signer use private key.
@params N N factor in RSA, aslo called the modulus, big integer in string format.
@params e e factor in RSA, aslo called public exponent, big integer in string format.
@params d d factor in RSA, aslo called private exponent, big integer in string format.
*/
public: void initPrivateKey(const char * N, const char * e, const char * d);
/**
the maximal cipher length after signed.
fixed and always is the key bit size/8, e.g. 1024 bits key, this value is 128.
@param len the plain data length will be encrypted.
@return the maximal cipher length.
*/
public: int getCipherLen(int len);
/**
sign indata use private key to outdata.
@param indata input data.
@param len the input data length.
@param outdata the output data length.
*/
public: int sign(const char * indata, int inlen, char * outdata);
/**
verify the indata with it's signer use public key.
@param indata input data.
@param len the input data length.
@param signdata the signer data.
@param signlen the signer data length.
*/
public: bool verify(const char * indata, int inlen, const char * signdata, int signlen);

private: CryptoPP::RSAFunction pk;  // public key.
private: CryptoPP::InvertibleRSAFunction sk;    // private key.
private: CryptoPP::RSASSA_PKCS1v15_SHA_Signer * ser;    // signer.
private: CryptoPP::RSASSA_PKCS1v15_SHA_Verifier * ver;  // verifier.
private: CryptoPP::AutoSeededRandomPool rng;        // auto seeded randomor.

};

}}}


