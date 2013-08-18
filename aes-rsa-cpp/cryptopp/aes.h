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


#include <aes.h>
#include <modes.h>

// namespace declare.
namespace org{ namespace bsmith{ namespace crypto{

/**
aes chiper class.
CBC mode with PKCS#1 v1.5 padding.
*/
class AES
{
public: AES();
public: ~AES();

/**
init the enc/dec key.
@param key the enc/dec key
@param len the key length in bytes, this value can be 16, 24, 32 (128, 196, 256 bits) bytes
@param iv block size 16 bytes initializaiton vector.
*/
public: void init(const char * key, int len, const char * iv);

/**
get the maximal cipher data length after encrypted.
@param len the plain data length.
@return the cipher data length.
*/
public: int getCipherLen(int len);

/**
encrypt the indata to outdata.
@param indata the input data to be encrypted.
@param len the input data length in bytes, must be times of 16 bytes.
@param outdata the output data, at least the length with input data.
*/
public: int encrypt(const char * indata, int len, char * outdata);

/**
the maximal plain data length after decrypted.
@param len the cipher data length that will be decrypted.
@return the maximal plain data length.
*/
public: int getPlainLen(int len);
        
/**
decrypt the indata to outdata.
@param indata the input data to be encrypted.
@param len the input data length in bytes, must be times of 16 bytes.
@param outdata the output data, at least the length with input data.
*/
public: int decrypt(const char * indata, int len, char * outdata);

private: CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;   // cryptopp implement aes CBC encryptor.
private: CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;   // cryptopp implement aes CBC decryptor.
private: char iv[16];   // initialization vector.

};


}}}



