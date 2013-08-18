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


#include <sha.h>

// namespace declare.
namespace org{ namespace bsmith{ namespace crypto{

/**
sha1 digest operation class.
*/
class SHA1
{
/**
the maximal cipher length after digested.
fixed and always 20 bytes.
@param len the plain data length will be digested.
@return the maximal cipher length.
*/
public: int getCipherLen(int len);

/**
reset the digest operation buffer to empty.
*/
public: void reset();
/**
push the indata to digest operation buffer.
@param indata input data.
@param len the input data length.
*/
public: void update(const char * indata, int len);
/**
do final digest operation, set the digest to outdata, and reset the digest operation.
@param outdata the digest output data, must at last 20 bytes length.
@return the cipher length.
*/
public: int final(char * outdata);
/**
do final digest operation at one time.
@param indata the input data.
@param len the input data length in bytes.
@param outdata the output data, must at least 20 bytes.
@return the cipher length.
*/
public: int digest(const char * indata, int len, char * outdata);

private: CryptoPP::SHA1 sha1; // the cryptopp sha1 implement.
};



}}}



