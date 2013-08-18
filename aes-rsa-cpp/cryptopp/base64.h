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

#include <base64.h>


// namespace declare.
namespace org{ namespace bsmith{ namespace encoding{


/**
base64 encode/decode class.
*/
class Base64
{
    /**
    get the maximal cipher length after encoded.
    @param len the plain binary data length.
    @return the cipher length.
    */
public: static int getCipherLen(int len);
    /**
    encode input data to base64 output data.
    @param indata input data.
    @param inlen input data length.
    @param outdata output data.
    @return the actual encoded cipher length.
    */
public: static int encode(const char * indata, int inlen, char * outdata);

    /**
    get the maximal plain binary length after decoded.
    @param len the cipher data length.
    @return the maximal plain length.
    */
public: static int getPlainLen(int len);
    /**
    decode base64 input data to output data.
    @param indata input data.
    @param inlen input data length.
    @param outdata output data.
    @return the actual decoded plain data length.
    */
public: static int decode(const char * indata, int inlen, char * outdata);

private: static CryptoPP::Base64Encoder enc;    // base64 encoder.
private: static CryptoPP::Base64Decoder dec;    // base64 decoder.
};



}}}







