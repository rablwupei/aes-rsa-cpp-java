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


// namespace declare.
namespace org{ namespace bsmith{ namespace encoding{


/**
base16 encode/decode class.
*/
class Base16
{

public: static const char ENC_TAB[];    // encoding constant table.
public: static const unsigned char DEC_TAB[];   // decoding constant table.

        /**
        get the maximal cipher data length after encoded.
        @param len the plain data length.
        @return the cipher data length.
        */
public: static int getCipherLen(int len)
        {
            return len<<1;
        }

        /**
        encode input data to base16 output data.
        @param indata input data.
        @param inlen input data length.
        @param outdata output data.
        */
public: static int encode(const char * indata, int inlen, char * outdata)
        {
            for (int i = 0;i < inlen;i ++)
            {
                outdata[i<<1] = ENC_TAB[(indata[i]&0xF0)>>4];
                outdata[(i<<1)+1] = ENC_TAB[indata[i]&0x0F];
            }
            return inlen<<1;
        }

        /**
        get the maximal plain data length after decoded.
        @param len the cipher data length.
        @return the plain data length.
        */
public: static int getPlainLen(int len)
        {
            return len>>1;
        }

        /**
        decode input base16 data to output data.
        @param indata input data.
        @param inlen input data length, the length must be times of 2, or the tail will be droped.
        @param outdata output data.
        */
public: static int decode(const char * indata, int inlen, char * outdata)
        {
            inlen = inlen>>1;
            for (int i = 0;i < inlen;i ++)
            {
                outdata[i] = (DEC_TAB[(unsigned char)indata[i<<1]]<<4) | DEC_TAB[(unsigned char)indata[(i<<1)+1]];
            }
            return inlen;
        }
};


}}}





