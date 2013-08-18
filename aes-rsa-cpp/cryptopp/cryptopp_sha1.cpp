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



#include "./sha1.h"



namespace org{ namespace bsmith{ namespace crypto{

int SHA1::getCipherLen(int len)
{
    return 20;
}


void SHA1::reset()
{
    sha1.Restart();
}

void SHA1::update(const char * indata, int len)
{
    sha1.Update((const unsigned char *)indata, len);
}

int SHA1::final(char * outdata)
{
    sha1.Final((unsigned char *)outdata);
    return 20;
}

int SHA1::digest(const char * indata, int len, char * outdata)
{
    sha1.CalculateDigest((unsigned char *)outdata, (const unsigned char *)indata, len);
    return 20;
}


}}}

