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

#include <modes.h>

#include "./rsa.h"
#include "./aes.h"
#include "./sign.h"
#include "./sha1.h"
#include "./base16.h"
#include "./base64.h"

using namespace org::bsmith::encoding;
using namespace org::bsmith::crypto;

/**
for debug only, no use in product, it is so slow.
*/
void dump(const char * data, int len)
{
    for (int i = 0;i < len;i ++)
    {
        printf("%02X", (unsigned char)data[i]);
    }
    printf("\n");
}

unsigned char* getFileData(const char* fullPath, unsigned long * pSize)
{
    unsigned char * pBuffer = NULL;
    *pSize = 0;
    
    // read the file from hardware
    FILE *fp = fopen(fullPath, "rb");
    
    fseek(fp,0,SEEK_END);
    *pSize = ftell(fp);
    fseek(fp,0,SEEK_SET);
    pBuffer = new unsigned char[*pSize];
    *pSize = fread(pBuffer,sizeof(unsigned char), *pSize,fp);
    fclose(fp);
    
    return pBuffer;
}

/**
testing.
*/
int mainCryptopp(const char* encryptPath, const char* decryptPath)
{
    printf("/***************************************************************************\n");
    printf("C++ crypto, wrap cryptopp interface, reference to www.cryptopp.com\n");
    printf("bsmith@qq.com 2006-5-25\n");
    printf("***************************************************************************/\n");

    // base64 testing.
    {
        printf("\n=======================base64=====================\n");
        // input data.
        const char * indata = "bsmith is a good guy.";
        int inlen = (int)strlen(indata);
        printf("inlen=%d\n", inlen);
        printf("indata(hex)=");
        dump(indata, inlen);
        
        // encoding ...
        int maxoutlen = Base64::getCipherLen(inlen);
        printf("maxoutlen=%d\n", maxoutlen);
        char * outdata = new char[maxoutlen];
        int outlen = Base64::encode(indata, inlen, outdata);
        printf("outlen=%d\n", outlen);
        printf("outdata(hex)=");
        dump(outdata, outlen);
        // encoded base64 string.
        char * outstr = new char[outlen+1];
        memcpy(outstr, outdata, outlen);
        outstr[outlen] = 0x00;
        printf("outstr=%s\n", outstr);

        // decoding ...
        int maxinlen = Base64::getPlainLen(outlen);
        printf("maxinlen=%d\n", maxinlen);
        char * orgdata = new char[maxinlen];
        int orglen = Base64::decode(outdata, outlen, orgdata);
        printf("orglen=%d\n", orglen);
        printf("orgdata(hex)=");
        dump(orgdata, orglen);

        delete[] outdata;
        delete[] outstr;
        delete[] orgdata;
    }

    // base16 testing.
    {
        printf("\n=======================base16=====================\n");
        // input data.
        const char * indata = "bsmith is a good guy.";
        int inlen = (int)strlen(indata);
        printf("inlen=%d\n", inlen);
        printf("indata(hex)=");
        dump(indata, inlen);
        
        // encoding ...
        int maxoutlen = Base16::getCipherLen(inlen);
        printf("maxoutlen=%d\n", maxoutlen);
        char * outdata = new char[maxoutlen];
        int outlen = Base16::encode(indata, inlen, outdata);
        printf("outlen=%d\n", outlen);
        printf("outdata(hex)=");
        dump(outdata, outlen);
        // encoded base16 string.
        char * outstr = new char[outlen+1];
        memcpy(outstr, outdata, outlen);
        outstr[outlen] = 0x00;
        printf("outstr=%s\n", outstr);

        // decoding ...
        int maxinlen = Base16::getPlainLen(outlen);
        printf("maxinlen=%d\n", maxinlen);
        char * orgdata = new char[maxinlen];
        int orglen = Base16::decode(outdata, outlen, orgdata);
        printf("orglen=%d\n", orglen);
        printf("orgdata(hex)=");
        dump(orgdata, orglen);

        delete[] outdata;
        delete[] outstr;
        delete[] orgdata;
    }

    // RSA testing.
    {
        printf("\n=======================RSA PKCS #1=====================\n");
        // key
        // N factor in RSA, aslo called modulus.
        const char * N = "90755611487566208138950675092879865387596685014726501531250157258482495478524769456222913843665634824684037468817980814231054856125127115894189385717148934026931120932481402379431731629550862846041784305274651476086892165805223719552575599962253392248079811268061946102234935422772131475340988882825043233323";
        // e factor in RSA, aslo called public exponent.
        const char * e = "65537";
        // d factor in RSA, aslo called private exponent
        const char * d = "17790520481266507102264359414044396762660094486842415203197747383916331528947124726552875080482359744765793816651732601742929364124685415229452844016482477236658413327331659722342187036963943428678684677279032263501011143882814728160215380051287503219732737197808611144507720521201393129692996926599975297921";

        // input data.
        const char * indata = "bsmith is a good guy.";
        int inlen = (int)strlen(indata);
        printf("inlen=%d\n", inlen);
        printf("indata(hex)=");
        dump(indata, inlen);

        // init RSA public key encryptor.
        RSA enc;
        enc.initPublicKey(N, e);

        // encrypt.
        int maxoutlen = enc.getCipherLen(inlen);
        printf("maxoutlen=%d\n", maxoutlen);
        char * outdata = new char[maxoutlen];
        int outlen = enc.encrypt(indata, inlen, outdata);
        printf("outlen=%d\n", outlen);
        printf("outdata(hex)=");
        dump(outdata, outlen);

        // init private for RSA decryptor.
        RSA dec;
        dec.initPrivateKey(N, e, d);

        // decrypt.
        int maxinlen = dec.getPlainLen(outlen);
        printf("maxinlen=%d\n", maxinlen);
        char * orgdata = new char[maxinlen];
        int orglen = dec.decrypt(outdata, outlen, orgdata);
        printf("orglen=%d\n", orglen);
        printf("orgdata(hex)=");
        dump(orgdata, orglen);

        delete[] outdata;
        delete[] orgdata;
    }

    // AES/CBC/PKCS5Padding testing.
    {
        printf("\n=======================AES/CBC/PKCS5Padding=====================\n");
        // key
        const char * key = "0123456789abcdef";
        // iv
        const char * iv = "fedcba9876543210";

        // init AES.
        AES aes;
        aes.init(key, 16, iv);

        // input data.
        // const char * indata = "bsmith is a good guy.";
        // const char * indata = "bsmith.";
        const char * indata = "I am a good guy.";
        int inlen = (int)strlen(indata);
        printf("inlen=%d\n", inlen);
        printf("indata(hex)=");
        dump(indata, inlen);

        // encrypt.
        int maxoutlen = aes.getCipherLen(inlen);
        printf("maxoutlen=%d\n", maxoutlen);
        char * outdata = new char[maxoutlen];
        int outlen = 0;
        {
            outlen = aes.encrypt(indata, inlen, outdata);
            printf("outlen=%d\n", outlen);
            printf("outdata(hex)=");
            dump(outdata, outlen);
        }
        {
            outlen = aes.encrypt(indata, inlen, outdata);
            printf("outlen=%d\n", outlen);
            printf("outdata(hex)=");
            dump(outdata, outlen);
        }

        // decrypt.
        int maxinlen = aes.getPlainLen(outlen);
        printf("maxinlen=%d\n", maxinlen);
        char * orgdata = new char[maxinlen];
        {
            
            int orglen = aes.decrypt(outdata, outlen, orgdata);
            printf("orglen=%d\n", orglen);
            printf("orgdata(hex)=");
            dump(orgdata, orglen);
        }
        {
            int orglen = aes.decrypt(outdata, outlen, orgdata);
            printf("orglen=%d\n", orglen);
            printf("orgdata(hex)=");
            dump(orgdata, orglen);
        }

        delete[] outdata;
        delete[] orgdata;

    }

    // SHA1 testing.
    {
        printf("\n=======================SHA1=====================\n");

        SHA1 sha1;

        // input data.
        const char * indata = "bsmith is a good guy.";
        int inlen = (int)strlen(indata);
        printf("inlen=%d\n", inlen);
        printf("indata(hex)=");
        dump(indata, inlen);
        
        // one time digest.
        {
            char * outdata = new char[sha1.getCipherLen(inlen)];
            int outlen = sha1.digest(indata, inlen, outdata);
            printf("outlen=%d\n", outlen);
            printf("outdata(hex)=");
            dump(outdata, outlen);

            delete[] outdata;
        }

        // serval times
        {
            char * outdata = new char[sha1.getCipherLen(inlen)];
            sha1.update(indata, 5);
            sha1.update(indata+5, inlen-5);
            int outlen = sha1.final(outdata);
            printf("outlen=%d\n", outlen);
            printf("outdata(hex)=");
            dump(outdata, outlen);

            delete[] outdata;
        }

        // one time digest.
        {
            char * outdata = new char[sha1.getCipherLen(inlen)];
            int outlen = sha1.digest(indata, inlen, outdata);
            printf("outlen=%d\n", outlen);
            printf("outdata(hex)=");
            dump(outdata, outlen);

            delete[] outdata;
        }

        // serval times
        {
            char * outdata = new char[sha1.getCipherLen(inlen)];
            sha1.update(indata, 5);
            sha1.update(indata+5, inlen-5);
            int outlen = sha1.final(outdata);
            printf("outlen=%d\n", outlen);
            printf("outdata(hex)=");
            dump(outdata, outlen);

            delete[] outdata;
        }
    }

    // RSA-SHA1 Sign testing.
    {
        printf("\n=======================RSA-SHA1 Sign=====================\n");

        // key
        // N factor in RSA, aslo called modulus.
        const char * N = "90755611487566208138950675092879865387596685014726501531250157258482495478524769456222913843665634824684037468817980814231054856125127115894189385717148934026931120932481402379431731629550862846041784305274651476086892165805223719552575599962253392248079811268061946102234935422772131475340988882825043233323";
        // e factor in RSA, aslo called public exponent.
        const char * e = "65537";
        // d factor in RSA, aslo called private exponent
        const char * d = "17790520481266507102264359414044396762660094486842415203197747383916331528947124726552875080482359744765793816651732601742929364124685415229452844016482477236658413327331659722342187036963943428678684677279032263501011143882814728160215380051287503219732737197808611144507720521201393129692996926599975297921";

        // input data.
        const char * indata = "bsmith is a good guy.";
        int inlen = (int)strlen(indata);
        printf("inlen=%d\n", inlen);
        printf("indata(hex)=");
        dump(indata, inlen);

        Sign sign;
        // private key for signer.
        sign.initPrivateKey(N, e, d);

        // sign.
        int maxoutlen = sign.getCipherLen(inlen);
        printf("maxoutlen=%d\n", maxoutlen);
        char * outdata = new char[maxoutlen];
        int outlen = sign.sign(indata, inlen, outdata);
        printf("outlen=%d\n", outlen);
        printf("outdata(hex)=");
        dump(outdata, outlen);

        // public key for verifier.
        sign.initPublicKey(N, e);

        // verify.
        {
            bool res = sign.verify(indata, inlen, outdata, outlen);
            printf("result <?> true : %s\n", res?"true":"false");
        }
        
        // another data.
        const char * indata1 = "bsmith is not a good guy.";
        int inlen1 = (int)strlen(indata1);
        {
            bool res = sign.verify(indata1, inlen1, outdata, outlen);
            printf("result <?> false : %s\n", res?"true":"false");
        }

        delete[] outdata;
    }

    //printf("press any key to exit!");
    //getchar();
    
    {
        //my test
        unsigned long decryptSize = 0;
        char* decryptBuffer = (char*)getFileData(decryptPath, &decryptSize);
        
        unsigned long encryptSize = 0;
        char* encryptBuffer = (char*)getFileData(encryptPath, &encryptSize);
        
        printf("decryptBuffer(hex)=");
        dump(decryptBuffer, decryptSize);
        
        // key
        const char * key = "0123456789abcdef";
        // iv
        const char * iv = "fedcba9876543210";
        
        // init AES.
        AES aes;
        aes.init(key, 16, iv);
        {
            // decrypt.
            int maxinlen = aes.getPlainLen(encryptSize);
            char * orgdata = new char[maxinlen];
            {
                int orglen = aes.decrypt(encryptBuffer, encryptSize, orgdata);
                printf("decryptWithCrypto++(hex)=");
                dump(orgdata, orglen);
            }
            delete [] orgdata;
        }
        
        printf("encryptBuffer(hex)=");
        dump(encryptBuffer, encryptSize);
        
        {
            // encrypt.
            int maxoutlen = aes.getCipherLen(decryptSize);
            char * outdata = new char[maxoutlen];
            int outlen = 0;
            {
                outlen = aes.encrypt(decryptBuffer, decryptSize, outdata);
                printf("encryptWithCrypto++(hex)=");
                dump(outdata, outlen);
            }
            delete [] outdata;
        }
        
        delete [] decryptBuffer;
        delete [] encryptBuffer;
        
        
    }

    return 0;
}



