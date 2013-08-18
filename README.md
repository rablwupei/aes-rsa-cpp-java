# Summary

This is a demo about "Match C++ and Java AES,RSA Encryption and Decryption Results"

## C++ Encryption and Decryption

Use Crypto++ ([http://www.cryptopp.com/](http://www.cryptopp.com/))

I ignore the "cryptopp561.a", because it's too big (130M)

The more information is in [CryptoPP-for-iOS](https://github.com/rablwupei/CryptoPP-for-iOS)

Also you can compile Crypto++ with yourself

## AES

Use the "AES/CBC/PKCS5Padding"

### AES Java Demo

```java
// key
byte[] key = "0123456789abcdef".getBytes("UTF-8");
// iv
byte[] iv = "fedcba9876543210".getBytes("UTF-8");

byte[] indata = "bsmith is a good guy.".getBytes("UTF-8");
//dump("indata", indata);

AES aes = new AES();
aes.init(key, iv);

// encrypt.
byte[] outdata = aes.encrypt(indata);
//dump("outdata", outdata);

// decrypt.
byte[] indata1 = aes.decrypt(outdata);
//dump("indata1", indata1);
```

### AES C++ Demo

```cpp
// key
const char * key = "0123456789abcdef";
// iv
const char * iv = "fedcba9876543210";

AES aes;
aes.init(key, 16, iv);

{
	// decrypt.
	int maxinlen = aes.getPlainLen(encryptSize);
	char * orgdata = new char[maxinlen];
	{
		int orglen = aes.decrypt(encryptBuffer, encryptSize, orgdata);
		//printf("decryptWithCrypto++(hex)=");
		//dump(orgdata, orglen);
	}
	delete [] orgdata;
}

{
	// encrypt.
	int maxoutlen = aes.getCipherLen(decryptSize);
	char * outdata = new char[maxoutlen];
	int outlen = 0;
	{
		outlen = aes.encrypt(decryptBuffer, decryptSize, outdata);
		//printf("encryptWithCrypto++(hex)=");
		//dump(outdata, outlen);
	}
	delete [] outdata;
}
```

## RSA

Use the "RSA PKCS #1"

