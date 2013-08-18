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


package org.bsmith.crypto;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bsmith.encoding.Base16;


/**
 * aes chiper class.
 * CBC mode with PKCS#1 v1.5 padding.
 */
public class AES
{
    public static void dump(String label, byte[] data)
    {
        String hex_str = Base16.encode(data);
        System.out.println(label+"="+hex_str);
    }

    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException
    {
        System.out.println("=======================AES/CBC/PKCS5Padding=====================");
        // key
        byte[] key = "0123456789abcdef".getBytes("UTF-8");
        dump("key", key);
        // iv
        byte[] iv = "fedcba9876543210".getBytes("UTF-8");
        dump("iv", iv);
        
        byte[] indata = "bsmith is a good guy.".getBytes("UTF-8");
        dump("indata", indata);
        
        AES aes = new AES();
        aes.init(key, iv);
        byte[] outdata = aes.encrypt(indata);
        dump("outdata", outdata);
        
        byte[] indata1 = aes.decrypt(outdata);
        dump("indata1", indata1);
        
        FileOutputStream fos = new FileOutputStream("../test/encrypt.bin");
        fos.write(outdata);
        fos.close();
        
        fos = new FileOutputStream("../test/decrypt.bin");
        fos.write(indata1);
        fos.close();
    }

    private Cipher enc;
    private Cipher dec;
    private SecretKeySpec keySpec;
    private IvParameterSpec ivSpec;

    public AES()
    {
    }
    
    /**
     * init the AES key.
     * the key must be 128, 192, or 256 bits.
     * @param key the AES key.
     * @param keyoff the AES key offset.
     * @param keylen the AES key length, the key length must be 16 bytes because SunJCE only support 16 bytes key.
     * @param iv the IV for CBC, the length of iv must be 16 bytes.
     * @param ivoff the iv offset.
     */
    public void init(byte[] key, int keyoff, int keylen, byte[] iv, int ivoff)
    {
        keySpec = new SecretKeySpec(key, keyoff, keylen, "AES");
        ivSpec = new IvParameterSpec(iv, ivoff, 16);
    }
    
    /**
     * init the AES key.
     * the key must be 16 bytes, because SunJCE only support 16 bytes key..
     * @param key the AES key.
     * @param iv the iv for CBC, iv must be 16 bytes length.
     */
    public void init(byte[] key, byte[] iv)
    {
        keySpec = new SecretKeySpec(key, "AES");
        ivSpec = new IvParameterSpec(iv);
    }
    
    /**
    * get the maximal cipher data length after encrypted.
    * @param len the plain data length.
    * @return the cipher data length.
    */
    public int getCipherLen(int len)
    {
        // for PKCS#1 v1.5 padding
        // max padding BLOCK_SIZE=16.
        int pad = len%16;
        if (0 == pad)
        {
            return len + 16;
        }
        return len - pad + 16;
    }
    
    /**
     * encrypt the input data to output data.
     * the input data length must be the times of 16 bytes.
     * and the output data length is equals to the input data.
     * @param indata the input data.
     * @param inoff the input data offset.
     * @param inlen the input data length.
     * @param outdata the output data.
     * @param outoff the output data offset.
     */
    public void encrypt(byte[] indata, int inoff, int inlen, byte[] outdata, int outoff) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    {
        initEncryptor();
        enc.doFinal(indata, inoff, inlen, outdata, outoff);
    }
    
    /**
     * encrypt the input data to output data.
     * @param indata the input data.
     * @param inoff the input data offset.
     * @param inlen the input data length.
     * @return the output encrypted data.
     */
    public byte[] encrypt(byte[] indata, int inoff, int inlen) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    {
        initEncryptor();
        return enc.doFinal(indata, inoff, inlen);
    }
    
    /**
     * encrypt the input data to output data.
     * @param indata the input data.
     * @return the output data.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public byte[] encrypt(byte[] indata) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        initEncryptor();
        return enc.doFinal(indata);
    }
    
    /**
    * the maximal plain data length after decrypted.
    * @param len the cipher data length that will be decrypted.
    * @return the maximal plain data length.
    */
    public int getPlainLen(int len)
    {
        // for PKCS#1 v1.5 padding
        // len always be times of BLOCK_SIZE=16.
        return len;
    }
    
    /**
     * decrypt the input data to output data.
     * @param indata the input data.
     * @param inoff the input data offset.
     * @param inlen the input data length.
     * @param outdata the output data.
     * @param outoff the output data offset.
     */
    public void decrypt(byte[] indata, int inoff, int inlen, byte[] outdata, int outoff) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
    {
        initDecryptor();
        dec.doFinal(indata, inoff, inlen, outdata, outoff);
    }
    
    /**
     * decrypt the input data to output data.
     * @param indata the input data.
     * @param inoff the input data offset.
     * @param inlen the input data length.
     * @return the output decrypted data.
     */
    public byte[] decrypt(byte[] indata, int inoff, int inlen) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, InvalidAlgorithmParameterException
    {
        initDecryptor();
        return dec.doFinal(indata, inoff, inlen);
    }
    
    /**
     * decrypt the input data to output data.
     * @param indata the input cipher data.
     * @return the output plain data.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public byte[] decrypt(byte[] indata) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        initDecryptor();
        return dec.doFinal(indata);
    }
    
    private void initEncryptor() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (null == enc)
        {
            enc = Cipher.getInstance("AES/CBC/PKCS5Padding");
            enc.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        }
    }
    
    private void initDecryptor() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (null == dec)
        {
            dec = Cipher.getInstance("AES/CBC/PKCS5Padding");
            dec.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        }
    }
}


