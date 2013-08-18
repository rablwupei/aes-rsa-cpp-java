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

import java.io.UnsupportedEncodingException;

import java.math.BigInteger;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bsmith.encoding.Base16;


/**
 * the RSA-SHA1 signature class with PKCS#1 v1.5 padding.
 */
public class Sign
{
    public static void dump(String label, byte[] data)
    {
        String hex_str = Base16.encode(data);
        System.out.println(label+"="+hex_str);
    }
    
    /**
     * the example.
     * @param args
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeySpecException
     * @throws ShortBufferException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, SignatureException
    {
        System.out.println("=======================RSA-SHA1 Sign=====================");
    
        String N = "90755611487566208138950675092879865387596685014726501531250157258482495478524769456222913843665634824684037468817980814231054856125127115894189385717148934026931120932481402379431731629550862846041784305274651476086892165805223719552575599962253392248079811268061946102234935422772131475340988882825043233323";
        String e ="65537";
        String d = "17790520481266507102264359414044396762660094486842415203197747383916331528947124726552875080482359744765793816651732601742929364124685415229452844016482477236658413327331659722342187036963943428678684677279032263501011143882814728160215380051287503219732737197808611144507720521201393129692996926599975297921";
        
        String msg = "bsmith am a good guy.";
        byte[] indata = msg.getBytes("UTF-8");
        {
            String hex_str = Base16.encode(indata);
            System.out.println(hex_str);
        }
        
        Sign ser = new Sign();
        ser.initPrivateKey(N, e, d);
        
        byte[] outdata = ser.sign(indata, 0, indata.length);
        dump("outdata", outdata);
        
        byte[] outdata1 = new byte[ser.getCipherLen()];
        ser.sign(indata, 0, indata.length, outdata1, 0);
        dump("outdata1", outdata1);
        
        Sign ver = new Sign();
        ver.initPublicKey(N, e);
        System.out.println(String.format("result <?> true : %s", ver.verify(indata, outdata)));
        System.out.println(String.format("result <?> true : %s", ver.verify(indata, outdata1)));
        
        byte[] indata1 = "bsmith is not a good guy.".getBytes("UTF-8");
        System.out.println(String.format("result <?> false : %s", ver.verify(indata1, outdata)));
    }

    private Signature ser;  // signer.
    private PrivateKey sk;  // private key for signer.
    private Signature ver;  // verifier
    private PublicKey pk;   // public key for verifier.
    private int KEY_BYTE_LEN;   // the RSA key bytes length.

    public Sign()
    {
    }
    
    /**
     * init public key for verifier.
     * @param N N factor in RSA, aslo called modulus.
     * @param e e factor in RSA, aslo called publicExponent.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeySpecException
     */
    public void initPublicKey(String N, String e) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException
    {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        BigInteger big_N = new BigInteger(N);
        KEY_BYTE_LEN = (big_N.bitLength())>>3;
        BigInteger big_e = new BigInteger(e);
        KeySpec keySpec = new RSAPublicKeySpec(big_N, big_e);
        pk = keyFactory.generatePublic(keySpec);
    }
    
    /**
     * init private key for signer.
     * @param N N factor in RSA, aslo called modulus.
     * @param e e factor in RSA, aslo called publicExponent, ignored, just keep compatible with C++ interface.
     * @param d d factor in RSA, aslo called privateExponent.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeySpecException
     */
    public void initPrivateKey(String N, String e, String d) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException
    {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        BigInteger big_N = new BigInteger(N);
        KEY_BYTE_LEN = (big_N.bitLength())>>3;
        BigInteger big_d = new BigInteger(d);
        KeySpec keySpec = new RSAPrivateKeySpec(big_N, big_d);
        sk = keyFactory.generatePrivate(keySpec);
    }
    
    /**
     * get the signer length in bytes.
     * this value is fixed, and is equals the RSA key bytes length.
     * @return the signer length.
     */
    public int getCipherLen()
    {
        return KEY_BYTE_LEN;
    }
    
    /**
     * sign the input data to output data.
     * @param indata the input data.
     * @param inoff the input data offset.
     * @param inlen the input data length.
     * @param outdata the output data.
     * @param outoff the output data offset.
     * @return the actual output data length.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public int sign(byte[] indata, int inoff, int inlen, byte[] outdata, int outoff) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        initSigner();
        ser.update(indata, inoff, inlen);
        return ser.sign(outdata, outoff, KEY_BYTE_LEN);
    }
    
    /**
     * sign the input data to output data.
     * @param indata the input data.
     * @param inoff the input data offset.
     * @param inlen the input data length.
     * @return the output data.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public byte[] sign(byte[] indata, int inoff, int inlen) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        initSigner();
        ser.update(indata, inoff, inlen);
        return ser.sign();
    }
    
    /**
     * sign the input data to output data.
     * @param indata the input data.
     * @return the output data.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public byte[] sign(byte[] indata) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        initSigner();
        ser.update(indata);
        return ser.sign();
    }
    
    /**
     * verify the input data and the signer.
     * @param plaindata the input plain data.
     * @param plainoff the input plain data offset.
     * @param plainlen the input plain data length.
     * @param signdata the signer data.
     * @param signoff the signer data offset.
     * @param signlen the signer data length.
     * @return the verify result, true passed, false failed.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public boolean verify(byte[] plaindata, int plainoff, int plainlen, byte[] signdata, int signoff, int signlen) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        initVerifier();
        ver.update(plaindata, plainoff, plainlen);
        return ver.verify(signdata, signoff, signlen);
    }
    
    /**
     * verify the input data and the signer.
     * @param plaindata the input plain data.
     * @param signdata the signer data.
     * @return the verify result, true passed, false failed.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public boolean verify(byte[] plaindata, byte[] signdata) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        initVerifier();
        ver.update(plaindata);
        return ver.verify(signdata);
    }
    
    private void initSigner() throws NoSuchAlgorithmException, InvalidKeyException
    {
        if (null == ser)
        {
            ser = Signature.getInstance("SHA1withRSA");
            ser.initSign(sk);
        }
    }
    
    private void initVerifier() throws NoSuchAlgorithmException, InvalidKeyException
    {
        if (null == ver)
        {
            ver = Signature.getInstance("SHA1withRSA");
            ver.initVerify(pk);
        }
    }
}

