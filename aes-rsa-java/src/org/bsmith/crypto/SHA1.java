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

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bsmith.encoding.Base16;


/**
 * sha1 digest operation class.
 */
public class SHA1
{
    /**
     * example.
     * @param args
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException
     * @throws DigestException
     */
    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, DigestException
    {
        System.out.println("=======================SHA1=====================");
    
        SHA1 sha1 = new SHA1();
        byte[] indata = "bsmith is a good guy.".getBytes("UTF-8");
        {
            byte[] outdata = sha1.digest(indata, 0, indata.length);
            String hex_str = Base16.encode(outdata);
            System.out.println(hex_str);
        }
        {
            byte[] outdata = new byte[20];
            sha1.digest(indata, 0, indata.length, outdata, 0);
            String hex_str = Base16.encode(outdata);
            System.out.println(hex_str);
        }
        
        {
            byte[] outdata = new byte[20];
            sha1.update(indata, 0, 10);
            sha1.update(indata, 10, indata.length-10);
            sha1.Final(outdata, 0);
            String hex_str = Base16.encode(outdata);
            System.out.println(hex_str);
        }
        
        {
            sha1.update(indata, 0, 10);
            sha1.update(indata, 10, indata.length-10);
            byte[] outdata = sha1.Final();
            String hex_str = Base16.encode(outdata);
            System.out.println(hex_str);
        }
        
        {
            byte[] outdata = new byte[20];
            sha1.update(indata);
            sha1.Final(outdata, 0);
            String hex_str = Base16.encode(outdata);
            System.out.println(hex_str);
        }
    }


    private MessageDigest sha1;     // sha1 object.
    
    public SHA1() throws NoSuchAlgorithmException
    {
        sha1 = MessageDigest.getInstance("SHA-1");
    }
    
    /**
     * get the cipher bytes length after sha1 operation.
     * this value is fixed and is 20 bytes.
     * @return the cipher bytes length. 
     */
    public int getCipherLen()
    {
        return 20;
    }
    
    /**
     * reset the sha1 buffer to empty.
     */
    public void reset()
    {
        sha1.reset();
    }
    
    /**
     * update indata to sha1 buffer.
     * @param indata the input data.
     */
    public void update(byte[] indata)
    {
        sha1.update(indata);
    }
    
    /**
     * update indata to sha1 buffer.
     * @param indata the input data.
     * @param inoff the input data offset.
     * @param inlen the input data length.
     */
    public void update(byte[] indata, int inoff, int inlen)
    {
        sha1.update(indata, inoff, inlen);
    }
    
    /**
     * caculate the sha1 digest value from updated buffer data and reset the buffer.
     * @param outdata the output data.
     * @param outoff the output data offset.
     * @throws DigestException
     */
    public int Final(byte[] outdata, int outoff) throws DigestException
    {
        return sha1.digest(outdata, outoff, 20);
    }
    
    /**
     * caculate the sha1 digest value from updated buffer data and reset the buffer.
     * @return the output data.
     */
    public byte[] Final()
    {
        return sha1.digest();
    }
    
    /**
     * caculate the sha1 digest value from indata and reset the buffer.
     * @param indata the input data.
     * @param inoff the input data offset.
     * @param inlen the input data length.
     * @return the output data.
     */
    public byte[] digest(byte[] indata, int inoff, int inlen)
    {
        sha1.reset();
        sha1.update(indata, inoff, inlen);
        return sha1.digest();
    }
    
    /**
     * caculate the sha1 digest value from indata and reset the buffer.
     * @param indata the input data.
     * @param inoff the input data offset.
     * @param inlen the input data length.
     * @param outdata the output data.
     * @param outoff the output data offset.
     * @throws DigestException
     */
    public void digest(byte[] indata, int inoff, int inlen, byte[] outdata, int outoff) throws DigestException
    {
        sha1.reset();
        sha1.update(indata, inoff, inlen);
        sha1.digest(outdata, outoff, 20);
    }
    
    /**
     * caculate the sha1 digest value from indata and reset the buffer.
     * @param indata the input data.
     * @return the output data.
     */
    public byte[] digest(byte[] indata)
    {
        sha1.reset();
        sha1.update(indata);
        return sha1.digest();
    }
}
