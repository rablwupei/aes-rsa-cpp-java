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

package org.bsmith.encoding;

import java.io.UnsupportedEncodingException;

/**
 * base 16 hex encoding.
 * @author bsmith.zhao
 * @date 2006-05-16 11:22:12
 */
public class Base16
{
    /**
     * the example.
     * @param args
     * @throws UnsupportedEncodingException
     */
    public static void main(String args[]) throws UnsupportedEncodingException
    {
        String str = "0123456abcdef中文123abc";
        // byte[] data = str.getBytes("UTF-8");
         byte[] data = str.getBytes("UTF-8");
        String hex = encode(data, 0, data.length);
        System.out.println(hex);
        
        data = decode(hex);
        str = new String(data, "UTF-8");
        System.out.println(str);
        
        hex += "a";
        data = decode(hex);
        str = new String(data, "UTF-8");
        System.out.println(str);
    }
    
    // encoding characters table.
    public static final char[] ENC_TAB =
    {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    
    // decoding characters table.
    public static final byte[] DEC_TAB =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 16
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 32
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 48
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 64
        
        0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 80
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 96
        0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 112
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    /**
     * encode byte array data to base 16 hex string.
     * @param data byte array data.
     * @return base 16 hex string.
     */
    public static String encode(byte[] data)
    {
        return encode(data, 0, data.length);
    }

    /**
     * encode byte array data from offset to offset+length to base 16 hex string.
     * @param data byte array data.
     * @param offset start index, included.
     * @param length total encode length.
     * @return the base 16 hex string.
     */
    public static String encode(byte[] data, int offset, int length)
    {
        StringBuffer buff = new StringBuffer(length*2);
        int i = offset, total = offset+length;
        while (i < total)
        {
            buff.append(ENC_TAB[(data[i]&0xF0)>>4]);
            buff.append(ENC_TAB[data[i]&0x0F]);
            i ++;
        }

        return buff.toString();
    }
    
    /**
     * decode base 16 hex string to byte array.
     * @param hex base 16 hex string.
     * @return byte array data.
     */
    public static byte[] decode(String hex)
    {
        byte[] data = new byte[hex.length()/2];
        decode(hex, data, 0);
        return data;
    }
    
    /**
     * decode base 16 hex string to byte array.
     * @param hex base 16 hex string.
     * @param data byte array data.
     * @param offset byte array data start index, included.
     */
    public static void decode(String hex, byte[] data, int offset)
    {
        int i = 0, total = (hex.length()/2)*2, idx = offset;
        while (i < total)
        {
            data[idx++] = (byte)((DEC_TAB[hex.charAt(i++)]<<4)|DEC_TAB[hex.charAt(i++)]);
        }
    }
}
