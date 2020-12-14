package com.c332030.mfa;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import lombok.Cleanup;
import lombok.val;

/**
 * <p>
 * Description: Mfa
 * </p>
 *
 * @author c332030
 * @version 1.0
 */
public class Mfa {

    private static final String EMPTY = "";

    private static final String HMAC_SHA1 = "HmacSHA1";

    private static final int SECRET_CODE_LENGTH = 6;

    private Mfa() {}

    /**
     * <p>
     * Description: get secret code
     * </p>
     *
     * @param secretKey secret key
     * @param timeMillis time millis
     * @return secret code
     * @author c332030
     */
    public static String getCode(String secretKey, long timeMillis) {
        try {

            val data = sha1(secretKey, timeMillis / 30_000);

            // 通过对最后一个字节的低4位二进制位建立索引，索引范围为  （0-15）+4  ，正好20个字节。
            val o = data[19] & 0xf;

            // //然后计算索引指向的连续4字节空间生成int整型数据。
            val number = hashToInt(data, o)& 0x7f_fff_fff;
            return leftPad(String.valueOf(number % 1000_000));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String leftPad(String str) {

        val strLen = str.length();
        var lackLen = SECRET_CODE_LENGTH - strLen;
        if(0 == lackLen) {
            return str;
        }

        val stringBuilder = new StringBuilder(SECRET_CODE_LENGTH);
        while (lackLen-- > 0){
            stringBuilder.append('0');
        }
        return stringBuilder.append(str).toString();
    }

    /**
     * <p>
     * Description:
     * </p>
     *
     * @param bytes number bytes
     * @param start array index
     * @return int
     * @throws IOException convert exception
     * @author c332030
     */
    public static int hashToInt(byte[] bytes, int start) throws IOException {

        @Cleanup
        val inputStream = new DataInputStream(
            new ByteArrayInputStream(bytes, start, bytes.length - start));
        return inputStream.readInt();
    }

    /**
     * <p>
     * Description:
     * </p>
     *
     * @param key secret key
     * @param mills time millis
     * @return encrypted bytes of number
     * @throws NoSuchAlgorithmException HmacSHA1 Algorithm
     * @throws InvalidKeyException invalid secret key
     * @throws Base32String.DecodingException decoding exception
     * @author Mr.Chen
     */
    public static byte[] sha1(String key, long mills) throws NoSuchAlgorithmException,
        InvalidKeyException, Base32String.DecodingException {

        // 创建秘钥
        val secretKey = new SecretKeySpec(Base32String.decode(key), EMPTY);

        // 初始化秘钥
        val mac= Mac.getInstance(HMAC_SHA1);
        mac.init(secretKey);

        //将long类型的数据转换为byte数组
        val value = ByteBuffer.allocate(8).putLong(mills).array();

        //计算数据摘要
        return mac.doFinal(value);
    }
}
