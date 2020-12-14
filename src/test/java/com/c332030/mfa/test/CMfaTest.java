package com.c332030.mfa.test;

import org.junit.Test;

import lombok.val;

import com.c332030.mfa.CMfa;

/**
 * <p>
 * Description: CMfaTest
 * </p>
 *
 * @author c332030
 * @version 1.0
 */
public class CMfaTest {

    private static final String SECRET_KEY = "secret key";

    @Test
    public void testGetCode() {

        val code = CMfa.getCode(SECRET_KEY);
        System.out.println(code);
    }

    @Test
    public void testVerify() {

        String code = "secret code";

        val result = CMfa.verify(SECRET_KEY, code);
        System.out.println(result);
    }
}
