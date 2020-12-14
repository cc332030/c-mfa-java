package com.c332030.mfa;

/**
 * <p>
 * Description: CMfa
 *
 * ref from @link https://github.com/WorkingChen/GoogleAuthenticator.git
 * </p>
 *
 * @author c332030
 * @version 1.0
 */
public class CMfa {

    private CMfa() {}

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
        return Mfa.getCode(secretKey, timeMillis);
    }

    /**
     * <p>
     * Description: get secret code
     * </p>
     *
     * @param secretKey secret key
     * @return secret code
     * @author c332030
     */
    public static String getCode(String secretKey) {
        return getCode(secretKey, System.currentTimeMillis());
    }

    /**
     * <p>
     * Description: verify secret code with now date
     * </p>
     *
     * @param code secret code
     * @param secretKey secret key
     * @param timeMillis current time millis
     * @return secret code valid or not
     * @author c332030
     */
    public static boolean verify(String code, String secretKey, long timeMillis) {
        return getCode(secretKey, timeMillis).equals(code);
    }

    /**
     * <p>
     * Description: verify secret code with now date
     * </p>
     *
     * @param code secret code
     * @param secretKey secret key
     * @return secret code valid or not
     * @author c332030
     */
    public static boolean verify(String code, String secretKey) {
        return getCode(secretKey).equals(code);
    }

}
