package com.zhaoyanblog.cassandra;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public abstract class SecureUtils {

    private static SecureRandom DEFAULT_SECURE_RANDOM;

    static {
        try {
            DEFAULT_SECURE_RANDOM = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            DEFAULT_SECURE_RANDOM = new SecureRandom();
        }
    }

    /**
     * rfc5802#section-8.3
     * printable       = %x21-2B / %x2D-7E
     * ;; Printable ASCII except ",".
     * ;; Note that any "printable" is also
     * ;; a valid "value".
     */
    private static final int PRINTABLE_CHAR_MIN = 0x21;
    private static final int PRINTABLE_CHAR_MAX = 0x7e;
    private static final int PRINTABLE_CHAR_EXCPT = 0x2c;

    public static String gengerateNonce(int length) {
        StringBuilder sb = new StringBuilder();
        while (sb.length() < length) {
            int random = DEFAULT_SECURE_RANDOM.nextInt(PRINTABLE_CHAR_MAX - PRINTABLE_CHAR_MIN + 1) + PRINTABLE_CHAR_MIN;
            if (random != PRINTABLE_CHAR_EXCPT) {
                sb.append((char) random);
            }
        }
        return sb.toString();
    }

    /**
     * Hi(str, salt, i):
     * <p>
     * U1   := HMAC(str, salt + INT(1))
     * U2   := HMAC(str, U1)
     * ...
     * Ui-1 := HMAC(str, Ui-2)
     * Ui   := HMAC(str, Ui-1)
     * <p>
     * Hi := U1 XOR U2 XOR ... XOR Ui
     *
     * @param password      real password
     * @param salt          salt
     * @param iterations    iterations
     * @param hmacAlgorithm HMAC algorithm HMACSHA1,HMACSHA256,HMACSHA512
     * @return pdkdf2 password
     */
    public static byte[] pbkdf2(final String password,
                                final byte[] salt,
                                int iterations,
                                String hmacAlgorithm) {
        try {
            Mac mac = Mac.getInstance(hmacAlgorithm);
            Key key = new SecretKeySpec(password.getBytes(StandardCharsets.UTF_8), hmacAlgorithm);
            mac.init(key);
            mac.update(salt);
            mac.update("\00\00\00\01".getBytes());
            byte[] Un = mac.doFinal();
            byte[] Hi = Un;
            for (int i = 1; i < iterations; ++i) {
                Un = mac.doFinal(Un);
                Hi = xor(Hi, Un);
            }
            return Hi;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Platform error: unsupported key for HMAC algorithm");
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Platform error: init key");
        }
    }

    public static byte[] hmac(String key, String hmacAlgorithm, String msg) {
        return hmac(fromBase64(key), hmacAlgorithm, msg.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] hmac(byte[] key, String hmacAlgorithm, String msg) {
        return hmac(key, hmacAlgorithm, msg.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] hmac(byte[] key, String hmacAlgorithm, byte[] msg) {
        try {
            Mac mac = Mac.getInstance(hmacAlgorithm);
            SecretKeySpec keySpec = new SecretKeySpec(key, hmacAlgorithm);
            mac.init(keySpec);
            return mac.doFinal(msg);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Platform error: unsupported key for HMAC algorithm");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Platform error: init key");
        }
    }

    public static byte[] hash(byte[] source, String hashAlgorithm) {

        try {
            MessageDigest instance = MessageDigest.getInstance(hashAlgorithm);
            return instance.digest(source);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Platform error: unsupported hash algorithm");
        }
    }

    public static String base64(byte[] sources)
    {
        return Base64.getEncoder().encodeToString(sources);
    }
    public static byte[] fromBase64(String sources)
    {
        return Base64.getDecoder().decode(sources);
    }
    public static byte[] xor(byte[] value1, byte[] value2) {
        byte[] result = new byte[value1.length];
        for (int i = 0; i < value1.length; i++) {
            result[i] = (byte) (value1[i] ^ value2[i]);
        }

        return result;
    }
}
