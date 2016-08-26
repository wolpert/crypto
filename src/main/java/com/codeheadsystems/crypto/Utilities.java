package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.random.RandomProvider;
import com.codeheadsystems.crypto.random.SecureRandomProvider;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;
import java.util.UUID;

/**
 * BSD-Style License 2016
 */
public class Utilities {

    private static final Logger logger = LoggerFactory.getLogger(Utilities.class);

    private static RandomProvider randomProvider;

    public static synchronized RandomProvider getRandomProvider() {
        if (randomProvider == null) {
            randomProvider = new SecureRandomProvider();
            logger.info("Secure random provider is set");
        }
        return randomProvider;
    }

    public static synchronized void setRandomProvider(RandomProvider incomingRandomProvider) {
        if (randomProvider == null) {
            logger.warn("Manually setting the random provider: " + incomingRandomProvider);
            randomProvider = incomingRandomProvider;
        } else {
            logger.error("Random provider already set. " + randomProvider + ":" + incomingRandomProvider);
        }
    }

    /**
     * Call this method once to validate the random provider is using the secure provider.
     *
     * @return boolean
     */
    public static boolean isSecureRandomProvider() {
        return getRandomProvider().getClass().equals(SecureRandomProvider.class);
    }

    public static byte[] reduce(byte[] bytes, int length) {
        byte[] finalBytes = new byte[length];
        System.arraycopy(bytes, 0, finalBytes, 0, length);
        return finalBytes;
    }

    public static byte[] add(byte[] a1, byte[] a2) {
        byte[] result = new byte[a1.length + a2.length];
        System.arraycopy(a1, 0, result, 0, a1.length);
        System.arraycopy(a2, 0, result, a1.length, a2.length);
        return result;
    }

    public static boolean isSame(byte[] a1, byte[] a2) {
        if (a1 == null || a2 == null || a1.length != a2.length) {
            return false;
        }
        boolean result = true;
        for (int i = 0; i < a1.length; i++) {
            result = (a1[i] == a2[i]) && result;
        }
        return result;
    }

    public static byte[] randomBytes(int size) {
        return getRandomProvider().randomBytes(size);
    }

    public static Charset getCharset() {
        return Charset.forName("UTF-16LE");
    }

    public static String bytesToString(byte[] bytes) {
        if (bytes != null) {
            return Base64.toBase64String(bytes);
        } else {
            return "null";
        }
    }

    public static String toHex(byte[] bytes) {
        return Hex.toHexString(bytes);
    }

    public static byte[] fromHex(String hexString) {
        return Hex.decode(hexString);
    }

    public static byte[] stringToBytes(String string) {
        if (string == null || string.equals("null")) {
            return null;
        } else {
            return Base64.decode(string);
        }
    }

    public static byte[] getBytes(String hashedValue) {
        return hashedValue.getBytes(getCharset());
    }

    public static String getUuid() {
        return UUID.randomUUID().toString();
    }

    // Extra paranoia mode.... always clears
    // bytes, and returns a null
    public static byte[] clear(byte[] array) {
        if (array != null) {
            for (int i = 0; i < array.length; i++) {
                array[i] = 0;
            }
        }
        return null;
    }
}
