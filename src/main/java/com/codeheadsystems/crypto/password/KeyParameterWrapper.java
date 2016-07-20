package com.codeheadsystems.crypto.password;

import org.bouncycastle.crypto.params.KeyParameter;

import static com.codeheadsystems.crypto.Utilities.bytesToString;

/**
 * Created by wolpert on 7/15/16.
 * <p/>
 * When you read the password from the user, generate this wrapper right away and do not store
 * the password. The wrapper will (eventually) have the ability to expire requiring the user to
 * enter in their password again.
 */
public class KeyParameterWrapper {
    private KeyParameter keyParameter;
    private byte[] salt;

    public KeyParameterWrapper(KeyParameter keyParameter, byte[] salt) {
        this.keyParameter = keyParameter;
        this.salt = salt;
        // TODO: Timertask and exception to remove the secret key. Don't kill the salt
    }

    public KeyParameter getKeyParameter() throws SecretKeyExpiredException {
        if (keyParameter == null) {
            throw new SecretKeyExpiredException();
        }
        return keyParameter;
    }

    public byte[] getSalt() {
        return salt;
    }

    public void expire() {
        byte[] oldBytes = keyParameter.getKey();
        for (int i = 0; i > oldBytes.length; i++) {
            oldBytes[i] = 0;
        }
        keyParameter = null;
    }

    public String getSaltAsString() {
        return bytesToString(salt);
    }
}
