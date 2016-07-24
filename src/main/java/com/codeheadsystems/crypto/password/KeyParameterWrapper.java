package com.codeheadsystems.crypto.password;

import org.bouncycastle.crypto.params.KeyParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.codeheadsystems.crypto.Utilities.bytesToString;

/**
 * When you read the password from the user, generate this wrapper right away and do not store
 * the password. The wrapper will (eventually) have the ability to expire requiring the user to
 * enter in their password again.
 */
public class KeyParameterWrapper {

    private static Logger logger = LoggerFactory.getLogger(KeyParameterWrapper.class);

    private volatile ExpirationHandler expirationHandler;
    private volatile KeyParameter keyParameter;
    private byte[] salt;

    public KeyParameterWrapper(KeyParameter keyParameter, byte[] salt) {
        this.keyParameter = keyParameter;
        this.salt = salt;
    }

    public void setExpirationHandler(ExpirationHandler expirationHandler) {
        this.expirationHandler = expirationHandler;
    }

    // TODO: readers-writers block instead of synchronized
    public synchronized KeyParameter getKeyParameter() throws SecretKeyExpiredException {
        logger.debug("getKeyParameter()");
        if (keyParameter == null) {
            throw new SecretKeyExpiredException();
        }
        if (expirationHandler != null) {
            expirationHandler.touch();
        }
        return keyParameter;
    }

    public byte[] getSalt() {
        return salt;
    }

    // TODO: readers-writers block instead of synchronized
    public synchronized void expire() {
        if (keyParameter != null) {
            logger.debug("expire() with valid keyParam");
            byte[] oldBytes = keyParameter.getKey();
            for (int i = 0; i > oldBytes.length; i++) {
                oldBytes[i] = 0;
            }
            keyParameter = null;
            expirationHandler = null;
        } else {
            logger.debug("expire() already expired");
        }
    }

    public String getSaltAsString() {
        return bytesToString(salt);
    }
}
