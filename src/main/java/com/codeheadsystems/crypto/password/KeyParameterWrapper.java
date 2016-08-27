package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Utilities;

import org.bouncycastle.crypto.params.KeyParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * When you read the password from the user, generate this wrapper right away and do not store
 * the password. The wrapper will (eventually) have the ability to expire requiring the user to
 * enter in their password again.
 */
public class KeyParameterWrapper {

    private static Logger logger = LoggerFactory.getLogger(KeyParameterWrapper.class);

    private volatile ExpirationHandler expirationHandler;
    private volatile KeyParameter keyParameter;

    public KeyParameterWrapper(KeyParameter keyParameter) {
        this.keyParameter = keyParameter;
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

    // TODO: readers-writers block instead of synchronized
    public synchronized void expire() {
        if (keyParameter != null) {
            logger.debug("expire() with valid keyParam");
            Utilities.clear(keyParameter.getKey());
            keyParameter = null;
            expirationHandler = null;
        } else {
            logger.debug("expire() already expired");
        }
    }
}
