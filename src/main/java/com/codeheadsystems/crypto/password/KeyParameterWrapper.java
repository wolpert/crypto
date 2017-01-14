package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.types.TemporaryObject;

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

    private volatile TemporaryObject<KeyParameter> keyParameter;

    public KeyParameterWrapper(KeyParameter keyParameter) {
        this(keyParameter, 20000);
    }

    public KeyParameterWrapper(KeyParameter keyParameter, long expirationInMills) {
        this.keyParameter = new TemporaryObject<>(keyParameter, expirationInMills, (kp) -> Utilities.clear(kp.getKey()));
    }

    public synchronized KeyParameter getKeyParameter() throws SecretKeyExpiredException {
        logger.debug("getKeyParameter()");
        return keyParameter.getValue().orElseThrow(SecretKeyExpiredException::new);
    }

    // TODO: readers-writers block instead of synchronized
    public synchronized void expire() {
        keyParameter.destroy();
    }
}
