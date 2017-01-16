package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.types.ExceptionFunction;
import com.codeheadsystems.crypto.types.TemporaryObject;
import com.codeheadsystems.crypto.types.TemporaryObjectExpiredException;

import org.bouncycastle.crypto.params.KeyParameter;

/**
 * When you read the password from the user, generate this wrapper right away and do not store
 * the password. The wrapper will (eventually) have the ability to expire requiring the user to
 * enter in their password again.
 */
public class KeyParameterWrapper {

    private volatile TemporaryObject<KeyParameter> keyParameter;

    public KeyParameterWrapper(KeyParameter keyParameter) {
        this(keyParameter, 20000);
    }

    public KeyParameterWrapper(KeyParameter keyParameter, long expirationInMills) {
        this.keyParameter = new TemporaryObject<>(keyParameter, expirationInMills, (kp) -> Utilities.clear(kp.getKey()));
    }

    /**
     * The key used here should be not stored in the current form, as when the key expires, this key will
     * change.
     *
     * @return byte[] that was used for this key
     * @throws SecretKeyExpiredException if the key has expired
     */
    public byte[] getKey() throws SecretKeyExpiredException {
        return processWithKeyParameter(KeyParameter::getKey);
    }

    /**
     * This is the preferred way to do stuff with this key. You will be assured that the key will not
     * be destroyed while proforming this action.
     *
     * @param function that will take he key parameter, returning any object.
     * @param <R>      The resulting object from the function
     * @param <E>      The possible exception thrown by this function, not including the expiring exception
     * @return The R as defined above.
     * @throws SecretKeyExpiredException thrown should the key have expired
     * @throws E                         Any underlying exception that could have been thrown. If the underlying exception can throw multiple exceptions, you must catch Exception itself. (Sorry!)
     */
    public <R, E extends Exception> R processWithKeyParameter(ExceptionFunction<KeyParameter, R, E> function) throws SecretKeyExpiredException, E {
        try {
            return keyParameter.applyWithValue(function);
        } catch (TemporaryObjectExpiredException e) {
            throw new SecretKeyExpiredException(e);
        }
    }

    public synchronized void expire() {
        keyParameter.destroy();
    }
}
