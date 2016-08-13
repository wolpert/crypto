package com.codeheadsystems.crypto;

/**
 * BSD-Style License 2016
 */
public class ParanoidException extends Exception {

    public ParanoidException() {
    }

    public ParanoidException(String message) {
        super(message);
    }

    public ParanoidException(String message, Throwable cause) {
        super(message, cause);
    }

    public ParanoidException(Throwable cause) {
        super(cause);
    }

    public ParanoidException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
