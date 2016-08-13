package com.codeheadsystems.crypto.manager;

/**
 * BSD-Style License 2016
 */
public class ParanoidManagerException extends Exception {

    public ParanoidManagerException() {
    }

    public ParanoidManagerException(String message) {
        super(message);
    }

    public ParanoidManagerException(String message, Throwable cause) {
        super(message, cause);
    }

    public ParanoidManagerException(Throwable cause) {
        super(cause);
    }

    public ParanoidManagerException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
