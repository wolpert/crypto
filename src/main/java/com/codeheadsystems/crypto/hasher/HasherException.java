package com.codeheadsystems.crypto.hasher;

/**
 * BSD-Style License 2016
 */
public class HasherException extends RuntimeException {
    public HasherException() {
        super();
    }

    public HasherException(String message) {
        super(message);
    }

    public HasherException(String message, Throwable cause) {
        super(message, cause);
    }

    public HasherException(Throwable cause) {
        super(cause);
    }
}
