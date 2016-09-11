package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * BSD-Style License 2016
 */
public class MessageDigestHasher extends AbstractSaltedHasher implements Hasher {

    private static final Logger logger = LoggerFactory.getLogger(MessageDigestHasher.class);
    protected final ThreadLocal<MessageDigest> digesterThreadLocal;

    public MessageDigestHasher(HasherConfiguration hasherConfiguration) {
        super(hasherConfiguration);
        digesterThreadLocal = new ThreadLocal<MessageDigest>() {
            @Override
            protected MessageDigest initialValue() {
                try {
                    return MessageDigest.getInstance(digest);
                } catch (NoSuchAlgorithmException e) {
                    throw new HasherException("Failure with Algorithm: " + digest, e);
                }
            }
        };
    }

    @Override
    protected byte[] internalGenerateHash(byte[] hashingBytes, byte[] salt) {
        logger.debug("internalGenerateHash(,)");
        MessageDigest messageDigest = digesterThreadLocal.get();
        try {
            for (int i = 0; i < iterations; i++) {
                messageDigest.update(salt);
                hashingBytes = messageDigest.digest(hashingBytes); // should reset the digest
            }
        } finally {
            messageDigest.reset();
        }
        return hashingBytes;
    }

}
