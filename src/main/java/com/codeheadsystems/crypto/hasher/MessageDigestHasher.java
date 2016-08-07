package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * BSD-Style License 2016
 */
public class MessageDigestHasher extends AbstractSaltedHasher<MessageDigest> implements Hasher {

    private static final Logger logger = LoggerFactory.getLogger(MessageDigestHasher.class);

    public MessageDigestHasher(HasherConfiguration hasherConfiguration) {
        super(hasherConfiguration);
    }

    private MessageDigest getMessageDigest() {
        logger.debug("getMessageDigest()");
        MessageDigest result = digesterThreadLocal.get();
        if (result == null) {
            try {
                result = MessageDigest.getInstance(digest);
            } catch (NoSuchAlgorithmException e) {
                throw new HasherException("Failure with Algorithm: " + digest, e);
            }
            digesterThreadLocal.set(result);
        }
        return result;
    }

    @Override
    protected byte[] internalGenerateHash(String unhashedString, byte[] salt) {
        logger.debug("internalGenerateHash(,)");
        byte[] hashingBytes = getBytes(unhashedString);
        MessageDigest messageDigest = getMessageDigest();
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
