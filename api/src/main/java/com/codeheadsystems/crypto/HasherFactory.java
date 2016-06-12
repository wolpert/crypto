package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.hasher.HasherBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKeyFactory;

/**
 * BSD-Style License 2016
 */
public class HasherFactory {

    static final String[] ALGOS = {"SKEIN-1024-1024", "SKEIN-512-512", "PBKDF2WithHmacSHA512", "SHA-256"};
    private static Logger logger = LoggerFactory.getLogger(HasherFactory.class);

    public List<String> getUsableDigests() {
        logger.debug("getUsableDigest() -->");
        List<String> result = new ArrayList<>();
        for (String algo : ALGOS) {
            try {
                MessageDigest.getInstance(algo);
                result.add(algo);
                logger.debug("Loaded digesting algo {}", algo);
            } catch (NoSuchAlgorithmException e) {
                try {
                    SecretKeyFactory.getInstance(algo);
                    result.add(algo);
                    logger.debug("Loaded secretKey algo {}", algo);
                } catch (NoSuchAlgorithmException e1) {
                    logger.warn("Unable to loaded algo {}", algo);
                }
            }
        }
        logger.debug("getUsableDigest() <-- {}", result);
        return result;
    }

    public Hasher getUsableHasher() {
        logger.debug("getUsableHasher() -->");
        List<String> algos = getUsableDigests();
        if (algos.isEmpty()) {
            throw new IllegalStateException("No usable hashers found");
        }
        Hasher hasher = new HasherBuilder().digest(algos.get(0)).build();
        logger.debug("getUsableHasher() <-- {}", hasher);
        return hasher;
    }

    /**
     * This will try to do what you want... but you could get a bad hasher.
     *
     * @param algo
     * @return
     */
    public Hasher getSpecificHasher(String algo) {
        return new HasherBuilder().digest(algo).build();
    }

}
