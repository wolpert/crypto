package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.hasher.HasherBuilder;
import com.codeheadsystems.crypto.hasher.ParanoidHasherProviderImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * BSD-Style License 2016
 */
public class HasherFactory {

    private static Logger logger = LoggerFactory.getLogger(HasherFactory.class);

    public Hasher hasher() {
        logger.debug("hasher() -->");
        Hasher hasher = new HasherBuilder()
                .hasherProviderClass(ParanoidHasherProviderImpl.class)
                .digest("SKEIN-1024-1024")
                .build();
        logger.debug("hasher() <-- {}", hasher);
        return hasher;
    }

}
