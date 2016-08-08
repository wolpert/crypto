package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.hasher.HasherBuilder;
import com.codeheadsystems.crypto.hasher.MessageDigestHasherProviderImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * BSD-Style License 2016
 */
public class MessageDigestKeyParameterFactory extends AbstractKeyParameterFactory {

    private static final Logger logger = LoggerFactory.getLogger(MessageDigestKeyParameterFactory.class);

    private MessageDigestKeyParameterFactory(int expirationInMins, Hasher hasher) {
        super(expirationInMins, hasher);
        logger.debug("MessageDigestKeyParameterFactory("+expirationInMins+","+hasher+")");
    }

    public static class Builder {
        int iterationCount = 65536;
        int expirationInMins = 10;

        public Builder iterationCount(int iterationCount) {
            this.iterationCount = iterationCount;
            return this;
        }

        public Builder expirationInMins(int expirationInMins) {
            this.expirationInMins = expirationInMins;
            return this;
        }

        public MessageDigestKeyParameterFactory build() {
            Hasher hasher = new HasherBuilder()
                    .hasherProviderClass(MessageDigestHasherProviderImpl.class)
                    .digest("SKEIN-512-256")
                    .iterations(iterationCount)
                    .build();
            return new MessageDigestKeyParameterFactory(expirationInMins, hasher);
        }
    }

}
