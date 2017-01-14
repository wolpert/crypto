package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.hasher.HasherBuilder;
import com.codeheadsystems.crypto.hasher.MessageDigestHasherProviderImpl;
import com.codeheadsystems.crypto.timer.TimerProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * BSD-Style License 2016
 */
public class MessageDigestKeyParameterFactory extends KeyParameterFactory {

    private static final Logger logger = LoggerFactory.getLogger(MessageDigestKeyParameterFactory.class);

    private MessageDigestKeyParameterFactory(long expirationInMills, Hasher hasher) {
        super(expirationInMills, hasher);
        logger.debug("MessageDigestKeyParameterFactory(" + expirationInMills + "," + hasher + ")");
    }

    public static class Builder extends AbstractKeyParameterFactoryBuilder<MessageDigestKeyParameterFactory> {

        @Override
        public MessageDigestKeyParameterFactory build() {
            Hasher hasher = new HasherBuilder()
                    .hasherProviderClass(MessageDigestHasherProviderImpl.class)
                    .digest("SKEIN-512-256")
                    .iterations(iterationCount)
                    .build();
            return new MessageDigestKeyParameterFactory(expirationInMills, hasher);
        }
    }

}
