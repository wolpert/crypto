package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.hasher.HasherBuilder;
import com.codeheadsystems.crypto.hasher.ParanoidHasherProviderImpl;
import com.codeheadsystems.crypto.timer.TimerProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * BSD-Style License 2016
 */
public class ParanoidKeyParameterFactory extends KeyParameterFactory {

    private static final Logger logger = LoggerFactory.getLogger(ParanoidKeyParameterFactory.class);

    protected ParanoidKeyParameterFactory(long expirationInMills, Hasher hasher, TimerProvider timerProvider) {
        super(expirationInMills, hasher, timerProvider);
        logger.debug("ParanoidKeyParameterFactory(" + expirationInMills + "," + hasher + ")");
    }

    public static class Builder extends AbstractKeyParameterFactoryBuilder<ParanoidKeyParameterFactory> {

        @Override
        public AbstractKeyParameterFactoryBuilder iterationCount(int iterationCount) {
            if (iterationCount < 16384) {
                throw new IllegalArgumentException("Unable to have an iteration count less then 16384: found " + iterationCount);
            }
            return super.iterationCount(iterationCount);
        }

        @Override
        public ParanoidKeyParameterFactory build() {
            Hasher hasher = new HasherBuilder()
                    .hasherProviderClass(ParanoidHasherProviderImpl.class)
                    .iterations(iterationCount)
                    .saltSize(16) // 128 bit
                    .build();
            return new ParanoidKeyParameterFactory(expirationInMills, hasher, timerProvider);
        }
    }

}
