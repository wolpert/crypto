package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

import org.junit.Before;
import org.junit.Test;

/**
 * BSD-Style License 2016
 */
public class ParanoidHasherTest extends AbstractHasherTest {

    @Before
    public void createDefaultObjects() {
        hasherBuilder = new HasherBuilder().hasherProviderClass(HasherProviderImpl.class).digest("SKEIN-1024-1024");
        testWord = "This is a test";
    }

    @Test
    public void testAlgoChangeFailure() {
        Hasher hasher1 = hasherBuilder.digest("SKEIN-1024-1024").build();
        Hasher hasher2 = hasherBuilder.digest("SKEIN-512-512").build();

        hashersShouldBehaveDifferently(hasher1, hasher2);
    }

    @Test
    public void testCharsetChangeDoesFail() {
        Hasher hasher1 = hasherBuilder.charSet("UTF-8").build();
        Hasher hasher2 = hasherBuilder.charSet("UTF-16LE").build();

        hashersShouldBehaveDifferently(hasher1, hasher2);
    }


}
