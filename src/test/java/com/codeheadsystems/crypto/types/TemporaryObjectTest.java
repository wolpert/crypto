package com.codeheadsystems.crypto.types;

import com.codeheadsystems.crypto.Utilities;

import org.junit.Test;

import java.util.Optional;

import static com.codeheadsystems.crypto.Utilities.cloneBytes;
import static com.codeheadsystems.crypto.Utilities.randomBytes;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * BSD-Style License 2017
 */

public class TemporaryObjectTest {

    @Test
    public void testDefaultBehavior() throws TemporaryObjectExpiredException {
        TemporaryObject<String> to = new TemporaryObject<>("blah");
        Optional<String> value = to.getValue();
        assertTrue(value.isPresent());
        assertEquals("blah", value.get());
        to.callWithValue((str) -> assertEquals("blah", str));
        assertEquals("blah1", to.applyWithValue((str) -> str + "1"));
    }


    private void sleep(long mills) {
        try {
            Thread.sleep(mills + 10);
        } catch (InterruptedException e) {
        }
    }

    @Test(expected = TemporaryObjectExpiredException.class)
    public void testExpiringBehaviorWithCallWithValue() throws TemporaryObjectExpiredException {
        TemporaryObject<String> to = new TemporaryObject<>("blah", 10);
        sleep(10);
        to.callWithValue((str) -> assertEquals("blah", str));
    }

    @Test(expected = TemporaryObjectExpiredException
            .class)
    public void testExpiringBehaviorWithApplyWithValue() throws TemporaryObjectExpiredException {
        TemporaryObject<String> to = new TemporaryObject<>("blah", 10);
        sleep(10);
        assertEquals("blah1", to.applyWithValue((str) -> str + "1"));
    }

    @Test
    public void testExpiringBehaviorWithGetValue() {
        TemporaryObject<String> to = new TemporaryObject<>("blah", 10);
        sleep(10);
        assertFalse(to.getValue().isPresent());
    }

    @Test
    public void testGetTempBytesDefaultBehavior() throws TemporaryObjectExpiredException {
        byte[] array = randomBytes(5);
        TemporaryObject<byte[]> to = TemporaryObject.getTemporaryBytes(cloneBytes(array), 2000);
        Optional<byte[]> value = to.getValue();
        assertTrue(value.isPresent());
        assertTrue(Utilities.isSame(array, value.get()));
        to.callWithValue((a2) -> assertTrue(Utilities.isSame(array, a2)));
        assertTrue(Utilities.isSame(array, to.applyWithValue((a2)->a2)));
    }

    @Test
    public void testDestroyMethod() {
        byte[] array = randomBytes(5);
        TemporaryObject<byte[]> to = TemporaryObject.getTemporaryBytes(cloneBytes(array), 100);
        Optional<byte[]> value = to.getValue();
        assertTrue(value.isPresent());
        byte[] values = value.get();
        assertTrue(Utilities.isSame(array, values));
        sleep(100);
        assertFalse(to.getValue().isPresent());
        assertFalse(Utilities.isSame(array, values));
    }
}
