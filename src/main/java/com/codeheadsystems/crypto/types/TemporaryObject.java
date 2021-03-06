package com.codeheadsystems.crypto.types;

import com.codeheadsystems.crypto.Utilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.Timer;
import java.util.TimerTask;
import java.util.function.Consumer;

import static java.util.Objects.requireNonNull;

/**
 * BSD-Style License 2017
 */
public class TemporaryObject<T> {

    private static final Logger logger = LoggerFactory.getLogger(TemporaryObject.class);

    private static final Timer timer = new Timer("TemporaryObjectTimer", true);
    private final long millsToExpire;
    private volatile T value;
    private Consumer<T> destroyer;
    private volatile TimerTask timerTask;

    public TemporaryObject(T value) {
        this(value, 2000l, null);
    }

    public TemporaryObject(T value, long millsToExpire) {
        this(value, millsToExpire, null);
    }

    public TemporaryObject(T value, Consumer<T> destroyer) {
        this(value, 2000l, null);
    }

    /**
     * Basic constructor for a temporary object. Values stored are unavailable after the number of
     * milliseconds have expired. (Null'd out) Every time you get the value, the timer is reset.
     *
     * @param value         to be stored up to the number of milliseconds listed.
     * @param millsToExpire is a long that is the number of milliseconds before the object is null'd out. If this number is less then 1, there is no timer.
     * @param destroyer     an optional Consumer that can further modify the value before nulling out.
     */
    public TemporaryObject(T value, long millsToExpire, Consumer<T> destroyer) {
        this.value = requireNonNull(value);
        this.millsToExpire = millsToExpire;
        this.destroyer = destroyer;
        setTimerTask();
        logger.debug("TemporaryObject({},{},{})", value.getClass(), millsToExpire, destroyer);
    }

    public static TemporaryObject<byte[]> getTemporaryBytes(byte[] bytes, long millsToExpire) {
        return new TemporaryObject<>(bytes, millsToExpire, Utilities::clear);
    }

    private void setTimerTask() {
        if (millsToExpire < 1) {
            return;
        }
        if (timerTask != null) {
            timerTask.cancel();
        }
        timerTask = new TimerTask() {
            @Override
            public void run() {
                destroy();
            }
        };
        timer.schedule(timerTask, millsToExpire);
    }

    /**
     * This is not safe in the sense that the value returned could be destroyed
     * if its not used by the time the millisecond timer expires.
     *
     * @return Optional holding onto the value.
     */
    public Optional<T> getValue() {
        synchronized (this) {
            if (value == null) {
                return Optional.empty();
            } else {
                setTimerTask();
                return Optional.of(value); // timertask should not have executed,
            }
        }
    }

    /**
     * This method provides a way to ensure you either have the legitimate value
     * or its unavailable. Unlike getValue since the destroyer can operate on the value
     * that was returned.
     *
     * @param caller that will use the value given here.
     * @param <E>    Expected exception to be thrown
     * @throws TemporaryObjectExpiredException if the value is gone
     * @throws E                               as defined by the caller
     */
    public <E extends Exception> void callWithValue(ExceptionConsumer<T, E> caller) throws TemporaryObjectExpiredException, E {
        synchronized (this) {
            setTimerTask();
            if (value == null) {
                throw new TemporaryObjectExpiredException();
            }
            caller.accept(value);
        }
    }


    /**
     * This method provides a way to ensure you either have the legitimate value
     * or its unavailable. Unlike getValue since the destroyer can operate on the value
     * that was returned.
     *
     * @param function that will use the value given here, returning a result
     * @param <R>      Expected return type
     * @param <E>      Expected exception to be thrown
     * @return R which resulted from the function
     * @throws TemporaryObjectExpiredException if the value is gone
     * @throws E                               as defined by the caller
     */
    public <R, E extends Exception> R applyWithValue(ExceptionFunction<T, R, E> function) throws TemporaryObjectExpiredException, E {
        synchronized (this) {
            setTimerTask();
            if (value == null) {
                throw new TemporaryObjectExpiredException();
            }
            return function.apply(value);
        }
    }

    public void destroy() {
        synchronized (this) {
            if (value != null) {
                if (destroyer != null) {
                    destroyer.accept(value);
                }
                value = null;
                timerTask = null;
            }
        }
    }

    @Override
    protected void finalize() throws Throwable {
        destroy();
        super.finalize();
    }
}
