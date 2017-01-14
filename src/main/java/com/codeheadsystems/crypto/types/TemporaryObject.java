package com.codeheadsystems.crypto.types;

import com.codeheadsystems.crypto.Utilities;

import java.util.Optional;
import java.util.Timer;
import java.util.TimerTask;
import java.util.function.Consumer;

import static java.util.Objects.requireNonNull;

/**
 * BSD-Style License 2017
 */
public class TemporaryObject<T> {

    private static final Timer timer = new Timer("TemporaryObjectTimer", true);

    public static TemporaryObject<byte[]> getTemporaryBytes(byte[] bytes, long millsToExpire) {
        return new TemporaryObject<>(bytes, millsToExpire, Utilities::clear);
    }

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
    }

    private void setTimerTask() {
        if(millsToExpire<1){
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
     * @throws TemporaryObjectExpiredException if the value is gone
     */
    public void callWithValue(Consumer<T> caller) throws TemporaryObjectExpiredException {
        synchronized (this) {
            setTimerTask();
            if (value == null) {
                throw new TemporaryObjectExpiredException();
            }
            caller.accept(value);
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
