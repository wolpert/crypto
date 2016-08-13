package com.codeheadsystems.crypto.timer;

import java.util.Timer;

/**
 * BSD-Style License 2016
 */
public class DefaultTimerProvider implements TimerProvider {

    private final Timer timer;

    public DefaultTimerProvider() {
        this.timer = new Timer("Paranoid Timer", true);
    }

    @Override
    public Timer getTimer() {
        return timer;
    }
}
