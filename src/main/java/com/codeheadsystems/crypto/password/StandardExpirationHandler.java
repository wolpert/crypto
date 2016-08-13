package com.codeheadsystems.crypto.password;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Timer;
import java.util.TimerTask;

/**
 * BSD-Style License 2016
 */
public class StandardExpirationHandler implements ExpirationHandler {

    private static Logger logger = LoggerFactory.getLogger(StandardExpirationHandler.class);

    private final long expirationInMills;
    private final KeyParameterWrapper keyParameterWrapper;
    private volatile Timer timer;
    private volatile TimerTask timerTask;

    public StandardExpirationHandler(long expirationInMills, Timer timer, KeyParameterWrapper keyParameterWrapper) {
        this.expirationInMills = expirationInMills;
        this.timer = timer;
        this.keyParameterWrapper = keyParameterWrapper;
        this.keyParameterWrapper.setExpirationHandler(this);
        timerTask = getTimerTask();
        timer.schedule(timerTask, expirationInMills);
    }

    private TimerTask getTimerTask() {
        logger.debug("getTimerTask()");
        return new TimerTask() {
            @Override
            public void run() {
                synchronized (keyParameterWrapper) {
                    keyParameterWrapper.expire();
                    timer = null;
                }
            }
        };
    }

    @Override
    public void touch() {
        logger.debug("touch()");
        synchronized (keyParameterWrapper) {
            if (timer != null) {
                logger.debug("\thasTimer");
                if (timerTask != null) {
                    logger.debug("\tCancelingExistingTask");
                    timerTask.cancel();
                }
                timerTask = getTimerTask();
                timer.schedule(timerTask, expirationInMills);
            } else {
                logger.debug("\tdisabled since timer is null. (already expired)");
            }
        }
    }
}
