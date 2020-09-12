package snortcontroller.utils;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SingleThreadExecutorSingleton {
    // private static final ExecutorService service = Executors.newSingleThreadExecutor();
    private static final ExecutorService service = Executors.newFixedThreadPool(8, r -> {
        Thread t = new Thread(r);
        t.setDaemon(true);
        return t;
    });

    public static ExecutorService getService(){
        return service;
    }
}
