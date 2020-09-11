package snortcontroller.utils;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SingleThreadExecutorSingleton {
    private static final ExecutorService service = Executors.newSingleThreadExecutor();
    public static ExecutorService getService(){
        return service;
    }
}
