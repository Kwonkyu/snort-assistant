package snortcontroller;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

public class ScheduledExecutorSingleton {
    private static final ScheduledExecutorService service = Executors.newSingleThreadScheduledExecutor();
    public static ScheduledExecutorService getService(){ return service; }
}
