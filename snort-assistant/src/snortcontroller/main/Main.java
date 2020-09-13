package snortcontroller.main;
	
import javafx.application.Application;
import javafx.stage.Stage;
import javafx.scene.Scene;
import javafx.scene.layout.HBox;
import javafx.fxml.FXMLLoader;
import snortcontroller.utils.ScheduledExecutorSingleton;
import snortcontroller.test.Test;
import snortcontroller.utils.SingleThreadExecutorSingleton;

import java.util.concurrent.TimeUnit;


public class Main extends Application {
	private static Test test = new Test();

	@Override
	public void start(Stage primaryStage) {
		try {
			HBox main = FXMLLoader.load(getClass().getResource("maincontroller.fxml"));

			Scene scene = new Scene(main);
			scene.getStylesheets().add(getClass().getResource("application.css").toExternalForm());
			primaryStage.setScene(scene);
			primaryStage.setOnCloseRequest(event -> {
				var serviceSingle = SingleThreadExecutorSingleton.getService();
				var serviceScheduled = ScheduledExecutorSingleton.getService();
				serviceSingle.shutdown();
				serviceScheduled.shutdown();
				try {
					serviceSingle.awaitTermination(10, TimeUnit.SECONDS);
					serviceSingle.shutdownNow();
					serviceScheduled.awaitTermination(10, TimeUnit.SECONDS);
					serviceScheduled.shutdownNow();
				} catch (InterruptedException e) {
					System.err.println("Service shutdown interrupted.");
					e.printStackTrace();
				}
			});
			primaryStage.show();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		test.test();
		launch(args);
	}
}
