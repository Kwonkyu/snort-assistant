package snortcontroller.main;
	
import javafx.application.Application;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.layout.HBox;
import javafx.fxml.FXMLLoader;
import snortcontroller.test.Test;


public class Main extends Application {
	private static Test test = new Test();

	@Override
	public void start(Stage primaryStage) {
		try {
			//HBox rootContainer = new HBox();
			//rootContainer.setPrefSize(800, 300);
			HBox main = FXMLLoader.load(getClass().getResource("maincontroller.fxml"));

			// rootContainer.getChildren().addAll(mainElement, subElement);
			Scene scene = new Scene(main);
			main.getStylesheets().add(getClass().getResource("application.css").toExternalForm());
			primaryStage.setScene(scene);
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
