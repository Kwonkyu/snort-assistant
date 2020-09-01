package snortcontroller.main;
	
import javafx.application.Application;
import javafx.stage.Stage;
import net.sourceforge.jpcap.capture.CaptureFileOpenException;
import net.sourceforge.jpcap.capture.CapturePacketException;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.fxml.FXMLLoader;


public class Main extends Application {
	@Override
	public void start(Stage primaryStage) {
		try {
			HBox rootContainer = new HBox();
			rootContainer.setPrefSize(800, 300);
			Node mainElement = FXMLLoader.load(getClass().getResource("maincontroller.fxml"));
			Node subElement = FXMLLoader.load(getClass().getResource("subcontroller.fxml"));
			rootContainer.getChildren().addAll(mainElement, subElement);
			
			Scene scene = new Scene(rootContainer);
			scene.getStylesheets().add(getClass().getResource("application.css").toExternalForm());
			primaryStage.setScene(scene);
			primaryStage.show();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		PcapParser parse = new PcapParser("/home/kwonkyu/Documents/snortlog");
		try {
			parse.parse();
		} catch (CaptureFileOpenException e) {
			// TODO Auto-generated catch block
			System.err.println("Could not open pcap file.");
		} catch (CapturePacketException e) {
			System.err.println("Could not capture packets.");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		launch(args);
	}
}
