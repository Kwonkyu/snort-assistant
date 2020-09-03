package snortcontroller.main;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.BorderPane;

import java.io.IOException;
import java.net.URL;
import java.util.ResourceBundle;

public class MainController implements Initializable {
    @FXML
    Button pcapParserButton;
    @FXML
    Button ruleParserButton;
    @FXML
    Button snortSettingButton;

    @FXML
    Label activityLabel;

    @FXML
    BorderPane activityFrame;

    private final String pcapParserLabel = "PCAP Parser";
    private final String ruleParserLabel = "Snort Rule Parser";
    private final String snortControllerLabel = "Snort Controller";

    @FXML
    private void drawActivity(ActionEvent event){
        Button clickedButton = (Button)event.getSource();
        if(clickedButton == pcapParserButton){
            activityFrame.setCenter(PcapParserBorderPane);
            activityLabel.setText(pcapParserLabel);
        }
        else if(clickedButton == ruleParserButton){
            activityFrame.setCenter(RuleParserBorderPane);
            activityLabel.setText(ruleParserLabel);
        }
        else if(clickedButton == snortSettingButton){
            activityFrame.setCenter(null);
            activityLabel.setText(snortControllerLabel);
        }
    }

    BorderPane PcapParserBorderPane = null;
    BorderPane RuleParserBorderPane = null;
    BorderPane SnortControllerBorderPane = null;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        try {
            PcapParserBorderPane = FXMLLoader.load(getClass().getResource("pcapparsercontroller.fxml"));
            RuleParserBorderPane = FXMLLoader.load(getClass().getResource("ruleparsercontroller.fxml"));
            SnortControllerBorderPane = FXMLLoader.load(getClass().getResource("snortcontroller.fxml"));
        } catch (IOException e) {
            System.err.println(e.getLocalizedMessage());
        }

    }
}
