package snortcontroller.main;

import javafx.animation.TranslateTransition;
import javafx.application.Platform;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.BorderPane;
import snortcontroller.ScheduledExecutorSingleton;
import snortcontroller.utils.SingleThreadExecutorSingleton;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

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
    Button statusButton;

    @FXML
    BorderPane activityFrame;

    TranslateTransition buttonToggleTransition = new TranslateTransition();
    BooleanProperty statusRunning = new SimpleBooleanProperty(false);

    ExecutorService singleThreadService = SingleThreadExecutorSingleton.getService();
    ScheduledExecutorService scheduledThreadService = ScheduledExecutorSingleton.getService();
    Optional<Process> snortProcess = Optional.empty();

    private void animateToggleButton(Button b, boolean running){
        b.setDisable(true);
        buttonToggleTransition.setNode(statusButton);
        buttonToggleTransition.setFromX(statusButton.getLayoutX());
        if(running){
            buttonToggleTransition.setFromX(statusButton.getLayoutX());
            buttonToggleTransition.setToX(statusButton.getLayoutX() + 80);
        } else {
            buttonToggleTransition.setFromX(statusButton.getLayoutX() + 80);
            buttonToggleTransition.setToX(statusButton.getLayoutX());
        }
        buttonToggleTransition.play();
        b.setDisable(false);
    }

    private void updateStatusButtonText(String s){
        statusButton.setText(s);
    }

    @FXML
    private void onStatusButtonClicked(ActionEvent event){
        // TODO: turn off, or on snort. It should not BLOCK events!
        statusButton.setDisable(true);
        if(statusRunning.get()){
            // TODO: try to turn off snort
            singleThreadService.submit(new Runnable() {
                @Override
                public void run() {
                    if(snortProcess.isPresent()){
                        Process snort = snortProcess.get();
                        while(snort.isAlive()){
                            snort.destroy();
                        }
                        System.out.println("Snort terminated.");
                        snortProcess = Optional.empty();
                    }

                    Platform.runLater(new Runnable() {
                        @Override
                        public void run() {
                            statusRunning.setValue(false);
                            statusButton.setDisable(false);
                        }
                    });
                }
            });
        } else {
            // TODO: try to turn on snort
            singleThreadService.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        // TODO: generate command based on snort settings
                        // first problem: sudo blocks event because it requires password. handle with 'S' option.
                        Process process = Runtime.getRuntime().exec(new String[]{"bash", "-c", "snort"});
                        Thread.sleep(1000);
                        if(process.isAlive()){
                            System.out.println("Snort process started and alive.");
                            snortProcess = Optional.of(process);
                        } else {
                            if(process.exitValue() == 1) {
                                System.err.println("Snort process not generated.");
                            } else {
                                System.err.println("Unknown error.");
                            }
                        }

                        Platform.runLater(new Runnable() {
                            @Override
                            public void run() {
                                statusRunning.setValue(snortProcess.isPresent());
                                statusButton.setDisable(false);
                            }
                        });
                    } catch (IOException | InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            });
        }
    }

    @FXML
    private void drawActivity(ActionEvent event){
        Button clickedButton = (Button)event.getSource();
        if(clickedButton == pcapParserButton){
            activityFrame.setCenter(PcapParserBorderPane);
            String pcapParserLabel = "PCAP Parser";
            activityLabel.setText(pcapParserLabel);
        }
        else if(clickedButton == ruleParserButton){
            activityFrame.setCenter(RuleParserBorderPane);
            String ruleParserLabel = "Snort Rule Parser";
            activityLabel.setText(ruleParserLabel);
        }
        else if(clickedButton == snortSettingButton){
            activityFrame.setCenter(null);
            String snortControllerLabel = "Snort Controller";
            activityLabel.setText(snortControllerLabel);
        }
    }

    BorderPane PcapParserBorderPane = null;
    BorderPane RuleParserBorderPane = null;
    BorderPane SnortControllerBorderPane = null;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        statusRunning.addListener((observable, oldValue, newValue) -> {
            if(newValue){
                updateStatusButtonText("RUNNING");
            }
            else{
                updateStatusButtonText("STOPPED");
            }
            animateToggleButton(statusButton, newValue);
        });
        
        try {
            PcapParserBorderPane = FXMLLoader.load(getClass().getResource("pcapparsercontroller.fxml"));
            RuleParserBorderPane = FXMLLoader.load(getClass().getResource("ruleparsercontroller.fxml"));
            SnortControllerBorderPane = FXMLLoader.load(getClass().getResource("snortcontroller.fxml"));
        } catch (IOException e) {
            // System.err.println(e.getLocalizedMessage());
            e.printStackTrace();
        }

    }
}
