package snortcontroller.main;

import javafx.animation.TranslateTransition;
import javafx.application.Platform;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import snortcontroller.utils.ScheduledExecutorSingleton;
import snortcontroller.utils.SingleThreadExecutorSingleton;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.ArrayList;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static snortcontroller.utils.UserInteractions.showAlert;


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
    Label statusLabel;
    @FXML
    HBox statusButtonContainer;
    @FXML
    Button statusButton;
    @FXML
    Label pidLabel;

    @FXML
    Label rootPrivilegeLabel;

    @FXML
    BorderPane activityFrame;

    TranslateTransition buttonToggleTransition = new TranslateTransition();
    BooleanProperty statusRunning = new SimpleBooleanProperty(false);
    boolean isRoot = false;

    ExecutorService singleThreadService = SingleThreadExecutorSingleton.getService();
    ScheduledExecutorService scheduledThreadService = ScheduledExecutorSingleton.getService();
    Optional<Process> snortProcess = Optional.empty();

    SnortController snortController;

    private void animateToggleButton(Button b, boolean running){
        b.setDisable(true);
        buttonToggleTransition.setNode(statusButton);
        buttonToggleTransition.setFromX(statusButton.getLayoutX());
        if(running){
            buttonToggleTransition.setFromX(statusButton.getLayoutX());
            buttonToggleTransition.setToX(statusButton.getLayoutX() + 100);
        } else {
            buttonToggleTransition.setFromX(statusButton.getLayoutX() + 100);
            buttonToggleTransition.setToX(statusButton.getLayoutX());
        }
        buttonToggleTransition.play();
        b.setDisable(false);
    }

    private void updateStatusButtonText(String s){
        statusButton.setText(s);
    }

    private void updateStatusText(String s){
        statusLabel.setText(s);
    }

    private void updatePIDText(String s){
        pidLabel.setText(s);
    }

    public static String read(InputStream input) throws IOException {
        try (BufferedReader buffer = new BufferedReader(new InputStreamReader(input))) {
            return buffer.lines().collect(Collectors.joining("\n"));
        }
    }

    public static ArrayList<String> readAsList(InputStream input) throws IOException {
        ArrayList<String> pslist = new ArrayList<>();
        try (BufferedReader buffer = new BufferedReader(new InputStreamReader(input))) {
            //buffer.lines().collect(Collectors.joining("\n"));
            buffer.lines().forEach(pslist::add);
        }
        return pslist;
    }

    @FXML
    private void onStatusButtonClicked(){
        statusButton.setDisable(true);
        if(statusRunning.get()){
            singleThreadService.submit(() -> { // destroy snort process
                if(snortProcess.isPresent()){
                    Process snort = snortProcess.get();
                    while(snort.isAlive()){
                        // TODO: possible problem when snort cannot be destroyed, it blocks forever.
                        snort.destroy();
                    }

                    snortProcess = Optional.empty();
                }

                Platform.runLater(() -> {
                    statusRunning.setValue(false);
                    statusButton.setDisable(false);
                });
            });
        } else {
            singleThreadService.submit(() -> { // start snort process
                try {
                    Process process = Runtime.getRuntime().exec(new String[]{"bash", "-c", snortController.getSnortRunCommand()});
                    Thread.sleep(1000);
                    if(process.isAlive()){
                        snortProcess = Optional.of(process);
                    } else {
                        Platform.runLater(() -> {
                            if (process.exitValue() == 1) {
                                //System.err.println("Snort process not generated. Try with root privilege.");
                                showAlert(Alert.AlertType.ERROR, "Snort process not generated. Try with root privilege.");
                            } else {
                                //System.err.println("Snort process not generated. Unknown error.");
                                showAlert(Alert.AlertType.ERROR, "Snort process not generated. Unknown error.");
                            }
                        });
                    }

                    Platform.runLater(() -> {
                        statusRunning.setValue(snortProcess.isPresent());
                        statusButton.setDisable(false);
                    });
                } catch (Exception e) {
                    e.printStackTrace();
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
            activityFrame.setCenter(SnortControllerBorderPane);
            String snortControllerLabel = "Snort Controller";
            activityLabel.setText(snortControllerLabel);
        }
    }

    BorderPane PcapParserBorderPane = null;
    BorderPane RuleParserBorderPane = null;
    BorderPane SnortControllerBorderPane = null;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        // change listener when running status of snort process is changed.
        statusRunning.addListener((observable, oldValue, newValue) -> {
            if(newValue){
                updateStatusButtonText("RUNNING");
                updateStatusText("RUNNING");
            }
            else{
                updateStatusButtonText("STOPPED");
                updateStatusText("STOPPED");
            }
            animateToggleButton(statusButton, newValue);
        });

        // check application runner is root or not.
        try {
            Process process = Runtime.getRuntime().exec("id -u");
            isRoot = Integer.parseInt(read(process.getInputStream())) == 0;
            rootPrivilegeLabel.setText(isRoot ? "root" : "not root");
            if(!isRoot){
                showAlert(Alert.AlertType.WARNING, "You're not root. You may not perform some actions which need root privilege.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // check snort process is running every 0.1 seconds.
        scheduledThreadService.scheduleAtFixedRate(() -> {
            try {
                // using 'ps' command to check 'snort' process is running
                Process ps = Runtime.getRuntime().exec(new String[]{"bash", "-c", "ps -a | grep snort"});
                ArrayList<String> pslist = readAsList(ps.getInputStream());
                ArrayList<String> snortPID = new ArrayList<>();

                // if there is(are) running snort process(es), get PID and save it.
                for(String element: pslist){
                    String[] infos = element.split(" ");
                    if(infos[infos.length-1].equals("snort")){
                        snortPID.add(element.trim().split(" ")[0]);
                    }
                }

                Platform.runLater(() -> {
                    // if one or more snort process is running(or not), set text and snort-running-status properly.
                    if(snortPID.isEmpty()) {
                        statusRunning.setValue(false);
                        updatePIDText("-");
                        pidLabel.setTooltip(new Tooltip("Snort is not running"));
                    } else {
                        statusRunning.setValue(true);
                        // concat every pid into single string.
                        Optional<String> snortPIDString = snortPID.stream().reduce((s, s2) -> s.concat(" ").concat(s2));
                        updatePIDText(snortPIDString.orElse("N/A"));
                        pidLabel.setTooltip(new Tooltip(String.format("Snort is running at %s", snortPIDString.orElse("N/A"))));
                        // if snort process is not started by this application, disable toggle button.
                        if(snortProcess.isEmpty()){
                            statusButton.setDisable(true);
                        }
                    }
                });
            } catch (IOException e) {
                e.printStackTrace();
            }
        }, 0, 100, TimeUnit.MILLISECONDS);

        try {
            PcapParserBorderPane = FXMLLoader.load(getClass().getResource("pcapparsercontroller.fxml"));
            RuleParserBorderPane = FXMLLoader.load(getClass().getResource("ruleparsercontroller.fxml"));

            FXMLLoader loader = new FXMLLoader(getClass().getResource("snortcontroller.fxml"));
            SnortControllerBorderPane = loader.load();
            snortController = loader.getController();
            // works like charm! but why?
            //SnortControllerBorderPane = FXMLLoader.load(getClass().getResource("snortcontroller.fxml"));
            //snortController = new FXMLLoader(getClass().getResource("snortcontroller.fxml")).getController();

        } catch (IOException e) {
            e.printStackTrace();
        }

        snortController.runButton.setOnAction(event -> {
            if(statusRunning.get()) {
                showAlert(Alert.AlertType.ERROR, "Snort is already running!");
            } else {
                statusButton.fire();
            }
        });
        snortController.runButton.disableProperty().bind(statusButton.disabledProperty());
    }
}
