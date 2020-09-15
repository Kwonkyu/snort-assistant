package snortcontroller.main;

import javafx.beans.property.MapProperty;
import javafx.beans.property.SimpleMapProperty;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.MapChangeListener;
import javafx.collections.ObservableMap;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Window;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.ResourceBundle;

import static snortcontroller.utils.UserInteractions.*;

public class SnortController implements Initializable {

    // Toolbar components
    @FXML
    ToolBar toolBar;
    @FXML
    TextField generatedCommandTextField;
    @FXML
    Button runButton;
    @FXML
    Button saveButton;
    @FXML
    Button loadButton;

    // Sniffer mode accordion panel
    @FXML
    Button snifferModeHelpButton;
    @FXML
    CheckBox verboseCheckBox;
    @FXML
    CheckBox dumpApplicationLayerCheckBox;
    @FXML
    CheckBox ethernetLayerCheckBox;
    @FXML
    Button snifferModeResetButton;

    // Packet Logger mode accordion panel
    @FXML
    Button packetLoggerModeHelpButton;
    @FXML
    CheckBox logToDirectoryCheckBox;
    @FXML
    TextField logToDirectoryTextField;
    @FXML
    Button logToDirectoryFindButton;
    @FXML
    Button logToDirectoryApplyButton;
    @FXML
    CheckBox homeAddressCheckBox;
    @FXML
    TextField homeAddressTextField;
    @FXML
    Button homeAddressApplyButton;
    @FXML
    CheckBox tcpdumpFormatCheckBox;
    @FXML
    Button packetLoggerModeResetButton;


    // NIDS mode accordion panel
    @FXML
    Button NIDSModeHelpButton;
    @FXML
    CheckBox configurationFileCheckBox;
    @FXML
    TextField configurationFileLocationTextField;
    @FXML
    Button configurationFileFindButton;
    @FXML
    Button configurationFileApplyButton;
    @FXML
    CheckBox alertModeCheckBox;
    @FXML
    ChoiceBox<AlertMode> alertModeChoiceBox;
    @FXML
    CheckBox sendAlertToSyslogCheckBox;
    @FXML
    Button NIDSModeResetButton;

    ObservableMap<String, String> selectedOptions = FXCollections.observableHashMap();
    MapProperty<String, String> selectedOptionsProperty = new SimpleMapProperty<>(selectedOptions);

    MainController mainControllerLoader;

    enum AlertMode {
        FAST("Fast alert mode. Writes the alert in a simple format with a timestamp, alert message, source and destination IPs/ports."),
        FULL("Full alert mode. This is the default alert mode and will be used automatically if you do not specify a mode"),
        UNSOCK("Sends alerts to a UNIX socket that another program can listen on."),
        NONE("Turns off alerting."),
        CONSOLE("Sends “fast-style” alerts to the console (screen)."),
        CMG("Generates “cmg style” alerts.");
        private final String description;
        AlertMode(String description) { this.description = description; }
        public String getDescription(){ return description; }
    }


    private File chooseFile(Window window, FileChooser.ExtensionFilter... filters){
        final FileChooser fileChooser = new FileChooser();
        fileChooser.getExtensionFilters().clear();
        for (FileChooser.ExtensionFilter filter : filters) fileChooser.setSelectedExtensionFilter(filter);
        return fileChooser.showOpenDialog(window);
    }

    private File chooseDirectory(Window window){
        final DirectoryChooser directoryChooser = new DirectoryChooser();
        return directoryChooser.showDialog(window);
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        // init FXML loader
        mainControllerLoader = new FXMLLoader(getClass().getResource("maincontroller.fxml")).getController();
        

        // initialize helper button.
        snifferModeHelpButton.setOnAction(event -> {
            showAlert(Alert.AlertType.INFORMATION, "Sniffer mode, which simply reads the packets off of the" +
                    " network and displays them for you in a continuous stream on the console (screen).");
        });
        packetLoggerModeHelpButton.setOnAction(event -> {
            showAlert(Alert.AlertType.INFORMATION, "Packet Logger mode, which logs the packets to disk.");
        });
        NIDSModeHelpButton.setOnAction(event -> {
            showAlert(Alert.AlertType.INFORMATION, "Network Intrusion Detection System (NIDS) mode, which performs " +
                    "detection and analysis on network traffic. This is the most complex and configurable mode.");
        });

        // add listener to options property
        selectedOptionsProperty.addListener((observable, oldValue, newValue) -> {
            StringBuilder command = new StringBuilder("snort ");
            selectedOptions.forEach((optName, optVal) -> {
                command.append(String.format("%s %s ", optName, optVal));
            });
            generatedCommandTextField.setText(command.toString());
        });

        // initialize toolbar elements
        // TODO: if snort process is alive, don't run(duplicated!).
        runButton.setOnAction(null);
        // TODO: save current snort command to shell script(bash?)
        saveButton.setOnAction(null);
        // TODO: load snort command and parse it to check options.
        loadButton.setOnAction(null);

        // initialize sniffer mode option elements.
        verboseCheckBox.selectedProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue){
                selectedOptions.putIfAbsent("-v", "");
            } else {
                selectedOptions.remove("-v");
            }
        });
        dumpApplicationLayerCheckBox.selectedProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue){
                selectedOptions.putIfAbsent("-d", "");
            } else {
                selectedOptions.remove("-d");
            }
        });
        ethernetLayerCheckBox.selectedProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue){
                selectedOptions.putIfAbsent("-e", "");
            } else {
                selectedOptions.remove("-e");
            }
        });

        snifferModeResetButton.setOnAction(event -> {
            verboseCheckBox.setSelected(true);
            dumpApplicationLayerCheckBox.setSelected(false);
            ethernetLayerCheckBox.setSelected(false);
        });

        // initialize packet filter mode option elements.
        logToDirectoryTextField.disableProperty().bind(logToDirectoryCheckBox.selectedProperty().not());
        logToDirectoryFindButton.disableProperty().bind(logToDirectoryCheckBox.selectedProperty().not());
        logToDirectoryApplyButton.disableProperty().bind(logToDirectoryCheckBox.selectedProperty().not());

        logToDirectoryTextField.disabledProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue){
                selectedOptions.remove("-l");
            } else {
                selectedOptions.put("-l", logToDirectoryTextField.getText());
            }
        });
        logToDirectoryFindButton.setOnAction(event -> {
            File choosedDirectory = chooseDirectory(logToDirectoryFindButton.getScene().getWindow());
            if(choosedDirectory.exists() && choosedDirectory.isDirectory()){
                logToDirectoryTextField.setText(choosedDirectory.getAbsolutePath());
                logToDirectoryApplyButton.fire();
            }
        });
        logToDirectoryApplyButton.setOnAction(event -> {
            selectedOptions.put("-l", logToDirectoryTextField.getText());
        });

        homeAddressTextField.disableProperty().bind(homeAddressCheckBox.selectedProperty().not());
        homeAddressApplyButton.disableProperty().bind(homeAddressCheckBox.selectedProperty().not());

        homeAddressTextField.disabledProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue){
                selectedOptions.remove("-h");
            } else {
                // homeAddressApplyButton.fire(); << it doesn't work because button is disabled!
                selectedOptions.put("-h", homeAddressTextField.getText());
            }
        });
        homeAddressApplyButton.setOnAction(event -> {
            selectedOptions.put("-h", homeAddressTextField.getText());
        });

        tcpdumpFormatCheckBox.selectedProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue) selectedOptions.put("-b", "");
            else selectedOptions.remove("-b");
        });

        packetLoggerModeResetButton.setOnAction(event -> {
            logToDirectoryCheckBox.setSelected(false);
            logToDirectoryTextField.clear();
            homeAddressCheckBox.setSelected(false);
            homeAddressTextField.clear();
            tcpdumpFormatCheckBox.setSelected(false);
        });

        // initialize NIDS mode option elements.
        configurationFileLocationTextField.disableProperty().bind(configurationFileCheckBox.selectedProperty().not());
        configurationFileFindButton.disableProperty().bind(configurationFileCheckBox.selectedProperty().not());
        configurationFileApplyButton.disableProperty().bind(configurationFileCheckBox.selectedProperty().not());

        configurationFileLocationTextField.disabledProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue){
                selectedOptions.remove("-c");
            } else {
                selectedOptions.put("-c", configurationFileLocationTextField.getText());
            }
        });
        configurationFileFindButton.setOnAction(event -> {
            File choosedFile = chooseFile(configurationFileFindButton.getScene().getWindow());
            if(choosedFile.exists() && choosedFile.isFile()){
                configurationFileLocationTextField.setText(choosedFile.getAbsolutePath());
                configurationFileApplyButton.fire();
            }
        });
        configurationFileApplyButton.setOnAction(event -> {
            selectedOptions.put("-c", configurationFileLocationTextField.getText());
        });

        alertModeChoiceBox.disableProperty().bind(alertModeCheckBox.selectedProperty().not());
        alertModeChoiceBox.disabledProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue) selectedOptions.remove("-A");
            else selectedOptions.put("-A", alertModeChoiceBox.getSelectionModel().selectedItemProperty().get().name());
        });
        alertModeChoiceBox.getItems().addAll(AlertMode.values());
        alertModeChoiceBox.getSelectionModel().select(0);
        alertModeChoiceBox.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {
            selectedOptions.put("-A", newValue.name());
        });

        sendAlertToSyslogCheckBox.selectedProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue) selectedOptions.put("-s", "");
            else selectedOptions.remove("-s");
        });

        NIDSModeResetButton.setOnAction(event -> {
            configurationFileCheckBox.setSelected(false);
            configurationFileLocationTextField.clear();
            alertModeCheckBox.setSelected(false);
            sendAlertToSyslogCheckBox.setSelected(false);
        });
    }
}
