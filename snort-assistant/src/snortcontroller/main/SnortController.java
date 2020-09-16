package snortcontroller.main;

import javafx.application.Platform;
import javafx.beans.property.MapProperty;
import javafx.beans.property.SimpleMapProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.ObservableMap;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.control.cell.TextFieldTableCell;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Window;
import org.apache.commons.cli.*;
import snortcontroller.utils.SingleThreadExecutorSingleton;
import snortcontroller.utils.configuration.ConfigurationParser;
import snortcontroller.utils.configuration.NetworkVariable;
import snortcontroller.utils.configuration.NetworkVariableParser;

import java.io.*;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.util.Enumeration;
import java.util.ResourceBundle;
import java.util.concurrent.ExecutorService;

import static snortcontroller.utils.UserInteractions.showAlert;
import static snortcontroller.utils.SingleThreadExecutorSingleton.*;

public class SnortController implements Initializable {

    // variables for 'Run Command' tab
    // Toolbar components
    @FXML
    ToolBar runCommandToolbar;
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

    // etc accordion panel
    @FXML
    CheckBox interfaceCheckBox;
    @FXML
    ChoiceBox<String> interfaceChoiceBox;
    @FXML
    Button etcResetButton;


    // variables for 'General Configurations' tab
    // toolbar elements
    @FXML
    ToolBar generalConfigurationsToolBar;
    @FXML
    TextField snortConfigurationFileLocationTextField;
    @FXML
    Button findConfigurationFileButton;
    @FXML
    Button openConfigurationFileButton;
    @FXML
    TableView<NetworkVariable> networkVariableTableView;


    ObservableMap<String, String> selectedOptions = FXCollections.observableHashMap();
    MapProperty<String, String> selectedOptionsProperty = new SimpleMapProperty<>(selectedOptions);
    ObservableList<NetworkVariable> parsedNetworkVariables = FXCollections.observableArrayList();

    CommandLineParser parser = null;
    Options options = null;

    MainController mainControllerLoader;
    ExecutorService service = SingleThreadExecutorSingleton.getService();

    enum AlertMode {
        FAST("Fast alert mode. Writes the alert in a simple format with a timestamp, alert message, source and destination IPs/ports."),
        FULL("Full alert mode. This is the default alert mode and will be used automatically if you do not specify a mode"),
        UNSOCK("Sends alerts to a UNIX socket that another program can listen on."),
        NONE("Turns off alerting."),
        CONSOLE("Sends “fast-style” alerts to the console (screen)."),
        CMG("Generates “cmg style” alerts.");

        private final String description;
        AlertMode(String description) {
            this.description = description;
        }
    }

    protected String getSnortRunCommand(){
        return generatedCommandTextField.getText().length() > 0 ? generatedCommandTextField.getText() : "snort";
    }

    private File openFile(Window window, String initialDirectory, FileChooser.ExtensionFilter... filters){
        final FileChooser fileChooser = new FileChooser();
        if(initialDirectory != null && new File(initialDirectory).exists()) fileChooser.setInitialDirectory(new File(initialDirectory));
        fileChooser.getExtensionFilters().clear();
        for (FileChooser.ExtensionFilter filter : filters) fileChooser.setSelectedExtensionFilter(filter);
        return fileChooser.showOpenDialog(window);
    }

    private File chooseDirectory(Window window){
        final DirectoryChooser directoryChooser = new DirectoryChooser();
        return directoryChooser.showDialog(window);
    }

    private File saveFile(Window window, String initialDirectory, FileChooser.ExtensionFilter... filters){
        final FileChooser fileChooser = new FileChooser();
        if(initialDirectory != null && new File(initialDirectory).exists()) fileChooser.setInitialDirectory(new File(initialDirectory));
        fileChooser.getExtensionFilters().clear();
        for (FileChooser.ExtensionFilter filter : filters) fileChooser.setSelectedExtensionFilter(filter);
        return fileChooser.showSaveDialog(window);
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        // init FXML loader
        mainControllerLoader = new FXMLLoader(getClass().getResource("maincontroller.fxml")).getController();

        // initialize options
        parser = new DefaultParser();
        options = new Options();

        options.addOption(new Option("v", "verbose", false, "be verbose"));
        options.addOption(new Option("d", "application-layer", false, "dump the application layer"));
        options.addOption(new Option("e", "ethernet-layer", false, "dump the ethernet layer"));
        options.addOption(new Option("l", "log-directory", true, "log to directory"));
        options.addOption(new Option("h", "home-network", true, "set home network"));
        options.addOption(new Option("b", "binary", false, "log packets in tcpdump format"));
        options.addOption(new Option("c", "config-file", true, "use rules file"));
        options.addOption(new Option("A", "alert", true, "set alert mode"));
        options.addOption(new Option("s", "syslog", false, "send alert to syslog"));
        options.addOption(new Option("i", "interface", true, "listen on interface"));

        // initialize helper button.
        snifferModeHelpButton.setOnAction(event -> showAlert(Alert.AlertType.INFORMATION, "Sniffer mode, which simply reads the packets off of the" +
                " network and displays them for you in a continuous stream on the console (screen)."));
        packetLoggerModeHelpButton.setOnAction(event -> showAlert(Alert.AlertType.INFORMATION, "Packet Logger mode, which logs the packets to disk."));
        NIDSModeHelpButton.setOnAction(event -> showAlert(Alert.AlertType.INFORMATION, "Network Intrusion Detection System (NIDS) mode, which performs " +
                "detection and analysis on network traffic. This is the most complex and configurable mode."));

        // add listener to options property
        selectedOptionsProperty.addListener((observable, oldValue, newValue) -> {
            StringBuilder command = new StringBuilder("snort ");
            selectedOptions.forEach((optName, optVal) -> command.append(String.format("%s %s ", optName, optVal)));
            generatedCommandTextField.setText(command.toString());
        });

        // initialize toolbar elements
        // runButton.setOnAction(null); << implemented in MainController.java
        saveButton.setOnAction(onClickSaveCommandButton);
        loadButton.setOnAction(onClickLoadCommandButton);

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
            if(!new File(logToDirectoryTextField.getText()).exists()){
                showAlert(Alert.AlertType.WARNING, "Directory doesn't exist! Snort may not run");
            }
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
        homeAddressApplyButton.setOnAction(event -> selectedOptions.put("-h", homeAddressTextField.getText()));

        tcpdumpFormatCheckBox.selectedProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue){
                selectedOptions.put("-b", "");
                verboseCheckBox.setSelected(false);
                dumpApplicationLayerCheckBox.setSelected(false);
                ethernetLayerCheckBox.setSelected(false);
            }
            else{
                selectedOptions.remove("-b");
            }
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

        configurationFileCheckBox.selectedProperty().addListener((observable, oldValue, newValue) -> {
            if(verboseCheckBox.selectedProperty().get() && newValue){
                showAlert(Alert.AlertType.INFORMATION, "Turning off verbose option(-v) is recommended when NIDS mode.");
            }
        });
        configurationFileLocationTextField.disabledProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue){
                selectedOptions.remove("-c");
            } else {
                selectedOptions.put("-c", configurationFileLocationTextField.getText());
            }
        });
        configurationFileFindButton.setOnAction(event -> {
            File choosedFile = openFile(configurationFileFindButton.getScene().getWindow(), "/etc/snort/");
            if(choosedFile == null) return;
            if(choosedFile.exists() && choosedFile.isFile()){
                configurationFileLocationTextField.setText(choosedFile.getAbsolutePath());
                configurationFileApplyButton.fire();
            }
        });
        configurationFileApplyButton.setOnAction(event -> selectedOptions.put("-c", configurationFileLocationTextField.getText()));

        alertModeChoiceBox.disableProperty().bind(alertModeCheckBox.selectedProperty().not());
        alertModeChoiceBox.disabledProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue) selectedOptions.remove("-A");
            else selectedOptions.put("-A", alertModeChoiceBox.getSelectionModel().selectedItemProperty().get().name());
        });
        alertModeChoiceBox.getItems().addAll(AlertMode.values());
        alertModeChoiceBox.getSelectionModel().select(0);
        alertModeChoiceBox.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) ->{
            alertModeChoiceBox.setTooltip(new Tooltip(newValue.description));
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

        // etc mode option elements.
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            interfaces.asIterator().forEachRemaining(networkInterface -> interfaceChoiceBox.getItems().add(networkInterface.getName()));
            interfaceChoiceBox.getSelectionModel().select(0);
        } catch (SocketException e) {
            e.printStackTrace();
        }

        interfaceChoiceBox.disableProperty().bind(interfaceCheckBox.selectedProperty().not());
        interfaceChoiceBox.disabledProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue){
                selectedOptions.remove("-i");
            } else {
                selectedOptions.put("-i", interfaceChoiceBox.getSelectionModel().selectedItemProperty().get());
            }
        });
        interfaceChoiceBox.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> selectedOptions.put("-i", newValue));

        etcResetButton.setOnAction(event -> interfaceCheckBox.setSelected(false));


        // TODO: general configuration setting page
        // network variables
        TableColumn<NetworkVariable, String> variableTypeTableColumn = new TableColumn<>("Type");
        TableColumn<NetworkVariable, String> variableNameTableColumn = new TableColumn<>("Name");
        TableColumn<NetworkVariable, String> variableValueTableColumn = new TableColumn<>("Value");

        variableTypeTableColumn.setMinWidth(100.0);
        variableNameTableColumn.setMinWidth(100.0);
        variableValueTableColumn.setMinWidth(250.0);

        variableTypeTableColumn.setCellValueFactory(new PropertyValueFactory<>("type"));
        variableNameTableColumn.setCellValueFactory(new PropertyValueFactory<>("name"));
        variableValueTableColumn.setCellValueFactory(new PropertyValueFactory<>("value"));

        variableTypeTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        variableNameTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        variableValueTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());

        variableTypeTableColumn.setOnEditCommit(onEditCommitTypeColumn);
        variableNameTableColumn.setOnEditCommit(onEditCommitNameColumn);
        variableValueTableColumn.setOnEditCommit(onEditCommitValueColumn);

        networkVariableTableView.setEditable(true);
        networkVariableTableView.getColumns().addAll(variableTypeTableColumn, variableNameTableColumn, variableValueTableColumn);

        findConfigurationFileButton.setOnAction(onClickFindConfigurationFileButton);
        findConfigurationFileButton.setOnAction(onClickOpenConfigurationFileButton);
    }

    private final EventHandler<ActionEvent> onClickSaveCommandButton = new EventHandler<>() {
        @Override
        public void handle(ActionEvent event) {
            File saveFile = saveFile(saveButton.getScene().getWindow(), null);
            if (saveFile != null) {
                try {
                    BufferedWriter bw = new BufferedWriter(new FileWriter(saveFile));
                    bw.write("#!/bin/bash\n");
                    bw.write(String.format("# This script is generated by SnortController in %s\n", java.time.LocalDateTime.now()));
                    bw.write(generatedCommandTextField.getText());
                    bw.write("\n");
                    bw.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                if (!saveFile.getName().endsWith(".sh")) {
                    if (!saveFile.renameTo(new File(String.format("%s.sh", saveFile.getAbsolutePath())))) {
                        showAlert(Alert.AlertType.WARNING, "Unable to append extension(*.sh) to file.");
                    }
                }
            }
        }
    };

    private final EventHandler<ActionEvent> onClickLoadCommandButton = new EventHandler<>() {
        @Override
        public void handle(ActionEvent event) {
            File openFile = openFile(loadButton.getScene().getWindow(), null);
            if (openFile == null) { return; }

            BufferedReader br;
            try {
                br = new BufferedReader(new FileReader(openFile));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                showAlert(Alert.AlertType.ERROR, "Unable to open file.");
                return;
            }
            br.lines().forEach(s -> {
                if (!s.startsWith("#") && s.contains("snort")) {
                    // parse run command options
                    CommandLine cmd;
                    try {
                        cmd = parser.parse(options, s.split(" "));
                    } catch (ParseException e) {
                        e.printStackTrace();
                        return;
                    }

                    for (Option option : cmd.getOptions()) {
                        switch (option.getOpt()) {
                            case "v":
                                verboseCheckBox.setSelected(true);
                                break;

                            case "d":
                                dumpApplicationLayerCheckBox.setSelected(true);
                                break;

                            case "e":
                                ethernetLayerCheckBox.setSelected(true);
                                break;

                            case "l":
                                logToDirectoryTextField.setText(option.getValue("/var/log/snort"));
                                logToDirectoryCheckBox.setSelected(true);
                                break;

                            case "h":
                                homeAddressTextField.setText(option.getValue());
                                homeAddressCheckBox.setSelected(true);
                                break;

                            case "b":
                                tcpdumpFormatCheckBox.setSelected(true);
                                break;

                            case "c":
                                configurationFileLocationTextField.setText(option.getValue("/etc/snort/snort.conf"));
                                configurationFileCheckBox.setSelected(true);
                                break;

                            case "A":
                                alertModeChoiceBox.getSelectionModel().select(AlertMode.valueOf(option.getValue("FAST")));
                                alertModeCheckBox.setSelected(true);
                                break;

                            case "s":
                                sendAlertToSyslogCheckBox.setSelected(true);
                                break;

                            case "i":
                                interfaceChoiceBox.getSelectionModel().select(option.getValue());
                                interfaceCheckBox.setSelected(true);
                                break;
                        }
                        // generatedCommandTextField.setText(s);
                    }
                }
            });
        }
    };

    EventHandler<ActionEvent> onClickFindConfigurationFileButton = new EventHandler<>() {
        @Override
        public void handle(ActionEvent event) {
            File selectedFile = openFile(findConfigurationFileButton.getScene().getWindow(), "/etc/snort/");
            if(selectedFile == null) return;
            snortConfigurationFileLocationTextField.setText(selectedFile.getAbsolutePath());
        }
    };

    EventHandler<ActionEvent> onClickOpenConfigurationFileButton = new EventHandler<>() {
        @Override
        public void handle(ActionEvent event) {
            if(snortConfigurationFileLocationTextField.getText().isBlank()){
                showAlert(Alert.AlertType.ERROR, "Please specify configuration files location");
                return;
            }

            File configFile = new File(snortConfigurationFileLocationTextField.getText());
            if(!configFile.canRead()){
                showAlert(Alert.AlertType.ERROR, String.format("Cannot read specified rule file(%s). Try as root", configFile.getAbsolutePath()));
                return;
            }

            generalConfigurationsToolBar.getChildrenUnmodifiable().forEach(node -> node.setDisable(true));
            networkVariableTableView.setDisable(true);

            Runnable openFile = () -> {
                ConfigurationParser parser = new ConfigurationParser(configFile);

                parsedNetworkVariables = FXCollections.observableArrayList(parser.parseNetworkVariables());
                networkVariableTableView.setItems(parsedNetworkVariables);

                // TODO: now what? use save button to update configuration file?
                // if to do so, we need to remember where this network variable is declared in configuration file.
                Platform.runLater(() -> {
                    generalConfigurationsToolBar.getChildrenUnmodifiable().forEach(node -> node.setDisable(false));
                    networkVariableTableView.setDisable(false);
                });
            };
            service.submit(openFile);
        }
    };

    EventHandler<TableColumn.CellEditEvent<NetworkVariable, String>> onEditCommitTypeColumn = event -> {
        NetworkVariable networkVariable = event.getTableView().getItems().get(event.getTablePosition().getRow());
        networkVariable.setType(event.getNewValue());
        // what's difference with NetworkVariable networkVariable = event.getTableView().getSelectionModel().getSelectedItem();
    };
    EventHandler<TableColumn.CellEditEvent<NetworkVariable, String>> onEditCommitNameColumn = event -> {
        NetworkVariable networkVariable = event.getTableView().getItems().get(event.getTablePosition().getRow());
        networkVariable.setName(event.getNewValue());
    };
    EventHandler<TableColumn.CellEditEvent<NetworkVariable, String>> onEditCommitValueColumn = event -> {
        NetworkVariable networkVariable = event.getTableView().getItems().get(event.getTablePosition().getRow());
        networkVariable.setValue(event.getNewValue());
    };
}
