package snortcontroller.main;

import javafx.application.Platform;
import javafx.beans.property.MapProperty;
import javafx.beans.property.SimpleMapProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableMap;
import javafx.event.ActionEvent;
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
import snortcontroller.utils.configuration.*;

import java.io.*;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.ResourceBundle;
import java.util.concurrent.ExecutorService;

import static snortcontroller.utils.UserInteractions.showAlert;

public class SnortController implements Initializable {

    // variables for 'Run Command' tab
    // Toolbar components
    @FXML ToolBar runCommandToolbar;
    @FXML TextField generatedCommandTextField;
    @FXML Button runButton;
    @FXML Button saveButton;
    @FXML Button loadButton;

    // Sniffer mode accordion panel
    @FXML Button snifferModeHelpButton;
    @FXML CheckBox verboseCheckBox;
    @FXML CheckBox arpCheckBox;
    @FXML CheckBox dumpApplicationLayerCheckBox;
    @FXML CheckBox ethernetLayerCheckBox;
    @FXML Button snifferModeResetButton;

    // Packet Logger mode accordion panel
    @FXML Button packetLoggerModeHelpButton;
    @FXML CheckBox logToDirectoryCheckBox;
    @FXML TextField logToDirectoryTextField;
    @FXML Button logToDirectoryFindButton;
    @FXML Button logToDirectoryApplyButton;
    @FXML CheckBox homeAddressCheckBox;
    @FXML TextField homeAddressTextField;
    @FXML Button homeAddressApplyButton;
    @FXML CheckBox tcpdumpFormatCheckBox;
    @FXML Button packetLoggerModeResetButton;

    // NIDS mode accordion panel
    @FXML Button NIDSModeHelpButton;
    @FXML CheckBox configurationFileCheckBox;
    @FXML TextField configurationFileLocationTextField;
    @FXML Button configurationFileFindButton;
    @FXML Button configurationFileApplyButton;
    @FXML CheckBox alertModeCheckBox;
    @FXML ChoiceBox<AlertMode> alertModeChoiceBox;
    @FXML CheckBox sendAlertToSyslogCheckBox;
    @FXML Button NIDSModeResetButton;

    // etc accordion panel
    @FXML CheckBox interfaceCheckBox;
    @FXML ChoiceBox<String> interfaceChoiceBox;
    @FXML Button etcResetButton;


    // variables for 'General Configurations' tab
    // toolbar elements
    @FXML ToolBar generalConfigurationsToolBar;
    @FXML TextField snortConfigurationFileLocationTextField;
    @FXML Button findConfigurationFileButton;
    @FXML Button openConfigurationFileButton;

    // network variables tableview elements
    @FXML TableView<NetworkVariable> networkVariablesTableView;
    @FXML Button networkVariablesAddButton;
    @FXML Button networkVariablesResetButton;
    @FXML Button networkVariablesHelpButton;
    @FXML TableColumn<NetworkVariable, String> networkVariableTypeTableColumn;
    @FXML TableColumn<NetworkVariable, String> networkVariableNameTableColumn;
    @FXML TableColumn<NetworkVariable, String> networkVariableValueTableColumn;

    // network decoders tableview elements
    @FXML TableView<NetworkDecoder> networkDecodersTableView;
    @FXML Button networkDecodersAddButton;
    @FXML Button networkDecodersResetButton;
    @FXML Button networkDecodersHelpButton;
    @FXML TableColumn<NetworkDecoder, String> networkDecoderKeywordTableColumn;
    @FXML TableColumn<NetworkDecoder, String> networkDecoderNameTableColumn;
    @FXML TableColumn<NetworkDecoder, String> networkDecoderValueTableColumn;

    // dynamic modules tableview elements
    @FXML TableView<DynamicModule> dynamicModulesTableView;
    @FXML Button dynamicModulesAddButton;
    @FXML Button dynamicModulesResetButton;
    @FXML Button dynamicModulesHelpButton;
    @FXML TableColumn<DynamicModule, String> dynamicModuleTypeTableColumn;
    @FXML TableColumn<DynamicModule, String> dynamicModuleValueTypeTableColumn;
    @FXML TableColumn<DynamicModule, String> dynamicModuleValueTableColumn;

    // preprocessors tableview elements
    @FXML TableView<Preprocessor> preprocessorTableView;
    @FXML Button preprocessorAddButton;
    @FXML Button preprocessorResetButton;
    @FXML Button preprocessorHelpButton;
    @FXML TableColumn<Preprocessor, String> preprocessorKeywordTableColumn;
    @FXML TableColumn<Preprocessor, String> preprocessorOptionTableColumn;
    @FXML TableColumn<Preprocessor, String> preprocessorValueTableColumn;

    // output modules tableview elements
    @FXML TableView<OutputModule> outputModuleTableView;
    @FXML Button outputModuleAddButton;
    @FXML Button outputModuleResetButton;
    @FXML Button outputModuleHelpButton;
    @FXML TableColumn<OutputModule, String> outputModuleKeywordTableColumn;
    @FXML TableColumn<OutputModule, String> outputModuleOptionTableColumn;
    @FXML TableColumn<OutputModule, String> outputModuleValueTableColumn;

    // inclusion tableview elements
    @FXML TableView<Inclusion> inclusionTableView;
    @FXML Button inclusionAddButton;
    @FXML Button inclusionResetButton;
    @FXML Button inclusionHelpButton;
    @FXML TableColumn<Inclusion, String> inclusionKeywordTableColumn;
    @FXML TableColumn<Inclusion, String> inclusionValueTableColumn;

    ObservableMap<String, String> selectedOptions = FXCollections.observableHashMap();
    MapProperty<String, String> selectedOptionsProperty = new SimpleMapProperty<>(selectedOptions);
    ArrayList<NetworkVariable> parsedNetworkVariables;
    ArrayList<NetworkDecoder> parsedNetworkDecoders;
    ArrayList<DynamicModule> parsedDynamicModules;
    ArrayList<Preprocessor> parsedPreprocessors;
    ArrayList<OutputModule> parsedOutputModules;
    ArrayList<Inclusion> parsedInclusions;

    CommandLineParser parser = null;
    Options options = null;

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

    // TODO: move these to user interactions.
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
        // initialize options
        parser = new DefaultParser();
        options = new Options();

        options.addOption(new Option("v", "verbose", false, "be verbose"));
        options.addOption(new Option("a", "arp", false, "display arp packets"));
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
        // initialize sniffer mode option elements.
        verboseCheckBox.selectedProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue){
                selectedOptions.putIfAbsent("-v", "");
            } else {
                selectedOptions.remove("-v");
            }
        });
        arpCheckBox.selectedProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue) selectedOptions.putIfAbsent("-a", "");
            else selectedOptions.remove("-a");
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


        // GENERAL CONFIGURATIONS TAB.
        // network variables
        networkVariableTypeTableColumn.setCellValueFactory(new PropertyValueFactory<>("type"));
        networkVariableNameTableColumn.setCellValueFactory(new PropertyValueFactory<>("name"));
        networkVariableValueTableColumn.setCellValueFactory(new PropertyValueFactory<>("value"));

        networkVariableTypeTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        networkVariableNameTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        networkVariableValueTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());

        // network decoders
        networkDecoderKeywordTableColumn.setCellValueFactory(new PropertyValueFactory<>("keyword"));
        networkDecoderNameTableColumn.setCellValueFactory(new PropertyValueFactory<>("name"));
        networkDecoderValueTableColumn.setCellValueFactory(new PropertyValueFactory<>("value"));

        networkDecoderKeywordTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        networkDecoderNameTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        networkDecoderValueTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());

        // dynamic modules
        dynamicModuleTypeTableColumn.setCellValueFactory(new PropertyValueFactory<>("moduleType"));
        dynamicModuleValueTypeTableColumn.setCellValueFactory(new PropertyValueFactory<>("valueType"));
        dynamicModuleValueTableColumn.setCellValueFactory(new PropertyValueFactory<>("value"));

        dynamicModuleTypeTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        dynamicModuleValueTypeTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        dynamicModuleValueTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());

        // preprocessors
        preprocessorKeywordTableColumn.setCellValueFactory(new PropertyValueFactory<>("keyword"));
        preprocessorOptionTableColumn.setCellValueFactory(new PropertyValueFactory<>("option"));
        preprocessorValueTableColumn.setCellValueFactory(new PropertyValueFactory<>("value"));

        preprocessorKeywordTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        preprocessorOptionTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        preprocessorValueTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());

        // output modules
        outputModuleKeywordTableColumn.setCellValueFactory(new PropertyValueFactory<>("keyword"));
        outputModuleOptionTableColumn.setCellValueFactory(new PropertyValueFactory<>("option"));
        outputModuleValueTableColumn.setCellValueFactory(new PropertyValueFactory<>("value"));

        outputModuleKeywordTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        outputModuleOptionTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        outputModuleValueTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());

        // file inclusions
        inclusionKeywordTableColumn.setCellValueFactory(new PropertyValueFactory<>("keyword"));
        inclusionValueTableColumn.setCellValueFactory(new PropertyValueFactory<>("value"));

        inclusionKeywordTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        inclusionValueTableColumn.setCellFactory(TextFieldTableCell.forTableColumn());
    }

    // run command button handlers
    @FXML
    private void onClickSaveCommandButton(){
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

    @FXML
    private void onClickLoadCommandButton() {
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

                        case "a":
                            arpCheckBox.setSelected(true);
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
                }
            }
        });
    }


    // configuration file button handlers
    @FXML
    private void onClickFindConfigurationFileButton(){
        File selectedFile = openFile(findConfigurationFileButton.getScene().getWindow(), "/etc/snort/");
        if(selectedFile == null) return;
        snortConfigurationFileLocationTextField.setText(selectedFile.getAbsolutePath());
    }

    @FXML
    private void onClickOpenConfigurationFileButton(){
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
        networkVariablesTableView.setDisable(true);
        networkDecodersTableView.setDisable(true);
        dynamicModulesTableView.setDisable(true);
        preprocessorTableView.setDisable(true);
        outputModuleTableView.setDisable(true);
        inclusionTableView.setDisable(true);

        Runnable openFile = () -> {
            ConfigurationParser parser = new ConfigurationParser(configFile);

            try {
                parsedNetworkVariables = parser.parseNetworkVariables();
                parsedNetworkDecoders = parser.parseNetworkDecoders();
                parsedDynamicModules = parser.parseDynamicModules();
                parsedPreprocessors = parser.parsePreprocessors();
                parsedOutputModules = parser.parseOutputModules();
                parsedInclusions = parser.parseInclusions();

                ArrayList<NetworkVariable> editedNetworkVariables = new ArrayList<>();
                ArrayList<NetworkDecoder> editedNetworkDecoders = new ArrayList<>();
                ArrayList<DynamicModule> editedDynamicModules = new ArrayList<>();
                ArrayList<Preprocessor> editedPreprocessors = new ArrayList<>();
                ArrayList<OutputModule> editedOutputModules = new ArrayList<>();
                ArrayList<Inclusion> editedInclusions = new ArrayList<>();

                parsedNetworkVariables.forEach(networkVariable -> editedNetworkVariables.add(networkVariable.copy()));
                parsedNetworkDecoders.forEach(networkDecoder -> editedNetworkDecoders.add(networkDecoder.copy()));
                parsedDynamicModules.forEach(dynamicModule -> editedDynamicModules.add(dynamicModule.copy()));
                parsedPreprocessors.forEach(preprocessor -> editedPreprocessors.add(preprocessor.copy()));
                parsedOutputModules.forEach(outputModule -> editedOutputModules.add(outputModule.copy()));
                parsedInclusions.forEach(inclusion -> editedInclusions.add(inclusion.copy()));

                networkVariablesTableView.setItems(FXCollections.observableArrayList(editedNetworkVariables));
                networkDecodersTableView.setItems(FXCollections.observableArrayList(editedNetworkDecoders));
                dynamicModulesTableView.setItems(FXCollections.observableArrayList(editedDynamicModules));
                preprocessorTableView.setItems(FXCollections.observableArrayList(editedPreprocessors));
                outputModuleTableView.setItems(FXCollections.observableArrayList(editedOutputModules));
                inclusionTableView.setItems(FXCollections.observableArrayList(editedInclusions));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }

            networkVariablesTableView.itemsProperty().addListener((observable, oldValue, newValue) -> networkVariablesTableView.refresh());
            networkDecodersTableView.itemsProperty().addListener((observable, oldValue, newValue) -> networkDecodersTableView.refresh());
            dynamicModulesTableView.itemsProperty().addListener((observable, oldValue, newValue) -> dynamicModulesTableView.refresh());
            preprocessorTableView.itemsProperty().addListener((observable, oldValue, newValue) -> preprocessorTableView.refresh());
            outputModuleTableView.itemsProperty().addListener((observable, oldValue, newValue) -> outputModuleTableView.refresh());
            inclusionTableView.itemsProperty().addListener((observable, oldValue, newValue) -> inclusionTableView.refresh());

            Platform.runLater(() -> {
                generalConfigurationsToolBar.getChildrenUnmodifiable().forEach(node -> node.setDisable(false));
                networkVariablesTableView.setDisable(false);
                networkDecodersTableView.setDisable(false);
                dynamicModulesTableView.setDisable(false);
                preprocessorTableView.setDisable(false);
                outputModuleTableView.setDisable(false);
                inclusionTableView.setDisable(false);
            });
        };
        service.submit(openFile);
    }

    // network variables button handlers
    // TODO: implement here
    @FXML
    private void onClickAddNetworkVariablesButton(ActionEvent event){

    }
    @FXML
    private void onClickResetNetworkVariablesButton(){
        networkVariablesTableView.getItems().clear();
        parsedNetworkVariables.forEach(networkVariable -> networkVariablesTableView.getItems().add(networkVariable.copy()));
        // binding direction editedNetworkVariables to tableview's observable list? changes are applied to data structure
        // but not towards observable list. maybe setItems() event should happen.
    }
    @FXML
    private void onClickHelpNetworkVariablesButton(){
        String string = "-- DEFAULT VARIABLES --\n" +
                "HOME_NET: Use this to specify the IP addresses of the systems you are protecting.\n" +
                "EXTERNAL_NET: Use this to specify the IP addresses outside of the systems you are protecting.\n";
        showAlert(Alert.AlertType.INFORMATION, string);
    }

    // network decoders button handlers
    @FXML  // TODO: implement here
    private void onClickAddNetworkDecodersButton(ActionEvent event){

    }
    @FXML
    private void onClickResetNetworkDecodersButton(){
        networkDecodersTableView.getItems().clear();
        parsedNetworkDecoders.forEach(networkDecoder -> networkDecodersTableView.getItems().add(networkDecoder.copy()));
    }
    @FXML
    private void onClickHelpNetworkDecodersButton(){
        String string = "The Snort decoder watches the structure of network packets to make sure they are constructed " +
                "according to specification.";
        showAlert(Alert.AlertType.INFORMATION, string);
    }

    // dynamic modules button handlers
    @FXML // TODO: implement here
    private void onClickAddDynamicModulesButton(ActionEvent event){

    }
    @FXML
    private void onClickResetDynamicModulesButton(){
        dynamicModulesTableView.getItems().clear();
        parsedDynamicModules.forEach(dynamicModule -> dynamicModulesTableView.getItems().add(dynamicModule.copy()));
    }
    @FXML
    private void onClickHelpDynamicModulesButton(){
        String string = "Dynamically loadable modules were introduced with Snort 2.6." +
                " They can be loaded via directives in snort.conf or via command-line options.";
        showAlert(Alert.AlertType.INFORMATION, string);
    }

    // preprocessors button handlers
    @FXML // TODO: implement here
    private void onClickAddPreprocessorsButton(ActionEvent event){

    }
    @FXML
    private void onClickResetPreprocessorsButton(){
        preprocessorTableView.getItems().clear();
        parsedPreprocessors.forEach(preprocessor -> preprocessorTableView.getItems().add(preprocessor.copy()));
    }
    @FXML
    private void onClickHelpPreprocessorsButton(){
        String string = "Preprocessors were introduced in version 1.5 of Snort. They allow the functionality of Snort" +
                " to be extended by allowing users and programmers to drop modular plugins into Snort fairly easily.";
        showAlert(Alert.AlertType.INFORMATION, string);
    }

    // output modules button handlers
    @FXML // TODO: implement here
    private void onClickAddOutputModulesButton(ActionEvent event){

    }
    @FXML
    private void onClickResetOutputModulesButton(){
        outputModuleTableView.getItems().clear();
        parsedOutputModules.forEach(outputModule -> outputModuleTableView.getItems().add(outputModule.copy()));
    }
    @FXML
    private void onClickHelpOutputModulesButton(){
        String string = "They allow Snort to be much more flexible in the formatting and presentation of output to its users. " +
                "The output modules are run when the alert or logging subsystems of Snort are called, after the preprocessors and detection engine.";
        showAlert(Alert.AlertType.INFORMATION, string);
    }

    // inclusion button handlers
    @FXML // TODO: implement here
    private void onClickAddInclusionButton(ActionEvent event){

    }
    @FXML
    private void onClickResetInclusionButton(){
        inclusionTableView.getItems().clear();
        parsedInclusions.forEach(inclusion -> inclusionTableView.getItems().add(inclusion.copy()));
    }
    @FXML
    private void onClickHelpInclusionButton(){
        String string = "The include command tells Snort to include the information in files located in the Snort sensor's filesystem." +
                " These files include configuration information and the files containing the rules that Snort uses to catch bad guys.";
        showAlert(Alert.AlertType.INFORMATION, string);
    }

    // cell edit commmit event handlers
    @FXML
    private void onEditCommitNetworkVariableTypeColumn(TableColumn.CellEditEvent<NetworkVariable, String> event){
        NetworkVariable networkVariable = event.getTableView().getSelectionModel().getSelectedItem();
        networkVariable.setType(event.getNewValue());
        // what's difference with NetworkVariable networkVariable = event.getTableView().getSelectionModel().getSelectedItem();
    }
    @FXML
    private void onEditCommitNetworkVariableNameColumn(TableColumn.CellEditEvent<NetworkVariable, String> event){
        NetworkVariable networkVariable = event.getTableView().getSelectionModel().getSelectedItem();
        networkVariable.setName(event.getNewValue());
        // what's difference with NetworkVariable networkVariable = event.getTableView().getSelectionModel().getSelectedItem();
    }
    @FXML
    private void onEditCommitNetworkVariableValueColumn(TableColumn.CellEditEvent<NetworkVariable, String> event){
        NetworkVariable networkVariable = event.getTableView().getSelectionModel().getSelectedItem();
        networkVariable.setValue(event.getNewValue());
        // what's difference with NetworkVariable networkVariable = event.getTableView().getSelectionModel().getSelectedItem();
    }

    @FXML
    private void onEditCommitNetworkDecoderKeywordColumn(TableColumn.CellEditEvent<NetworkDecoder, String> event){
        NetworkDecoder networkDecoder = event.getTableView().getSelectionModel().getSelectedItem();
        networkDecoder.setKeyword(event.getNewValue());
    }
    @FXML
    private void onEditCommitNetworkDecoderNameColumn(TableColumn.CellEditEvent<NetworkDecoder, String> event) {
        NetworkDecoder networkDecoder = event.getTableView().getSelectionModel().getSelectedItem();
        networkDecoder.setName(event.getNewValue());
    }
    @FXML
    private void onEditCommitNetworkDecoderValueColumn(TableColumn.CellEditEvent<NetworkDecoder, String> event) {
        NetworkDecoder networkDecoder = event.getTableView().getSelectionModel().getSelectedItem();
        networkDecoder.setValue(event.getNewValue());
    }

    @FXML
    private void onEditCommitDynamicModuleTypeColumn(TableColumn.CellEditEvent<DynamicModule, String> event){
        DynamicModule dynamicModule = event.getTableView().getSelectionModel().getSelectedItem();
        dynamicModule.setModuleType(event.getNewValue());
    };
    @FXML
    private void onEditCommitDynamicModuleValueTypeColumn(TableColumn.CellEditEvent<DynamicModule, String> event){
        DynamicModule dynamicModule = event.getTableView().getSelectionModel().getSelectedItem();
        dynamicModule.setValueType(event.getNewValue());
    }
    @FXML
    private void onEditCommitDynamicModuleValueColumn(TableColumn.CellEditEvent<DynamicModule, String> event){
        DynamicModule dynamicModule = event.getTableView().getSelectionModel().getSelectedItem();
        dynamicModule.setValue(event.getNewValue());
    }

    @FXML
    private void onEditCommitPreprocessorKeywordColumn(TableColumn.CellEditEvent<Preprocessor, String> event){
        Preprocessor preprocessor = event.getTableView().getSelectionModel().getSelectedItem();
        preprocessor.setKeyword(event.getNewValue());
    }
    @FXML
    private void onEditCommitPreprocessorOptionColumn(TableColumn.CellEditEvent<Preprocessor, String> event){
        Preprocessor preprocessor = event.getTableView().getSelectionModel().getSelectedItem();
        preprocessor.setOption(event.getNewValue());
    }
    @FXML
    private void onEditCommitPreprocessorValueColumn(TableColumn.CellEditEvent<Preprocessor, String> event){
        Preprocessor preprocessor = event.getTableView().getSelectionModel().getSelectedItem();
        preprocessor.setValue(event.getNewValue());
    }

    @FXML
    private void onEditCommitOutputModuleKeywordColumn(TableColumn.CellEditEvent<OutputModule, String> event){
        OutputModule outputModule = event.getTableView().getSelectionModel().getSelectedItem();
        outputModule.setKeyword(event.getNewValue());
    }
    @FXML
    private void onEditCommitOutputModuleOptionColumn(TableColumn.CellEditEvent<OutputModule, String> event){
        OutputModule outputModule = event.getTableView().getSelectionModel().getSelectedItem();
        outputModule.setOption(event.getNewValue());
    }
    @FXML
    private void onEditCommitOutputModuleValueColumn(TableColumn.CellEditEvent<OutputModule, String> event){
        OutputModule outputModule = event.getTableView().getSelectionModel().getSelectedItem();
        outputModule.setValue(event.getNewValue());
    }

    @FXML
    private void onEditCommitInclusionKeywordColumn(TableColumn.CellEditEvent<Inclusion, String> event){
        Inclusion inclusion = event.getTableView().getSelectionModel().getSelectedItem();
        inclusion.setKeyword(event.getNewValue());
    }
    @FXML
    private void onEditCommitInclusionValueColumn(TableColumn.CellEditEvent<Inclusion, String> event){
        Inclusion inclusion = event.getTableView().getSelectionModel().getSelectedItem();
        inclusion.setValue(event.getNewValue());
    }
}
