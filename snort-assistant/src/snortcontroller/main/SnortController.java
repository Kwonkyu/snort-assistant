package snortcontroller.main;

import javafx.application.Platform;
import javafx.beans.property.MapProperty;
import javafx.beans.property.SimpleMapProperty;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.collections.ObservableMap;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.control.cell.TextFieldTableCell;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
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
import java.util.regex.Pattern;

import static snortcontroller.utils.UserInteractions.*;

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

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        // initialize options
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
            File choosedDirectory = openDirectory(logToDirectoryFindButton.getScene().getWindow());
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
        MenuItem networkVariablesEditMenuItem = new MenuItem("Edit");
        MenuItem networkVariablesRemoveMenuItem = new MenuItem("Remove");
        networkVariablesEditMenuItem.setOnAction(event -> {
            Stage stage = new Stage(StageStyle.DECORATED);
            NetworkVariable selectedItem = networkVariablesTableView.getSelectionModel().getSelectedItem();
            ChoiceBox<String> typeChoiceBox = new ChoiceBox<>(FXCollections.observableArrayList("ipvar", "portvar", "var"));
            TextField nameField = new TextField(selectedItem.getName());
            TextField valueField = new TextField(selectedItem.getValue());
            VBox container = new VBox(10);
            Button saveButton = new Button("Save");
            Button closeButton = new Button("Close");

            saveButton.setOnAction(e ->{
                selectedItem.setType(typeChoiceBox.getValue());
                selectedItem.setName(nameField.getText());
                selectedItem.setValue(valueField.getText());
                // TODO: how to use listener on this?
                networkVariablesTableView.refresh();
            });

            closeButton.setOnAction(value -> ((Stage)((Node)value.getSource()).getScene().getWindow()).close());

            // it's better not to close this window because.. if you want to add multiple variables?
            typeChoiceBox.getSelectionModel().select(selectedItem.getType());
            container.setPadding(new Insets(10));
            container.getChildren().addAll(new Label("Type"), typeChoiceBox, new Label("Name"), nameField,
                    new Label("Value"), valueField, new HBox(10, saveButton, closeButton));
            stage.setScene(new Scene(container));
            stage.initOwner(networkVariablesTableView.getScene().getWindow());
            stage.setAlwaysOnTop(true);
            stage.show();
        });
        networkVariablesRemoveMenuItem.setOnAction(event -> networkVariablesTableView.getItems().remove(networkVariablesTableView.getSelectionModel().getSelectedItem()));
        networkVariablesTableView.setContextMenu(new ContextMenu(networkVariablesEditMenuItem, networkVariablesRemoveMenuItem));

        networkVariableTypeTableColumn.setCellValueFactory(new PropertyValueFactory<>("type"));
        networkVariableNameTableColumn.setCellValueFactory(new PropertyValueFactory<>("name"));
        networkVariableValueTableColumn.setCellValueFactory(new PropertyValueFactory<>("value"));

        // network decoders
        MenuItem networkDecodersEditMenuItem = new MenuItem("Edit");
        MenuItem networkDecodersRemoveMenuItem = new MenuItem("Remove");
        networkDecodersEditMenuItem.setOnAction(event -> {
            Stage stage = new Stage(StageStyle.DECORATED);
            NetworkDecoder selectedItem = networkDecodersTableView.getSelectionModel().getSelectedItem();
            TextField keywordField = new TextField("config");
            TextField nameField = new TextField(selectedItem.getName());
            TextField valueField = new TextField(selectedItem.getValue());
            VBox container = new VBox(10);
            Button saveButton = new Button("Save");
            Button closeButton = new Button("Close");

            saveButton.setOnAction(e ->{
                selectedItem.setKeyword(keywordField.getText());
                selectedItem.setName(nameField.getText());
                selectedItem.setValue(valueField.getText());
                networkDecodersTableView.refresh();
            });

            closeButton.setOnAction(value -> ((Stage)((Node)value.getSource()).getScene().getWindow()).close());

            // it's better not to close this window because.. if you want to add multiple variables?
            keywordField.setEditable(false);
            container.setPadding(new Insets(10));
            container.getChildren().addAll(new Label("Keyword"), keywordField, new Label("Name"), nameField,
                    new Label("Value"), valueField, new HBox(10, saveButton, closeButton));
            stage.setScene(new Scene(container));
            stage.initOwner(networkDecodersTableView.getScene().getWindow());
            stage.setAlwaysOnTop(true);
            stage.show();
        });
        networkDecodersRemoveMenuItem.setOnAction(event -> networkDecodersTableView.getItems().remove(networkDecodersTableView.getSelectionModel().getSelectedItem()));
        networkDecodersTableView.setContextMenu(new ContextMenu(networkDecodersEditMenuItem, networkDecodersRemoveMenuItem));

        networkDecoderKeywordTableColumn.setCellValueFactory(new PropertyValueFactory<>("keyword"));
        networkDecoderNameTableColumn.setCellValueFactory(new PropertyValueFactory<>("name"));
        networkDecoderValueTableColumn.setCellValueFactory(new PropertyValueFactory<>("value"));

        // dynamic modules
        MenuItem dynamicModulesEditMenuItem = new MenuItem("Edit");
        MenuItem dynamicModulesRemoveMenuItem = new MenuItem("Remove");
        dynamicModulesEditMenuItem.setOnAction(event -> {
            Stage stage = new Stage(StageStyle.DECORATED);
            DynamicModule selectedItem = dynamicModulesTableView.getSelectionModel().getSelectedItem();
            ChoiceBox<String> typeChoiceBox = new ChoiceBox<>(FXCollections.observableArrayList("dynamicpreprocessor", "dynamicengine", "dynamicdetection"));
            ChoiceBox<String> valueTypeChoiceBox = new ChoiceBox<>(FXCollections.observableArrayList("directory", "file"));
            TextField valueField = new TextField(selectedItem.getValue());
            VBox container = new VBox(10);
            Button saveButton = new Button("Save");
            Button closeButton = new Button("Close");

            saveButton.setOnAction(e ->{
                selectedItem.setModuleType(typeChoiceBox.getValue());
                selectedItem.setValueType(valueTypeChoiceBox.getValue());
                selectedItem.setValue(valueField.getText());
                dynamicModulesTableView.refresh();
            });

            closeButton.setOnAction(value -> ((Stage)((Node)value.getSource()).getScene().getWindow()).close());

            // it's better not to close this window because.. if you want to add multiple variables?
            typeChoiceBox.getSelectionModel().select(selectedItem.getModuleType());
            valueTypeChoiceBox.getSelectionModel().select(selectedItem.getValueType());
            container.setPadding(new Insets(10));
            container.getChildren().addAll(new Label("Module Type"), typeChoiceBox, new Label("Value Type"), valueTypeChoiceBox,
                    new Label("Value"), valueField, new HBox(10, saveButton, closeButton));
            stage.setScene(new Scene(container));
            stage.initOwner(dynamicModulesTableView.getScene().getWindow());
            stage.setAlwaysOnTop(true);
            stage.show();
        });
        dynamicModulesRemoveMenuItem.setOnAction(event -> dynamicModulesTableView.getItems().remove(dynamicModulesTableView.getSelectionModel().getSelectedItem()));
        dynamicModulesTableView.setContextMenu(new ContextMenu(dynamicModulesEditMenuItem, dynamicModulesRemoveMenuItem));

        dynamicModuleTypeTableColumn.setCellValueFactory(new PropertyValueFactory<>("moduleType"));
        dynamicModuleValueTypeTableColumn.setCellValueFactory(new PropertyValueFactory<>("valueType"));
        dynamicModuleValueTableColumn.setCellValueFactory(new PropertyValueFactory<>("value"));

        // preprocessors
        MenuItem preprocessorsEditMenuItem = new MenuItem("Edit");
        MenuItem preprocessorsRemoveMenuItem = new MenuItem("Remove");
        preprocessorsEditMenuItem.setOnAction(event -> {
            Stage stage = new Stage(StageStyle.DECORATED);
            Preprocessor selectedItem = preprocessorTableView.getSelectionModel().getSelectedItem();
            TextField keywordField = new TextField(selectedItem.getKeyword());
            TextField optionNameField = new TextField(selectedItem.getOption());
            TextField optionValueField = new TextField(selectedItem.getValue());
            VBox container = new VBox(10);
            Button saveButton = new Button("Save");
            Button closeButton = new Button("Close");

            saveButton.setOnAction(e ->{
                selectedItem.setKeyword(keywordField.getText());
                selectedItem.setOption(optionNameField.getText());
                selectedItem.setValue(optionValueField.getText());
                preprocessorTableView.refresh();
            });

            closeButton.setOnAction(value -> ((Stage)((Node)value.getSource()).getScene().getWindow()).close());

            // it's better not to close this window because.. if you want to add multiple variables?
            keywordField.setEditable(false);
            container.setPadding(new Insets(10));
            container.getChildren().addAll(new Label("Keyword"), keywordField, new Label("Option"), optionNameField,
                    new Label("Value"), optionValueField, new HBox(10, saveButton, closeButton));
            stage.setScene(new Scene(container));
            stage.initOwner(preprocessorTableView.getScene().getWindow());
            stage.setAlwaysOnTop(true);
            stage.show();
        });
        preprocessorsRemoveMenuItem.setOnAction(event -> preprocessorTableView.getItems().remove(preprocessorTableView.getSelectionModel().getSelectedItem()));
        preprocessorTableView.setContextMenu(new ContextMenu(preprocessorsEditMenuItem, preprocessorsRemoveMenuItem));

        preprocessorKeywordTableColumn.setCellValueFactory(new PropertyValueFactory<>("keyword"));
        preprocessorOptionTableColumn.setCellValueFactory(new PropertyValueFactory<>("option"));
        preprocessorValueTableColumn.setCellValueFactory(new PropertyValueFactory<>("value"));

        // output modules
        MenuItem outputModulesEditMenuItem = new MenuItem("Edit");
        MenuItem outputModulesRemoveMenuItem = new MenuItem("Remove");
        outputModulesEditMenuItem.setOnAction(event -> {
            Stage stage = new Stage(StageStyle.DECORATED);
            OutputModule selectedItem = outputModuleTableView.getSelectionModel().getSelectedItem();
            TextField keywordField = new TextField("output");
            TextField optionNameField = new TextField(selectedItem.getOption());
            TextField optionValueField = new TextField(selectedItem.getValue());
            VBox container = new VBox(10);
            Button saveButton = new Button("Save");
            Button closeButton = new Button("Close");

            saveButton.setOnAction(e ->{
                selectedItem.setKeyword(keywordField.getText());
                selectedItem.setOption(optionNameField.getText());
                selectedItem.setValue(optionValueField.getText());
                outputModuleTableView.refresh();
            });

            closeButton.setOnAction(value -> ((Stage)((Node)value.getSource()).getScene().getWindow()).close());

            // it's better not to close this window because.. if you want to add multiple variables?
            keywordField.setEditable(false);
            container.setPadding(new Insets(10));
            container.getChildren().addAll(new Label("Keyword"), keywordField, new Label("Option"), optionNameField,
                    new Label("Value"), optionValueField, new HBox(10, saveButton, closeButton));
            stage.setScene(new Scene(container));
            stage.initOwner(outputModuleTableView.getScene().getWindow());
            stage.setAlwaysOnTop(true);
            stage.show();
        });
        outputModulesRemoveMenuItem.setOnAction(event -> outputModuleTableView.getItems().remove(outputModuleTableView.getSelectionModel().getSelectedItem()));
        outputModuleTableView.setContextMenu(new ContextMenu(outputModulesEditMenuItem, outputModulesRemoveMenuItem));

        outputModuleKeywordTableColumn.setCellValueFactory(new PropertyValueFactory<>("keyword"));
        outputModuleOptionTableColumn.setCellValueFactory(new PropertyValueFactory<>("option"));
        outputModuleValueTableColumn.setCellValueFactory(new PropertyValueFactory<>("value"));

        // file inclusions
        MenuItem inclusionsEditMenuItem = new MenuItem("Edit");
        MenuItem inclusionsRemoveMenuItem = new MenuItem("Remove");
        inclusionsEditMenuItem.setOnAction(event -> {
            Stage stage = new Stage(StageStyle.DECORATED);
            Inclusion selectedItem = inclusionTableView.getSelectionModel().getSelectedItem();
            TextField keywordField = new TextField("include");
            TextField valueField = new TextField(selectedItem.getValue());
            VBox container = new VBox(10);
            Button saveButton = new Button("Save");
            Button closeButton = new Button("Close");

            saveButton.setOnAction(e ->{
                selectedItem.setKeyword(keywordField.getText());
                selectedItem.setValue(valueField.getText());
                inclusionTableView.refresh();
            });

            closeButton.setOnAction(value -> ((Stage)((Node)value.getSource()).getScene().getWindow()).close());

            // it's better not to close this window because.. if you want to add multiple variables?
            keywordField.setEditable(false);
            container.setPadding(new Insets(10));
            container.getChildren().addAll(new Label("Keyword"), keywordField, new Label("Value"), valueField,
                    new HBox(10, saveButton, closeButton));
            stage.setScene(new Scene(container));
            stage.initOwner(inclusionTableView.getScene().getWindow());
            stage.setAlwaysOnTop(true);
            stage.show();
        });
        inclusionsRemoveMenuItem.setOnAction(event -> inclusionTableView.getItems().remove(inclusionTableView.getSelectionModel().getSelectedItem()));
        inclusionTableView.setContextMenu(new ContextMenu(inclusionsEditMenuItem, inclusionsRemoveMenuItem));

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
                    cmd = new DefaultParser().parse(options, s.split(" "));
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

    @FXML
    private void onClickSaveConfigurationFileButton(ActionEvent event){
        File saveFile = saveFile(((Button)event.getSource()).getScene().getWindow(), null);
        if (saveFile != null) {
            try {
                BufferedWriter bw = new BufferedWriter(new FileWriter(saveFile));
                bw.write(String.format("# This configuration file is generated by SnortController in %s\n", java.time.LocalDateTime.now()));
                bw.write("# Step 1. Network variables.\n");
                networkVariablesTableView.getItems().forEach(networkVariable -> {
                    try {
                        bw.write(String.format("%s %s %s\n", networkVariable.getType(), networkVariable.getName(), networkVariable.getValue()));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });
                bw.write("# Step 2. Network decoders.\n");
                networkDecodersTableView.getItems().forEach(networkDecoder -> {
                    try{
                        bw.write(String.format("%s %s %s\n", networkDecoder.getKeyword(), networkDecoder.getName(), networkDecoder.getValue()));
                    } catch (IOException e){
                        e.printStackTrace();
                    }
                });
                bw.write("# Step 3. Dynamic modules.\n");
                dynamicModulesTableView.getItems().forEach(dynamicModule -> {
                    try{
                        bw.write(String.format("%s %s %s\n", dynamicModule.getModuleType(), dynamicModule.getValueType(), dynamicModule.getValue()));
                    } catch (IOException e){
                        e.printStackTrace();
                    }
                });
                bw.write("# Step 4. Preprocessors.\n");
                preprocessorTableView.getItems().forEach(preprocessor -> {
                    try{
                        bw.write(String.format("%s %s ", preprocessor.getKeyword(), preprocessor.getOption()));
                        if(!preprocessor.getValue().isBlank()){
                            String[] values = preprocessor.getValue().split(Pattern.quote("\\"));
                            for(int i=0;i<values.length;i++){
                                bw.write(values[i]);
                                if(i < values.length - 1){
                                    bw.write(" \\ \n\t");
                                } else {
                                    bw.write(" \n");
                                }
                            }
                        } else {
                            bw.write("\n");
                        }
                    } catch (IOException e){
                        e.printStackTrace();
                    }
                });
                bw.write("# Step 5. Output modules.\n");
                outputModuleTableView.getItems().forEach(outputModule -> {
                    try{
                        bw.write(String.format("%s %s %s\n", outputModule.getKeyword(), outputModule.getOption(), outputModule.getValue()));
                    } catch (IOException e){
                        e.printStackTrace();
                    }
                });
                bw.write("# Step 6. File inclusions.\n");
                inclusionTableView.getItems().forEach(inclusion -> {
                    try{
                        bw.write(String.format("%s %s\n", inclusion.getKeyword(), inclusion.getValue()));
                    } catch (IOException e){
                        e.printStackTrace();
                    }
                });
                bw.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            if (!saveFile.getName().endsWith(".conf")) {
                if (!saveFile.renameTo(new File(String.format("%s.conf", saveFile.getAbsolutePath())))) {
                    showAlert(Alert.AlertType.WARNING, "Unable to append extension(*.sh) to file.");
                }
            }
        }
    }

    // network variables button handlers
    @FXML
    private void onClickAddNetworkVariablesButton(ActionEvent event){
        Stage stage = new Stage(StageStyle.DECORATED);
        ChoiceBox<String> choiceBox = new ChoiceBox<>(FXCollections.observableArrayList("ipvar", "portvar", "var"));
        TextField nameField = new TextField();
        TextField valueField = new TextField();
        VBox container = new VBox(10);
        Button addButton = new Button("Add");
        Button closeButton = new Button("Close");

        addButton.setOnAction(e -> networkVariablesTableView.getItems().add(new NetworkVariable(choiceBox.getValue(), nameField.getText(), valueField.getText())));

        closeButton.setOnAction(value -> ((Stage)((Node)value.getSource()).getScene().getWindow()).close());

        // it's better not to close this window because.. if you want to add multiple variables?
        choiceBox.getSelectionModel().select(0);
        container.setPadding(new Insets(10));
        container.getChildren().addAll(new Label("Type"), choiceBox, new Label("Name"), nameField,
                new Label("Value"), valueField, new HBox(10, addButton, closeButton));
        stage.setScene(new Scene(container));
        stage.initOwner(((Button)event.getSource()).getScene().getWindow());
        stage.setAlwaysOnTop(true);
        stage.show();
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
    @FXML
    private void onClickAddNetworkDecodersButton(ActionEvent event){
        Stage stage = new Stage(StageStyle.DECORATED);
        TextField keywordField = new TextField("config");
        TextField nameField = new TextField();
        TextField valueField = new TextField();
        VBox container = new VBox(10);
        Button addButton = new Button("Add");
        Button closeButton = new Button("Close");

        addButton.setOnAction(e -> networkDecodersTableView.getItems().add(new NetworkDecoder(keywordField.getText(), nameField.getText(), valueField.getText())));

        closeButton.setOnAction(value -> ((Stage)((Node)value.getSource()).getScene().getWindow()).close());

        // it's better not to close this window because.. if you want to add multiple variables?
        keywordField.setEditable(false);
        container.setPadding(new Insets(10));
        container.getChildren().addAll(new Label("Keyword"), keywordField, new Label("Name"), nameField,
                new Label("Value"), valueField, new HBox(10, addButton, closeButton));
        stage.setScene(new Scene(container));
        stage.initOwner(((Button)event.getSource()).getScene().getWindow());
        stage.setAlwaysOnTop(true);
        stage.show();
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
    @FXML
    private void onClickAddDynamicModulesButton(ActionEvent event){
        Stage stage = new Stage(StageStyle.DECORATED);
        ChoiceBox<String> typeChoiceBox = new ChoiceBox<>(FXCollections.observableArrayList("dynamicpreprocessor", "dynamicengine", "dynamicdetection"));
        ChoiceBox<String> valueTypeChoiceBox = new ChoiceBox<>(FXCollections.observableArrayList("directory", "file"));
        TextField valueField = new TextField();
        VBox container = new VBox(10);
        Button addButton = new Button("Add");
        Button closeButton = new Button("Close");

        addButton.setOnAction(e -> dynamicModulesTableView.getItems().add(new DynamicModule(typeChoiceBox.getValue(), valueTypeChoiceBox.getValue(), valueField.getText())));

        closeButton.setOnAction(value -> ((Stage)((Node)value.getSource()).getScene().getWindow()).close());

        // it's better not to close this window because.. if you want to add multiple variables?
        typeChoiceBox.getSelectionModel().select(0);
        valueTypeChoiceBox.getSelectionModel().select(0);
        container.setPadding(new Insets(10));
        container.getChildren().addAll(new Label("Module Type"), typeChoiceBox, new Label("Value Type"), valueTypeChoiceBox,
                new Label("Value"), valueField, new HBox(10, addButton, closeButton));
        stage.setScene(new Scene(container));
        stage.initOwner(((Button)event.getSource()).getScene().getWindow());
        stage.setAlwaysOnTop(true);
        stage.show();
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
    @FXML
    private void onClickAddPreprocessorsButton(ActionEvent event){
        Stage stage = new Stage(StageStyle.DECORATED);
        TextField keywordField = new TextField("preprocessor");
        TextField optionNameField = new TextField();
        TextField optionValueField = new TextField();
        VBox container = new VBox(10);
        Button addButton = new Button("Add");
        Button closeButton = new Button("Close");

        addButton.setOnAction(e -> preprocessorTableView.getItems().add(new Preprocessor(keywordField.getText(), optionNameField.getText(), optionValueField.getText())));

        closeButton.setOnAction(value -> ((Stage)((Node)value.getSource()).getScene().getWindow()).close());

        // it's better not to close this window because.. if you want to add multiple variables?
        keywordField.setEditable(false);
        container.setPadding(new Insets(10));
        container.getChildren().addAll(new Label("Keyword"), keywordField, new Label("Option"), optionNameField,
                new Label("Value"), optionValueField, new HBox(10, addButton, closeButton));
        stage.setScene(new Scene(container));
        stage.initOwner(((Button)event.getSource()).getScene().getWindow());
        stage.setAlwaysOnTop(true);
        stage.show();
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
    @FXML
    private void onClickAddOutputModulesButton(ActionEvent event){
        Stage stage = new Stage(StageStyle.DECORATED);
        TextField keywordField = new TextField("output");
        TextField optionNameField = new TextField();
        TextField optionValueField = new TextField();
        VBox container = new VBox(10);
        Button addButton = new Button("Add");
        Button closeButton = new Button("Close");

        addButton.setOnAction(e -> outputModuleTableView.getItems().add(new OutputModule(keywordField.getText(), optionNameField.getText(), optionValueField.getText())));

        closeButton.setOnAction(value -> ((Stage)((Node)value.getSource()).getScene().getWindow()).close());

        // it's better not to close this window because.. if you want to add multiple variables?
        keywordField.setEditable(false);
        container.setPadding(new Insets(10));
        container.getChildren().addAll(new Label("Keyword"), keywordField, new Label("Option"), optionNameField,
                new Label("Value"), optionValueField, new HBox(10, addButton, closeButton));
        stage.setScene(new Scene(container));
        stage.initOwner(((Button)event.getSource()).getScene().getWindow());
        stage.setAlwaysOnTop(true);
        stage.show();
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
    @FXML
    private void onClickAddInclusionButton(ActionEvent event){
        Stage stage = new Stage(StageStyle.DECORATED);
        TextField keywordField = new TextField("include");
        TextField optionValueField = new TextField();
        VBox container = new VBox(10);
        Button addButton = new Button("Add");
        Button closeButton = new Button("Close");

        addButton.setOnAction(e -> inclusionTableView.getItems().add(new Inclusion(keywordField.getText(), optionValueField.getText())));

        closeButton.setOnAction(value -> ((Stage)((Node)value.getSource()).getScene().getWindow()).close());

        // it's better not to close this window because.. if you want to add multiple variables?
        keywordField.setEditable(false);
        container.setPadding(new Insets(10));
        container.getChildren().addAll(new Label("Keyword"), keywordField, new Label("Value"), optionValueField,
                new HBox(10, addButton, closeButton));
        stage.setScene(new Scene(container));
        stage.initOwner(((Button)event.getSource()).getScene().getWindow());
        stage.setAlwaysOnTop(true);
        stage.show();
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
    }
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
