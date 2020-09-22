package snortcontroller.main;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.geometry.Insets;
import javafx.geometry.Orientation;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.control.cell.TextFieldTableCell;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.util.Callback;
import snortcontroller.utils.SingleThreadExecutorSingleton;
import snortcontroller.utils.rules.Rule;
import snortcontroller.utils.rules.RuleParser;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ExecutorService;

import static snortcontroller.utils.UserInteractions.*;

public class RuleParserController implements Initializable {
    // top toolbar components
    @FXML
    ToolBar topToolBar;
    @FXML
    TextField ruleFilePathTextField;
    @FXML
    Button findButton;
    @FXML
    Button openButton;

    // main components
    @FXML
    TableView<Rule> ruleTableView;

    // bottom toolbar components
    @FXML
    ToolBar bottomToolBar;
    @FXML
    Button saveButton;
    @FXML
    Button resetButton;

    RuleParser ruleParser;
    ArrayList<Rule> rules;
    ArrayList<Rule> editedRules;

    ExecutorService service = SingleThreadExecutorSingleton.getService();

    File ruleFile;
    final FileChooser fileChooser = new FileChooser();
    FileChooser.ExtensionFilter anyFilter = new FileChooser.ExtensionFilter("any file", "*");
    FileChooser.ExtensionFilter ruleFilter = new FileChooser.ExtensionFilter("snort rules", "*.rules");

    ContextMenu cellContextMenu;

    TableColumn<Rule, String> actionColumn;
    TableColumn<Rule, String> protocolColumn;
    TableColumn<Rule, String> sourceAddressColumn;
    TableColumn<Rule, String> sourcePortColumn;
    TableColumn<Rule, String> directionColumn;
    TableColumn<Rule, String> destinationAddressColumn;
    TableColumn<Rule, String> destinationPortColumn;
    TableColumn<Rule, String> optionBodyColumn;

    Stage optionBodyWindow = new Stage(StageStyle.DECORATED);
    VBox dialogContainer = new VBox(10);

    @FXML
    private void onClickFindButton(ActionEvent event){
        if (ruleFile != null){ // already opened log file
            fileChooser.setInitialDirectory(new File(ruleFile.getParent()));
        }
        File selectedFile = fileChooser.showOpenDialog(((Node)event.getSource()).getScene().getWindow());
        if (selectedFile != null){
            ruleFile = selectedFile;
            ruleFilePathTextField.setText(ruleFile.getAbsolutePath());
        }
    }

    @FXML
    private void onClickOpenButton(){
        if (ruleFilePathTextField.getText().isBlank() || ruleFile == null){
            showAlert(Alert.AlertType.ERROR, "Please specify rule files location");
            return;
        }

        if(!ruleFile.canRead()){
            showAlert(Alert.AlertType.ERROR, String.format("Cannot read specified rule file(%s). Try as root", ruleFilePathTextField.getText()));
            return;
        }

        ruleParser = new RuleParser(ruleFilePathTextField.getText());
        topToolBar.getItems().forEach(node -> node.setDisable(true));
        bottomToolBar.getItems().forEach(node -> node.setDisable(true));
        ruleTableView.setDisable(true);

        Runnable openFile = () -> {
            // TODO: visual element(loading circle?) to let user know program is loading rules
            try {
                ruleParser.parse();
                rules = ruleParser.getParsedRules();
                editedRules.clear();
                rules.forEach(rule -> editedRules.add(rule.copy()));
            } catch (Exception e) {
                e.printStackTrace();
            }
            ruleTableView.setItems(FXCollections.observableArrayList(editedRules));

            Platform.runLater(() -> {
                topToolBar.getItems().forEach(node -> node.setDisable(false));
                bottomToolBar.getItems().forEach(node -> node.setDisable(false));
                ruleTableView.setDisable(false);
            });
        };
        service.submit(openFile);
    }

    @FXML
    private void onClickSaveButton(ActionEvent event){
        if (ruleFile != null){ // already opened log file
            fileChooser.setInitialDirectory(new File(ruleFile.getParent()));
        }
        // TODO: give window parameter to block events. apply to PcapParser later.
        Optional<File> selectedFile = Optional.ofNullable(fileChooser.showSaveDialog(((Node)event.getSource()).getScene().getWindow()));
        if(selectedFile.isPresent()) {
            try {
                File writeFile = selectedFile.get();
                BufferedWriter writer = new BufferedWriter(new FileWriter(writeFile));
                writer.write(String.format("# This rule file is saved at %s\n", java.time.LocalDateTime.now()));
                for (Rule rule : editedRules) {
                    writer.write(String.format("%s %s %s %s %s %s %s (", rule.getRuleAction(), rule.getRuleProtocol(),
                            rule.getRuleSourceAddress(), rule.getRuleSourcePort(), rule.getRuleDirection(),
                            rule.getRuleDestinationAddress(), rule.getRuleDestinationPort()));
                    var bodyElementEntries = rule.getRuleBodyElements().entrySet();
                    for(var elementEntry: bodyElementEntries){
                        if(elementEntry.getValue().isBlank()){
                            writer.write(String.format("%s; ", elementEntry.getKey()));
                        } else {
                            writer.write(String.format("%s:%s; ", elementEntry.getKey(), elementEntry.getValue()));
                        }
                    }
                    writer.write(")\n");
                }
                writer.close();
                if(!writeFile.getName().contains(".rules")){
                    if(!writeFile.renameTo(new File(String.format("%s.rules", writeFile.getAbsolutePath())))){
                        showAlert(Alert.AlertType.INFORMATION, "Unable to append extension(.rules) to file");
                    }
                }
            } catch (IOException e) {
                showAlert(Alert.AlertType.ERROR, "Unable to write file!");
            }
        } else {
            System.err.println("Unable to create save file");
        }
    }

    @FXML
    private void onClickResetButton(){
        editedRules.clear();
        rules.forEach(rule -> editedRules.add(rule.copy()));
        ruleTableView.setItems(FXCollections.observableArrayList(editedRules));
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        // initialize container for storing edited rules
        editedRules = new ArrayList<>();

        // initialize window which will show option body elements.
        optionBodyWindow.initModality(Modality.APPLICATION_MODAL);
        optionBodyWindow.initOwner(null);
        optionBodyWindow.setAlwaysOnTop(true);
        dialogContainer.setPadding(new Insets(10.0, 10.0, 10.0, 10.0));
        dialogContainer.alignmentProperty().set(Pos.CENTER_LEFT);
        optionBodyWindow.setScene(new Scene(new ScrollPane(dialogContainer)));

        // initialize context menu for tableview
        cellContextMenu = new ContextMenu();
        MenuItem itemAddRow = new MenuItem("Add new row");
        MenuItem itemDeleteRow = new MenuItem("Delete this row");
        itemAddRow.setOnAction(onClickContextMenuAdd);
        itemDeleteRow.setOnAction(onClickContextMenuDelete);
        cellContextMenu.getItems().addAll(itemAddRow, itemDeleteRow);

        // set filter to file chooser
        fileChooser.getExtensionFilters().addAll(ruleFilter, anyFilter);
        File ruleDir = new File("/etc/snort/rules");
        if(ruleDir.exists()) fileChooser.setInitialDirectory(ruleDir);

        // initialize table columns
        actionColumn = new TableColumn<>("Action");
        protocolColumn = new TableColumn<>("Protocol");
        sourceAddressColumn = new TableColumn<>("Source Address");
        sourcePortColumn = new TableColumn<>("Port");
        directionColumn = new TableColumn<>("Direction");
        destinationAddressColumn = new TableColumn<>("Destination Address");
        destinationPortColumn = new TableColumn<>("Port");
        optionBodyColumn = new TableColumn<>("Body");

        actionColumn.setMinWidth(80.0);
        protocolColumn.setMinWidth(80.0);
        sourceAddressColumn.setMinWidth(150.0);
        sourcePortColumn.setMinWidth(50.0);
        directionColumn.setMinWidth(80.0);
        destinationAddressColumn.setMinWidth(175.0);
        destinationPortColumn.setMinWidth(50.0);
        optionBodyColumn.setMinWidth(120.0);

        // read values from pcap log.
        actionColumn.setCellValueFactory(new PropertyValueFactory<>("ruleAction"));
        protocolColumn.setCellValueFactory(new PropertyValueFactory<>("ruleProtocol"));
        sourceAddressColumn.setCellValueFactory(new PropertyValueFactory<>("ruleSourceAddress"));
        sourcePortColumn.setCellValueFactory(new PropertyValueFactory<>("ruleSourcePort"));
        directionColumn.setCellValueFactory(new PropertyValueFactory<>("ruleDirection"));
        destinationAddressColumn.setCellValueFactory(new PropertyValueFactory<>("ruleDestinationAddress"));
        destinationPortColumn.setCellValueFactory(new PropertyValueFactory<>("ruleDestinationPort"));

        actionColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        protocolColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        sourceAddressColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        sourcePortColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        directionColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        destinationAddressColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        destinationPortColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        optionBodyColumn.setCellFactory(cellOptionBodyButtonFactory);

        actionColumn.setOnEditCommit(onActionCellEditCommit);
        protocolColumn.setOnEditCommit(onProtocolCellEditCommit);
        sourceAddressColumn.setOnEditCommit(onSourceAddressCellEditCommit);
        sourcePortColumn.setOnEditCommit(onSourcePortCellEditCommit);
        directionColumn.setOnEditCommit(onDirectionCellEditCommit);
        destinationAddressColumn.setOnEditCommit(onDestinationAddressCellEditCommit);
        destinationPortColumn.setOnEditCommit(onDestinationPortCellEditCommit);

        // add columns to table and make it editable.
        ruleTableView.getColumns().addAll(actionColumn, protocolColumn, sourceAddressColumn, sourcePortColumn,
                directionColumn, destinationAddressColumn, destinationPortColumn, optionBodyColumn);
        // wait, wtf? you don't have to implement cell value factory with context menu! dang it.
        ruleTableView.setContextMenu(cellContextMenu);
        ruleTableView.itemsProperty().addListener(observable -> ruleTableView.refresh());
    }

    Callback<TableColumn<Rule, String>, TableCell<Rule, String>> cellOptionBodyButtonFactory = new Callback<>() {
        @Override
        public TableCell<Rule, String> call(TableColumn<Rule, String> param) {
            return new TextFieldTableCell<>() {
                final Button btn = new Button("Option Body");

                @Override
                public void updateItem(String item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty) {
                        setGraphic(null);
                    } else {
                        btn.setOnAction(event -> {
                            // TODO: somewhere around here.. add and delete element button
                            Rule rule = this.getTableRow().getItem();
                            Map<String, String> ruleBodyElements = rule.getRuleBodyElements();
                            dialogContainer.getChildren().clear();
                            ruleBodyElements.forEach((key, value) -> {
                                Label optionName = new Label(key);
                                TextField optionValue = new TextField(value);
                                Button removeOption = new Button("-");
                                HBox container = new HBox(optionName, optionValue, removeOption);

                                optionName.setMinWidth(80.0);
                                optionValue.setMinWidth(300.0);
                                HBox.setHgrow(optionName, Priority.ALWAYS);
                                HBox.setHgrow(optionValue, Priority.ALWAYS);
                                container.alignmentProperty().set(Pos.CENTER_LEFT);
                                removeOption.setOnAction(e -> dialogContainer.getChildren().remove(container));

                                dialogContainer.getChildren().add(container);
                            });

                            Button addElementButton = new Button("+");
                            addElementButton.setOnAction(value -> {
                                // two text field for option name, value each.
                                TextField optionName = new TextField();
                                optionName.setId("OptionName");
                                TextField optionValue = new TextField();
                                optionValue.setId("OptionValue");
                                Button removeOption = new Button("-");
                                HBox container = new HBox(10, optionName, optionValue, removeOption);

                                optionName.setMinWidth(30.0);
                                optionValue.setMinWidth(300.0);
                                HBox.setHgrow(optionName, Priority.ALWAYS);
                                HBox.setHgrow(optionValue, Priority.ALWAYS);
                                container.alignmentProperty().set(Pos.CENTER_LEFT);
                                removeOption.setOnAction(e -> dialogContainer.getChildren().remove(container));

                                int position = -1;
                                for(var node: dialogContainer.getChildren()){
                                    if (node instanceof Separator){
                                        position = dialogContainer.getChildren().lastIndexOf(node);
                                    }
                                }
                                if (position > -1){
                                    container.setId("AddedElement");
                                    dialogContainer.getChildren().add(position-1, container);
                                }
                            });

                            Button saveOptionButton = new Button("Save");
                            saveOptionButton.setOnAction(value -> {
                                Map<String, String> newRuleBodyElements = new HashMap<>();
                                dialogContainer.getChildren().forEach(container -> {
                                    Optional<String> optionName = Optional.empty();
                                    Optional<String> optionValue = Optional.empty();
                                    if(!(container instanceof HBox)) return;
                                    for(Node node: ((HBox)container).getChildren()) {
                                        Optional<String> containerID = Optional.ofNullable(container.getId());
                                        if(containerID.orElse("ExistingElement").equals("AddedElement")){
                                            // handle conditions when option name and value is empty. ';' should not be written.
                                            Optional<String> nodeID = Optional.ofNullable(node.getId());
                                            if(nodeID.orElse("ExistingOptionName").equals("OptionName")){
                                                optionName = Optional.ofNullable(((TextField)node).getText());
                                            } else if(nodeID.orElse("ExistingOptionValue").equals("OptionValue")){
                                                optionValue = Optional.ofNullable(((TextField)node).getText());
                                            }
                                        } else {
                                            if(node instanceof Label) {
                                                optionName = Optional.of(((Label)node).getText());
                                            } else if(node instanceof TextField) {
                                                optionValue = Optional.of(((TextField) node).getText());
                                            }
                                        }
                                    }
                                    // option name and values from buttons(which are also in hbox container) are empty.
                                    //if(optionName.isPresent() && optionName.get().length() > 0 &&
                                    //    optionValue.isPresent() && optionValue.get().length() > 0){
                                    if(optionName.isPresent() && optionName.get().length() > 0){
                                        newRuleBodyElements.put(optionName.get(), optionValue.orElse(""));
                                    }
                                });
                                rule.setRuleBodyElements(newRuleBodyElements);
                                ((Stage)((Node)value.getSource()).getScene().getWindow()).close();
                            });

                            Button closeButton = new Button("Close");
                            closeButton.setOnAction(value -> ((Stage)((Node)value.getSource()).getScene().getWindow()).close());

                            dialogContainer.getChildren().add(new HBox(10, addElementButton));
                            dialogContainer.getChildren().add(new Separator(Orientation.HORIZONTAL));
                            dialogContainer.getChildren().add(new HBox(10, saveOptionButton, closeButton));
                            optionBodyWindow.show();
                        });
                        setGraphic(btn);
                    }
                    setText(null);
                }
            };
        }
    };

    EventHandler<TableColumn.CellEditEvent<Rule, String>> onActionCellEditCommit = event -> {
        Rule editedRule = event.getTableView().getItems().get(event.getTablePosition().getRow());
        editedRule.setRuleAction(event.getNewValue());
    };

    EventHandler<TableColumn.CellEditEvent<Rule, String>> onProtocolCellEditCommit = event -> {
        Rule editedRule = event.getTableView().getItems().get(event.getTablePosition().getRow());
        editedRule.setRuleProtocol(event.getNewValue());
    };

    EventHandler<TableColumn.CellEditEvent<Rule, String>> onSourceAddressCellEditCommit = event -> {
        Rule editedRule = event.getTableView().getItems().get(event.getTablePosition().getRow());
        editedRule.setRuleSourceAddress(event.getNewValue());
    };

    EventHandler<TableColumn.CellEditEvent<Rule, String>> onSourcePortCellEditCommit = event -> {
        Rule editedRule = event.getTableView().getItems().get(event.getTablePosition().getRow());
        editedRule.setRuleSourcePort(event.getNewValue());
    };

    EventHandler<TableColumn.CellEditEvent<Rule, String>> onDirectionCellEditCommit = event -> {
        Rule editedRule = event.getTableView().getItems().get(event.getTablePosition().getRow());
        editedRule.setRuleDirection(event.getNewValue());
    };

    EventHandler<TableColumn.CellEditEvent<Rule, String>> onDestinationAddressCellEditCommit = event -> {
        Rule editedRule = event.getTableView().getItems().get(event.getTablePosition().getRow());
        editedRule.setRuleDestinationAddress(event.getNewValue());
    };

    EventHandler<TableColumn.CellEditEvent<Rule, String>> onDestinationPortCellEditCommit = event -> {
        Rule editedRule = event.getTableView().getItems().get(event.getTablePosition().getRow());
        editedRule.setRuleDestinationPort(event.getNewValue());
    };

    EventHandler<ActionEvent> onClickContextMenuAdd = new EventHandler<ActionEvent>() {

        // TODO: here!
        @Override
        public void handle(ActionEvent event) {
            Rule newRule = new Rule("alert", "tcp", "$HOME_NET", "80",
                    "->", "$EXTERNAL_NET", "any", new HashMap<>());
            editedRules.add(newRule);
            ruleTableView.getItems().add(newRule);
            ruleTableView.refresh();
        }
    };

    EventHandler<ActionEvent> onClickContextMenuDelete = new EventHandler<>() {
        @Override
        public void handle(ActionEvent event) {
            // TODO: apply selection model to pcap parser
            Rule data = ruleTableView.getSelectionModel().getSelectedItem();
            if (showAlert(Alert.AlertType.CONFIRMATION, "Delete this rule?", ButtonType.YES, ButtonType.NO).orElse(ButtonType.OK) == ButtonType.YES) {
                // TODO: maybe i can bind these?
                ruleTableView.getItems().remove(data);
                editedRules.remove(data);
            }
        }
    };
}
