package snortcontroller.main;

import javafx.collections.FXCollections;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.chart.PieChart;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.MouseButton;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.util.Callback;
import net.sourceforge.jpcap.util.HexHelper;
import snortcontroller.utils.pcap.PcapLog;
import snortcontroller.utils.pcap.PcapParser;

import java.io.File;
import java.net.URL;
import java.util.*;
import java.util.stream.Stream;

import static java.util.Collections.reverseOrder;

public class PcapParserController implements Initializable {
    // Toolbar components.
	@FXML
    TextField pcapFilePathTextField;
	@FXML
    Button findButton;
	@FXML
    Button openButton;
	@FXML
    Button updateChartButton;

	// Main components.
	@FXML
    TableView<PcapLog> pcapLogTableView;
    @FXML
    PieChart pcapLogPieChart;

    // Side components.
    @FXML
    RadioButton sourceAddressRadioButton;
    @FXML
    RadioButton packetTypeRadioButton;
    @FXML
    RadioButton dateRadioButton;
    @FXML
    Spinner<Integer> chartThresholdSpinner;
    @FXML
    Label statisticsLabel;

    File pcapFile;
    final FileChooser fileChooser = new FileChooser();
    FileChooser.ExtensionFilter anyFilter = new FileChooser.ExtensionFilter("any file", "*.*");
    FileChooser.ExtensionFilter pcapFilter = new FileChooser.ExtensionFilter("libpcap formatted log", "*.pcap", "*.pcapng");

    PcapParser pcapParser;
    ArrayList<PcapLog> pcapLogs;

    TableColumn<PcapLog, String> sourceAddressColumn;
    TableColumn<PcapLog, String> sourceHwAddressColumn;
    TableColumn<PcapLog, String> sourcePortColumn;
    TableColumn<PcapLog, String> destinationAddressColumn;
    TableColumn<PcapLog, String> destinationHwAddressColumn;
    TableColumn<PcapLog, String> destinationPortColumn;
    TableColumn<PcapLog, String> timevalColumn;
    TableColumn<PcapLog, String> protocolColumn;
    TableColumn<PcapLog, String> payloadColumn;

    Alert readUnavailableAlert = new Alert(Alert.AlertType.INFORMATION,"You're not able to read this file.");
    Stage dialogWindow = new Stage();
    TextArea headerTextArea, bodyTextArea;
    ContextMenu menu;

    @FXML
    private void onClickFindButton(ActionEvent event){
        if (pcapFile != null){ // already opened log file
            fileChooser.setInitialDirectory(new File(pcapFile.getParent()));
        }
        File selectedFile = fileChooser.showOpenDialog(((Node)event.getSource()).getScene().getWindow());
        if (selectedFile != null){
            pcapFile = selectedFile;
            pcapFilePathTextField.setText(pcapFile.getAbsolutePath());
        }
    }

    @FXML
    private void onClickOpenButton(){
        if (pcapFilePathTextField.getText().isBlank() || pcapFile == null){
            System.err.println("Please specify log file's location.");
            return;
        }

        if(!pcapFile.canRead()){
            readUnavailableAlert.show();
            return;
        }

        pcapParser = new PcapParser(pcapFilePathTextField.getText());

        try {
            pcapParser.parse();
            pcapLogs = pcapParser.getParsedPackets();
        } catch (Exception e) {
            e.printStackTrace();
        }

        pcapLogTableView.setItems(FXCollections.observableArrayList(pcapLogs));
        updateChartButton.fire();
    }

    @FXML
    private void onClickUpdateChartButton(){
        pcapLogPieChart.getData().clear();
        Map<String, Integer> counter = new HashMap<>();
        if(sourceAddressRadioButton.isSelected()){
            for(PcapLog pcapLog: pcapLogs){
                if(pcapLog.getSourceAddress().equals("-")) continue;
                int count = counter.getOrDefault(pcapLog.getSourceAddress(), 0);
                counter.put(pcapLog.getSourceAddress(), count + 1);
            }
        }
        else if(packetTypeRadioButton.isSelected()){
            for(PcapLog pcapLog: pcapLogs){
                int count = counter.getOrDefault(pcapLog.getProtocol(), 0);
                counter.put(pcapLog.getProtocol(), count + 1);
            }
        }
        else if(dateRadioButton.isSelected()){
            for(PcapLog pcapLog: pcapLogs){
                String time = pcapLog.getTimeval().split("-")[0]; // yyyy/MM/dd-HH:mm:ss
                int count = counter.getOrDefault(time, 0);
                counter.put(time, count + 1);
            }
        }
        Set<Map.Entry<String, Integer>> entries = counter.entrySet();
        Stream<Map.Entry<String, Integer>> sortedEntries = entries.stream().sorted(reverseOrder(Map.Entry.comparingByValue())).limit(chartThresholdSpinner.getValue());
        sortedEntries.forEach(stringIntegerEntry -> pcapLogPieChart.getData().add(new PieChart.Data(stringIntegerEntry.getKey(), stringIntegerEntry.getValue())));
    }

    private final EventHandler<ActionEvent> onContextMenuFilter = new EventHandler<ActionEvent>() {
        @Override
        public void handle(ActionEvent event) {
            MenuItem origin = (MenuItem)event.getSource();
            //TableCell<PcapLog, String> origin = (TableCell<PcapLog, String>) event.getSource(); // MenuItem cannot be casted to TableCell.
            //PcapLog pcapLog = origin.getTableRow().getItem();
            //PcapLog pcapLog = (PcapLog)origin.getParentMenu().getUserData();
            // TODO: why I can't access userdata?
            PcapLog pcapLog = (PcapLog)menu.getUserData();
            System.out.println(pcapLog.getSourceAddress() + " is filtered.");

        }
    };

    private final EventHandler<ActionEvent> onContextMenuBlock = new EventHandler<ActionEvent>() {
        @Override
        public void handle(ActionEvent event) {

        }
    };

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        // Popup dialog to show payload
        dialogWindow.initModality(Modality.NONE);
        dialogWindow.initOwner(null);

        VBox headerContainer = new VBox(10);
        headerTextArea = new TextArea();
        headerContainer.getChildren().addAll(new Label("Header"), headerTextArea);

        VBox bodyContainer = new VBox(10);
        bodyTextArea = new TextArea();
        bodyContainer.getChildren().addAll(new Label("Body"), bodyTextArea);

        VBox dialogContainer = new VBox(20);
        dialogContainer.getChildren().addAll(headerContainer, bodyContainer);
        dialogWindow.setScene(new Scene(dialogContainer));

        // Adjust alert windows height to show all texts properly.
        readUnavailableAlert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);

        // 'Find' button to open file chooser window.
        fileChooser.getExtensionFilters().addAll(pcapFilter, anyFilter);

        // Context menu for right click on table cell
        menu = new ContextMenu();
        MenuItem itemFilter = new MenuItem("Filter");
        itemFilter.setOnAction(onContextMenuFilter);
        MenuItem itemBlock = new MenuItem("Block");
        itemBlock.setOnAction(onContextMenuBlock);
        menu.getItems().addAll(itemFilter, itemBlock);

        pcapLogTableView.setEditable(true);
        sourceAddressColumn = new TableColumn<>("Source Address");
        sourceHwAddressColumn = new TableColumn<>("Source MAC Address");
        sourcePortColumn = new TableColumn<>("Source Port");
        destinationAddressColumn = new TableColumn<>("Destination Address");
        destinationHwAddressColumn = new TableColumn<>("Destination MAC Address");
        destinationPortColumn = new TableColumn<>("Destination Port");
        timevalColumn = new TableColumn<>("Time");
        protocolColumn = new TableColumn<>("Protocol");
        payloadColumn = new TableColumn<>("Payload");

        // column layout settings.
        sourceAddressColumn.setMinWidth(150.0);
        sourceHwAddressColumn.setMinWidth(200.0);
        sourcePortColumn.setMinWidth(100.0);
        destinationAddressColumn.setMinWidth(175.0);
        destinationHwAddressColumn.setMinWidth(200.0);
        destinationPortColumn.setMinWidth(150.0);
        timevalColumn.setMinWidth(150.0);
        protocolColumn.setMinWidth(80.0);
        payloadColumn.setMinWidth(80.0);

        // read values from pcap log.
        sourceAddressColumn.setCellValueFactory(new PropertyValueFactory<>("sourceAddress"));
        sourceHwAddressColumn.setCellValueFactory(new PropertyValueFactory<>("sourceHwAddress"));
        sourcePortColumn.setCellValueFactory(new PropertyValueFactory<>("sourcePort"));
        destinationAddressColumn.setCellValueFactory(new PropertyValueFactory<>("destinationAddress"));
        destinationHwAddressColumn.setCellValueFactory(new PropertyValueFactory<>("destinationHwAddress"));
        destinationPortColumn.setCellValueFactory(new PropertyValueFactory<>("destinationPort"));
        timevalColumn.setCellValueFactory(new PropertyValueFactory<>("timeval"));
        protocolColumn.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        payloadColumn.setCellFactory(cellPayloadButtonFactory);

        // apply context menu factory to columns which has address to block or filter
        sourceAddressColumn.setCellFactory(cellContextMenuFactory);
        sourceHwAddressColumn.setCellFactory(cellContextMenuFactory);
        destinationAddressColumn.setCellFactory(cellContextMenuFactory);
        destinationHwAddressColumn.setCellFactory(cellContextMenuFactory);
        protocolColumn.setCellFactory(cellContextMenuFactory);

        pcapLogTableView.getColumns().addAll(timevalColumn, sourceAddressColumn, sourceHwAddressColumn, sourcePortColumn,
                destinationAddressColumn, destinationHwAddressColumn, destinationPortColumn, protocolColumn, payloadColumn);


        // PieChart threshold spinner initialization.
        chartThresholdSpinner.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(1, Integer.MAX_VALUE));
        chartThresholdSpinner.increment(9); // set initial value to 10.
    }


    Callback<TableColumn<PcapLog, String>, TableCell<PcapLog, String>> cellPayloadButtonFactory = new Callback<>() {
        @Override
        public TableCell<PcapLog, String> call(TableColumn<PcapLog, String> param) {
            return new TableCell<>() {
                final Button btn = new Button("Payload");

                @Override
                public void updateItem(String item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty) {
                        setGraphic(null);
                    } else {
                        btn.setOnAction(event -> {
                            PcapLog payloadPcap = this.getTableRow().getItem();
                            String[] headerHexText = HexHelper.toString(payloadPcap.getHeader()).split(" ");
                            String[] bodyHexText = HexHelper.toString(payloadPcap.getBody()).split(" ");

                            StringBuilder editedHeaderHexText = new StringBuilder();
                            StringBuilder editedBodyHexText = new StringBuilder();

                            int counter = 0;
                            for(String text: headerHexText){
                                editedHeaderHexText.append(text).append(" ");
                                counter++;
                                if(counter == 8) {
                                    editedHeaderHexText.append(" ");
                                }
                                if(counter == 16){
                                    editedHeaderHexText.append("\n");
                                    counter = 0;
                                }
                            }

                            counter = 0;
                            for(String text: bodyHexText){
                                editedBodyHexText.append(text).append(" ");
                                counter++;
                                if(counter == 8) {
                                    editedBodyHexText.append(" ");
                                }
                                if(counter == 16){
                                    editedBodyHexText.append("\n");
                                    counter = 0;
                                }
                            }

                            headerTextArea.setText(editedHeaderHexText.toString());
                            bodyTextArea.setText(editedBodyHexText.toString());
                            dialogWindow.show();

                            //Popup popup = new Popup();
                            //popup.getContent().add(null);
                            //popup.show(((Node)event.getSource()).getScene().getWindow());
                        });
                        setGraphic(btn);
                    }
                    setText(null);
                }
            };
        }
    };

    Callback<TableColumn<PcapLog, String>, TableCell<PcapLog, String>> cellContextMenuFactory = new Callback<>() {
        @Override
        public TableCell<PcapLog, String> call(TableColumn<PcapLog, String> param) {
            TableCell<PcapLog, String> tableCell = new TableCell<>(){
                @Override
                protected void updateItem(String item, boolean empty) {
                    super.updateItem(item, empty);
                    if (item != null){
                        setText(item);
                    }
                }
            };

            tableCell.setOnMouseClicked(event -> {
                if(event.getButton() == MouseButton.SECONDARY){
                    // TODO: maybe something here to set user data.
                    menu.setUserData(tableCell.getTableRow().getItem());
                    menu.show(((Node)event.getSource()).getScene().getWindow(), event.getScreenX(), event.getScreenY());
                }
            });
            return tableCell;
        }
    };
}
