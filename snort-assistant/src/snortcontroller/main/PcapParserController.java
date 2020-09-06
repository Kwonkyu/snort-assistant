package snortcontroller.main;

import javafx.collections.FXCollections;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.chart.PieChart;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.stage.FileChooser;
import javafx.util.Callback;
import snortcontroller.utils.pcap.PcapLog;
import snortcontroller.utils.pcap.PcapParser;

import java.io.File;
import java.net.URL;
import java.util.*;
import java.util.stream.Stream;

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

    File pcapFile;
    final FileChooser fileChooser = new FileChooser();
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

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        // Show tooltip on text field.
        pcapFilePathTextField.setTooltip(new Tooltip("The absolute path of pcap log file."));

        // 'Find' button to open file chooser window.
        fileChooser.getExtensionFilters().add(pcapFilter);
        findButton.setOnAction(event -> {
            if (pcapFile != null){ // already opened log file
                fileChooser.setInitialDirectory(new File(pcapFile.getParent()));
            }
            File selectedFile = fileChooser.showOpenDialog(((Node)event.getSource()).getScene().getWindow());
            if (selectedFile != null){
                pcapFile = selectedFile;
                pcapFilePathTextField.setText(pcapFile.getAbsolutePath());
            }
        });

        // 'Open' button to open choosed file.
        openButton.setOnAction(event -> {
            if (pcapFilePathTextField.getText().isBlank()){
                System.err.println("Please specify log file's location.");
                return;
            }
            pcapParser = new PcapParser(pcapFilePathTextField.getText());
            try {
                pcapParser.parse();
                pcapLogs = pcapParser.getParsedPackets();
            } catch (Exception e) {
                System.err.println(e.getLocalizedMessage());
            }

            pcapLogTableView.setItems(FXCollections.observableArrayList(pcapLogs));
            updateChartButton.fire();
        });

        updateChartButton.setOnAction(event -> {
            pcapLogPieChart.getData().clear();
            Map<String, Integer> counter = new HashMap<>();
            if(sourceAddressRadioButton.isSelected()){
                for(PcapLog pcapLog: pcapLogs){
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
            Stream<Map.Entry<String, Integer>> sortedEntries = entries.stream().sorted(Map.Entry.comparingByValue());
            sortedEntries.forEach(stringIntegerEntry -> pcapLogPieChart.getData().add(new PieChart.Data(stringIntegerEntry.getKey(), stringIntegerEntry.getValue())));

        });

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
        payloadColumn.setCellFactory(
                new Callback<>() {
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
                                        // TODO: show payload of packet.
                                        System.out.println("PAYLOAD");
                                    });
                                    setGraphic(btn);
                                }
                                setText(null);
                            }
                        };
                    }
                });


        pcapLogTableView.getColumns().addAll(timevalColumn, sourceAddressColumn, sourceHwAddressColumn, sourcePortColumn,
                destinationAddressColumn, destinationHwAddressColumn, destinationPortColumn, protocolColumn, payloadColumn);

        // TODO: radio button handler
    }
}
