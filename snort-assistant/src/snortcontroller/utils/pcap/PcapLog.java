package snortcontroller.utils.pcap;

// This class holds information of each log in pcap.
public class PcapLog {
    private byte[] header;
    private byte[] body;

    private String sourceAddress;
    private String sourceHwAddress;
    private int sourcePort;
    private String destinationAddress;
    private String destinationHwAddress;

    public PcapLog(){

    }

    public PcapLog(byte[] header, byte[] body){
        this.header = header;
        this.body = body;
    }

    public PcapLog(String sourceAddress, String sourceHwAddress, int sourcePort, String destinationAddress, String destinationHwAddress, int destinationPort) {
        this.sourceAddress = sourceAddress;
        this.sourceHwAddress = sourceHwAddress;
        this.sourcePort = sourcePort;
        this.destinationAddress = destinationAddress;
        this.destinationHwAddress = destinationHwAddress;
        this.destinationPort = destinationPort;
    }

    public String getSourceAddress() {
        return sourceAddress;
    }

    public void setSourceAddress(String sourceAddress) {
        this.sourceAddress = sourceAddress;
    }

    public String getSourceHwAddress() {
        return sourceHwAddress;
    }

    public void setSourceHwAddress(String sourceHwAddress) {
        this.sourceHwAddress = sourceHwAddress;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(int sourcePort) {
        this.sourcePort = sourcePort;
    }

    public String getDestinationAddress() {
        return destinationAddress;
    }

    public void setDestinationAddress(String destinationAddress) {
        this.destinationAddress = destinationAddress;
    }

    public String getDestinationHwAddress() {
        return destinationHwAddress;
    }

    public void setDestinationHwAddress(String destinationHwAddress) {
        this.destinationHwAddress = destinationHwAddress;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    public void setDestinationPort(int destinationPort) {
        this.destinationPort = destinationPort;
    }

    private int destinationPort;
}
