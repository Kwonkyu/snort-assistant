package snortcontroller.utils.pcap;

import net.sourceforge.jpcap.util.Timeval;

// This class holds information of each log in pcap.
public class PcapLog {
    private byte[] header;
    private byte[] body;

    private String sourceAddress;
    private String sourceHwAddress;
    private int sourcePort;
    private String destinationAddress;
    private String destinationHwAddress;
    private int destinationPort;
    private Timeval timeval;

    public PcapLog(){

    }

    public PcapLog(byte[] header, byte[] body){
        this.header = header;
        this.body = body;
    }

    public PcapLog(String sourceAddress, String sourceHwAddress, int sourcePort,
                   String destinationAddress, String destinationHwAddress, int destinationPort,
                   Timeval timeval) {
        this.sourceAddress = sourceAddress;
        this.sourceHwAddress = sourceHwAddress;
        this.sourcePort = sourcePort;
        this.destinationAddress = destinationAddress;
        this.destinationHwAddress = destinationHwAddress;
        this.destinationPort = destinationPort;
        this.timeval = timeval;
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

    public String getTimeval() {
        return timeval.getDate().toString();
    }

    public void setTimeval(Timeval timeval) { this.timeval = timeval; }

    @Override
    public String toString() {
        // return super.toString();
        return String.format("[PcapLog] %s:%d / %s -> %s:%d / %s",
                sourceAddress, sourcePort, sourceHwAddress, destinationAddress, destinationPort, destinationHwAddress);
    }
}
