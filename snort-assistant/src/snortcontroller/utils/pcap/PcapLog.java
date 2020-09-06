package snortcontroller.utils.pcap;

import net.sourceforge.jpcap.util.Timeval;
import snortcontroller.utils.WellKnownPorts;

import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Map;

// This class holds information of each log in pcap.
public class PcapLog {
    private byte[] header;
    private byte[] body;

    private String protocol;
    private String sourceAddress;
    private String sourceHwAddress;
    private String sourcePort;
    private String destinationAddress;
    private String destinationHwAddress;
    private String destinationPort;
    private Timeval timeval;


    public PcapLog(){

    }

    public PcapLog(byte[] header, byte[] body){
        this.header = header;
        this.body = body;
    }

    public PcapLog(String sourceAddress, String sourceHwAddress, String sourcePort,
                   String destinationAddress, String destinationHwAddress, String destinationPort, String protocol,
                   Timeval timeval) {
        this.sourceAddress = sourceAddress;
        this.sourceHwAddress = sourceHwAddress;
        this.sourcePort = sourcePort;
        this.destinationAddress = destinationAddress;
        this.destinationHwAddress = destinationHwAddress;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.timeval = timeval;
    }

    public byte[] getHeader() {
        return header;
    }

    public void setHeader(byte[] header) {
        this.header = header;
    }

    public byte[] getBody() {
        return body;
    }

    public void setBody(byte[] body) {
        this.body = body;
    }

    public String getProtocol() { return protocol; }

    public void setProtocol(String protocol) { this.protocol = protocol; }

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

    public String getSourcePort() {
        // return sourcePort;
        if (sourcePort.equals("-")) return "-";;
        return WellKnownPorts.portsMap.getOrDefault(Integer.parseInt(sourcePort), sourcePort);
    }

    public void setSourcePort(String sourcePort) {
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

    public String getDestinationPort() {
        // return destinationPort;
        if (destinationPort.equals("-")) return "-";
        return WellKnownPorts.portsMap.getOrDefault(Integer.parseInt(destinationPort), destinationPort);
    }

    public void setDestinationPort(String destinationPort) {
        this.destinationPort = destinationPort;
    }

    public String getTimeval() {
        SimpleDateFormat format = new SimpleDateFormat("yyyy/MM/dd-HH:mm:ss");
        return format.format(timeval.getDate());
        // return timeval.getDate().toString();
    }

    public void setTimeval(Timeval timeval) { this.timeval = timeval; }

    @Override
    public String toString() {
        // return super.toString();
        return String.format("[PcapLog] %s:%s / %s -> %s:%s / %s",
                sourceAddress, sourcePort, sourceHwAddress, destinationAddress, destinationPort, destinationHwAddress);
    }
}
