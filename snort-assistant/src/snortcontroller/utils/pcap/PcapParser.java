package snortcontroller.utils.pcap;

import net.sourceforge.jpcap.capture.*;
import net.sourceforge.jpcap.net.*;
import net.sourceforge.jpcap.util.Timeval;

import java.io.File;
import java.util.ArrayList;
import java.util.Optional;

public class PcapParser {
	private String pcapFileLocation;
	private File pcapFile;
	
	private final PacketCapture pcapture;
	private final PacketHandler phandler;
	private final RawPacketHandler rphandler;
	private final ArrayList<PcapLog> parsedPackets = new ArrayList<>();

	public PcapParser(String location) {
		pcapFileLocation = location;
		pcapFile = new File(pcapFileLocation);
		pcapture = new PacketCapture();
		// apply default packet handler
		phandler = new PacketHandler();
		rphandler = new RawPacketHandler();
	}

	public void setPcapFileLocation(String location){
		pcapFileLocation = location;
		pcapFile = new File(pcapFileLocation);
	}

	public void setPacketHandler(PacketListener listener){
		pcapture.addPacketListener(listener);
	}

	public void setRawPacketHandler(RawPacketListener listener){
		pcapture.addRawPacketListener(listener);
	}

	public void parse() throws Exception{
		pcapture.openOffline(pcapFileLocation); // throws CaptureFileOpenException
		pcapture.setFilter("", true); // throws InvalidFilterException
		pcapture.addPacketListener(phandler);
		pcapture.addRawPacketListener(rphandler);
		pcapture.capture((int) Double.POSITIVE_INFINITY); // throws CapturePacketException
	}

	public ArrayList<PcapLog> getParsedPackets(){
		return parsedPackets;
	}
	
	class PacketHandler implements PacketListener 
	{
		public void packetArrived(Packet packet) {
			Optional<PcapLog> parsedPacket = Optional.empty();
			if (packet.getClass() == ARPPacket.class) {
				ARPPacket arpPacket = (ARPPacket)packet;
				parsedPacket = Optional.of(new PcapLog("-", arpPacket.getSourceHwAddress(), "-",
						"-", arpPacket.getDestinationHwAddress(), "-", "ARP", packet.getTimeval()));
			}
			else if (packet.getClass() == EthernetPacket.class){
				EthernetPacket ethernetPacket = (EthernetPacket)packet;
				parsedPacket = Optional.of(new PcapLog("-", ethernetPacket.getSourceHwAddress(), "-", "-",
						ethernetPacket.getDestinationHwAddress(), "-", "ETHERNET", packet.getTimeval()));
			}
			else if (packet.getClass() == ICMPPacket.class) {
				ICMPPacket icmpPacket = (ICMPPacket)packet;
				parsedPacket = Optional.of(new PcapLog(icmpPacket.getSourceAddress(), icmpPacket.getSourceHwAddress(),"-",
						icmpPacket.getDestinationAddress(), icmpPacket.getDestinationHwAddress(),"-", "ICMP", packet.getTimeval()));
			}
			else if (packet.getClass() == IGMPPacket.class){
				IGMPPacket igmpPacket = (IGMPPacket)packet;
				parsedPacket = Optional.of(new PcapLog(igmpPacket.getSourceAddress(), igmpPacket.getSourceHwAddress(), "-",
						igmpPacket.getDestinationAddress(), igmpPacket.getDestinationHwAddress(), "-", "IGMP", packet.getTimeval()));
			}
			else if (packet.getClass() == IPPacket.class) {
				IPPacket ipPacket = (IPPacket)packet;
				parsedPacket = Optional.of(new PcapLog(ipPacket.getSourceAddress(), "-", "-", ipPacket.getDestinationAddress(),
						"-", "-", "IP", packet.getTimeval()));
			}
			else if (packet.getClass() == TCPPacket.class){
				TCPPacket tcpPacket = (TCPPacket)packet;
				parsedPacket = Optional.of(new PcapLog(tcpPacket.getSourceAddress(), tcpPacket.getSourceHwAddress(), String.valueOf(tcpPacket.getSourcePort()),
						tcpPacket.getDestinationAddress(), tcpPacket.getDestinationHwAddress(), String.valueOf(tcpPacket.getDestinationPort()),
						"TCP",packet.getTimeval()));
			}
			else if (packet.getClass() == UDPPacket.class){
				UDPPacket udpPacket = (UDPPacket)packet;
				parsedPacket = Optional.of(new PcapLog(udpPacket.getSourceAddress(), udpPacket.getSourceHwAddress(), String.valueOf(udpPacket.getSourcePort()),
						udpPacket.getDestinationAddress(), udpPacket.getDestinationHwAddress(), String.valueOf(udpPacket.getDestinationPort()),
						"TCP",packet.getTimeval()));
			}
			if (parsedPacket.isPresent()){
				parsedPacket.get().setHeader(packet.getHeader());
				parsedPacket.get().setBody(packet.getData());
				parsedPackets.add(parsedPacket.get());
			}
		  }
	}
	
	static class RawPacketHandler implements RawPacketListener
	{
	  public void rawPacketArrived(RawPacket rawPacket) {
	  	// System.out.println(rawPacket);
	  }
	}

}