package snortcontroller.utils.pcap;

import net.sourceforge.jpcap.capture.*;
import net.sourceforge.jpcap.net.*;

import java.io.File;
import java.util.ArrayList;

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
//		pcap.capture(4);
	}

	public ArrayList<PcapLog> getParsedPackets(){
		return parsedPackets;
	}
	
	class PacketHandler implements PacketListener 
	{
	  public void packetArrived(Packet packet) {
	    if (packet.getClass() == ICMPPacket.class) {
			// PacketInformationPrinter.icmpPacketInfo(packet);
			ICMPPacket icmpPacket = (ICMPPacket)packet;
			parsedPackets.add(new PcapLog(icmpPacket.getSourceAddress(), icmpPacket.getSourceHwAddress(),-1,
					icmpPacket.getDestinationAddress(), icmpPacket.getDestinationHwAddress(),-1, packet.getTimeval()));
	    }
	    else if(packet.getClass() == ARPPacket.class) {
			// PacketInformationPrinter.arpPacketInfo(packet);
		}
	  }
	}
	
	class RawPacketHandler implements RawPacketListener 
	{
	  public void rawPacketArrived(RawPacket rawPacket) {
	    System.out.println(rawPacket);
	  }

	  String name;
	}

}