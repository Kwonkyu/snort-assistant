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

	private ArrayList<PcapLog> parsedPackets = new ArrayList<>();

	public PcapParser(String location) {
		pcapFileLocation = location;
		pcapFile = new File(pcapFileLocation);
		pcapture = new PacketCapture();
		// apply default packet handler
		phandler = new PacketHandler(pcapFile.getName());
		rphandler = new RawPacketHandler(pcapFile.getName());
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
	  private int counter = 0;
	  private String name;
	  
	  public PacketHandler(String name) {
	    this.name = name;
	  }

	  public void packetArrived(Packet packet) {
	    counter++;
	    String type = packet.getClass().getName();
	    System.out.printf("(%s) Packet #%d: %s%n%n", this.name, counter, type);

	    if (packet.getClass() == ICMPPacket.class) {
			PacketInformationPrinter.icmpPacketInfo(packet);
			parsedPackets.add(new PcapLog(((ICMPPacket) packet).getSourceAddress(), ((ICMPPacket) packet).getSourceHwAddress(),
					-1, ((ICMPPacket) packet).getDestinationAddress(), ((ICMPPacket) packet).getDestinationHwAddress(), -1));
	    }
	    else if(packet.getClass() == ARPPacket.class) {
			PacketInformationPrinter.arpPacketInfo(packet);
		}
	  }
	}
	
	class RawPacketHandler implements RawPacketListener 
	{
	  private int counter = 0;

	  public RawPacketHandler(String name) {
	    this.name = name;
	  }

	  public void rawPacketArrived(RawPacket rawPacket) {
	    counter++;
	    System.out.println(name + ": Packet(" + counter + 
                ") is of type " + rawPacket.getClass().getName() + ".");
	    System.out.println(rawPacket);
	  }

	  String name;
	}

}