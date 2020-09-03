package snortcontroller.utils;


import net.sourceforge.jpcap.capture.*;
import net.sourceforge.jpcap.net.*;
import net.sourceforge.jpcap.util.HexHelper;

public class PcapParser {
	private String pcapFileLocation;
	
	private PacketCapture pcap;
	private PacketHandler phandler;
	
	byte[] globalHeader = new byte[24];
	
	public PcapParser(String location) {
		pcapFileLocation = location;
		pcap = new PacketCapture();
		phandler = new PacketHandler("OFFLINE");
	}
	
	public void parse() throws Exception{
		pcap.openOffline(pcapFileLocation);
		pcap.setFilter("", true);
		pcap.addPacketListener(phandler);
//		pcap.capture((int) Double.POSITIVE_INFINITY);
		pcap.capture(4);
	}
	
	
	class PacketHandler implements PacketListener 
	{
	  private int counter = 0;

	  public PacketHandler(String name) {
	    this.name = name;
	  }

	  public void packetArrived(Packet packet) {
	    counter++;
	    String type = packet.getClass().getName();
//	    System.out.println(name + ": Packet(" + counter + ") is of type " + type + ".");
//	    System.out.println(HexHelper.toString(packet.getHeader()));
//	    System.out.println(HexHelper.toString(packet.getData()));
	    
	    if (packet.getClass() == ICMPPacket.class) {
	    	ICMPPacket icmpPacket = (ICMPPacket)packet;
	    	System.out.println("From: " + icmpPacket.getSourceAddress() + " / " + icmpPacket.getSourceHwAddress());
	    	System.out.println("To: " + icmpPacket.getDestinationAddress() + " / " + icmpPacket.getDestinationHwAddress());
	    	System.out.println(icmpPacket.toColoredVerboseString(true));
	    }
	    
	    
	    
	  }

	  String name;
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
