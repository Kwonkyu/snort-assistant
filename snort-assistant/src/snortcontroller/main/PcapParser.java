package snortcontroller.main;


import net.sourceforge.jpcap.capture.CaptureFileOpenException;
import net.sourceforge.jpcap.capture.PacketCapture;

public class PcapParser {
	byte[] globalHeader = new byte[24];
	
	public PcapParser(String location) {
		PacketCapture pcap = new PacketCapture();
		try {
			pcap.openOffline(location);
		} catch (CaptureFileOpenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
