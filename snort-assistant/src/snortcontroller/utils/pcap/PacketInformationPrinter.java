package snortcontroller.utils.pcap;

import net.sourceforge.jpcap.net.*;
import net.sourceforge.jpcap.util.HexHelper;

class PacketInformationPrinter {
    static public void arpPacketInfo(Packet packet) {
        ARPPacket arpPacket = (ARPPacket) packet;
        System.out.println("From: " + arpPacket.getSourceHwAddress() + " / " + arpPacket.getSourceProtoAddress());
        System.out.println("To: " + arpPacket.getDestinationHwAddress() + " / " + arpPacket.getDestinationProtoAddress());
        System.out.println(arpPacket.toColoredString(true));
    }

    static public void icmpPacketInfo(Packet packet) {
        ICMPPacket icmpPacket = (ICMPPacket) packet;
        System.out.println("From: " + icmpPacket.getSourceAddress() + " / " + icmpPacket.getSourceHwAddress());
        System.out.println("To: " + icmpPacket.getDestinationAddress() + " / " + icmpPacket.getDestinationHwAddress());
        System.out.println(icmpPacket.toColoredVerboseString(true));
    }

    static public void ethernetPacketInfo(Packet packet) {
        EthernetPacket ethernetPacket = (EthernetPacket) packet;
        System.out.println("From: " + ethernetPacket.getSourceHwAddress());
        System.out.println("To: " + ethernetPacket.getDestinationHwAddress());
        System.out.println(ethernetPacket.toColoredString(true));
    }

    static public void ipPacketInfo(Packet packet) {
        IPPacket ipPacket = (IPPacket) packet;
        System.out.println("From: " + ipPacket.getSourceAddress() + " / " + ipPacket.getSourceHwAddress());
        System.out.println("To: " + ipPacket.getDestinationAddress() + " / " + ipPacket.getDestinationHwAddress());
        System.out.println(ipPacket.toColoredVerboseString(true));
    }

    static public void tcpPacketInfo(Packet packet) {
        TCPPacket tcpPacket = (TCPPacket) packet;
        System.out.println("From: " + tcpPacket.getSourceAddress() + " / " + tcpPacket.getSourceHwAddress());
        System.out.println("To: " + tcpPacket.getDestinationAddress() + " / " + tcpPacket.getDestinationHwAddress());
        System.out.println(tcpPacket.toColoredVerboseString(true));
    }

    static public void rawPacketInfo(RawPacket packet) {
        System.out.println(HexHelper.toString(packet.getData()));
        System.out.println(packet.toString());
    }
}
