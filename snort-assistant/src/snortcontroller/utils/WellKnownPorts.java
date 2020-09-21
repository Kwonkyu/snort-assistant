package snortcontroller.utils;

import java.util.HashMap;
import java.util.Map;

public class WellKnownPorts {
    public static Map<Integer, String> portsMap = new HashMap<>();
    static {
        portsMap.put(7, "Echo");
        portsMap.put(19, "CHARGEN");
        portsMap.put(20, "FTP-Data");
        portsMap.put(21, "FTP-Control");
        portsMap.put(22, "SSH");
        portsMap.put(25, "SMTP");
        portsMap.put(53, "DNS");
        portsMap.put(69, "TFTP");
        portsMap.put(70, "Gopher");
        portsMap.put(80, "HTTP");
        portsMap.put(110, "POP3");
        portsMap.put(123, "NTP");
        portsMap.put(139, "NetBIOS");
        portsMap.put(143, "IMAP4");
        portsMap.put(161, "SNMP-Agent");
        portsMap.put(162, "SNMP-Manager");
        portsMap.put(220, "IMAP3");
        portsMap.put(389, "LDAP");
        portsMap.put(443, "HTTPS");
        portsMap.put(445, "MS-DS");
        portsMap.put(990, "FTPoSSL");
        portsMap.put(992, "TelnetoSSL");
        portsMap.put(993, "IMAP4oSSL");
        portsMap.put(995, "POP3oSSL");
    };
}
