package snortcontroller.test;

import snortcontroller.utils.*;

public class Test {
    private PcapParser pcapParser;
    private RuleParser ruleParser;

    public Test(){
        pcapParser = new PcapParser("/home/kwonkyu/Documents/snortlog.pcap");
        ruleParser = new RuleParser("/home/kwonkyu/Documents/community-icmp.rules");
    }

    public void test(){
        pcapParser.parse();
        ruleParser.parseBody();
    }
}
