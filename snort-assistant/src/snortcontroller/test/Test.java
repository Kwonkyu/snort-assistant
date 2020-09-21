package snortcontroller.test;

import snortcontroller.utils.pcap.PcapLog;
import snortcontroller.utils.pcap.PcapParser;
import snortcontroller.utils.rules.Rule;
import snortcontroller.utils.rules.RuleParser;

import java.util.ArrayList;

public class Test {
    private PcapParser pcapParser;
    private RuleParser ruleParser;

    public Test(){
        pcapParser = new PcapParser("/home/kwonkyu/Documents/snortlog.pcap");
        ruleParser = new RuleParser("/home/kwonkyu/Documents/community-icmp.rules");
    }

    public void test(){
        /*
        try {
            pcapParser.parse();
            ArrayList<PcapLog> parsedPackets = pcapParser.getParsedPackets();
            for(PcapLog pcapLog: parsedPackets){
                System.out.println(pcapLog);
            }

            ruleParser.parse();
            ArrayList<Rule> parsedRules = ruleParser.getParsedRules();
            for(Rule rule: parsedRules){
                System.out.println(rule);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        */
    }
}
