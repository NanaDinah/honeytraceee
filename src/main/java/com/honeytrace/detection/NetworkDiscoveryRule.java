package com.honeytrace.detection;

import java.util.List;
import java.util.regex.Pattern;

/**
 * HT-005: commands that reveal the machine's network configuration,
 * including RouterOS-style commands used to probe for routers.
 * MITRE ATT&CK T1016 System Network Configuration Discovery.
 */
public class NetworkDiscoveryRule extends CommandPatternRule {

    public NetworkDiscoveryRule() {
        super("HT-005", "Network configuration discovery",
                "T1016 System Network Configuration Discovery",
                List.of(
                        Pattern.compile("\\bifconfig\\b"),
                        Pattern.compile("\\bip\\s+(a|addr|address|route|link)\\b"),
                        Pattern.compile("\\bnetstat\\b"),
                        Pattern.compile("/etc/resolv\\.conf"),
                        Pattern.compile("\\bhostname\\s+-I\\b"),
                        Pattern.compile("^\\s*/(ip|system|interface)\\s")));
    }
}