package com.honeytrace.detection;

import java.util.List;

/** The rules the analysis runs. Add new rules here so Main never needs to change. */
public final class RuleSet {

    private RuleSet() {
    }

    public static List<DetectionRule> defaults() {
        return List.of(
                new SystemDiscoveryRule(),
                new DefaultAccountLoginRule(),
                new FileUploadRule(),
                new ScriptStagingRule(),
                new NetworkDiscoveryRule());
    }
}