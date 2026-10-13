package com.honeytrace.detection;

import java.time.Instant;

/** One detection hit, tied to a MITRE ATT&CK technique. */
public record Alert(
        String ruleId,
        String ruleName,
        String technique,
        String srcIp,
        String session,
        Instant time,
        String evidence) {

    private static final int MAX_EVIDENCE = 200;

    /**
     * Attacker-supplied text must never be trusted: strip control characters
     * (terminal escape codes, newlines) and cap the length before storing or printing.
     */
    public static String clean(String text) {
        if (text == null) {
            return "";
        }
        String cleaned = text.replaceAll("\\p{Cntrl}", "?");
        return cleaned.length() > MAX_EVIDENCE ? cleaned.substring(0, MAX_EVIDENCE) : cleaned;
    }
}