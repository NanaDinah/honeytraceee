package com.honeytrace.detection;

import com.honeytrace.parser.CowrieEvent;

import java.util.Optional;

/**
 * HT-003: attacker puts a file on the honeypot (SFTP upload, or a wget/curl download).
 * Usually a tool, backdoor or malware being staged. The file is only ever recorded by
 * name and hash; it is never opened or executed.
 * MITRE ATT&CK T1105 Ingress Tool Transfer.
 */
public class FileUploadRule implements DetectionRule {

    @Override
    public String id() {
        return "HT-003";
    }

    @Override
    public String name() {
        return "File transferred to honeypot";
    }

    @Override
    public String technique() {
        return "T1105 Ingress Tool Transfer";
    }

    @Override
    public Optional<Alert> evaluate(CowrieEvent event) {
        String type = event.eventId();
        boolean transfer = "cowrie.session.file_upload".equals(type)
                || "cowrie.session.file_download".equals(type);
        if (!transfer) {
            return Optional.empty();
        }
        String name = event.filename() == null ? "-" : event.filename();
        String hash = event.shasum() == null ? "-" : event.shasum();
        return Optional.of(new Alert(id(), name(), technique(), event.srcIp(),
                event.session(), event.time(), Alert.clean("file=" + name + " sha256=" + hash)));
    }
}