package com.honeytrace.detection;

import com.honeytrace.parser.CowrieEvent;

import java.util.Optional;

/** A single detection rule: looks at one event and may raise an alert. */
public interface DetectionRule {

    /** Short stable id, for example HT-001. */
    String id();

    String name();

    /** MITRE ATT&CK technique id and name. */
    String technique();

    Optional<Alert> evaluate(CowrieEvent event);
}