package com.honeytrace.detection;

import com.honeytrace.parser.CowrieEvent;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Base for rules that flag a shell command matching any of a list of patterns.
 * Subclasses only supply the id, name, ATT&CK technique and patterns.
 */
public abstract class CommandPatternRule implements DetectionRule {

    private final String id;
    private final String name;
    private final String technique;
    private final List<Pattern> patterns;

    protected CommandPatternRule(String id, String name, String technique, List<Pattern> patterns) {
        this.id = id;
        this.name = name;
        this.technique = technique;
        this.patterns = List.copyOf(patterns);
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public String technique() {
        return technique;
    }

    @Override
    public Optional<Alert> evaluate(CowrieEvent event) {
        if (!"cowrie.command.input".equals(event.eventId()) || event.input() == null) {
            return Optional.empty();
        }
        boolean hit = patterns.stream().anyMatch(p -> p.matcher(event.input()).find());
        if (!hit) {
            return Optional.empty();
        }
        return Optional.of(new Alert(id, name, technique, event.srcIp(),
                event.session(), event.time(), Alert.clean(event.input())));
    }
}