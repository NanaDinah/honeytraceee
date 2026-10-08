package com.honeytrace.parser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Reads Cowrie's newline-delimited JSON log.
 * Log content comes from attackers, so every line is treated as untrusted:
 * malformed lines are skipped instead of crashing the run (see threat T5).
 */
public final class LogParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private LogParser() {
    }

    /** Parses one line. Returns empty for blank, malformed, or eventid-less lines. */
    public static Optional<CowrieEvent> parseLine(String line) {
        if (line == null || line.isBlank()) {
            return Optional.empty();
        }
        try {
            CowrieEvent event = MAPPER.readValue(line, CowrieEvent.class);
            return event.eventId() == null ? Optional.empty() : Optional.of(event);
        } catch (JsonProcessingException e) {
            return Optional.empty();
        }
    }

    /** Parses a whole log file, skipping bad lines. */
    public static List<CowrieEvent> parseFile(Path file) throws IOException {
        try (Stream<String> lines = Files.lines(file)) {
            return lines.map(LogParser::parseLine)
                    .flatMap(Optional::stream)
                    .toList();
        }
    }
}