package com.honeytrace.parser;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.time.format.DateTimeParseException;

/**
 * One line of Cowrie's cowrie.json output.
 * Unknown fields are ignored so new Cowrie versions don't break parsing.
 * All fields may be null, because different event types carry different fields.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CowrieEvent(
        @JsonProperty("eventid") String eventId,
        @JsonProperty("session") String session,
        @JsonProperty("src_ip") String srcIp,
        @JsonProperty("src_port") Integer srcPort,
        @JsonProperty("timestamp") String timestamp,
        @JsonProperty("username") String username,
        @JsonProperty("password") String password,
        @JsonProperty("input") String input,
        @JsonProperty("message") String message) {

    /** Parsed timestamp, or null if missing or malformed. */
    public Instant time() {
        if (timestamp == null) {
            return null;
        }
        try {
            return Instant.parse(timestamp);
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}