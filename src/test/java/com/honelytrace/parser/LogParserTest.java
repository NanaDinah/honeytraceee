package com.honeytrace.parser;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogParserTest {

    // 203.0.113.0/24 is a documentation range, so these are not real attacker IPs.
    private static final String CONNECT_LINE =
            "{\"session\":\"abc123\",\"protocol\":\"ssh\",\"src_ip\":\"203.0.113.7\",\"src_port\":43321,"
                    + "\"eventid\":\"cowrie.session.connect\",\"timestamp\":\"2026-10-08T08:59:37.615939Z\","
                    + "\"message\":\"New connection\"}";

    private static final String LOGIN_LINE =
            "{\"session\":\"abc123\",\"src_ip\":\"203.0.113.7\",\"eventid\":\"cowrie.login.failed\","
                    + "\"username\":\"root\",\"password\":\"123456\",\"timestamp\":\"2026-10-08T08:59:40.000000Z\","
                    + "\"someNewField\":\"ignored\"}";

    @Test
    void parsesConnectEvent() {
        Optional<CowrieEvent> parsed = LogParser.parseLine(CONNECT_LINE);

        assertTrue(parsed.isPresent());
        CowrieEvent event = parsed.get();
        assertEquals("cowrie.session.connect", event.eventId());
        assertEquals("203.0.113.7", event.srcIp());
        assertEquals(43321, event.srcPort());
        assertNotNull(event.time());
    }

    @Test
    void parsesLoginEventAndIgnoresUnknownFields() {
        CowrieEvent event = LogParser.parseLine(LOGIN_LINE).orElseThrow();

        assertEquals("cowrie.login.failed", event.eventId());
        assertEquals("root", event.username());
        assertEquals("123456", event.password());
    }

    @Test
    void skipsMalformedAndBlankLines() {
        assertTrue(LogParser.parseLine("{not valid json").isEmpty());
        assertTrue(LogParser.parseLine("").isEmpty());
        assertTrue(LogParser.parseLine("   ").isEmpty());
        assertTrue(LogParser.parseLine(null).isEmpty());
    }

    @Test
    void skipsLinesWithoutEventId() {
        assertTrue(LogParser.parseLine("{\"src_ip\":\"203.0.113.7\"}").isEmpty());
    }

    @Test
    void badTimestampGivesNullTime() {
        String line = "{\"eventid\":\"cowrie.session.connect\",\"timestamp\":\"not-a-date\"}";
        assertNull(LogParser.parseLine(line).orElseThrow().time());
    }
}