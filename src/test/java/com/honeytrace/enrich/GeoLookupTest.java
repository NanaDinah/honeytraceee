package com.honeytrace.enrich;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GeoLookupTest {

    @Test
    void findsCountryInThreeColumnLayout() {
        GeoLookup geo = GeoLookup.fromLines(List.of(
                "1.0.0.0,1.0.0.255,AU",
                "41.0.0.0,41.0.255.255,ZA"));

        assertEquals("ZA", geo.countryCode("41.0.10.5").orElseThrow());
        assertEquals("AU", geo.countryCode("1.0.0.1").orElseThrow());
    }

    @Test
    void findsCountryInSevenColumnLayoutWithQuotes() {
        GeoLookup geo = GeoLookup.fromLines(List.of(
                "\"8.8.8.0\",\"8.8.8.255\",\"NA\",\"North America\",\"US\",\"0\",\"United States\""));

        assertEquals("US", geo.countryCode("8.8.8.8").orElseThrow());
    }

    @Test
    void skipsHeadersIpv6AndBadLines() {
        GeoLookup geo = GeoLookup.fromLines(List.of(
                "ip_start,ip_end,country",
                "2001:db8::,2001:db8::ffff,XX",
                "not,an,ip",
                "",
                "5.5.5.0,5.5.5.255,DE"));

        assertEquals(1, geo.size());
        assertEquals("DE", geo.countryCode("5.5.5.5").orElseThrow());
    }

    @Test
    void addressOutsideEveryRangeIsUnknown() {
        GeoLookup geo = GeoLookup.fromLines(List.of("10.0.0.0,10.0.0.255,AA", "20.0.0.0,20.0.0.255,BB"));

        assertTrue(geo.countryCode("15.0.0.1").isEmpty());
        assertTrue(geo.countryCode("9.255.255.255").isEmpty());
        assertTrue(geo.countryCode("20.0.1.0").isEmpty());
    }

    @Test
    void rangeEdgesAreInclusive() {
        GeoLookup geo = GeoLookup.fromLines(List.of("10.0.0.0,10.0.0.255,AA"));

        assertTrue(geo.countryCode("10.0.0.0").isPresent());
        assertTrue(geo.countryCode("10.0.0.255").isPresent());
    }

    @Test
    void invalidAddressesAreRejected() {
        GeoLookup geo = GeoLookup.fromLines(List.of("10.0.0.0,10.0.0.255,AA"));

        assertTrue(geo.countryCode("999.1.1.1").isEmpty());
        assertTrue(geo.countryCode("abc").isEmpty());
        assertTrue(geo.countryCode(null).isEmpty());
        assertTrue(GeoLookup.empty().countryCode("10.0.0.1").isEmpty());
    }

    @Test
    void unsortedInputStillWorks() {
        GeoLookup geo = GeoLookup.fromLines(List.of("20.0.0.0,20.0.0.255,BB", "10.0.0.0,10.0.0.255,AA"));

        assertEquals("AA", geo.countryCode("10.0.0.7").orElseThrow());
        assertEquals("BB", geo.countryCode("20.0.0.7").orElseThrow());
    }

    @Test
    void countryNameUsesEnglishNames() {
        assertEquals("South Africa", GeoLookup.countryName("ZA"));
    }
}
