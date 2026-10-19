package com.honeytrace.enrich;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Looks up the country of an IPv4 address from a DB-IP "IP to Country Lite" CSV file.
 * No external libraries are needed. Lines that are not IPv4 ranges (headers, IPv6) are skipped.
 *
 * Supported layouts:
 *   first_ip,last_ip,country_code
 *   first_ip,last_ip,continent_code,continent_name,country_code,...
 */
public final class GeoLookup {

    private record Range(long start, long end, String code) {
    }

    private final long[] starts;
    private final long[] ends;
    private final String[] codes;

    private GeoLookup(List<Range> ranges) {
        ranges.sort(Comparator.comparingLong(Range::start));
        starts = new long[ranges.size()];
        ends = new long[ranges.size()];
        codes = new String[ranges.size()];
        for (int i = 0; i < ranges.size(); i++) {
            starts[i] = ranges.get(i).start();
            ends[i] = ranges.get(i).end();
            codes[i] = ranges.get(i).code();
        }
    }

    public static GeoLookup empty() {
        return new GeoLookup(new ArrayList<>());
    }

    public static GeoLookup fromCsv(Path file) throws IOException {
        List<Range> ranges = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(file)) {
            String line;
            while ((line = reader.readLine()) != null) {
                parseLine(line, ranges);
            }
        }
        return new GeoLookup(ranges);
    }

    public static GeoLookup fromLines(List<String> lines) {
        List<Range> ranges = new ArrayList<>();
        lines.forEach(line -> parseLine(line, ranges));
        return new GeoLookup(ranges);
    }

    private static void parseLine(String line, List<Range> out) {
        if (line == null || line.isBlank() || line.startsWith("#") || line.contains(":")) {
            return;
        }
        String[] cols = line.split(",");
        if (cols.length < 3) {
            return;
        }
        for (int i = 0; i < cols.length; i++) {
            cols[i] = cols[i].replace("\"", "").trim();
        }
        long start = ipv4ToLong(cols[0]);
        long end = ipv4ToLong(cols[1]);
        if (start < 0 || end < start) {
            return;
        }
        String code = (cols.length >= 5 ? cols[4] : cols[2]).toUpperCase(Locale.ROOT);
        if (code.length() == 2 && Character.isLetter(code.charAt(0)) && Character.isLetter(code.charAt(1))) {
            out.add(new Range(start, end, code));
        }
    }

    public int size() {
        return starts.length;
    }

    public Optional<String> countryCode(String ip) {
        long value = ipv4ToLong(ip);
        if (value < 0 || starts.length == 0) {
            return Optional.empty();
        }
        int low = 0;
        int high = starts.length - 1;
        int found = -1;
        while (low <= high) {
            int mid = (low + high) >>> 1;
            if (starts[mid] <= value) {
                found = mid;
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }
        if (found >= 0 && value <= ends[found]) {
            return Optional.of(codes[found]);
        }
        return Optional.empty();
    }

    /** English country name for an ISO code, or the code itself if Java does not know it. */
    public static String countryName(String code) {
        String name = Locale.of("", code).getDisplayCountry(Locale.ENGLISH);
        return name.isBlank() ? code : name;
    }

    /** Dotted IPv4 to a number, or -1 if the text is not a valid IPv4 address. */
    static long ipv4ToLong(String ip) {
        if (ip == null) {
            return -1;
        }
        String[] parts = ip.split("\\.", -1);
        if (parts.length != 4) {
            return -1;
        }
        long value = 0;
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return -1;
            }
            int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                return -1;
            }
            if (octet < 0 || octet > 255) {
                return -1;
            }
            value = value * 256 + octet;
        }
        return value;
    }
}
