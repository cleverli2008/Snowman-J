package test;

import example.DateTime;
import example.LunarDate;
import org.junit.jupiter.api.Test;
import scheme.IBEET_FTBA;
import scheme.IBEET_FTBA_TypeD;
import utils.Rule;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class test {

    @Test
    void examplesRunDuringMavenTest() {
        // System.out.println("Running example: DateTime.iso8601");
        assertTrue(DateTime.iso8601());
        // System.out.println("Running example: LunarDate.ftba");
        assertTrue(LunarDate.ftba());
    }

    @Test
    void typeAFTBARunsWithWildcardAndTimeIntervalRule() {
        IBEET_FTBA scheme = new IBEET_FTBA();
        List<Map<String, Object>> keys = scheme.setup(5, Rule.dateRule());
        Map<String, Object> pk = keys.get(0);
        Map<String, Object> sk = scheme.keyGen(pk, keys.get(1), "1701110680");

        assertEquals("time interval", ((Rule) pk.get("vectorRule")).vectorName());
        assertEquals("year", ((Rule) pk.get("vectorRule")).meaningOf(0));
        assertEquals("hour", ((Rule) pk.get("vectorRule")).meaningOf(3));

        Map<String, Object> ct = scheme.encrypt(pk, "1701110680", message(), new String[]{"2024", "2", "29", "23", "30"});
        Map<String, Object> td = scheme.trapdoor(pk, sk, new String[]{"2024", "*", "29", "23", "30"});
        Map<String, Object> invalidCt = scheme.encrypt(pk, "1701110680", message(), new String[]{"2023", "2", "29", "23", "30"});
        Map<String, Object> invalidWildcardMonthDayTd = scheme.trapdoor(pk, sk, new String[]{"2023", "*", "*", "23", "30"});
        Map<String, Object> fixedInvalidDateTd = scheme.trapdoor(pk, sk, new String[]{"2023", "2", "29", "23", "30"});

        assertNotNull(ct);
        assertNotNull(td);
        assertNotNull(invalidCt);
        assertNotNull(invalidWildcardMonthDayTd);
        assertNotNull(fixedInvalidDateTd);
        assertTrue((Boolean) scheme.test(pk, ct, td, ct, td));

        String output = captureOutput(() ->
                assertFalse((Boolean) scheme.test(pk, invalidCt, invalidWildcardMonthDayTd, invalidCt, invalidWildcardMonthDayTd))
        );
        System.out.print(output);
        assertTrue((Boolean) scheme.test(pk, invalidCt, fixedInvalidDateTd, invalidCt, fixedInvalidDateTd));
        assertTrue(output.contains("The time interval vector 2023-2-29 23:30 is invalid. [IBEET_FTBA, Error Index:1,2]"));

        Rule.ValidationResult result = ((Rule) pk.get("vectorRule"))
                .validateWildcardMatch(new String[]{"2023", "*", "*", "23", "30"}, new String[]{"2023", "2", "29", "23", "30"});
        assertFalse(result.isValid());
        assertTrue(result.errors().get(0).contains("index 1 [month]"));
        assertTrue(result.errors().get(0).contains("The time interval vector 2023-2-29 23:30 is invalid."));
        assertTrue(result.errors().get(1).contains("index 2 [day]"));
        assertTrue(result.errors().get(1).contains("The time interval vector 2023-2-29 23:30 is invalid."));

        Rule.ValidationResult invalidHour = ((Rule) pk.get("vectorRule"))
                .validateWildcardMatch(new String[]{"2024", "2", "29", "*", "30"}, new String[]{"2024", "2", "29", "24", "30"});
        assertFalse(invalidHour.isValid());
        assertTrue(invalidHour.errors().get(0).contains("index 3 [hour]"));
        assertTrue(invalidHour.errors().get(0).contains("integer range [0, 23]"));
    }

    @Test
    void typeDFTBARunsWithWildcardAndTimeIntervalRule() {
        IBEET_FTBA_TypeD scheme = new IBEET_FTBA_TypeD();
        List<Map<String, Object>> keys = scheme.setup(5, Rule.dateRule());
        Map<String, Object> pk = keys.get(0);
        Map<String, Object> sk = scheme.keyGen(pk, keys.get(1), "1701110680");

        assertEquals("time interval", ((Rule) pk.get("vectorRule")).vectorName());
        assertEquals("month", ((Rule) pk.get("vectorRule")).meaningOf(1));
        assertEquals("minute", ((Rule) pk.get("vectorRule")).meaningOf(4));

        Map<String, Object> ct = scheme.encrypt(pk, "1701110680", message(), new String[]{"2024", "2", "29", "10", "15"});
        Map<String, Object> td = scheme.trapdoor(pk, sk, new String[]{"2024", "*", "29", "10", "15"});
        Map<String, Object> invalidCt = scheme.encrypt(pk, "1701110680", message(), new String[]{"2023", "2", "29", "10", "15"});
        Map<String, Object> invalidWildcardMonthDayTd = scheme.trapdoor(pk, sk, new String[]{"2023", "*", "*", "10", "15"});
        Map<String, Object> fixedInvalidDateTd = scheme.trapdoor(pk, sk, new String[]{"2023", "2", "29", "10", "15"});

        assertNotNull(ct);
        assertNotNull(td);
        assertNotNull(invalidCt);
        assertNotNull(invalidWildcardMonthDayTd);
        assertNotNull(fixedInvalidDateTd);
        assertTrue((Boolean) scheme.test(pk, ct, td, ct, td));

        String output = captureOutput(() ->
                assertFalse((Boolean) scheme.test(pk, invalidCt, invalidWildcardMonthDayTd, invalidCt, invalidWildcardMonthDayTd))
        );
        System.out.print(output);
        assertTrue((Boolean) scheme.test(pk, invalidCt, fixedInvalidDateTd, invalidCt, fixedInvalidDateTd));
        assertTrue(output.contains("The time interval vector 2023-2-29 10:15 is invalid. [IBEET_FTBA_TypeD, Error Index:1,2]"));

        Rule.ValidationResult result = ((Rule) pk.get("vectorRule"))
                .validateWildcardMatch(new String[]{"2023", "*", "*", "10", "15"}, new String[]{"2023", "2", "29", "10", "15"});
        assertFalse(result.isValid());
        assertTrue(result.errors().get(0).contains("index 1 [month]"));
        assertTrue(result.errors().get(0).contains("The time interval vector 2023-2-29 10:15 is invalid."));
        assertTrue(result.errors().get(1).contains("index 2 [day]"));
        assertTrue(result.errors().get(1).contains("The time interval vector 2023-2-29 10:15 is invalid."));

        Rule.ValidationResult invalidMinute = ((Rule) pk.get("vectorRule"))
                .validateWildcardMatch(new String[]{"2024", "2", "29", "10", "*"}, new String[]{"2024", "2", "29", "10", "60"});
        assertFalse(invalidMinute.isValid());
        assertTrue(invalidMinute.errors().get(0).contains("index 4 [minute]"));
        assertTrue(invalidMinute.errors().get(0).contains("integer range [0, 59]"));
    }

    @Test
    void customJavaScriptHelpersCanBeUsedByRulesAndMessages() {
        Rule rule = Rule.builder(2)
                .vectorName("region level")
                .field(0, "region").allowedValues("CN", "US").done()
                .field(1, "level").regex("[A-D]").done()
                .jsFunction(
                        "function isAllowedRegionLevel(region, level) {"
                                + "  return !(region === 'CN' && level === 'D');"
                                + "}"
                                + "function regionLevelMessage(region, level) {"
                                + "  return 'region ' + region + ' does not allow level ' + level;"
                                + "}"
                )
                .expression(
                        "region-level-compatibility",
                        Rule.meanings("region", "level"),
                        "isAllowedRegionLevel(region, level)",
                        "regionLevelMessage(region, level)"
                )
                .build();

        assertTrue(rule.validateWildcardMatch(
                new String[]{"CN", "*"},
                new String[]{"CN", "A"}
        ).isValid());

        Rule.ValidationResult result = rule.validateWildcardMatch(
                new String[]{"CN", "*"},
                new String[]{"CN", "D"}
        );
        assertFalse(result.isValid());
        assertTrue(result.errors().get(0).contains("index 1 [level]"));
        assertTrue(result.errors().get(0).contains("region CN does not allow level D"));
    }

    private static byte[] message() {
        return "This is a test!".getBytes(StandardCharsets.UTF_8);
    }

    private static String captureOutput(Runnable action) {
        PrintStream original = System.out;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        PrintStream capture = new PrintStream(buffer, true, StandardCharsets.UTF_8);
        try {
            System.setOut(capture);
            action.run();
        } finally {
            System.setOut(original);
            capture.close();
        }
        return new String(buffer.toByteArray(), StandardCharsets.UTF_8);
    }
}
