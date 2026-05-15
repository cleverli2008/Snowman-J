package example;

import scheme.IBEET_FTBA;
import utils.Rule;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Minimal FTBA example using a custom lunar-date rule.
 *
 * <p>The vector format is:
 * [lunarYear, lunarMonth, lunarDay, season, solarTerm]</p>
 *
 * <p>This file focuses on the smallest complete flow:
 * build a rule, run setup, encrypt, build a trapdoor, and test.</p>
 */
public class LunarDate {

    /**
     * Builds a custom rule that checks:
     * 1. field-level white lists
     * 2. whether the lunar year/month/day combination is legal
     * 3. whether the date matches the given season
     * 4. whether the date matches the given solar term
     */
    public static Rule rule() {
        return Rule.builder(5)
                .vectorName("lunar date")
                // Position 0 stores the lunar year.
                // We keep both an integer range and a white list here to show
                // that field-level constraints can be combined.
                .field(0, "lunarYear").integerRange(2024, 2025).allowedValues("2024", "2025").done()
                // Position 1 stores the lunar month.
                // The white list says which months are allowed in this demo dataset.
                .field(1, "lunarMonth").integerRange(1, 12).allowedValues("1", "2", "8", "11").done()
                // Position 2 stores the lunar day.
                // The final legality check is still done later by a custom expression,
                // because different months can have different maximum days.
                .field(2, "lunarDay").integerRange(1, 30).allowedValues(days()).done()
                // Position 3 stores the season name.
                .field(3, "season").allowedValues("spring", "summer", "autumn", "winter").done()
                // Position 4 stores the solar term name.
                .field(4, "solarTerm").allowedValues("lichun", "yushui", "qiufen", "lidong").done()
                // The custom JavaScript block defines a tiny demo dataset and the
                // helper functions used by the expressions below.
                // LEGAL_MONTHS describes how many days each demo lunar month has.
                // LUNAR_INFO records which season and solar term a specific
                // lunar date should map to.
                .jsFunction(
                        "var LEGAL_MONTHS = {"
                                + "  '2024-1': 30,"
                                + "  '2024-2': 29,"
                                + "  '2024-8': 30,"
                                + "  '2024-11': 30,"
                                + "  '2025-1': 30"
                                + "};"
                                + "var LUNAR_INFO = {"
                                + "  '2024-1-1': { season: 'spring', solarTerm: 'lichun' },"
                                + "  '2024-2-15': { season: 'spring', solarTerm: 'yushui' },"
                                + "  '2024-8-15': { season: 'autumn', solarTerm: 'qiufen' },"
                                + "  '2024-11-7': { season: 'winter', solarTerm: 'lidong' },"
                                + "  '2025-1-1': { season: 'spring', solarTerm: 'lichun' }"
                                + "};"
                                + "function monthKey(year, month) {"
                                + "  return year + '-' + month;"
                                + "}"
                                + "function dateKey(year, month, day) {"
                                + "  return year + '-' + month + '-' + day;"
                                + "}"
                                + "function isLegalLunarDate(year, month, day) {"
                                + "  var maxDay = LEGAL_MONTHS[monthKey(year, month)];"
                                + "  return maxDay !== undefined && day >= 1 && day <= maxDay;"
                                + "}"
                                + "function matchesSeason(year, month, day, season) {"
                                + "  if (!isLegalLunarDate(year, month, day)) return true;"
                                + "  var info = LUNAR_INFO[dateKey(year, month, day)];"
                                + "  return info !== undefined && info.season === season;"
                                + "}"
                                + "function matchesSolarTerm(year, month, day, solarTerm) {"
                                + "  if (!isLegalLunarDate(year, month, day)) return true;"
                                + "  var info = LUNAR_INFO[dateKey(year, month, day)];"
                                + "  return info !== undefined && info.solarTerm === solarTerm;"
                                + "}"
                                + "function dateMessage(year, month, day) {"
                                + "  return 'lunar date ' + year + '-' + month + '-' + day + ' is not legal in this demo dataset';"
                                + "}"
                                + "function seasonMessage(year, month, day, season) {"
                                + "  return 'lunar date ' + year + '-' + month + '-' + day + ' does not match season ' + season;"
                                + "}"
                                + "function solarTermMessage(year, month, day, solarTerm) {"
                                + "  return 'lunar date ' + year + '-' + month + '-' + day + ' does not match solar term ' + solarTerm;"
                                + "}"
                )
                // This expression checks whether year-month-day is a legal
                // lunar date inside the demo dataset.
                // The error is attached to lunarDay so the message points to
                // the date part that most directly failed.
                .expression(
                        "legal-lunar-date",
                        Rule.meanings("lunarYear", "lunarMonth", "lunarDay"),
                        "isLegalLunarDate(lunarYear, lunarMonth, lunarDay)",
                        "lunarDay",
                        "dateMessage(lunarYear, lunarMonth, lunarDay)"
                )
                // This expression checks whether the chosen season matches
                // the given lunar date.
                .expression(
                        "season-match",
                        Rule.meanings("lunarYear", "lunarMonth", "lunarDay", "season"),
                        "matchesSeason(lunarYear, lunarMonth, lunarDay, season)",
                        "season",
                        "seasonMessage(lunarYear, lunarMonth, lunarDay, season)"
                )
                // This expression checks whether the chosen solar term matches
                // the given lunar date.
                .expression(
                        "solar-term-match",
                        Rule.meanings("lunarYear", "lunarMonth", "lunarDay", "solarTerm"),
                        "matchesSolarTerm(lunarYear, lunarMonth, lunarDay, solarTerm)",
                        "solarTerm",
                        "solarTermMessage(lunarYear, lunarMonth, lunarDay, solarTerm)"
                )
                .build();
    }

    /**
     * Runs one minimal FTBA flow with a valid lunar vector.
     */
    public static boolean ftba() {
        IBEET_FTBA scheme = new IBEET_FTBA();
        // Attach the custom lunar rule during setup so later matching
        // automatically uses the same validation policy.
        List<Map<String, Object>> keys = scheme.setup(5, rule());
        Map<String, Object> pk = keys.get(0);
        Map<String, Object> sk = scheme.keyGen(pk, keys.get(1), "1701110680");

        // This sample vector is legal in the demo dataset.
        String[] lunar = {"2024", "1", "1", "spring", "lichun"};
        Map<String, Object> ct = scheme.encrypt(pk, "1701110680", "example".getBytes(StandardCharsets.UTF_8), lunar);
        // The trapdoor uses wildcards on day and solar term.
        // During test(...), the rule will validate the concrete values that
        // fill these wildcard positions.
        Map<String, Object> td = scheme.trapdoor(pk, sk, new String[]{"2024", "1", "*", "spring", "*"});
        // System.out.println("pk: " + pk);
        // System.out.println("ct: " + ct);
        // System.out.println("td: " + td);
        return (Boolean) scheme.test(pk, ct, td, ct, td);
    }

    /**
     * Runs the minimal example and prints the final FTBA result.
     */
    public static void main(String[] args) {
        System.out.println("lunar date : " + ftba());
    }

    /**
     * Builds the white list {"1", "2", ..., "30"} for lunar-day values.
     */
    private static String[] days() {
        String[] values = new String[30];
        for (int i = 0; i < values.length; i++) {
            values[i] = String.valueOf(i + 1);
        }
        return values;
    }
}
