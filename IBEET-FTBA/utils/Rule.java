package utils;

import javax.script.Bindings;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Rule validates string vectors used by the scheme layer.
 *
 * <p>A vector is a {@code String[]} where each index has a meaning, such as
 * year, month, day, hour, or minute. This class supports:</p>
 * <p>1. Single-field checks such as integer ranges, regex rules, and
 * allowed/blocked values.</p>
 * <p>2. Cross-field checks written as JavaScript expressions, for example
 * leap-year aware date validation.</p>
 *
 * <p>The default preset returned by {@link #dateRule()} uses the format
 * {@code [year, month, day, hour, minute]}.</p>
 */
public final class Rule {

    /** Wildcard token used in pattern vectors. */
    private static final String WILDCARD = "*";

    /*
     * Java 11 still provides the Nashorn JavaScript engine.
     * This only hides its deprecation warning in test output.
     */
    static {
        String nashornArgs = System.getProperty("nashorn.args", "");
        if (!nashornArgs.contains("--no-deprecation-warning")) {
            System.setProperty("nashorn.args", (nashornArgs + " --no-deprecation-warning").trim());
        }
    }

    /*
     * These helper functions are loaded into every JavaScript expression.
     * They are used by built-in and custom rules.
     */
    private static final String JS_PRELUDE =
            "function v(name) { return __values.get(name); }"
                    + "function isLeapYear(year) {"
                    + "  return (year % 4 === 0 && year % 100 !== 0) || (year % 400 === 0);"
                    + "}"
                    + "function daysInMonth(year, month) {"
                    + "  if (month === 2) return isLeapYear(year) ? 29 : 28;"
                    + "  if (month === 4 || month === 6 || month === 9 || month === 11) return 30;"
                    + "  return 31;"
                    + "}";

    private final String vectorName;
    private final int length;
    private final Map<Integer, FieldRule> fieldRules;
    private final List<ExpressionRule> expressionRules;
    private final List<String> helperScripts;

    /**
     * Builds an immutable rule from builder data.
     *
     * @param length expected vector length
     * @param vectorName human-readable name of the vector
     * @param fieldRules field-level validation rules
     * @param expressionRules cross-field JavaScript rules
     * @param helperScripts extra JavaScript helper code
     */
    private Rule(String vectorName, int length, Map<Integer, FieldRule> fieldRules, List<ExpressionRule> expressionRules, List<String> helperScripts) {
        if (length <= 0) {
            throw new IllegalArgumentException("Vector rule length must be positive.");
        }
        this.vectorName = vectorName;
        this.length = length;
        this.fieldRules = Collections.unmodifiableMap(new LinkedHashMap<>(fieldRules));
        this.expressionRules = Collections.unmodifiableList(new ArrayList<>(expressionRules));
        this.helperScripts = Collections.unmodifiableList(new ArrayList<>(helperScripts));
    }

    /** Creates a builder for a vector with fixed length. */
    public static Builder builder(int length) {
        return new Builder(length);
    }

    /**
     * Returns the default preset of this project.
     *
     * <p>Vector format: {@code [year, month, day, hour, minute]}.</p>
     */
    public static Rule dateRule() {
        return builder(5)
                .vectorName("time interval")
                .field(0, "year").integerRange(1, 9999).done()
                .field(1, "month").integerRange(1, 12).done()
                .field(2, "day").integerRange(1, 31).done()
                .field(3, "hour").integerRange(0, 23).done()
                .field(4, "minute").integerRange(0, 59).done()
                .expression(
                        "valid-calendar-day",
                        meanings("year", "month", "day"),
                        "day <= daysInMonth(year, month)",
                        "'The time interval vector ' + year + '-' + month + '-' + day + ' ' + hour + ':' + minute + ' is invalid.'"
                )
                .build();
    }

    /** Convenience helper for naming the fields used by one expression rule. */
    public static Set<String> meanings(String... meanings) {
        return new LinkedHashSet<>(Arrays.asList(meanings));
    }

    /** Returns the expected vector length. */
    public int length() {
        return length;
    }

    /** Returns the human-readable name of this vector, such as {@code "time interval"}. */
    public String vectorName() {
        return vectorName;
    }

    /** Returns the meaning of one vector index, such as {@code "year"}. */
    public String meaningOf(int index) {
        FieldRule rule = fieldRules.get(index);
        return rule == null ? null : rule.meaning;
    }

    /** Returns all configured index-to-meaning mappings. */
    public Map<Integer, String> indexMeanings() {
        Map<Integer, String> meanings = new LinkedHashMap<>();
        for (Map.Entry<Integer, FieldRule> entry : fieldRules.entrySet()) {
            meanings.put(entry.getKey(), entry.getValue().meaning);
        }
        return Collections.unmodifiableMap(meanings);
    }

    /**
     * Validates a pattern vector.
     *
     * <p>Wildcards ({@code "*"}) are allowed and skipped during field checks.</p>
     */
    public ValidationResult validatePattern(String[] vector) {
        return validateVector(vector, true);
    }

    /** Validates a concrete target vector with no wildcards. */
    public ValidationResult validateTarget(String[] vector) {
        return validateVector(vector, false);
    }

    /**
     * Validates one wildcard match between a pattern and a target.
     *
     * <p>Important: only values coming from wildcard positions are checked here.
     * Fixed values already written into the pattern are not re-validated. This
     * matches how wildcard trapdoors are used by the scheme.</p>
     */
    public ValidationResult validateWildcardMatch(String[] pattern, String[] target) {
        List<Violation> violations = new ArrayList<>();
        if (pattern == null || target == null) {
            violations.add(new Violation(null, null, null, null, "pattern or target is null", true));
            return new ValidationResult(false, violations);
        }
        if (pattern.length != target.length) {
            violations.add(new Violation(null, null, null, null,
                    "pattern length " + pattern.length + " does not match target length " + target.length, true));
            return new ValidationResult(false, violations);
        }
        if (pattern.length != length) {
            violations.add(new Violation(null, null, null, null,
                    "matched vector length " + pattern.length + " does not match rule length " + length, true));
            return new ValidationResult(false, violations);
        }

        Map<String, Object> valuesByMeaning = new HashMap<>();
        Map<String, Integer> indexByMeaning = new HashMap<>();
        Set<String> wildcardMeanings = new LinkedHashSet<>();

        for (int index = 0; index < pattern.length; index++) {
            FieldRule fieldRule = fieldRules.get(index);
            if (fieldRule == null) {
                continue;
            }

            boolean wildcard = WILDCARD.equals(pattern[index]);
            String value = wildcard ? target[index] : pattern[index];

            if (wildcard) {
                wildcardMeanings.add(fieldRule.meaning);
                int before = violations.size();
                Object normalized = fieldRule.readValue(value, violations);
                if (violations.size() != before) {
                    continue;
                }
                valuesByMeaning.put(fieldRule.meaning, normalized);
                indexByMeaning.put(fieldRule.meaning, index);
            } else {
                valuesByMeaning.put(fieldRule.meaning, fieldRule.readUnchecked(value));
                indexByMeaning.put(fieldRule.meaning, index);
            }
        }

        for (ExpressionRule expressionRule : expressionRules) {
            boolean touchesWildcard = false;
            for (String meaning : expressionRule.requiredMeanings) {
                if (wildcardMeanings.contains(meaning)) {
                    touchesWildcard = true;
                    break;
                }
            }
            if (!touchesWildcard) {
                continue;
            }
            if (!valuesByMeaning.keySet().containsAll(expressionRule.requiredMeanings)) {
                violations.add(new Violation(null, null, null, null,
                        "constraint '" + expressionRule.name + "' cannot be evaluated because fields are missing", true));
                continue;
            }
            expressionRule.validate(valuesByMeaning, indexByMeaning, wildcardMeanings, helperScripts, violations);
        }

        return new ValidationResult(violations.isEmpty(), violations);
    }

    /** Shared logic for validating a single vector. */
    private ValidationResult validateVector(String[] vector, boolean allowWildcard) {
        List<Violation> violations = new ArrayList<>();
        if (vector == null) {
            violations.add(new Violation(null, null, null, null, "vector is null", true));
            return new ValidationResult(false, violations);
        }
        if (vector.length != length) {
            violations.add(new Violation(null, null, null, null,
                    "vector length " + vector.length + " does not match rule length " + length, true));
            return new ValidationResult(false, violations);
        }

        Map<String, Object> valuesByMeaning = new HashMap<>();
        Map<String, Integer> indexByMeaning = new HashMap<>();

        for (int index = 0; index < vector.length; index++) {
            FieldRule fieldRule = fieldRules.get(index);
            if (fieldRule == null) {
                continue;
            }

            String value = vector[index];
            if (allowWildcard && WILDCARD.equals(value)) {
                continue;
            }

            int before = violations.size();
            Object normalized = fieldRule.readValue(value, violations);
            if (violations.size() != before) {
                continue;
            }
            valuesByMeaning.put(fieldRule.meaning, normalized);
            indexByMeaning.put(fieldRule.meaning, index);
        }

        for (ExpressionRule expressionRule : expressionRules) {
            if (!valuesByMeaning.keySet().containsAll(expressionRule.requiredMeanings)) {
                if (!allowWildcard) {
                    violations.add(new Violation(null, null, null, null,
                            "constraint '" + expressionRule.name + "' cannot be evaluated because fields are missing", true));
                }
                continue;
            }
            expressionRule.validate(valuesByMeaning, indexByMeaning, valuesByMeaning.keySet(), helperScripts, violations);
        }

        return new ValidationResult(violations.isEmpty(), violations);
    }

    /** Builder for a full rule. */
    public static final class Builder {
        private String vectorName = "vector";
        private final int length;
        private final Map<Integer, FieldRule> fieldRules = new LinkedHashMap<>();
        private final List<ExpressionRule> expressionRules = new ArrayList<>();
        private final List<String> helperScripts = new ArrayList<>();

        private Builder(int length) {
            this.length = length;
        }

        /** Sets the human-readable name used when this rule is summarized. */
        public Builder vectorName(String vectorName) {
            if (vectorName == null || vectorName.trim().isEmpty()) {
                throw new IllegalArgumentException("Vector name cannot be empty.");
            }
            this.vectorName = vectorName.trim();
            return this;
        }

        /** Starts the definition of one field. */
        public FieldBuilder field(int index, String meaning) {
            return new FieldBuilder(this, index, meaning);
        }

        /** Adds raw JavaScript helper code. */
        public Builder helperScript(String script) {
            if (script == null || script.trim().isEmpty()) {
                throw new IllegalArgumentException("JavaScript helper script cannot be empty.");
            }
            helperScripts.add(script);
            return this;
        }

        /** Adds a JavaScript helper function. */
        public Builder jsFunction(String functionSource) {
            if (functionSource == null || functionSource.trim().isEmpty()) {
                throw new IllegalArgumentException("JavaScript helper script cannot be empty.");
            }
            helperScripts.add(functionSource);
            return this;
        }

        /** Adds a boolean JavaScript expression rule. */
        public Builder expression(String name, Collection<String> requiredMeanings, String expression) {
            expressionRules.add(new ExpressionRule(name, requiredMeanings, expression, null, null));
            return this;
        }

        /** Adds a boolean JavaScript expression with a custom error message. */
        public Builder expression(String name, Collection<String> requiredMeanings, String expression, String messageExpression) {
            expressionRules.add(new ExpressionRule(name, requiredMeanings, expression, null, messageExpression));
            return this;
        }

        /** Adds a JavaScript expression and chooses which field should own the error. */
        public Builder expression(String name, Collection<String> requiredMeanings, String expression, String errorMeaning, String messageExpression) {
            expressionRules.add(new ExpressionRule(name, requiredMeanings, expression, errorMeaning, messageExpression));
            return this;
        }

        /** Finishes the builder and returns an immutable rule. */
        public Rule build() {
            return new Rule(vectorName, length, fieldRules, expressionRules, helperScripts);
        }
    }

    /** Builder for one field rule. */
    public static final class FieldBuilder {
        private final Builder parent;
        private final int index;
        private final String meaning;
        private Integer minInteger;
        private Integer maxInteger;
        private Pattern regex;
        private Set<String> allowedValues;
        private Set<String> blockedValues;

        private FieldBuilder(Builder parent, int index, String meaning) {
            if (index < 0 || index >= parent.length) {
                throw new IllegalArgumentException("Field index out of rule range: " + index);
            }
            this.parent = parent;
            this.index = index;
            this.meaning = Objects.requireNonNull(meaning, "meaning");
        }

        /** Requires the field to be an integer inside {@code [min, max]}. */
        public FieldBuilder integerRange(int min, int max) {
            this.minInteger = min;
            this.maxInteger = max;
            return this;
        }

        /** Requires the field to match a Java regular expression. */
        public FieldBuilder regex(String regex) {
            this.regex = Pattern.compile(regex);
            return this;
        }

        /** Limits the field to a fixed set of allowed values. */
        public FieldBuilder allowedValues(String... values) {
            this.allowedValues = new LinkedHashSet<>(Arrays.asList(values));
            return this;
        }

        /** Rejects a fixed set of blocked values. */
        public FieldBuilder blockedValues(String... values) {
            this.blockedValues = new LinkedHashSet<>(Arrays.asList(values));
            return this;
        }

        /** Stores this field rule into the parent builder. */
        public Builder done() {
            parent.fieldRules.put(index, new FieldRule(index, meaning, minInteger, maxInteger, regex, allowedValues, blockedValues));
            return parent;
        }
    }

    /** Final validation result returned by the rule. */
    public static final class ValidationResult {
        private final boolean valid;
        private final List<Violation> violations;

        private ValidationResult(boolean valid, List<Violation> violations) {
            this.valid = valid;
            this.violations = Collections.unmodifiableList(new ArrayList<>(violations));
        }

        /** Returns whether validation succeeded. */
        public boolean isValid() {
            return valid;
        }

        /** Returns readable error strings. */
        public List<String> errors() {
            List<String> errors = new ArrayList<>();
            for (Violation violation : violations) {
                errors.add(violation.toString());
            }
            return errors;
        }

        /** Returns structured violation objects. */
        public List<Violation> violations() {
            return violations;
        }

        @Override
        public String toString() {
            return valid ? "valid" : String.join("; ", errors());
        }
    }

    /** One validation problem. */
    public static final class Violation {
        private final Integer index;
        private final String meaning;
        private final String value;
        private final String rule;
        private final String message;
        private final boolean expressionViolation;

        private Violation(Integer index, String meaning, String value, String rule, String message, boolean expressionViolation) {
            this.index = index;
            this.meaning = meaning;
            this.value = value;
            this.rule = rule;
            this.message = message;
            this.expressionViolation = expressionViolation;
        }

        /** Returns the failed index, or {@code null} for a general error. */
        public Integer index() {
            return index;
        }

        /** Returns the field meaning, such as {@code "month"}. */
        public String meaning() {
            return meaning;
        }

        /** Returns the failed value. */
        public String value() {
            return value;
        }

        /** Returns the field-level rule text when available. */
        public String rule() {
            return rule;
        }

        /** Returns the expression-level message when available. */
        public String message() {
            return message;
        }

        @Override
        public String toString() {
            if (meaning == null) {
                return message;
            }
            String label = index == null ? "[" + meaning + "]" : "index " + index + " [" + meaning + "]";
            if (expressionViolation) {
                return label + " has invalid value [" + value + "], does not satisfy: " + message;
            }
            return label + " has invalid value [" + value + "], violates rule [" + rule + "]";
        }
    }

    /** Internal data object for one field rule. */
    private static final class FieldRule {
        private final int index;
        private final String meaning;
        private final Integer minInteger;
        private final Integer maxInteger;
        private final Pattern regex;
        private final Set<String> allowedValues;
        private final Set<String> blockedValues;

        private FieldRule(int index, String meaning, Integer minInteger, Integer maxInteger, Pattern regex, Set<String> allowedValues, Set<String> blockedValues) {
            this.index = index;
            this.meaning = meaning;
            this.minInteger = minInteger;
            this.maxInteger = maxInteger;
            this.regex = regex;
            this.allowedValues = allowedValues == null ? null : Collections.unmodifiableSet(new LinkedHashSet<>(allowedValues));
            this.blockedValues = blockedValues == null ? null : Collections.unmodifiableSet(new LinkedHashSet<>(blockedValues));
        }

        /**
         * Validates a value and returns the normalized object used by
         * JavaScript expressions. Numeric fields become {@code Integer}.
         */
        private Object readValue(String value, List<Violation> violations) {
            int before = violations.size();
            if (value == null || value.trim().isEmpty()) {
                violations.add(new Violation(index, meaning, value, "non-empty", null, false));
                return null;
            }
            if (allowedValues != null && !allowedValues.contains(value)) {
                violations.add(new Violation(index, meaning, value, "allowed values " + allowedValues, null, false));
            }
            if (blockedValues != null && blockedValues.contains(value)) {
                violations.add(new Violation(index, meaning, value, "blocked values " + blockedValues, null, false));
            }
            if (regex != null && !regex.matcher(value).matches()) {
                violations.add(new Violation(index, meaning, value, "regex " + regex.pattern(), null, false));
            }

            if (minInteger != null || maxInteger != null) {
                int intValue;
                try {
                    intValue = Integer.parseInt(value);
                } catch (NumberFormatException e) {
                    violations.add(new Violation(index, meaning, value, "integer", null, false));
                    return null;
                }

                String rangeText = "integer range ["
                        + (minInteger == null ? "-inf" : minInteger)
                        + ", "
                        + (maxInteger == null ? "+inf" : maxInteger)
                        + "]";

                if (minInteger != null && intValue < minInteger) {
                    violations.add(new Violation(index, meaning, value, rangeText, null, false));
                }
                if (maxInteger != null && intValue > maxInteger) {
                    violations.add(new Violation(index, meaning, value, rangeText, null, false));
                }
                return violations.size() == before ? intValue : null;
            }

            return value;
        }

        /** Reads a fixed pattern value without adding field errors. */
        private Object readUnchecked(String value) {
            if (minInteger != null || maxInteger != null) {
                try {
                    return Integer.parseInt(value);
                } catch (NumberFormatException e) {
                    return value;
                }
            }
            return value;
        }
    }

    /** Internal data object for one cross-field JavaScript rule. */
    private static final class ExpressionRule {
        private final String name;
        private final Set<String> requiredMeanings;
        private final String expression;
        private final String errorMeaning;
        private final String messageExpression;

        private ExpressionRule(String name, Collection<String> requiredMeanings, String expression, String errorMeaning, String messageExpression) {
            this.name = Objects.requireNonNull(name, "name");
            this.requiredMeanings = Collections.unmodifiableSet(new LinkedHashSet<>(requiredMeanings));
            this.expression = Objects.requireNonNull(expression, "expression");
            this.errorMeaning = errorMeaning;
            this.messageExpression = messageExpression;
        }

        /** Evaluates the JavaScript rule and appends violations when needed. */
        private void validate(Map<String, Object> valuesByMeaning, Map<String, Integer> indexByMeaning, Set<String> activeMeanings, List<String> helperScripts, List<Violation> violations) {
            ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
            if (engine == null) {
                violations.add(new Violation(null, null, null, null,
                        "JavaScript expression engine is unavailable; cannot evaluate constraint '" + name + "'", true));
                return;
            }

            try {
                Bindings bindings = engine.createBindings();
                bindings.putAll(valuesByMeaning);
                bindings.put("__values", valuesByMeaning);

                // Load built-in helpers first, then caller-supplied helpers.
                engine.eval(JS_PRELUDE, bindings);
                for (String helperScript : helperScripts) {
                    engine.eval(helperScript, bindings);
                }

                Object result = engine.eval(expression, bindings);
                if (result instanceof Boolean && (Boolean) result) {
                    return;
                }

                String message = "JS rule [" + name + "] returned false. Expression: " + expression;
                if (messageExpression != null && !messageExpression.trim().isEmpty()) {
                    message = String.valueOf(engine.eval(messageExpression, bindings));
                }

                Set<String> meaningsToReport = new LinkedHashSet<>();
                if (errorMeaning != null && !errorMeaning.trim().isEmpty()) {
                    meaningsToReport.add(errorMeaning);
                } else {
                    for (String meaning : requiredMeanings) {
                        if (activeMeanings.contains(meaning)) {
                            meaningsToReport.add(meaning);
                        }
                    }
                    if (meaningsToReport.isEmpty()) {
                        meaningsToReport.addAll(requiredMeanings);
                    }
                }

                for (String meaning : meaningsToReport) {
                    Object value = valuesByMeaning.get(meaning);
                    violations.add(new Violation(indexByMeaning.get(meaning), meaning, String.valueOf(value), null, message, true));
                }
            } catch (ScriptException e) {
                violations.add(new Violation(null, null, null, null,
                        "constraint '" + name + "' failed to evaluate: " + e.getMessage(), true));
            }
        }
    }
}
