# `Rule` Guide

This document explains how to use `utils.Rule` in the current project, and how
it is applied inside `scheme.IBEET_FTBA`.

The goal is simple: after reading this file, you are able to write your
own validation rule for a vector and to plug it into the IBEET-FTBA without
any other document.

The examples in this repository are:

- `example/DateTime.java`: use the built-in default time interval rule
- `example/LunarDate.java`: define and use a custom lunar-date rule

## 1. Running tests and examples

The repository is set up so that the current tests and examples can be run
through Maven in one unified way.

Use:

```bash
mvn test
```

It completes the following steps:

- compile the main source files
- run `test/test.java`
- run `example/DateTime.java` and `example/LunarDate.java`

This is the recommended way.

## 2. Core idea

### 2.1 What a `Rule` validates

A `Rule` validates the meaning of a string vector.

In other words, it describes:

- what each index of a `String[]` means
- which values are allowed at each index
- which relationships must hold across multiple indices

For example, a 5-dimensional time interval vector may be defined as:

```text
[year, month, day, hour, minute]
```

A different 5-dimensional vector may be defined as:

```text
[lunarYear, lunarMonth, lunarDay, season, solarTerm]
```

### 2.2 What `T`, `P`, and `"*"` mean

In IBEET-FTBA:

- `T` is the target vector stored in a ciphertext
- `P` is the pattern vector stored in a trapdoor
- `P[i] == "*"` means that the index i in `P` is a wildcard

Example:

```text
P = ["2024", "*", "29", "23", "30"]
T = ["2024", "2", "29", "23", "30"]
```

This means that the year, day, hour, and minute are fixed, while the month is
allowed to be any valid one.

### 2.3 When the rule is applied

A rule is attached to the public key through `setup(int l, Rule rule)`:

```java
IBEET_FTBA scheme = new IBEET_FTBA();
List<Map<String, Object>> keys = scheme.setup(5, Rule.dateRule());
Map<String, Object> pk = keys.get(0);
```

After that:

- `encrypt(...)` does not reject invalid vectors
- `trapdoor(...)` does not reject invalid patterns
- the rule is checked inside `test(...)`

You can think of `test(...)` as doing the following:

1. Check whether both components use the same `ID`
2. Check whether `P` matches `T`
3. If the basic match succeeds, read `pk.vectorRule`
4. Validate the concrete values matched by wildcard positions
5. If validation fails, print the issues and return `false`

### 2.4 The most important behavior: only wildcard positions are directly checked

This is the key behavior of the current implementation.

`Rule.validateWildcardMatch(P, T)` directly checks only positions where
`P[i] == "*"`.

Non-wildcard positions are not re-validated by field rules. They are treated as
fixed constants, but expression rules may still read them.

Example:

```text
P = ["2023", "*", "29"]
T = ["2023", "2", "29"]
```

Here:

- `month` is a wildcard, so it is directly validated
- `year = 2023` and `day = 29` are fixed constants, so field rules do not
  re-check them
- however, an expression rule may still use them to decide that `2023-2-29` is
  invalid

Another example:

```text
P = ["2023", "2", "29"]
T = ["2023", "2", "29"]
```

There is no wildcard in `P`, so `validateWildcardMatch(...)` does not run
time-interval checks again.

If you want to validate a full vector by itself, use:

- `validateTarget(...)`
- `validatePattern(...)`

instead of relying only on `test(...)`.

## 3. Simple runnable example

If you only require a simple example, use:

```java
IBEET_FTBA scheme = new IBEET_FTBA();
List<Map<String, Object>> keys = scheme.setup(5, Rule.dateRule());
Map<String, Object> pk = keys.get(0);
Map<String, Object> sk = scheme.keyGen(pk, keys.get(1), "1701110680");

String[] time = {"2024", "2", "29", "23", "30"};
Map<String, Object> ct = scheme.encrypt(pk, "1701110680", "example".getBytes(StandardCharsets.UTF_8), time);
Map<String, Object> td = scheme.trapdoor(pk, sk, new String[]{"2024", "*", "29", "23", "30"});

boolean ok = (Boolean) scheme.test(pk, ct, td, ct, td);
```

This is the same idea used in `example/DateTime.java`.

## 4. Main API surface

In practice, the major entry points are:

```java
Rule.builder(length)
Rule.dateRule()
Rule.meanings(...)
```

### 4.1 `Rule.builder(length)`

Creates a builder for a custom rule:

```java
Rule.Builder builder = Rule.builder(5);
```

`length` is the vector length described by the rule.

Important notes:

- the length must be positive
- in `scheme.setup(l, rule)`, `rule.length()` should not be larger than `l`
- it may be smaller than `l`
- if it is smaller than `l`, positions outside the rule are not constrained by
  the rule

### 4.2 `Rule.dateRule()`

Return the default time interval preset used in this project.

The fixed format is:

```text
[year, month, day, hour, minute]
```

It includes the following checks:

- `year` in `1..9999`
- `month` in `1..12`
- `day` in `1..31`
- `hour` in `0..23`
- `minute` in `0..59`
- leap-year aware calendar-day validation

### 4.3 `Rule.meanings(...)`

This is a convenience helper for expression rules. It tells the rule which
named fields an expression depends on.

```java
Rule.meanings("year", "month", "day")
```

## 5. Builder structure

A common style of a custom rule as follows:

```java
Rule rule = Rule.builder(3)
        .field(0, "year").integerRange(1, 9999).done()
        .field(1, "month").integerRange(1, 12).done()
        .field(2, "day").integerRange(1, 31).done()
        .expression(
                "valid-calendar-day",
                Rule.meanings("year", "month", "day"),
                "day <= daysInMonth(year, month)",
                "day",
                "'date ' + year + '-' + month + '-' + day + ' is not valid'"
        )
        .build();
```

There are four key parts:

1. `field(index, meaning)`: declare what one position means
2. `integerRange / allowedValues / blockedValues / regex`: add field-level rules
3. `done()`: complete the current field definition and return to the parent builder
4. `build()`: create the final immutable `Rule`

`done()`: note that, if be forgotten, the field cannot be stored in the rule.

## 6. Writing field rules

Field rules validate each position in a standalone manner.

You may combine multiple field rules on the same position employing AND operations.

### 6.1 Integer range

```java
.field(0, "year").integerRange(2000, 2099).done()
```

Meaning:

- the value must be parseable as an integer
- the integer is required to fall in `[2000, 2099]`

### 6.2 White list

```java
.field(3, "region").allowedValues("CN", "US", "EU").done()
```

Meaning: the value should belong to the given set.

### 6.3 Black list

```java
.field(3, "region").blockedValues("UNKNOWN", "BANNED").done()
```

Meaning: the value should not belong to the given set.

### 6.4 Regular expression

```java
.field(4, "level").regex("[A-C]").done()
```

Meaning: the value must match a Java regular expression.

### 6.5 Combining multiple field rules

```java
.field(4, "level")
        .regex("[A-Z]")
        .blockedValues("X", "Z")
        .done()
```

The value at the specific position must:

- be a single uppercase letter
- not be `X`
- not be `Z`

### 6.6 Data types inside expressions

While the rule API still accepts all vector values as strings, 
any field utilizing `integerRange(...)` will have its value passed as an 
integer within JavaScript expressions.

Example:

```java
.field(1, "month").integerRange(1, 12).done()
```

Then `month` is numeric in expressions, so the following operation is valid:

```javascript
month >= 3
```

If a field does not adopt `integerRange(...)`, its value is typically passed in string form:

```javascript
region === 'CN'
```

## 7. Writing expression rules

Expression rules describe relationships across multiple fields.

Examples:

- whether `day` is valid together with `year` and `month`
- whether `season` matches `lunarYear/lunarMonth/lunarDay`
- whether `region` and `level` are compatible

### 7.1 The three overloads

#### Boolean expression only

```java
.expression(
        "simple-check",
        Rule.meanings("month"),
        "month >= 1 && month <= 12"
)
```

#### Boolean expression with a custom error message

```java
.expression(
        "month-check",
        Rule.meanings("month"),
        "month >= 1 && month <= 12",
        "'month is out of range: ' + month"
)
```

#### Boolean expression with explicit error ownership

```java
.expression(
        "valid-calendar-day",
        Rule.meanings("year", "month", "day"),
        "day <= daysInMonth(year, month)",
        "day",
        "'date ' + year + '-' + month + '-' + day + ' is not valid'"
)
```

### 7.2 Meaning of each argument

For the five-argument overload:

```java
.expression(name, requiredMeanings, expression, errorMeaning, messageExpression)
```

the arguments mean:

- `name`: the rule name, useful for debugging and fallback messages
- `requiredMeanings`: which named fields are read by this rule
- `expression`: a JavaScript expression that evaluates to `true` or `false`
- `errorMeaning`: specify which field carries the error.
- `messageExpression`: the message to show when the expression fails

### 7.3 When an expression is evaluated

In `validateWildcardMatch(P, T)`:

- An expression is evaluated only when at least one of 
its required fields originates from a wildcard position.

That aligns with the design intent of the existing rule system:

- Restrict specific values matched by wildcards
- Avoid full re-verification of all fixed pattern values

### 7.4 What error ownership means

Suppose:

```text
P = ["2023", "*", "29"]
T = ["2023", "2", "29"]
```

If the calendar-day rule fails, the error can be attached to different fields.

By default, errors are bound to the wildcard field that triggers the expression. 
In this example, the target field is `month`, so the error prompt will appear as follows:

```text
index 1 [month] has invalid value [2], does not satisfy: date 2023-2-29 is not valid
```

If you want this kind of error to consistently appear under `day`, write:

```java
.expression(
        "valid-calendar-day",
        Rule.meanings("year", "month", "day"),
        "day <= daysInMonth(year, month)",
        "day",
        "'date ' + year + '-' + month + '-' + day + ' is not valid'"
)
```

In this case, the violation is consistently reported under `day`, 
no matter which wildcard position activates the rule.

## 8. What is available in the JavaScript environment

Expressions currently run on the Java 11 Nashorn JavaScript engine.

### 8.1 Built-in helper functions

Before every expression is evaluated, the system loads these helpers:

```javascript
v(name)
isLeapYear(year)
daysInMonth(year, month)
```

Their purposes are:

- `v(name)`: read a value by the field name
- `isLeapYear(year)`: test whether a year is a leap year
- `daysInMonth(year, month)`: return the maximum day of that month

### 8.2 When the meaning is a valid JavaScript identifier

If your meaning is something like `year`, `month`, or `solarTerm`, you may use
it directly in expressions:

```java
.field(0, "year").integerRange(1, 9999).done()
.field(1, "month").integerRange(1, 12).done()
.expression("m", Rule.meanings("month"), "month >= 3")
```

### 8.3 When the meaning is not a valid JavaScript identifier

If the meaning contains Chinese text, spaces, or hyphens, use `v(...)` instead:

```java
Rule rule = Rule.builder(3)
        .field(0, "年份").integerRange(1, 9999).done()
        .field(1, "月份").integerRange(1, 12).done()
        .field(2, "日期").integerRange(1, 31).done()
        .expression(
                "chinese-date-rule",
                Rule.meanings("年份", "月份", "日期"),
                "v('日期') <= daysInMonth(v('年份'), v('月份'))",
                "日期",
                "'date ' + v('年份') + '-' + v('月份') + '-' + v('日期') + ' is not valid'"
        )
        .build();
```

### 8.4 Custom JavaScript helpers

For more complex logic, use `.helperScript(...)` or `.jsFunction(...)`.

They do the same thing, both of which add JavaScript code into the expression
environment.

```java
Rule rule = Rule.builder(2)
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
                "level",
                "regionLevelMessage(region, level)"
        )
        .build();
```

Evaluation order:

1. load built-in helpers
2. load all `helperScript/jsFunction` snippets in insertion order
3. evaluate the boolean expression
4. if it fails, evaluate the message expression

Recommended style:

- use `function`
- use `var`
- avoid the newer JavaScript syntax

This is the safest style for Nashorn compatibility.

## 9. How to debug a rule locally

It is not suggested to plug a rule into IBEET-FTBA immediately, but validate it by
itself first.

### 9.1 Validate one concrete target vector

```java
Rule.ValidationResult result = rule.validateTarget(
        new String[]{"2024", "2", "29", "23", "30"}
);

if (!result.isValid()) {
    for (String error : result.errors()) {
        System.out.println(error);
    }
}
```

Good for:

- checking whether a full vector is legal
- debugging a rule before using IBBET-FTBA

### 9.2 Validate one pattern vector

```java
Rule.ValidationResult result = rule.validatePattern(
        new String[]{"2024", "*", "29", "23", "30"}
);
```

Properties:

- `"*"` is allowed
- fixed fields are checked directly
- wildcard positions are skipped

### 9.3 Validate the "wildcard" match

```java
Rule.ValidationResult result = rule.validateWildcardMatch(
        new String[]{"2024", "*", "29", "23", "30"},
        new String[]{"2024", "2", "29", "23", "30"}
);
```

### 9.4 Read structured violations

Except for `errors()`, you may inspect structured `Violation` objects:

```java
for (Rule.Violation violation : result.violations()) {
    Integer index = violation.index();
    String meaning = violation.meaning();
    String value = violation.value();
    String ruleText = violation.rule();
    String message = violation.message();
}
```

In general:

- field-rule failures are usually explained by `rule()`
- expression-rule failures are usually explained by `message()`

## 10. Two complete examples

### 10.1 Default time interval rule

The typical case is to use the built-in preset directly:

```java
Rule rule = Rule.dateRule();
```

The fixed format is:

```text
[year, month, day, hour, minute]
```

So:

```java
String[] time = {"2024", "2", "29", "23", "30"};
```

is legal, while:

```java
String[] time = {"2023", "2", "29", "23", "30"};
```

fails under `validateTarget(...)`, because `2023` is not a leap year.

### 10.2 Custom lunar-date rule

`example/LunarDate.java` shows a case of custom rule.

It defines the vector:

```text
[lunarYear, lunarMonth, lunarDay, season, solarTerm]
```

and combines:

- white-list and range checks for year, month, day, season, and solar term
- lunar year-month-day legality
- date-to-season consistency
- date-to-solar-term consistency

The value is that it shows how field rules and JavaScript expression rules work
together.

## 11. Recommended workflow for writing a new rule

If you need to create a new rule from scratch, this order works is recommended.

### Step 1: define the vector first

Write down what each index means.

Examples:

```text
[year, month, day, city, level]
```

or:

```text
[province, hospital, department, doctorLevel]
```

Once the vector is defined, both `field(index, meaning)` and the actual `String[]`
inputs must follow the definition.

### Step 2: add the simple field constraints

Start with the easiest and most stable checks:

- numeric range
- white list
- black list
- regular expression

This catches obvious invalid values.

### Step 3: add cross-field expressions

Whenever legality depends on multiple fields together, use `expression(...)`.

In practice, the following are usually expression rules:

- calendar-day validity
- region-level compatibility
- season-date consistency
- solar-term-date consistency

### Step 4: test the rule with `validateTarget(...)`

```java
System.out.println(rule.validateTarget(vector));
```

A suggestion method to debug.

### Step 5: connect it to `setup(...)`

Once the rule is checked, plug it into the scheme:

```java
List<Map<String, Object>> keys = scheme.setup(length, rule);
```

## 12. Common mistakes

### 12.1 Forgetting `done()`

This is one of the most common mistakes.

```java
.field(0, "year").integerRange(1, 9999).done()
```

If `done()` is missing, the field is never stored in the rule.

### 12.2 Using a different name inside expressions

If you define:

```java
.field(0, "solarTerm")
```

then the expression must use `solarTerm`, not `solar_term`.

### 12.3 Using non-identifier meanings directly as variables

Some names are usable, but relying on them is not advisable.

For meanings such as Chinese text or space-containing names, please adopt:

```javascript
v('年份')
```

### 12.4 Assuming that `test(...)` checks all fixed fields

It does not.

The current implementation directly checks only the values matched by wildcard
positions.

If you want strict validation of a fully fixed vector, call:

- `validateTarget(...)`
- `validatePattern(...)`

explicitly.

### 12.5 Mentioning fields in expressions without defining them as fields

When you use:

```java
Rule.meanings("year", "month", "day")
```

but not define as follows:

```java
.field(0, "year")
.field(1, "month")
.field(2, "day")
```

the expression may fail to calculate since the required fields are missing.

### 12.6 Mixing white lists with formatted numeric strings

Example:

```java
.field(1, "month").integerRange(1, 12).allowedValues("01", "02").done()
```

`allowedValues(...)` checks the original string, not a normalized numeric form.

So:

- `"1"` may pass the integer range check
- but not pass the white list check

## 13. A reusable template

You can leverage this template as a starting point for a new rule:

```java
Rule rule = Rule.builder(5)
        .field(0, "field0").done()
        .field(1, "field1").done()
        .field(2, "field2").done()
        .field(3, "field3").done()
        .field(4, "field4").done()
        .jsFunction(
                "function customCheck(field0, field1, field2) {"
                        + "  return true;"
                        + "}"
                        + "function customMessage(field0, field1, field2) {"
                        + "  return 'custom rule failed';"
                        + "}"
        )
        .expression(
                "custom-rule",
                Rule.meanings("field0", "field1", "field2"),
                "customCheck(field0, field1, field2)",
                "field2",
                "customMessage(field0, field1, field2)"
        )
        .build();
```

In most cases, the only parts you need to modify are:

1. the vector length and field meanings
2. the field-level constraints
3. the custom JavaScript logic and error messages

## 14. Summary

When writing a `Rule`, follow the checklist:

1. define the meaning of each position
2. add the simple per-field constraints
3. use JavaScript expressions for the cross-field constraints
4. debug with `validateTarget(...)`
5. then attach the rule through `setup(l, rule)` for IBEET-FTBA

You may first refer to the following examples:

- `example/DateTime.java`
- `example/LunarDate.java`
