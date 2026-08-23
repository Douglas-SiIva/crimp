#include "crimp/yaml_rules.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#endif

static void make_dir(const char *path) {
#if defined(_WIN32)
    _mkdir(path);
#else
    mkdir(path, 0755);
#endif
}

static void write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "failed to create fixture: %s\n", path);
        exit(1);
    }
    fputs(content, f);
    fclose(f);
}

static int find_rule(const crimp_yaml_rule_list *list, const char *id) {
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i].id, id) == 0) {
            return (int)i;
        }
    }
    return -1;
}

int main(void) {
    /* 1. A valid rule file parses every field correctly. */
    const char *valid_path = "test_fixture_rules_valid.yaml";
    write_file(valid_path,
               "rules:\n"
               "  - id: custom-telnet-check\n"
               "    description: Telnet daemon binary referenced\n"
               "    severity: medium\n"
               "    pattern: telnetd\n"
               "  - id: custom-hardcoded-key\n"
               "    description: Hardcoded API key pattern\n"
               "    severity: HIGH\n"
               "    pattern: \"API_KEY=\"\n");

    crimp_yaml_rule_list rules;
    crimp_yaml_rule_list_init(&rules);
    if (crimp_yaml_rules_load_file(valid_path, &rules) != 0) {
        fprintf(stderr, "FAIL: expected a valid rule file to load successfully\n");
        return 1;
    }
    if (rules.count != 2) {
        fprintf(stderr, "FAIL: expected 2 rules, got %zu\n", rules.count);
        crimp_yaml_rule_list_free(&rules);
        return 1;
    }
    int idx = find_rule(&rules, "custom-telnet-check");
    if (idx < 0 || strcmp(rules.items[idx].pattern, "telnetd") != 0 ||
        strcmp(rules.items[idx].description, "Telnet daemon binary referenced") != 0 ||
        rules.items[idx].severity != CRIMP_SEVERITY_MEDIUM) {
        fprintf(stderr, "FAIL: 'custom-telnet-check' fields don't match\n");
        crimp_yaml_rule_list_free(&rules);
        return 1;
    }
    idx = find_rule(&rules, "custom-hardcoded-key");
    if (idx < 0 || rules.items[idx].severity != CRIMP_SEVERITY_HIGH) {
        fprintf(stderr,
                "FAIL: 'custom-hardcoded-key' missing or severity not case-insensitively "
                "parsed\n");
        crimp_yaml_rule_list_free(&rules);
        return 1;
    }
    crimp_yaml_rule_list_free(&rules);

    /* 2. A malformed file (missing required field, bad severity, not a
     * sequence) is rejected wholesale - nothing from it gets loaded. */
    const char *missing_field_path = "test_fixture_rules_missing_field.yaml";
    write_file(missing_field_path,
               "rules:\n"
               "  - id: incomplete-rule\n"
               "    severity: low\n"
               "    pattern: foo\n"); /* no description */
    crimp_yaml_rule_list bad1;
    crimp_yaml_rule_list_init(&bad1);
    if (crimp_yaml_rules_load_file(missing_field_path, &bad1) == 0) {
        fprintf(stderr, "FAIL: expected a rule missing 'description' to be rejected\n");
        crimp_yaml_rule_list_free(&bad1);
        return 1;
    }
    if (bad1.count != 0) {
        fprintf(stderr, "FAIL: a rejected file must not partially load\n");
        crimp_yaml_rule_list_free(&bad1);
        return 1;
    }
    crimp_yaml_rule_list_free(&bad1);

    const char *bad_severity_path = "test_fixture_rules_bad_severity.yaml";
    write_file(bad_severity_path,
               "rules:\n"
               "  - id: bad-severity-rule\n"
               "    description: something\n"
               "    severity: apocalyptic\n"
               "    pattern: foo\n");
    crimp_yaml_rule_list bad2;
    crimp_yaml_rule_list_init(&bad2);
    if (crimp_yaml_rules_load_file(bad_severity_path, &bad2) == 0) {
        fprintf(stderr, "FAIL: expected an unrecognized severity value to be rejected\n");
        crimp_yaml_rule_list_free(&bad2);
        return 1;
    }
    crimp_yaml_rule_list_free(&bad2);

    const char *not_yaml_path = "test_fixture_rules_not_yaml.yaml";
    write_file(not_yaml_path, "this is not: [valid yaml at all: :::\n");
    crimp_yaml_rule_list bad3;
    crimp_yaml_rule_list_init(&bad3);
    if (crimp_yaml_rules_load_file(not_yaml_path, &bad3) == 0) {
        fprintf(stderr, "FAIL: expected malformed YAML to be rejected\n");
        crimp_yaml_rule_list_free(&bad3);
        return 1;
    }
    crimp_yaml_rule_list_free(&bad3);

    /* A missing file must also fail cleanly. */
    crimp_yaml_rule_list bad4;
    crimp_yaml_rule_list_init(&bad4);
    if (crimp_yaml_rules_load_file("test_fixture_rules_does_not_exist.yaml", &bad4) == 0) {
        fprintf(stderr, "FAIL: expected a missing file to be rejected\n");
        crimp_yaml_rule_list_free(&bad4);
        return 1;
    }
    crimp_yaml_rule_list_free(&bad4);

    /* 3. load_dir loads every valid file, skips bad ones (best-effort, not
     * fatal to the good files in the same directory). */
    const char *rules_dir = "test_fixture_rules_dir";
    make_dir(rules_dir);
    char p[256];
    snprintf(p, sizeof(p), "%s/good.yaml", rules_dir);
    write_file(p, "rules:\n  - id: dir-rule-one\n    description: one\n    severity: low\n"
                  "    pattern: findme1\n");
    snprintf(p, sizeof(p), "%s/also_good.yml", rules_dir);
    write_file(p, "rules:\n  - id: dir-rule-two\n    description: two\n    severity: critical\n"
                  "    pattern: findme2\n");
    snprintf(p, sizeof(p), "%s/broken.yaml", rules_dir);
    write_file(p, "rules:\n  - id: incomplete\n    severity: low\n"); /* missing fields */
    snprintf(p, sizeof(p), "%s/not_a_rule_file.txt", rules_dir);
    write_file(p, "ignored - wrong extension\n");
    /* Uppercase extension - must not be silently excluded on a
     * case-sensitive filesystem (Linux, a first-class build target). */
    snprintf(p, sizeof(p), "%s/UPPERCASE.YAML", rules_dir);
    write_file(p, "rules:\n  - id: dir-rule-three\n    description: three\n    severity: high\n"
                  "    pattern: findme3\n");
    /* An empty pattern must be rejected, not silently loaded as a rule
     * that would match every file via strstr(buf, ""). */
    snprintf(p, sizeof(p), "%s/empty_pattern.yaml", rules_dir);
    write_file(p, "rules:\n  - id: empty-pattern-rule\n    description: x\n    severity: low\n"
                  "    pattern: \"\"\n");

    crimp_yaml_rule_list dir_rules;
    crimp_yaml_rule_list_init(&dir_rules);
    if (crimp_yaml_rules_load_dir(rules_dir, &dir_rules) != 0) {
        fprintf(stderr, "FAIL: expected load_dir to succeed on an openable directory\n");
        crimp_yaml_rule_list_free(&dir_rules);
        return 1;
    }
    if (dir_rules.count != 3 || find_rule(&dir_rules, "dir-rule-one") < 0 ||
        find_rule(&dir_rules, "dir-rule-two") < 0 || find_rule(&dir_rules, "dir-rule-three") < 0) {
        fprintf(stderr,
                "FAIL: expected exactly the 3 valid rules from load_dir (including the "
                "uppercase .YAML one), got %zu\n",
                dir_rules.count);
        crimp_yaml_rule_list_free(&dir_rules);
        return 1;
    }
    if (find_rule(&dir_rules, "empty-pattern-rule") >= 0) {
        fprintf(stderr, "FAIL: a rule with an empty pattern must be rejected, not loaded\n");
        crimp_yaml_rule_list_free(&dir_rules);
        return 1;
    }

    /* 4. End-to-end: scanning real file content against the loaded rules
     * produces findings with the rule's own id as detector_name. */
    const char *target_dir = "test_fixture_rules_target";
    make_dir(target_dir);
    snprintf(p, sizeof(p), "%s/init.d_script.sh", target_dir);
    write_file(p, "#!/bin/sh\nexec findme1 -D\n");

    crimp_finding_list findings;
    crimp_finding_list_init(&findings);
    crimp_scan_directory_for_yaml_rules(target_dir, &dir_rules, &findings);
    if (findings.count != 1 || strcmp(findings.items[0].detector_name, "dir-rule-one") != 0 ||
        findings.items[0].severity != CRIMP_SEVERITY_LOW) {
        fprintf(stderr, "FAIL: expected exactly 1 finding from 'dir-rule-one', got %zu\n",
                findings.count);
        crimp_finding_list_free(&findings);
        crimp_yaml_rule_list_free(&dir_rules);
        return 1;
    }

    /* detector_name must survive freeing the rule list that produced it -
     * regression coverage for crimp_finding_list_add now copying
     * detector_name instead of storing an unowned pointer into rule
     * storage that's about to be freed. */
    crimp_yaml_rule_list_free(&dir_rules);
    if (strcmp(findings.items[0].detector_name, "dir-rule-one") != 0) {
        fprintf(stderr,
                "FAIL: finding's detector_name changed/corrupted after freeing the rule list - "
                "it must be an owned copy, not a dangling pointer into freed rule storage\n");
        crimp_finding_list_free(&findings);
        return 1;
    }
    crimp_finding_list_free(&findings);

    printf("PASS: YAML rule loading, dir loading, and scanning all work end-to-end\n");
    return 0;
}
