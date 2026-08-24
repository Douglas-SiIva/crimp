#include "crimp/cve.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "failed to create fixture: %s\n", path);
        exit(1);
    }
    fputs(content, f);
    fclose(f);
}

static void add_component(crimp_component_list *list, const char *name, const char *version,
                           const char *path) {
    crimp_component_list_add(list, name, version, path);
}

static int find_finding(const crimp_finding_list *list, const char *detector_name) {
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i].detector_name, detector_name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

int main(void) {
    const char *dataset_path = "test_fixture_cve_dataset.yaml";
    write_file(dataset_path,
               "components:\n"
               "  - name: OpenSSL\n"
               "    cves:\n"
               "      - id: CVE-2022-0778\n"
               "        affected: \"<1.1.1n\"\n"
               "        severity: high\n"
               "        description: Infinite loop in BN_mod_sqrt\n"
               "      - id: CVE-RANGE-TEST\n"
               "        affected: \">=1.0.0,<1.1.0\"\n"
               "        severity: medium\n"
               "        description: compound range test\n"
               "      - id: CVE-EXACT-TEST\n"
               "        affected: \"==0.9.6d\"\n"
               "        severity: critical\n"
               "        description: exact version test\n"
               "  - name: BusyBox\n"
               "    cves:\n"
               "      - id: CVE-BUSYBOX-TEST\n"
               "        affected: \"<1.32.0\"\n"
               "        severity: low\n"
               "        description: busybox test\n");

    /* 1. Version below the exclusive upper bound (with a lettered suffix
     * bound) matches; the exact boundary version and anything above it
     * doesn't. */
    {
        crimp_component_list comps;
        crimp_component_list_init(&comps);
        add_component(&comps, "OpenSSL", "1.1.1k", "bin/libssl.so");   /* < 1.1.1n: affected */
        add_component(&comps, "OpenSSL", "1.1.1n", "bin/libssl2.so");  /* == bound: not affected (exclusive) */
        add_component(&comps, "OpenSSL", "1.1.1z", "bin/libssl3.so");  /* > bound: not affected */
        add_component(&comps, "OpenSSL", "3.0.13", "bin/libssl4.so");  /* well above: not affected */

        crimp_finding_list findings;
        crimp_finding_list_init(&findings);
        if (crimp_cve_match_components(dataset_path, &comps, &findings) != 0) {
            fprintf(stderr, "FAIL: expected a valid dataset to load successfully\n");
            return 1;
        }
        int idx = find_finding(&findings, "CVE-2022-0778");
        if (idx < 0) {
            fprintf(stderr, "FAIL: expected CVE-2022-0778 to match OpenSSL 1.1.1k\n");
            crimp_finding_list_free(&findings);
            crimp_component_list_free(&comps);
            return 1;
        }
        if (findings.items[idx].severity != CRIMP_SEVERITY_HIGH ||
            strstr(findings.items[idx].description, "1.1.1k") == NULL ||
            strstr(findings.items[idx].description, "bin/libssl.so") == NULL) {
            fprintf(stderr,
                    "FAIL: CVE-2022-0778 finding missing expected severity/version/path in "
                    "description: %s\n",
                    findings.items[idx].description);
            crimp_finding_list_free(&findings);
            crimp_component_list_free(&comps);
            return 1;
        }
        /* Only the 1.1.1k instance should have matched - not the boundary
         * or newer versions. */
        int match_count = 0;
        for (size_t i = 0; i < findings.count; i++) {
            if (strcmp(findings.items[i].detector_name, "CVE-2022-0778") == 0) {
                match_count++;
            }
        }
        if (match_count != 1) {
            fprintf(stderr,
                    "FAIL: expected exactly 1 CVE-2022-0778 match (only the vulnerable "
                    "instance), got %d\n",
                    match_count);
            crimp_finding_list_free(&findings);
            crimp_component_list_free(&comps);
            return 1;
        }
        crimp_finding_list_free(&findings);
        crimp_component_list_free(&comps);
    }

    /* 2. Compound range (>=X,<Y) - both bounds must hold. */
    {
        crimp_component_list comps;
        crimp_component_list_init(&comps);
        add_component(&comps, "OpenSSL", "0.9.9", "a");  /* below lower bound */
        add_component(&comps, "OpenSSL", "1.0.5", "b");  /* inside range */
        add_component(&comps, "OpenSSL", "1.1.0", "c");  /* == upper bound, exclusive */
        add_component(&comps, "OpenSSL", "1.5.0", "d");  /* above range */

        crimp_finding_list findings;
        crimp_finding_list_init(&findings);
        crimp_cve_match_components(dataset_path, &comps, &findings);
        int matches = 0;
        for (size_t i = 0; i < findings.count; i++) {
            if (strcmp(findings.items[i].detector_name, "CVE-RANGE-TEST") == 0) {
                matches++;
                if (strstr(findings.items[i].description, "1.0.5, b)") == NULL) {
                    fprintf(stderr,
                            "FAIL: expected the compound-range match to be the 'b' (1.0.5) "
                            "instance, got: %s\n",
                            findings.items[i].description);
                    crimp_finding_list_free(&findings);
                    crimp_component_list_free(&comps);
                    return 1;
                }
            }
        }
        if (matches != 1) {
            fprintf(stderr, "FAIL: expected exactly 1 compound-range match, got %d\n", matches);
            crimp_finding_list_free(&findings);
            crimp_component_list_free(&comps);
            return 1;
        }
        crimp_finding_list_free(&findings);
        crimp_component_list_free(&comps);
    }

    /* 3. Exact-version equality (==X) matches only that exact version. */
    {
        crimp_component_list comps;
        crimp_component_list_init(&comps);
        add_component(&comps, "OpenSSL", "0.9.6d", "a");
        add_component(&comps, "OpenSSL", "0.9.6c", "b");
        add_component(&comps, "OpenSSL", "0.9.6e", "c");

        crimp_finding_list findings;
        crimp_finding_list_init(&findings);
        crimp_cve_match_components(dataset_path, &comps, &findings);
        int matches = 0;
        for (size_t i = 0; i < findings.count; i++) {
            if (strcmp(findings.items[i].detector_name, "CVE-EXACT-TEST") == 0) {
                matches++;
            }
        }
        if (matches != 1) {
            fprintf(stderr, "FAIL: expected exactly 1 exact-version match, got %d\n", matches);
            crimp_finding_list_free(&findings);
            crimp_component_list_free(&comps);
            return 1;
        }
        crimp_finding_list_free(&findings);
        crimp_component_list_free(&comps);
    }

    /* 4. An unknown/empty version (component identified but version text
     * didn't parse) must never be judged affected either way - skipped
     * safely, no finding, no crash. */
    {
        crimp_component_list comps;
        crimp_component_list_init(&comps);
        add_component(&comps, "OpenSSL", "", "a");

        crimp_finding_list findings;
        crimp_finding_list_init(&findings);
        crimp_cve_match_components(dataset_path, &comps, &findings);
        if (findings.count != 0) {
            fprintf(stderr,
                    "FAIL: expected 0 findings for a component with an empty version, got %zu\n",
                    findings.count);
            crimp_finding_list_free(&findings);
            crimp_component_list_free(&comps);
            return 1;
        }
        crimp_finding_list_free(&findings);
        crimp_component_list_free(&comps);
    }

    /* 5. A component name absent from the dataset produces no findings. */
    {
        crimp_component_list comps;
        crimp_component_list_init(&comps);
        add_component(&comps, "Dropbear", "2020.79", "a");

        crimp_finding_list findings;
        crimp_finding_list_init(&findings);
        crimp_cve_match_components(dataset_path, &comps, &findings);
        if (findings.count != 0) {
            fprintf(stderr,
                    "FAIL: expected 0 findings for a component absent from the dataset, got "
                    "%zu\n",
                    findings.count);
            crimp_finding_list_free(&findings);
            crimp_component_list_free(&comps);
            return 1;
        }
        crimp_finding_list_free(&findings);
        crimp_component_list_free(&comps);
    }

    /* 6. Multiple components map to different dataset entries in one pass. */
    {
        crimp_component_list comps;
        crimp_component_list_init(&comps);
        add_component(&comps, "OpenSSL", "1.1.1a", "a");
        add_component(&comps, "BusyBox", "1.30.0", "b");

        crimp_finding_list findings;
        crimp_finding_list_init(&findings);
        crimp_cve_match_components(dataset_path, &comps, &findings);
        if (find_finding(&findings, "CVE-2022-0778") < 0 ||
            find_finding(&findings, "CVE-BUSYBOX-TEST") < 0) {
            fprintf(stderr,
                    "FAIL: expected matches for both OpenSSL and BusyBox components, got %zu "
                    "finding(s)\n",
                    findings.count);
            crimp_finding_list_free(&findings);
            crimp_component_list_free(&comps);
            return 1;
        }
        crimp_finding_list_free(&findings);
        crimp_component_list_free(&comps);
    }

    /* 7. A missing dataset file fails cleanly. */
    {
        crimp_component_list comps;
        crimp_component_list_init(&comps);
        add_component(&comps, "OpenSSL", "1.0.0", "a");
        crimp_finding_list findings;
        crimp_finding_list_init(&findings);
        if (crimp_cve_match_components("test_fixture_cve_dataset_does_not_exist.yaml", &comps,
                                        &findings) == 0) {
            fprintf(stderr, "FAIL: expected a missing dataset file to be rejected\n");
            crimp_finding_list_free(&findings);
            crimp_component_list_free(&comps);
            return 1;
        }
        if (findings.count != 0) {
            fprintf(stderr, "FAIL: a rejected dataset must add zero findings\n");
        }
        crimp_finding_list_free(&findings);
        crimp_component_list_free(&comps);
    }

    /* 8. Malformed YAML (no top-level 'components' sequence) fails cleanly. */
    {
        const char *bad_path = "test_fixture_cve_dataset_bad.yaml";
        write_file(bad_path, "not_components: []\n");
        crimp_component_list comps;
        crimp_component_list_init(&comps);
        crimp_finding_list findings;
        crimp_finding_list_init(&findings);
        if (crimp_cve_match_components(bad_path, &comps, &findings) == 0) {
            fprintf(stderr,
                    "FAIL: expected a dataset missing the top-level 'components' key to be "
                    "rejected\n");
            crimp_finding_list_free(&findings);
            crimp_component_list_free(&comps);
            return 1;
        }
        crimp_finding_list_free(&findings);
        crimp_component_list_free(&comps);
    }

    printf("PASS: CVE dataset loading, version-range matching, and edge cases all work\n");
    return 0;
}
