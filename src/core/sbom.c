#include "crimp/sbom.h"

static void write_json_string(FILE *out, const char *s) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
            case '"':
                fputs("\\\"", out);
                break;
            case '\\':
                fputs("\\\\", out);
                break;
            case '\n':
                fputs("\\n", out);
                break;
            case '\r':
                fputs("\\r", out);
                break;
            case '\t':
                fputs("\\t", out);
                break;
            default:
                if (*p < 0x20) {
                    fprintf(out, "\\u%04x", *p);
                } else {
                    fputc(*p, out);
                }
        }
    }
    fputc('"', out);
}

void crimp_sbom_write_cyclonedx(const crimp_component_list *components, FILE *out) {
    fputs("{\n", out);
    fputs("  \"bomFormat\": \"CycloneDX\",\n", out);
    fputs("  \"specVersion\": \"1.6\",\n", out);
    fputs("  \"version\": 1,\n", out);
    fputs("  \"components\": [\n", out);

    for (size_t i = 0; i < components->count; i++) {
        const crimp_component *c = &components->items[i];

        fputs("    {\n", out);
        fputs("      \"type\": \"library\",\n", out);
        fputs("      \"name\": ", out);
        write_json_string(out, c->component);
        fputs(",\n", out);

        if (c->version[0] != '\0') {
            fputs("      \"version\": ", out);
            write_json_string(out, c->version);
            fputs(",\n", out);
        }

        fputs("      \"evidence\": {\n", out);
        fputs("        \"occurrences\": [\n", out);
        fputs("          { \"location\": ", out);
        write_json_string(out, c->path);
        fputs(" }\n", out);
        fputs("        ]\n", out);
        fputs("      }\n", out);
        fputs(i + 1 < components->count ? "    },\n" : "    }\n", out);
    }

    fputs("  ]\n", out);
    fputs("}\n", out);
}
