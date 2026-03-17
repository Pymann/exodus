// Rule 10.3.1: unnamed namespaces should not appear in header files
namespace {
static int rule_10_3_1_header_value = 0; // Violation
}

