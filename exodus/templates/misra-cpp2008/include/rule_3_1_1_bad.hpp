/*
 * Deliberate ODR-risky header content for MISRA C++:2008 Rule 3-1-1 template.
 */

int rule_3_1_1_header_global = 1;  // Violation: definition in header

int rule_3_1_1_header_func() {     // Violation: non-inline function definition in header
    return rule_3_1_1_header_global;
}

namespace {                        // Violation: Rule 7-3-3 (unnamed namespace in header)
int rule_7_3_3_header_internal = 0;
}

using namespace std;               // Violation: Rule 7-3-6 (using-directive in header)
