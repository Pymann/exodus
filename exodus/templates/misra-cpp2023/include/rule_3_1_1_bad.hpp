/*
 * Deliberate ODR-risky header content for a legacy MISRA C++:2008 3-1-1 template.
 */

int rule_3_1_1_header_global = 1;  // Violation: definition in header

int rule_3_1_1_header_func() {     // Violation: non-inline function definition in header
    return rule_3_1_1_header_global;
}
