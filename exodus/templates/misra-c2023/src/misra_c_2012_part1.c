/*
 * Exhaustive MISRA C:2012 Violation Templates
 * This file attempts to trigger violations for every MISRA C:2012 rule sequentially.
 */

// #include <stdio.h>    // Rule 21.6: The stdio.h library shall not be used
// #include <stdlib.h>   // Rule 21.3: The memory allocation library shall not be used
// #include <setjmp.h>   // Rule 21.4: The setjmp macro and longjmp function shall not be used
// #include <signal.h>   // Rule 21.5: The signal.h library shall not be used
// #include <time.h>     // Rule 21.10: The time.h library shall not be used
// #include <tgmath.h>   // Rule 21.11: The tgmath.h library shall not be used
// #include <fenv.h>     // Rule 21.12: The fenv.h library shall not be used
// #include <stdarg.h>   // Rule 17.1: The features of <stdarg.h> shall not be used

// Rule 1.1: The program shall contain no violations of the standard C syntax and constraints (Intentionally hard to do without fatal compiler errors, omitting syntax error)
// Rule 1.2: Language extensions should not be used
int gcc_extension_asm(void) {
    __asm__("nop"); // Extension
    int x = ({ int y = 1; y; }); // GNU statement-expression extension
    (void)x;
    return 0;
}

// Rule 1.1: translation limits should not be exceeded
int identifier_name_exceeding_translation_limit_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx = 0; // Violation

// Rule 1.3: undefined/critical unspecified behavior shall not occur
void rule_1_3(void) {
    int z = 1 / 0; // Violation
    (void)z;
}

// Rule 1.4: emergent language features shall not be used
_BitInt(9) rule_1_4_emergent = 1; // Violation

// Rule 1.5: obsolescent language features shall not be used
void rule_1_5(void) {
    register int r = 0; // Violation
    (void)r;
}

// Rule 2.1: A project shall not contain unreachable code
int rule_2_1(void) {
    return 0;
    int x = 1; // Violation
}

// Rule 2.2: There shall be no dead code
void rule_2_2(void) {
    int v;
    v = 1; // Violation if v is never read
}

// Rule 2.3: A project should not contain unused type declarations
typedef int unused_type_t; // Violation

// Rule 2.4: A project should not contain unused tag declarations
struct unused_struct { int a; }; // Violation

// Rule 2.5: A project should not contain unused macro declarations
#define UNUSED_MACRO 42 // Violation

// Rule 2.6: A function should not contain unused label declarations
void rule_2_6(void) {
unused_label: // Violation
    return;
}

// Rule 2.7: There should be no unused parameters in functions
void rule_2_7(int unused_param) { // Violation
}

// Rule 3.1: The character sequences /* and // shall not be used within a comment
/* This is a comment /* Nested comment */ 

// Rule 3.2: Line-splicing shall not be used in // comments
// This comment is spliced \
   and continues here // Violation

// Rule 4.1: Octal and hexadecimal escape sequences shall be terminated
const char* rule_4_1 = "\x1g"; // Violation (not valid hex, or poorly terminated)

// Rule 4.2: Trigraphs shall not be used
const char* rule_4_2 = "??="; // Violation

// Rule 5.1: External identifiers shall be distinct
int external_id_very_long_name_1;
int external_id_very_long_name_2; // Violation if length limit applied

// Rule 5.2: Identifiers declared in the same scope and name space shall be distinct
// Rule 5.3: An identifier declared in an inner scope shall not hide an identifier in an outer scope
int rule_5_3_var = 0;
void rule_5_3(void) {
    int rule_5_3_var = 1; // Violation (hiding)
}

// Rule 5.4: Macro identifiers shall be distinct
#define MACRO_A 1
// #define MACRO_B 2 // Omitting to save space

// Rule 5.5: Identifiers shall be distinct from macro names
int MACRO_A; // Violation

// Rule 5.6: A typedef name shall be a unique identifier
typedef int my_type_t;
void rule_5_6(void) {
    int my_type_t = 0; // Violation
}

// Rule 5.7: A tag name shall be a unique identifier
struct my_struct_tag { int a; };
void rule_5_7(void) {
    int my_struct_tag = 0; // Violation
}

// Rule 5.8: Identifiers that define objects or functions with external linkage shall be unique
// Rule 5.9: Identifiers that define objects or functions with internal linkage shall be unique

// Rule 6.1: Bit-fields shall only be declared with an appropriate type
struct rule_6_1_s {
    int b : 1; // Violation (should be explicitly signed or unsigned)
};

// Rule 6.2: Single-bit named bit fields shall not be of a signed type
struct rule_6_2_s {
    signed int b : 1; // Violation
};

// Rule 7.1: Octal constants shall not be used
int rule_7_1 = 0123; // Violation

// Rule 7.2: A 'u' or 'U' suffix shall be applied to all integer constants that are represented in an unsigned type
unsigned int rule_7_2 = 1000000000; // Violation (no U suffix)

// Rule 7.3: The lowercase character 'l' shall not be used in a literal suffix
long str_7_3 = 123l; // Violation

// Rule 7.4: A string literal shall not be assigned to an object unless the object's type is "pointer to const-qualified char"
char *rule_7_4 = "literal"; // Violation

// Rule 8.1: Types shall be explicitly specified
extern rule_8_1_var; // Violation (implicit int)
extern implicit_func_decl(); // Violation (implicit int function declaration)

// Rule 8.2: Function types shall be in prototype form with named parameters
void rule_8_2(int); // Violation (parameter unnamed)

// Rule 8.3: All declarations of an object or function shall use the same names and type qualifiers
void rule_8_3_func(int a);
void rule_8_3_func(int b) {} // Violation (different param name)

// Rule 8.4: A compatible declaration shall be visible when an object or function with external linkage is defined
int rule_8_4_func(void) { return 0; } // Violation (no previous declaration)

// Rule 8.5: An external object or function shall be declared once in one and only one file
// Rule 8.6: An identifier with external linkage shall have exactly one external definition

// Rule 8.7: Functions and objects should not be defined with external linkage if they are referenced in only one translation unit
int rule_8_7_var = 1; // Violation (should be static)

// Rule 8.8: The static storage class specifier shall be used in all declarations of objects and functions that have internal linkage
static int rule_8_8_func(void);
int rule_8_8_func(void) { return 0; } // Violation: defined without static

// Rule 8.9: An object should be defined at block scope if its identifier only appears in a single function
int rule_8_9_var_test = 0; // Violation
void rule_8_9_func(void) {
    rule_8_9_var_test = 1;
}

// Rule 8.10: An inline function shall be declared with the static storage class
inline void rule_8_10(void) {} // Violation (missing static)

// Rule 8.11: When an array with external linkage is declared, its size should be explicitly specified
extern int rule_8_11_arr[]; // Violation

// Rule 8.12: Within an enumerator list, the value of an implicitly-specified enumeration constant shall be unique
enum rule_8_12_e { E1 = 1, E2, E3 = 2 }; // Violation (E2=2, E3=2)
enum rule_8_12_e_b { E10 = 0, E11 = 0, E12 }; // Violation candidate for duplicate implicit values

// Rule 8.13: A pointer should point to a const-qualified type whenever possible
void rule_8_13(int *p) { // Violation (if *p is not modified)
    int a = *p;
}
void rule_8_13_ok(int *p) { // OK (modified)
    *p = 1;
}

// Rule 8.14: The restrict type qualifier shall not be used
void rule_8_14(int * restrict p) {} // Violation

// Rule 9.1: The value of an object with automatic storage duration shall not be read before it has been set
void rule_9_1(void) {
    int a;
    int b = a; // Violation
}

// Rule 9.2: The initializer for an aggregate or union shall be enclosed in braces
int rule_9_2[2][2] = { 1, 2, 3, 4 }; // Violation

// Rule 9.3: Arrays shall not be partially initialized
int rule_9_3[3] = { 1, 2 }; // Violation

// Rule 9.4: An element of an object shall not be initialized more than once
int rule_9_4[2] = { [0] = 1, [0] = 2 }; // Violation

// Rule 9.5: Where designated initializers are used to initialize an array object the size of the array shall be specified explicitly
int rule_9_5_arr[] = { [0] = 1, [5] = 2 }; // Violation

#define UNUSED_MACRO_PHASE_6 42

void rule_phase_6_unused_code(void) {
    typedef int unused_typedef_phase6;
    struct unused_struct_phase6 { int a; };
    enum unused_enum_phase6 { A, B };
    
    int x = 0;
    goto my_label;
my_label:
    x++;
    
unused_label_phase6:
    x++;
}

// Rule 3.2: Line-splicing shall not be used in // comments
// This is a line-spliced comment \
   that should be flagged!

// Rule 4.1: Octal and hexadecimal escape sequences shall be terminated
const char* rule_4_1_bad = "\x12text"; // Violation: not terminated
const char* rule_4_1_good1 = "\x12" "text"; // OK: terminated by "
const char* rule_4_1_good2 = "\x12\n"; // OK: terminated by \

// Rule 5.1: External identifiers shall be distinct (within 31 characters)
int abcdefghijklmnopqrstuvwxyz123456_A = 0;
int abcdefghijklmnopqrstuvwxyz123456_B = 1; // Violation: same first 31 chars

void rule_phase_8_unused_code(void) {
    // Rule 5.2: Scope identifiers distinct (within 63 characters)
    int abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1_A = 0;
    int abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1_B = 1; // Violation 5.2
}

// Rule 5.4: Macro identifiers shall be distinct within 31 characters
#define VERY_LONG_MACRO_NAME_EXCEEDING_31_CHARS_A 1
#define VERY_LONG_MACRO_NAME_EXCEEDING_31_CHARS_B 2 // Violation 5.4

// Rule 5.5: Identifiers shall be distinct from macro names
int IDENTIFIER_BEFORE_MACRO = 5;
#define IDENTIFIER_BEFORE_MACRO 100 // Violation 5.5

// Rule 5.6 & 5.7: Typedef and Tag names shall be unique
typedef int MyUniqueTypedef;
struct MyUniqueTag { int x; };

void rule_phase_9_test(void) {
    int MyUniqueTypedef = 5; // Violation 5.6 (and 5.3)
    int MyUniqueTag = 10;    // Violation 5.7 (and 5.3)
}

// Cross-TU tests for Rules 5.8 and 5.9
int cross_tu_global_var = 1;
static int cross_tu_internal_var = 1;

void rule_phase_11_test(void) {
    // Rule 7.2: Unsigned types require 'U' suffix
    unsigned int unsigned_var = 4000000000; // Violation 7.2

    // Rule 7.4: A string literal shall not be assigned to a non-const pointer
    char *s = "misra_string"; // Violation 7.4
}

// Rule 8.5: Declared in multiple files
extern int my_rule_8_5_var;

// Rule 8.7: Referenced in only one TU, should be static
int rule_8_7_var = 10;
void test_8_7(void);
void test_8_7(void) {
    rule_8_7_var++; // Violation 8.7
}


/* NOTE: Section 10-22 will be continued below */
