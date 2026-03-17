/*
 * Mixed legacy fixtures reused for MISRA C++:2023 analysis.
 */

#include <iostream>
#include <cstdio>     // Rule 30.0.1: The standard header file <cstdio> shall not be used
#include <cstring>
#include <cstdlib>
#include <cstdarg>    // Rule 21.10.1: features of <cstdarg> shall not be used
#include <setjmp.h>   // Rule 21.10.2: the standard header file <setjmp.h> shall not be used
#include <signal.h>   // Rule 21.10.3: the standard header file <signal.h> shall not be used
#include <time.h>     // Rule 0.1.2: return value should be used

// Legacy 8-0-1: external object/function should be declared once in one file
extern int rule_8_0_1_multi_decl;

// Rule 0.0.1: A function shall not contain unreachable statements
void rule_0_1_1() {
    return;
    int x = 0; // Violation
}

// Legacy 0-1-3: A project shall not contain unused variables
void rule_0_1_3() {
    int unused_var = 5; // Violation
}

// Legacy 0-1-12: There shall be no unused variables in functions
void rule_0_1_12() {
    int never_used_local = 42; // Violation
}

// Legacy 0-1-4: A project shall not contain non-volatile POD variables with only one use
void rule_0_1_4() {
    int x = 5; // Violation if never used again
}

// Rule 5.7.1: The character sequence /* shall not be used within a C-style comment.
void rule_2_7_1() {
    /* This is a comment /* with a nested comment */ // Violation
}

// Rule 5.7.3: Trigraphs shall not be used
void rule_2_3_1() {
    const char* str = "??="; // Violation
}

// Legacy 2-5-1: Digraphs should not be used
// <% %> <: :> %: %:%:
void rule_2_5_1() {
}

// Legacy 2-10-2: Identifiers declared in an inner scope shall not hide an identifier in an outer scope
int rule_2_10_2_var = 0;
void rule_2_10_2() {
    int rule_2_10_2_var = 1; // Violation
}

// Legacy 2-10-3: A typedef name shall be a unique identifier
typedef int Rule_2_10_3_T;
typedef int Rule_2_10_3_T; // Violation

// Legacy 2-10-4: A class, union or enum name shall be a unique identifier
struct Rule_2_10_4_Tag {};
union Rule_2_10_4_Tag { int x; }; // Violation

// Legacy 2-7-2: Sections of code shall not be "commented out" using C-style comments
/* if (true) { return; } */
void rule_2_7_2() {
}

// Legacy 2-10-1: Different identifiers shall be typographically unambiguous
int ItemCount = 0;
int ltemCount = 1; // lowercase l to mimic uppercase I

// Legacy 2-10-5: Identifier name of non-member object/function with static storage duration should not be reused
namespace rule_2_10_5_ns_a { static int reused_name = 0; }
namespace rule_2_10_5_ns_b { static int reused_name = 1; }

// Legacy 2-10-6: Type and object/function identifiers should not be reused in the same scope
namespace rule_2_10_6_ns {
struct shared_name_type {};
}
int rule_2_10_6_ns = 0; // Violation
typedef int rule_2_10_6_name_t;
int rule_2_10_6_name_t() { return 0; } // Violation

// Legacy 3-1-3: When an array is declared, its size shall be explicitly specified
extern int rule_3_1_3_arr[]; // Violation (external linkage, size omitted)
extern int rule_3_2_4_missing_def; // Used but never defined (maps from C 8.6 -> C++ 3-2-4)

// Legacy 3-3-2: Internal-linkage function re-declarations should include static in all declarations
namespace {
int rule_3_3_2_internal_decl(); // Violation (internal linkage, missing static)
int rule_3_3_2_internal_decl() { return 1; } // Violation (internal linkage, missing static)
}

// Rule 5.13.3: Octal constants shall not be used
int rule_2_13_2 = 0123; // Violation

// Legacy 2-13-3: A "U" suffix shall be applied to all octal or hexadecimal integer constants of unsigned type
unsigned int rule_2_13_3 = 0x123; // Violation (Missing U)
unsigned int rule_2_13_3_b = 0xFFFFFFFF; // Violation (Missing U)

// Rule 5.13.1: Only documented escape sequences shall be used
const char* rule_2_13_1_bad_escape = "\q"; // Violation

// Rule 5.13.5: Literal suffixes shall be upper case
float rule_2_13_4 = 1.0f; // Violation (lowercase f)

// Legacy 3-1-2: Functions shall not be declared at block scope
void rule_3_1_2() {
    void inner_func(); // Violation
}

// Legacy 4-10-2: Literal zero (0) shall not be used as the null-pointer-constant
void rule_4_10_2() {
    int* ptr = 0; // Violation
}

// Legacy 5-0-4: An implicit integral conversion shall not change the signedness of the underlying type
void rule_5_0_4() {
    int s = -1;
    unsigned int u = s; // Violation
}

// Rule 8.2.2: C-style casts and functional notation casts shall not be used
void rule_5_2_4() {
    float f = 1.0f;
    int i = (int)f; // Violation
    int j = int(f); // Violation
}

// Rule 8.2.3: A cast shall not remove any const or volatile qualification
void rule_5_2_5() {
    const int c = 5;
    int* p = (int*)&c; // Violation
}

// Rule 8.2.4: A cast shall not convert a pointer to a function to any other pointer type
void rule_5_2_6_func() {}
void rule_5_2_6() {
    void* p = (void*)rule_5_2_6_func; // Violation
}

// Legacy 5-2-7: An object with pointer type shall not be converted to an unrelated pointer type
void rule_5_2_7() {
    int i = 0;
    float* f = (float*)&i; // Violation
}

// Legacy 5-2-9: A cast should not convert a pointer type to an integral type
void rule_5_2_9() {
    int* p = nullptr;
    int i = (int)p; // Violation
}

// Legacy 5-3-1: Each operand of the ! operator, the logical && or || operators shall have type bool
void rule_5_3_1() {
    int x = 5;
    if (!x) {} // Violation
}

// Legacy 5-3-2: The unary minus operator shall not be applied to an expression whose underlying type is unsigned
void rule_5_3_2() {
    unsigned int u = 5U;
    unsigned int v = -u; // Violation
}

// Legacy 5-8-1: The right hand operand of a shift operator shall lie between zero and one less than the width in bits of the left hand operand.
void rule_5_8_1() {
    unsigned int u = 1U;
    unsigned int v = u << 32; // Violation
}

// Rule 8.14.1: The right hand operand of a logical && or || operator shall not contain side effects
void rule_5_14_1() {
    int x = 0;
    int y = 0;
    if (x == 0 && y++ == 0) {} // Violation
}

// Rule 8.18.2: Assignment operators shall not be used in sub-expressions
void rule_6_2_1() {
    int a, b;
    if ((a = b)) {} // Violation
}

// Rule 9.3.1: The statement forming the body of a switch, while, do ... while or for statement shall be a compound statement
void rule_6_3_1() {
    while(false)
        return; // Violation (no braces)
}

// Legacy 6-4-3: A switch statement shall be a well-formed switch statement (Needs default)
void rule_6_4_3(int a) {
    switch (a) { // Violation (no default)
        case 1: break;
    }
}

// Legacy 6-4-5: An unconditional throw or break statement shall terminate every non-empty switch-clause
void rule_6_4_5(int a) {
    switch (a) {
        case 1:
            a++; // Violation (missing break)
        default:
            break;
    }
}

// Legacy 6-6-1: Any label referenced by a goto statement shall be declared in the same block, or in a block enclosing the goto
void rule_6_6_1() {
    goto label; // Violation
label:
    return;
}

// Legacy 6-6-1: goto shall not jump into a block
void rule_6_6_1_jump_into_block() {
    goto inner_label; // Violation
    {
inner_label:
        ;
    }
}

// Legacy 6-6-2: A goto statement shall jump to a label declared later in the same function
void rule_6_6_2() {
label:
    goto label; // Violation (backward jump)
}

// Legacy 6-4-7: A switch-expression shall not have essentially Boolean type
void rule_6_4_7() {
    bool b = true;
    switch (b) { // Violation
        case 0: break;
        default: break;
    }
}

// Legacy 6-6-5: A function shall have a single point of exit at the end
int rule_6_6_5(bool cond) {
    if (cond) return 1; // Violation
    return 0;
}

// Rule 9.4.1: if ... else if chains shall terminate with else
void rule_6_4_1(int x) {
    if (x == 0) {
        x = 1;
    } else if (x == 1) {
        x = 2;
    } // Violation
}

// Legacy 8-4-2: Function declarations shall use the same parameter names and qualifiers
int rule_8_4_2(int lhs);
int rule_8_4_2(int rhs) { return rhs; } // Violation (parameter name mismatch)

// Rule 9.6.5: All exit paths from non-void function shall return a value
int rule_8_4_3(bool cond) {
    if (cond) {
        return 1;
    }
} // Violation

// Rule 11.6.2: Variables shall not be used before they have been set
int rule_8_5_1() {
    int x;
    return x; // Violation
}

// Rule 6.0.3: The global namespace shall only contain main, namespace declarations and extern "C" declarations
int global_var = 0; // Violation

// Rule 0.2.3: Types with limited visibility should be used at least once
typedef int rule_0_1_5_unused_typedef;

// Rule 0.2.4: Every defined function should be called at least once
static int rule_0_1_10_unused_internal() {
    return 7;
}

// Legacy 0-1-8: A void function should have external side effects
static void rule_0_1_8_no_side_effect() {
    int local_value = 0;
    (void)local_value;
}

// Rule 4.1.3: Undefined behavior (division by zero)
int rule_0_1_6_div_zero() {
    return 1 / 0; // Violation
}

// Rule 4.6.1: Value under different evaluation orders
int rule_0_1_7_eval_order() {
    int i = 0;
    i = i++ + 1; // Violation
    return i;
}

// Rule 0.1.2: Error information should not be discarded
void rule_0_3_2_ignore_error_info() {
    fopen("missing.txt", "r"); // Violation
}

// Legacy 5-3-4: sizeof operand should have no side effects
void rule_5_3_4() {
    int i = 0;
    (void)sizeof(i++); // Violation
}

// Rule 8.19.1: The comma operator should not be used
int rule_5_18_1() {
    int a = 0;
    int b = (a++, a + 1); // Violation
    return b;
}

// Legacy 5-0-15: Pointer arithmetic should not be used
void rule_5_0_15() {
    int arr[4] = {0, 1, 2, 3};
    int* p = arr;
    p = p + 1; // Violation
}

// Rule 8.2.10: Functions shall not call themselves directly
int rule_7_5_4(int n) {
    if (n <= 0) {
        return 0;
    }
    return rule_7_5_4(n - 1); // Violation
}

// Legacy 8-5-2: Braces shall match aggregate structure
struct Rule_8_5_2_S {
    int a[2];
};
Rule_8_5_2_S rule_8_5_2_s = {1, 2}; // Violation
struct Rule_8_5_2_Outer {
    Rule_8_5_2_S members[2];
};
Rule_8_5_2_Outer rule_8_5_2_outer = {1, 2, 3, 4}; // Violation

// Legacy 8-4-4: A function identifier shall either be used to call the function or it shall be preceded by &
void func() {}
void rule_8_4_4() {
    void (*p)() = func; // Violation (missing &)
}

// Legacy 8-5-2: Braces shall be used to indicate and match the structure in the non-zero initialization of arrays and structures
int rule_8_5_2[2][2] = { 1, 2, 3, 4 }; // Violation

// Legacy 9-3-1: const member functions shall not return non-const pointers or references to class-data
class Rule9_3_1_Class {
    int data;
public:
    int* get_data() const { return (int*)&data; } // Violation
};

// Rule 12.3.1: Unions shall not be used
union Rule_9_5_1_Union {
    int a;
    float b;
};

// Legacy 16-2-1: The pre-processor shall only be used for file inclusion and include guards
#define MACRO_VAL 5 // Violation
#undef MACRO_VAL    // Violation
# // Rule 19.0.1: # token shall be followed by a preprocessing token

// Rule 18.4.1: Dynamic heap memory allocation shall not be used
void rule_18_4_1() {
    int* p = new int(5); // Violation
    delete p;            // Violation
}

// Rule 30.0.1: The stream I/O functions <cstdio> shall not be used
void rule_27_0_1() {
    printf("Hello\n"); // Violation
}

void rule_18_0_2_3_4() {
    (void)atoi("123"); // Legacy 18-0-2
    time(nullptr);     // Legacy 18-0-4
    exit(1);           // Legacy 18-0-3
}

int main() {
    rule_0_1_1();
    rule_0_1_3();
    rule_0_1_12();
    rule_0_1_4();
    rule_2_3_1();
    rule_2_5_1();
    rule_2_7_1();
    rule_2_7_2();
    rule_2_10_2();
    ItemCount += ltemCount;
    rule_3_1_2();
    rule_3_3_2_internal_decl();
    (void)rule_3_2_4_missing_def;
    rule_4_10_2();
    rule_5_0_4();
    rule_5_2_4();
    rule_5_2_5();
    rule_5_2_6();
    rule_5_2_7();
    rule_5_2_9();
    rule_5_3_1();
    rule_5_3_2();
    rule_5_8_1();
    rule_5_14_1();
    rule_6_2_1();
    rule_6_3_1();
    rule_6_4_3(1);
    rule_6_4_5(1);
    rule_6_6_1();
    rule_6_6_1_jump_into_block();
    rule_6_6_2();
    rule_6_4_7();
    rule_6_6_5(true);
    rule_6_4_1(1);
    rule_8_4_2(1);
    rule_8_4_3(true);
    rule_8_5_1();
    rule_8_4_4();
    (void)rule_0_1_6_div_zero();
    (void)rule_0_1_7_eval_order();
    rule_0_3_2_ignore_error_info();
    rule_5_3_4();
    (void)rule_5_18_1();
    rule_5_0_15();
    (void)rule_7_5_4(2);
    rule_18_0_2_3_4();
    rule_18_4_1();
    rule_27_0_1();
    return 0;
}
