/*
 * Exhaustive MISRA C:2012 Violation Templates - Part 2 (Sections 10-22)
 */

// #include <stdio.h>
// #include <stdint.h>

// Cross-TU tests for Rules 5.8 and 5.9
float cross_tu_global_var = 2.0f;
static int cross_tu_internal_var = 2;

// Rule 8.5
extern int my_rule_8_5_var;

// Rule 8.4
#include <stdlib.h>
#include <stdarg.h> // Rule 17.1 violation
#include <string.h>
#include <ctype.h>
#include <threads.h>
#include <stdatomic.h>
// #include <stddef.h>
// #include <math.h>

typedef unsigned long size_t;
typedef long ptrdiff_t;

// Helper types
typedef float float32_t;
typedef int int32_t;
typedef unsigned int uint32_t;

// Rule 10.1: Operands shall not be of an inappropriate essential type
void rule_10_1(void) {
    int32_t a = 1;
    float32_t b = 2.0f;
    int32_t c = a & b; // Violation: Float in bitwise
}

// Rule 10.2: Expressions of essentially character type shall not be used inappropriately in addition and subtraction
void rule_10_2(void) {
    char a = 'a';
    char b = 'b';
    int32_t c = a + b; // Violation
}

// Rule 10.3: The value of an expression shall not be assigned to an object with a narrower essential type or of a different essential type category
void rule_10_3(void) {
    int32_t a = -1;
    uint32_t b = a; // Violation
}

// Rule 10.4: Both operands of an operator in which the usual arithmetic conversions are performed shall have the same essential type category
void rule_10_4(void) {
    int32_t a = 5;
    float32_t b = 5.0f;
    int32_t c = (a == b); // Violation
}

// Rule 10.5: The value of an expression should not be cast to an inappropriate essential type
void rule_10_5(void) {
    float32_t a = 1.0f;
    _Bool b = (_Bool)a; // Violation
}

// Rule 10.6: The value of a composite expression shall not be assigned to an object with wider essential type
void rule_10_6(void) {
    uint32_t u32a;
    unsigned short u16a = 1, u16b = 2;
    u32a = u16a + u16b; // Violation
}

// Rule 10.7: If a composite expression is used as one operand of an operator..., the other operand shall not have wider essential type
void rule_10_7(void) {
    uint32_t u32a = 1;
    unsigned short u16a = 1, u16b = 2;
    uint32_t u32b = (u16a + u16b) + u32a; // Violation
}

// Rule 10.8: The value of a composite expression shall not be cast to a different essential type category or wider essential type
void rule_10_8(void) {
    unsigned short u16a = 1, u16b = 2;
    uint32_t u32a = (uint32_t)(u16a + u16b); // Violation
}

// Rule 11.1: Conversions shall not be performed between a pointer to a function and any other type
void rule_11_1(void) {
    void (*pf)(void) = NULL;
    long i = (long)pf; // Violation
    (void)i;
}

// Rule 11.2: Conversions shall not be performed between a pointer to an incomplete type and any other type
struct incomplete;
void rule_11_2(struct incomplete *pi) {
    void *pv = pi; // Violation
}

// Rule 11.3: A cast shall not be performed between a pointer to object type and a pointer to a different object type
void rule_11_3(void) {
    uint32_t a = 0;
    float32_t *p = (float32_t *)&a; // Violation
}

// Rule 11.4: A conversion should not be performed between a pointer to object and an integer type
void rule_11_4(void) {
    int32_t *p = (int32_t *)0x1000; // Violation
}

// Rule 11.5: A conversion should not be performed from pointer to void into pointer to object
void rule_11_5(void) {
    void *pv;
    int32_t *pi = (int32_t *)pv; // Violation
}

// Rule 11.6: A cast shall not be performed between pointer to void and an arithmetic type
void rule_11_6(void) {
    int32_t i;
    void *pv = (void *)i; // Violation
}

// Rule 11.7: A cast shall not be performed between pointer to object and a non-integer arithmetic type
void rule_11_7(void) {
    int32_t *pi;
    float32_t f = (float32_t)pi; // Violation
    double d = (double)pi; // Violation
    (void)d;
}

// Rule 11.8: A cast shall not remove any const or volatile qualification from the type pointed to by a pointer
void rule_11_8(void) {
    const int32_t ci = 0;
    int32_t *pi = (int32_t *)&ci; // Violation
}

// Rule 11.9: The macro NULL shall be the only permitted form of integer null pointer constant
void rule_11_9(void) {
    int32_t *pi = 0; // Violation
}

// Rule 12.1: The precedence of operators within expressions should be made explicit
void rule_12_1(void) {
    int32_t a = 1, b = 2, c = 3;
    int32_t d = a + b << c; // Violation
}

// Rule 12.2: The right hand operand of a shift operator shall lie in the range zero to one less than the width in bits of the essential type
void rule_12_2(void) {
    uint32_t u32a = 1;
    uint32_t u32b = u32a << 32; // Violation
}

// Rule 12.3: The comma operator should not be used
void rule_12_3(void) {
    int32_t a = 1, b = 2; // Fine
    a++, b++; // Violation
}

// Rule 12.4: Evaluation of constant expressions should not lead to unsigned integer wrap-around
void rule_12_4(void) {
    uint32_t a = 0xFFFFFFFF + 1; // Violation
}

// Rule 13.1: Initializer lists shall not contain persistent side effects
int32_t rule_13_1_helper(void) { return 1; }
void rule_13_1(void) {
    int32_t a[2] = { rule_13_1_helper(), 2 }; // Violation
}

// Rule 13.2: The value of an expression and its persistent side effects shall be the same under all permitted evaluation orders
void rule_13_2(void) {
    int32_t a = 0;
    a = a++; // Violation
}

// Rule 13.3: A full expression containing an increment or decrement should have no other potential side effects
void rule_13_3(void) {
    int32_t a = 0;
    int32_t b = a++ + 1; // Violation
}

// Rule 13.4: The result of an assignment operator should not be used
void rule_13_4(void) {
    int32_t a, b;
    if ((a = b)) {} // Violation
}

// Rule 13.5: The right hand operand of a logical && or || operator shall not contain persistent side effects
void rule_13_5(void) {
    int32_t a = 0;
    if (1 || (a++)) {} // Violation
}

// Rule 13.6: The operand of the sizeof operator shall not contain any expression which has potential side effects
void rule_13_6(void) {
    int32_t a = 0;
    size_t s = sizeof(a++); // Violation
}

// Rule 14.1: A loop counter shall not have essentially floating type
void rule_14_1(void) {
    for (float32_t f = 0.0f; f < 1.0f; f += 0.1f) {} // Violation
}

// Rule 14.2: A for loop shall be well-formed
void rule_14_2(void) {
    int i = 0;
    for (i = 0; i < 10; ) { i++; } // Violation (missing clause)
}

// Rule 14.3: Controlling expressions shall not be invariant
void rule_14_3(void) {
    if (1) {} // Violation
}

// Rule 14.4: The controlling expression of an if statement and the controlling expression of an iteration-statement shall have essentially Boolean type
void rule_14_4(void) {
    int32_t a = 5;
    if (a) {} // Violation
}

// Rule 15.1: The goto statement should not be used
void rule_15_1(void) {
    goto L1; // Violation
L1:
    return;
}

// Rule 15.2: The goto statement shall jump to a label declared later in the same function
void rule_15_2(void) {
L1:
    goto L1; // Violation (jumping back)
}

// Rule 15.3: Any label referenced by a goto statement shall be declared in the same block, or in any block enclosing the goto statement
void rule_15_3(void) {
    goto out_label; // Violation
    {
out_label:
        ;
    }
}
// Rule 15.4: There should be no more than one break or goto statement used to terminate any iteration statement
void rule_15_4(void) {
    for (int i = 0; i < 10; ++i) {
        if (i == 2) break;
        if (i == 5) break; // Violation
    }
}

// Rule 15.5: A function should have a single point of exit at the end
int32_t rule_15_5(int32_t a) {
    if (a) return 1; // Violation
    return 0;
}

// Rule 15.6: The body of an iteration-statement or a selection-statement shall be a compound-statement
void rule_15_6(void) {
    if (1) 
        return; // Violation (no braces)
}

// Rule 15.7: All if ... else if constructs shall be terminated with an else statement
void rule_15_7(int32_t a) {
    if (a > 0) {}
    else if (a < 0) {} // Violation (missing else)
}

// Rule 16.1: All switch statements shall be well-formed
void rule_16_1(int32_t type) {
    switch (type) {
        int a = 0; // Violation (code between switch and first case)
        case 1: break;
    }
}

// Rule 16.2: A switch label shall only be used when the most closely-enclosing compound statement is the body of a switch statement
void rule_16_2(int32_t a) {
    switch (a) {
        if (1) {
            case 1: break; // Violation (inside if)
        }
    }
}

// Rule 16.3: An unterminated case clause shall be used only for empty case clauses
void rule_16_3(int32_t a) {
    switch (a) {
        case 1:
            a++; // Violation (missing break)
        case 2:
            break;
    }
}

// Rule 16.4: Every switch statement shall have a default label
void rule_16_4(int32_t a) {
    switch (a) {
        case 1: break; // Violation (missing default)
    }
}

// Rule 16.5: A default label shall appear as either the first or the last switch label of a switch statement
void rule_16_5(int32_t a) {
    switch (a) {
        case 1: break;
        default: break; // Violation (not last)
        case 2: break;
    }
}

// Rule 16.6: Every switch statement shall have at least two switch-clauses
void rule_16_6(int32_t a) {
    switch (a) {
        default: break; // Violation (only one clause)
    }
}

// Rule 16.7: A switch-expression shall not have essentially Boolean type
void rule_16_7(_Bool b) {
    switch (b) { // Violation
        case 0: break;
        default: break;
    }
}

// Rule 17.1: The features of <stdarg.h> shall not be used (violated at top)
// Rule 17.2: Functions shall not call themselves, either directly or indirectly
void rule_17_2(void) {
    rule_17_2(); // Violation
}

// Rule 17.3: A function shall not be declared implicitly
void rule_17_3(void) {
    undeclared_func(); // Violation
    another_undeclared_func(1); // Violation
}

// Rule 17.4: All exit paths from a function with non-void return type shall have an explicit return statement with an expression
int32_t rule_17_4(int32_t a) {
    if (a) return 1;
    // Violation (missing return)
}

// Rule 17.5: The function argument corresponding to a parameter declared to have an array type shall have an appropriate number of elements
void rule_17_5_func(int32_t a[5]) {}
void rule_17_5(void) {
    int32_t arr[3];
    rule_17_5_func(arr); // Violation
}

// Rule 17.6: The declaration of an array parameter shall not contain the static keyword between the [ ]
void rule_17_6(int32_t a[static 5]) {} // Violation

// Rule 17.7: The value returned by a function having non-void return type shall be used
int32_t rule_17_7_func(void) { return 1; }
void rule_17_7(void) {
    rule_17_7_func(); // Violation
}

// Rule 17.8: A function parameter should not be modified
void rule_17_8(int32_t a) {
    a++; // Violation
}

// Rule 18.1: A pointer resulting from addition or subtraction shall address an element of the same array
void rule_18_1(void) {
    int32_t a[5];
    int32_t *p = a + 6; // Violation
}

// Rule 18.2: Subtraction between pointers shall only be applied to pointers that address elements of the same array
void rule_18_2(void) {
    int32_t a[5], b[5];
    ptrdiff_t diff = a - b; // Violation
}

// Rule 18.3: The relational operators >, >=, <, <= shall not be applied to objects of pointer type except where they point into the same object
void rule_18_3(void) {
    int32_t a[5];
    int32_t b[5];
    if (a > b) {} // Violation
}

// Rule 18.4: The +, -, += and -= operators should not be applied to an expression of pointer type
void rule_18_4(void) {
    int32_t a[5];
    int32_t *p = a;
    p++; // Violation
}

// Rule 18.5: Declarations should contain no more than two levels of pointer nesting
int32_t ***rule_18_5; // Violation

// Rule 18.6: The address of an object with automatic storage shall not be copied to another object that persists after the first object has ceased to exist
int32_t *rule_18_6_ptr;
void rule_18_6(void) {
    int32_t a;
    rule_18_6_ptr = &a; // Violation
}

// Rule 18.7: Flexible array members shall not be declared
struct rule_18_7_s {
    int32_t a;
    int32_t b[]; // Violation
};

// Rule 18.8: Variable-length array types shall not be used
void rule_18_8(int32_t n) {
    int32_t a[n]; // Violation
}

// Rule 19.1: An object shall not be assigned or copied to an overlapping object
void rule_19_1(void) {
    union { int32_t a[2]; int32_t b[2]; } u;
    u.a[0] = u.b[0]; // Violation
}

// Rule 19.2: The union keyword should not be used
union rule_19_2_u { // Violation
    int32_t a;
    float32_t b;
};

// Rule 20.1: #include directives should only be preceded by preprocessor directives or comments
int rule_20_1_var;
#include <limits.h> // Violation

// Rule 20.2: The ', " or \ characters and the /* or // character sequences shall not occur in a header file name
#include "my/*header.h" // Violation
// Rule 20.3: The \ character shall not be used to splice a macro definition across more than one line
#define SPLICE_MACRO \
    1 // Violation

// Rule 20.3: The #include directive shall be followed by either a <filename> or "filename" sequence
#define INC_FILE "stdio.h"
#include INC_FILE // Violation (should be literal string in most interpretations)

// Rule 20.4: A macro shall not be defined with the same name as a keyword
// (Moved to misra_c_2012_part3_fatal.c because it breaks Clang AST parsing)

// Rule 20.5: #undef should not be used
#define MACRO_C 1
#undef MACRO_C // Violation

// Rule 20.6: Tokens that look like a preprocessing directive shall not occur within a macro argument
#define MACRO_D(x) x
MACRO_D(#define Y 1) // Violation

// Rule 20.7: Expressions resulting from the expansion of macro parameters shall be enclosed in parentheses
#define MACRO_E(x) x * 2 // Violation

// Rule 20.8: The controlling expression of a #if or #elif shall evaluate to 0 or 1
#if 2 // Violation
#endif

// Rule 20.9: All identifiers used in the controlling expression of #if or #elif shall be defined
#if UNDEFINED_MACRO // Violation
#endif

// Rule 20.10: The # and ## preprocessor operators should not be used
#define MACRO_F(a, b) a ## b // Violation

// Rule 20.11: A macro parameter immediately following a # operator shall not immediately be followed by a ## operator
#define MACRO_G(x) #x ## _Suffix // Violation

// Rule 20.12: A macro parameter used as an operand to the # or ## operators...
#define MACRO_H(x) #x x // Violation
// Rule 20.13: A line whose first token is # shall be a valid preprocessing directive
// (Moved to misra_c_2012_part3_fatal.c because it breaks Clang AST parsing)

// Rule 20.14: All #else, #elif and #endif directives shall reside in the same file as the #if or #ifdef directive to which they are related
#if 1
// Missing #endif caused unbalanced file for Rule 20.14 but broke the Clang AST for everything after it.
#endif

// We will test Rule 20.14 by placing an unbalanced #if at the very end of the file.

// Rule 21.2: A reserved identifier or macro name shall not be declared
int __my_var; // Violation

// Rule 21.1: #define and #undef shall not be used on a reserved identifier or reserved macro name
#define __LINE__ 10 // Violation

// Rule 21.3: The memory allocation and deallocation functions of <stdlib.h> shall not be used
void rule_21_3(void) {
    void *p = malloc(10); // Violation
    free(p); // Violation
}

// Rule 21.4: The standard header file <setjmp.h> shall not be used
#include <setjmp.h> // Violation

// Rule 21.5: The standard header file <signal.h> shall not be used
#include <signal.h> // Violation

// Rule 21.6: The Standard Library input/output functions shall not be used
#include <stdio.h> // Violation
void rule_21_6(void) {
    printf("Violation\n"); // Violation
}

// Rule 21.7: The atof, atoi, atol and atoll functions of <stdlib.h> shall not be used
void rule_21_7(void) {
    int32_t a = atoi("123"); // Violation
}

// Rule 21.8: The abort, exit, getenv and system functions of <stdlib.h> shall not be used
void rule_21_8(void) {
    exit(0); // Violation
}

// Rule 21.9: The bsearch and qsort functions of <stdlib.h> shall not be used
void rule_21_9(void) {
    int arr[] = {1};
    bsearch(NULL, arr, 1, 4, NULL); // Violation
}

// Rule 21.10: The Standard Library time and date functions shall not be used
#include <time.h> // Violation

// Rule 21.11: The standard header file <tgmath.h> shall not be used
#include <tgmath.h> // Violation

// Rule 21.12: The standard header file <fenv.h> shall not be used
#include <fenv.h> // Violation

// Rule 21.14: The Standard Library function memcmp shall not be used to compare null terminated strings
void rule_21_14(void) {
    (void)memcmp("abc", "abd", 3); // Violation
}

// Rule 21.13: ctype argument shall be unsigned-char representable or EOF
void rule_21_13(void) {
    (void)isalpha(-2); // Violation
}

// Rule 21.15: memcpy/memmove/memcmp pointer arguments shall have compatible types
void rule_21_15(void) {
    int ia[4] = {0};
    float fa[4] = {0.0f};
    (void)memcmp((int *)ia, (float *)fa, sizeof(ia)); // Violation
}

// Rule 21.16: memcmp pointer arguments shall point to permitted essential types
void rule_21_16(void) {
    float fa[2] = {0.0f};
    (void)memcmp((float *)fa, (float *)fa, sizeof(fa)); // Violation
}

// Rule 21.18: size_t argument to string.h functions shall have appropriate value
void rule_21_18(void) {
    char dst[4] = {0};
    char src[4] = {0};
    (void)memcpy(dst, src, (size_t)-1); // Violation
}

// Rule 21.17: string handling functions shall not access beyond object bounds
void rule_21_17(void) {
    char small[4] = {0};
    (void)strcpy(small, "overflow"); // Violation
}

// Rule 21.19: returned pointers shall be used as pointer-to-const
void rule_21_19(void) {
    char *msg = strerror(1); // Violation
    msg[0] = 'X'; // Violation
}

// Rule 21.20: returned pointer shall not be used after a subsequent call to same function
void rule_21_20(void) {
    time_t now = 0;
    struct tm *first = localtime(&now);
    struct tm *second = localtime(&now);
    int y = first->tm_year; // Violation
    (void)second;
    (void)y;
}

// Rule 21.21: The Standard Library system of <stdlib.h> shall not be used
void rule_21_21(void) {
    (void)system("echo violated"); // Violation
}

// Rule 21.24: The random number generator functions of <stdlib.h> shall not be used
void rule_21_24(void) {
    srand(1U); // Violation
    (void)rand(); // Violation
}

// Rule 22.1: All resources obtained dynamically by means of Standard Library functions shall be explicitly released
void rule_22_1(void) {
    FILE *f = fopen("test.txt", "r"); // Violation (not closed)
}

// Rule 22.2: A block of memory shall only be freed if it was allocated by means of a Standard Library function
void rule_22_2(void) {
    int local = 0;
    free(&local); // Violation
}

// Rule 22.3: The same file shall not be open for read and write access at the same time on different streams
void rule_22_3(void) {
    FILE *fr = fopen("same_file.txt", "r");
    FILE *fw = fopen("same_file.txt", "a+"); // Violation (simultaneous read/write streams)
    (void)fr;
    (void)fw;
    // Intentionally not closing to keep both streams active at analysis end.
}

// Rule 22.4: There shall be no attempt to write to a stream which has been opened as read-only
void rule_22_4(void) {
    FILE *f = fopen("readonly.txt", "r");
    if (f) {
        fputs("write attempt\n", f); // Violation
        fclose(f);
    }
}

// Rule 22.5: A pointer to a FILE object shall not be dereferenced
void rule_22_5(void) {
    FILE *f = fopen("test.txt", "r");
    if (f) {
        FILE copy = *f; // Violation
        fclose(f);
    }
}

// Rule 22.6: The value of a pointer to a FILE shall not be used after the associated stream has been closed
void rule_22_6(void) {
    FILE *f = fopen("closed.txt", "w");
    if (f) {
        fclose(f);
        fputs("use after close\n", f); // Violation
    }
}

// Rule 22.7: The macro EOF shall only be compared with the unmodified return value from a function capable of returning EOF
void rule_22_7(void) {
    int c = fgetc(stdin);
    if (c == EOF) { // Violation
        return;
    }
}

// Rule 22.8: The value of errno shall be set to zero after it is tested.
// Rule 22.9: The value of errno shall be tested against zero after calling an errno-setting-function.
// Rule 22.10: The value of errno shall only be tested when the last function to be called was an errno-setting-function.
void rule_22_8_9_10(void) {
    char *endp = NULL;
    long v = strtol("123", &endp, 10); // Violation 22.8
    (void)v;
    errno = 0;
    v = strtol("456", &endp, 10); // Triggers 22.9 for previous call (untested errno)
    (void)v;
    if (errno != 0) {
        /* tested */
    }
    if (errno == 0) { // Violation 22.10
        /* tested without new errno-setting call */
    }
}

// Rule 22.11: The unbounded functions of string handling shall not be used.
// Rule 22.14: Thread synchronization objects shall be initialized before being accessed.
// Rule 22.16: All mutex objects locked by a thread shall be explicitly unlocked by the same thread.
// Rule 22.17: No thread shall unlock a mutex or call cnd_wait()/cnd_timedwait() for a mutex it has not locked.
// Rule 22.18: Non-recursive mutexes shall not be recursively locked.
// Rule 22.19: A condition variable shall be associated with at most one mutex object.
// Rule 22.20: Thread-specific storage pointers shall be created before being accessed.
void rule_22_threads(void) {
    thrd_t t;
    thrd_join(t, NULL);
    thrd_detach(t); // Violation 22.11

    mtx_t m1, m2;
    cnd_t c;
    tss_t key;

    mtx_lock(&m1); // Violation 22.14
    mtx_init(&m1, mtx_plain);
    mtx_lock(&m1);
    mtx_lock(&m1); // Violation 22.18
    mtx_unlock(&m2); // Violation 22.14 + 22.17

    cnd_init(&c);
    cnd_wait(&c, &m2); // Violation 22.14 + 22.17
    mtx_init(&m2, mtx_plain);
    cnd_wait(&c, &m1);
    cnd_wait(&c, &m2); // Violation 22.19

    (void)tss_get(key); // Violation 22.20
    (void)tss_create(&key, NULL);
    (void)tss_set(key, NULL);
    // m1 intentionally left locked -> Violation 22.16 at function end.
}

// Rule 22.13: Thread objects, thread synchronization objects and thread-specific storage pointers shall have appropriate storage duration.
static thrd_t g_rule_22_13_thread; // Violation 22.13

// Rule 22.12: Thread objects, thread synchronization objects, and thread-specific storage pointers shall only be accessed by the appropriate Standard Library functions.
// Rule 22.15: Thread synchronization objects and thread-specific storage pointers shall not be destroyed until after all threads accessing them have terminated.
void rule_22_12_13_15(void) {
    thrd_t t, u;
    mtx_t m;
    tss_t key;
    cnd_t c;

    thrd_join(u, NULL); // Violation 22.12 (not created by thrd_create in this function)
    (void)(void *)&m; // Violation 22.12 (direct access pattern)

    (void)thrd_create(&t, NULL, NULL);
    (void)tss_create(&key, NULL);
    (void)mtx_init(&m, mtx_plain);
    (void)cnd_init(&c);
    mtx_destroy(&m); // Violation 22.15 (destroy before thread termination)
    (void)thrd_join(t, NULL);
}

// Rule 6.3: A bit field shall not be declared as a member of a union
union rule_6_3_u {
    unsigned int bf : 3; // Violation
    unsigned int v;
};

// Rule 11.10: The _Atomic qualifier shall not be applied to the incomplete type void
_Atomic(void) *rule_11_10_p; // Violation

// Rule 12.5: sizeof operand shall not be array-typed function parameter
void rule_12_5(int arr[]) {
    size_t s = sizeof(arr); // Violation
    (void)s;
}

// Rule 17.10: A function declared with a _Noreturn function specifier shall have void return type.
// Rule 17.9: A function declared with a _Noreturn function specifier shall not return to its caller.
_Noreturn int rule_17_10_bad(void) { // Violation 17.10
    return 1; // Violation 17.9
}

// Rule 18.10: Pointers to variably-modified array types shall not be used
void rule_18_10(int n) {
    int (*p)[n]; // Violation
    (void)p;
}

// Rule 2.8: A project should not contain unused object definitions
int rule_2_8_unused_object = 0; // Violation

// Rule 8.15: The alignment specification of an object shall be consistent with the type.
// Rule 8.16: The alignment specification of zero should not appear in an object declaration.
// Rule 8.17: At most one explicit alignment specifier should appear in an object declaration.
_Alignas(8) int rule_8_15_obj;
_Alignas(16) int rule_8_15_obj; // Violation 8.15
_Alignas(0) int rule_8_16_zero_align; // Violation 8.16
_Alignas(8) _Alignas(16) int rule_8_17_multi_align; // Violation 8.17

// Rule 12.6: Structure and union members of atomic objects shall not be directly accessed
struct rule_12_6_s { int m; };
_Atomic(struct rule_12_6_s) rule_12_6_obj;
void rule_12_6(void) {
    int x = rule_12_6_obj.m; // Violation
    (void)x;
}

// Rule 17.12: Function identifier usage shall be with '&' or a call
int rule_17_12_target(void) { return 0; }
void rule_17_12(void) {
    int (*fp)(void) = rule_17_12_target; // Violation
    (void)fp;
}

_Atomic int rule_21_25_atomic = 0;
// Rule 21.25: memory synchronization operations shall be sequentially consistent
void rule_21_25(void) {
    atomic_store_explicit(&rule_21_25_atomic, 1, memory_order_relaxed); // Violation
}

// Rule 21.26: mtx_timedlock shall only be used with appropriate mutex type
void rule_21_26(void) {
    mtx_t m;
    struct timespec ts = {0};
    (void)mtx_init(&m, mtx_plain);
    (void)mtx_timedlock(&m, &ts); // Violation
}

// Rule 21.22: tgmath macro operands shall have appropriate essential type
void rule_21_22(void) {
    double d = fmax("bad", 1.0); // Violation
    (void)d;
}

// Rule 21.23: multi-argument tgmath operands shall have same standard type
void rule_21_23(void) {
    double d = fmax(1.0f, 2.0); // Violation
    (void)d;
}

// Rule 23.1: A generic selection should be expanded from a macro.
// Rule 23.2: A generic selection that is not expanded from a macro shall not contain potential side effects in the controlling expression.
void rule_23_1_2(void) {
    int x = 0;
    int y = _Generic(++x, int: 1, default: 0); // Violation 23.1 + 23.2
    (void)y;
}

// Rule 23.3: generic selection should contain at least one non-default association
void rule_23_3(void) {
    int x = 0;
    int y = _Generic(x, default: 0); // Violation
    (void)y;
}

// Rule 23.8: default association shall be first or last
void rule_23_8(void) {
    int x = 0;
    int y = _Generic(x, int: 1, default: 0, long: 2); // Violation
    (void)y;
}

// Rule 23.7: macro-expanded generic selection should evaluate argument once
#define RULE_23_7_MACRO(X) _Generic((X), int: (X), default: (X))
void rule_23_7(void) {
    int i = 0;
    int y = RULE_23_7_MACRO(i++); // Violation
    (void)y;
}

// Rule 23.4: generic association shall list appropriate type
void rule_23_4(void) {
    int x = 0;
    int y = _Generic(x, struct bad_type *: 1, default: 0); // Violation
    (void)y;
}

// Rule 23.5: generic selection should not depend on implicit pointer conversion
void rule_23_5(void) {
    int x = 0;
    int y = _Generic((char *)&x, int *: 1, default: 0); // Violation
    (void)y;
}

// Rule 23.6: controlling expression essential type shall match standard type
void rule_23_6(void) {
    enum rule_23_6_e { R23_6_A = 0 } e = R23_6_A;
    int y = _Generic(e, int: 1, default: 0); // Violation
    (void)y;
}

// Rule 7.5: argument of integer-constant macro shall have appropriate form
void rule_7_5(void) {
    intmax_t v = INT32_C(1.5); // Violation
    (void)v;
}

// Rule 7.6: small integer variants of min-width macros shall not be used
void rule_7_6(void) {
    intmax_t v = INT8_C(7); // Violation
    (void)v;
}

// Rule 9.6: chained designator initializer shall not contain non-designated entries
void rule_9_6(void) {
    struct { int a; int b; int c; } s = { .a = 1, 2, .c = 3 }; // Violation
    (void)s;
}

// Rule 9.7: atomic objects shall be initialized before being accessed
void rule_9_7(void) {
    _Atomic int ax;
    int y = atomic_load(&ax); // Violation
    (void)y;
}

// Rule 17.11: non-returning function should be declared _Noreturn
void rule_17_11(void) {
    for (;;) {
    }
}

// Rule 17.13: function type shall not be type qualified
typedef int (*rule_17_13_fn_t)(void) const; // Violation

// Rule 18.9: temporary-lifetime array object shall not undergo array-to-pointer conversion
void rule_18_9(void) {
    int *p = (int[]){1, 2, 3}; // Violation
    (void)p;
}

// Unbalanced #if for Rule 20.14
#if 1
