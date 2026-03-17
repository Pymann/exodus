/*
 * Extra MISRA C++:2008 template snippets to trigger cross-translation-unit rules.
 */

#include <cstring>
#include <cstddef>
#include <cerrno>
#include <typeinfo>
#include "r16_2_3_no_guard.hpp" // Rule 16-2-3 violation

// Rule 8-0-1: external object/function should be declared once in one file
extern int rule_8_0_1_multi_decl;

// Rule 2-10-4: tag names should be unique
namespace r2_10_4_a { struct DupTag {}; }
namespace r2_10_4_b { struct DupTag {}; } // Violation

// Rule 2-10-2: inner declarations should not hide outer declarations
int r2_10_2_shadow = 0;
void r2_10_2_fn() {
    int r2_10_2_shadow = 1; // Violation
    (void)r2_10_2_shadow;
}
void r2_10_2_nested() {
    int shadow_name = 0;
    {
        int shadow_name = 1; // Violation
        (void)shadow_name;
    }
    (void)shadow_name;
}

// Rule 0-1-9 / 0-1-12: unused local variable
void r0_1_9_unused_local() {
    int local_unused = 5; // Violation
    int set_only;
    set_only = 1; // Violation
}

// Rule 8-5-1: use before set
int r8_5_1_uninitialized(bool cond) {
    int x;
    if (cond) {
        x = 1;
    }
    return x; // Violation
}

// Rule 0-2-1: overlapping copy
union R0_2_1_U {
    int a;
    float b;
};
void r0_2_1_overlap() {
    R0_2_1_U u;
    u = u; // Violation
    ::memcpy(&u, &u, sizeof(u)); // Violation
}

// Rule 6-4-3: code before first case/default in switch
void r6_4_3_bad_switch(int n) {
    switch (n) {
        n = n + 1; // Violation
        case 1:
            break;
        default:
            break;
    }
}

// Rule 6-4-4: nested switch label placement
void r6_4_4_nested_label(int n) {
    switch (n) {
        case 0: {
            case 1: // Violation
                break;
        }
        default:
            break;
    }
}

// Rule 6-4-2: all switch statements shall be well-formed
void r6_4_2_bad_switch_shape(int n) {
    switch (n) {
        n += 1; // malformed before first case
        case 1:
            break;
        default:
            break;
    }
}

// Rule 6-2-2: floating-point expressions shall not be tested for equality/inequality
void r6_2_2_float_equality() {
    float a = 0.1f;
    float b = 0.2f;
    if (a == b) { // Violation
        a = b;
    }
    if (a != b) { // Violation
        b = a;
    }
}

// Rule 6-2-3: null statement shall only occur on a line by itself
void r6_2_3_inline_null_stmt() {
    if (true) ; // Violation
}

static int r6_step() { return 2; }

// Rule 6-5-1: for loop shall contain a single loop-counter
void r6_5_1_multi_counter() {
    for (int i = 0, j = 0; i < 3; ++i) { // Violation
        j++;
    }
}

// Rule 6-5-2: non ++/-- modification must be by compile-time constant
void r6_5_2_non_const_step() {
    int step = r6_step();
    for (int i = 0; i < 10; i += step) { // Violation
    }
}

// Rule 6-5-3: loop-counter shall not be modified in condition/statement
void r6_5_3_modify_counter_in_condition() {
    for (int i = 0; i++ < 3; ++i) { // Violation
    }
}

// Rule 6-5-4: loop-counter shall be modified by --, ++, -=n, +=n only
void r6_5_4_bad_counter_update() {
    for (int i = 0; i < 3; i = i + 1) { // Violation
    }
}

// Rule 6-5-5 / 6-5-6: non-counter control variable modified in statement (must be bool)
void r6_5_5_6_ctrl_var_modification() {
    int limit = 3;
    for (int i = 0; i < limit; ++i) {
        limit--; // Violation 6-5-5 + 6-5-6
    }
}

// Rule 6-6-3: continue shall only be used in a well-formed for loop
void r6_6_3_continue_while() {
    int i = 0;
    while (i < 2) { // Violation
        i++;
        continue;
    }
}

// Rule 0-3-2: ignored error information
void r0_3_2_ignored_error() {
    fopen("x.txt", "r"); // Violation
}

// Rule 5-3-4: sizeof operand with side effect
void r5_3_4_sizeof_side_effect() {
    int i = 0;
    (void)sizeof(i++); // Violation
}

// Rule 3-2-1 / 3-9-1: declarations shall be compatible / token-identical
extern int rule_8_4_2(double); // Conflicts with int rule_8_4_2(int) in misra_cpp_2008.cpp

// Rule 3-2-3: entity should be declared only once in one TU
int r3_2_3_dup_decl();
int r3_2_3_dup_decl(); // Violation

// Rule 3-9-2: use typedefs indicating size/signedness
int r3_9_2_plain_int = 0; // Violation

// Rule 3-9-3: underlying bit representation of floating point shall not be used
void r3_9_3_float_bits() {
    float f = 1.0f;
    unsigned int* bits = reinterpret_cast<unsigned int*>(&f); // Violation
    (void)bits;
}

// Rule 4-5-1: bool expressions should not be arithmetic operands
void r4_5_1_bool_operand() {
    bool flag = true;
    int x = flag + 1; // Violation
    (void)x;
}

// Rule 4-5-2: enum expressions should not be built-in operator operands (except subscript)
enum R4_5_2_E { R4_5_2_A = 0, R4_5_2_B = 1 };
void r4_5_2_enum_operand() {
    R4_5_2_E e = R4_5_2_A;
    int x = e + 1; // Violation
    (void)x;
}

// Rule 4-5-3: plain char / wchar_t expressions should not be built-in operator operands
void r4_5_3_char_operand() {
    char c = 'a';
    wchar_t wc = L'b';
    int x = c + 1;  // Violation
    int y = wc + 1; // Violation
    (void)x;
    (void)y;
}

// Rule 4-10-1: NULL shall not be used as an integer value
int r4_10_1_null_int = NULL; // Violation

// Rule 5-0-14: first operand of conditional operator shall be bool
int r5_0_14_conditional() {
    int cond = 1;
    return cond ? 1 : 0; // Violation
}

// Rule 5-0-16/17/18: pointer arithmetic/comparison constraints
void r5_0_16_17_18() {
    int a[4] = {0};
    int b[4] = {0};
    int* p = a;
    int* q = b;
    int* oob = a + 10; // Rule 5-0-16
    int diff = q - p;  // Rule 5-0-17
    bool rel = q > p;  // Rule 5-0-18
    (void)oob;
    (void)diff;
    (void)rel;
}

// Rule 5-0-13: conditions should have bool type
void r5_0_13_condition_int() {
    int c = 1;
    if (c) { // Violation
        c++;
    }
}

// Rule 5-0-19: no more than two levels of pointer indirection
void r5_0_19_ptr_nesting() {
    int x = 0;
    int* p1 = &x;
    int** p2 = &p1;
    int*** p3 = &p2; // Violation
    (void)p3;
}

// Rule 5-0-20: bitwise non-constant operands should have same underlying type
void r5_0_20_bitwise_types() {
    unsigned int u = 1U;
    int s = 2;
    unsigned int r = u & s; // Violation
    (void)r;
}

// Rule 5-3-1: logical operands should be bool
void r5_3_1_logical_non_bool() {
    int a = 1;
    int b = 2;
    if (a && b) { // Violation
        a++;
    }
}

// Rule 5-0-4/5/6: implicit conversions (signedness, float<->int, narrowing)
void r5_0_4_5_6_implicit() {
    int si = -1;
    unsigned int ui = si; // 5-0-4
    float f = 3.5f;
    int i = f;            // 5-0-5 / 5-0-6
    short s = ui;         // 5-0-6
    (void)i;
    (void)s;
}

// Rule 5-0-7/8/9: explicit conversions (float->int, signedness, narrowing)
void r5_0_7_8_9_explicit() {
    double d = 2.7;
    int i = static_cast<int>(d); // 5-0-7
    int si = -1;
    unsigned int ui = static_cast<unsigned int>(si); // 5-0-8
    unsigned int wide = 1024U;
    unsigned short nar = static_cast<unsigned short>(wide); // 5-0-9
    (void)i;
    (void)ui;
    (void)nar;
}

// Rule 5-0-10: shift of small operand without required cast
void r5_0_10_shift_small() {
    unsigned char uc = 1U;
    unsigned int x = uc << 2; // 5-0-10
    (void)x;
}

// Rule 5-0-11: plain char used as numeric value
void r5_0_11_plain_char_numeric() {
    char c = 1;
    int n = c + 2; // 5-0-11
    (void)n;
}

// Rule 5-0-12: signed/unsigned char used as character value
void r5_0_12_signed_char_charlit() {
    signed char sc = 'A';   // 5-0-12
    unsigned char uc = 'B'; // 5-0-12
    (void)sc;
    (void)uc;
}

// Rule 5-2-12: array identifier shall not decay to pointer as function argument
void r5_2_12_takes_ptr(int* p) {
    (void)p;
}
void r5_2_12_array_decay() {
    int arr[3] = {1, 2, 3};
    r5_2_12_takes_ptr(arr); // 5-2-12
}

// Rule 5-3-3: unary & shall not be overloaded
struct R5_3_3_OverloadAddr {
    int v;
    R5_3_3_OverloadAddr* operator&() { // 5-3-3
        return this;
    }
};

// Rule 5-2-1: each operand of && / || should be a postfix-expression
void r5_2_1_logical_operands() {
    int x = 1;
    bool flag = true;
    if ((x + 1) && (!flag)) { // 5-2-1
        x++;
    }
}

// Rule 5-2-2: cast from virtual base pointer to derived should use dynamic_cast
struct R5_2_2_VBase {
    virtual ~R5_2_2_VBase() {}
};
struct R5_2_2_Mid : virtual R5_2_2_VBase {};
struct R5_2_2_Derived : R5_2_2_Mid {};
void r5_2_2_virtual_base_cast(R5_2_2_VBase* p) {
    R5_2_2_Derived* d = reinterpret_cast<R5_2_2_Derived*>(p); // 5-2-2
    (void)d;
}

// Rule 5-2-3: base-to-derived cast on polymorphic type
struct R5_2_3_Base {
    virtual ~R5_2_3_Base() {}
};
struct R5_2_3_Derived : R5_2_3_Base {};
void r5_2_3_polymorphic_downcast(R5_2_3_Base* p) {
    R5_2_3_Derived* d = static_cast<R5_2_3_Derived*>(p); // 5-2-3
    (void)d;
}

// Rule 5-2-8: integral/enum/void* shall not be cast to pointer type
void r5_2_8_invalid_to_pointer() {
    void* pv = 0;
    int* from_void = static_cast<int*>(pv); // 5-2-8
    int raw = 0x1234;
    int* from_int = reinterpret_cast<int*>(raw); // 5-2-8
    (void)from_void;
    (void)from_int;
}

// Rule 5-19-1: constant unsigned wrap-around
unsigned int r5_19_1_wrap = 0xFFFFFFFFU + 1U; // Violation

// Rule 3-4-1: visibility should be minimized (global used by one function)
int r3_4_1_global = 0; // Violation (should be block scope)
void r3_4_1_use() {
    r3_4_1_global++;
}

// Rule 1-0-1: language extensions should not be used
int r1_0_1_extension() {
    int x = ({ int y = 1; y; }); // GNU statement-expression extension
    int n = 3;
    int arr[n]; // VLA extension in C++
    x += arr[0];
    return x;
}

// Rule 16-3-2: # / ## operators should not be used
#define R16_3_2_CAT(a, b) a ## b

// Rule 16-0-6: macro expansion expressions should be parenthesized
#define R16_0_6_BAD(x) x + 1

// Rule 16-0-5: preprocessor-like tokens in macro argument
#define R16_0_5_WRAP(x) x
R16_0_5_WRAP(#define BAD_INSIDE_ARG 1)

// Rule 16-0-7: identifier in #if should be defined before evaluation
#if R16_0_7_UNDEFINED_FLAG
int r16_0_7_anchor = 1;
#endif

// Rule 16-0-1: include should only be preceded by preprocessor directives/comments
int r16_0_1_code_before_include = 0;
#include "bad\\header.h" // Rule 16-2-4 and Rule 16-0-1

// Rule 7-3-4: using-directives shall not be used
using namespace std; // Violation

// Rule 7-3-2: 'main' identifier shall not be used for non-global main
struct R7_3_2_MainCarrier {
    static int main(); // Violation
};
int R7_3_2_MainCarrier::main() { return 1; }

// Rule 7-1-1: non-modified local variable should be const
void r7_1_1_non_modified_local() {
    int not_modified = 7; // Violation
    (void)not_modified;
}

// Rule 7-5-1: do not return pointer/reference to automatic local variable
int* r7_5_1_return_local_ptr() {
    int local = 1;
    return &local; // Violation
}
int& r7_5_1_return_local_ref() {
    int local = 2;
    return local; // Violation
}

// Rule 7-5-3: do not return pointer/reference based on pointer/reference parameter
int* r7_5_3_return_param_ptr(int* p) {
    return p; // Violation
}
int& r7_5_3_return_param_ref(int& r) {
    return r; // Violation
}

// Rule 7-5-2: address of automatic object assigned to persistent object
int* r7_5_2_persistent_sink = nullptr;
void r7_5_2_store_auto_address() {
    int local = 3;
    r7_5_2_persistent_sink = &local; // Violation
}

// Rule 7-2-1: enum expression should only use enumerator values
enum R7_2_1_E { R7_2_1_A = 0, R7_2_1_B = 1 };
void r7_2_1_bad_enum_values() {
    R7_2_1_E e = static_cast<R7_2_1_E>(5); // Violation
    e = (R7_2_1_E)6; // Violation
    e = 7; // Violation
}

// Rule 7-3-5: declarations shall not straddle using-declaration
namespace r7_3_5_b {
int f(int);
}
namespace r7_3_5_a {
int f(double);
using r7_3_5_b::f; // Violation
int f(int);
}

// Rule 7-4-1/7-4-2/7-4-3: assembler usage
void r7_4_asm_mixed() {
    int x = 0;
    asm("nop");
    x++;
    (void)x;
}

// Rule 8-3-1: overriding virtual function default arguments
struct R8_3_1_Base {
    virtual int f(int x = 1) { return x; }
};
struct R8_3_1_Derived : R8_3_1_Base {
    int f(int x = 2) override { return x; } // Violation
};

// Rule 8-5-3: explicit enum initializers after first enumerator
enum R8_5_3_E {
    R8_5_3_A = 0,
    R8_5_3_B = 1, // Violation
    R8_5_3_C = 2  // Violation
};

// Rule 9-3-2 / 9-3-3: non-const handles and const-capable methods
class R9_3_Class {
    int data_;
public:
    R9_3_Class() : data_(0) {}
    int* expose_ptr() { return &data_; } // 9-3-2
    int& expose_ref() { return data_; }  // 9-3-2
    int read_only() { return data_; }    // 9-3-3
};

// Rule 9-6-1/2/3/4: bit-field constraints
enum R9_6_E { R9_6_E0 = 0, R9_6_E1 = 1 };
struct R9_6_Bits {
    int signed_one : 1;            // 9-6-1, 9-6-2, 9-6-4
    signed int signed_two : 2;     // 9-6-1, 9-6-2
    unsigned int unsigned_ok : 2;  // 9-6-1
    R9_6_E enum_bits : 2;          // 9-6-1, 9-6-2, 9-6-3
};

// Rule 10-1-1 / 10-1-2: virtual base in (non-multiple) inheritance
struct R10_1_1_Base {};
struct R10_1_1_Derived : virtual R10_1_1_Base {}; // Violation

// Rule 10-1-3: same base reachable virtually and non-virtually
struct R10_1_3_A {};
struct R10_1_3_Left : virtual R10_1_3_A {};
struct R10_1_3_Right : R10_1_3_A {};
struct R10_1_3_Derived : R10_1_3_Left, R10_1_3_Right {}; // Violation

// Rule 10-2-1 / 10-3-1: ambiguous base entities / multiple virtual defs
struct R10_CommonV {
    virtual void vf() {}
};
struct R10_Left : R10_CommonV {
    void vf() override {}
    int shared() { return 1; }
};
struct R10_Right : R10_CommonV {
    void vf() override {}
    int shared() { return 2; }
};
struct R10_DerivedAmbiguous : R10_Left, R10_Right {}; // Violation

// Rule 10-3-2 / 10-3-3: overriding virtual function declarations
struct R10_3_2_Base {
    virtual void f();
};
void R10_3_2_Base::f() {}
struct R10_3_2_Derived : R10_3_2_Base {
    void f() override {} // Violation 10-3-2 (no 'virtual' keyword)
};

struct R10_3_3_Base {
    virtual void g();
};
void R10_3_3_Base::g() {}
struct R10_3_3_Derived : R10_3_3_Base {
    virtual void g() = 0; // Violation 10-3-3
};

// Rule 11-0-1: member data in non-POD classes shall be private
class R11_0_1_NonPod {
public:
    int public_data; // Violation
    R11_0_1_NonPod() : public_data(0) {}
    void touch() {}
};

// Rule 12-1-1: dynamic type usage in constructor/destructor body
class R12_1_1_Base {
public:
    virtual void vf() {}
};
class R12_1_1_Derived : public R12_1_1_Base {
public:
    R12_1_1_Derived() {
        vf(); // Violation
    }
    ~R12_1_1_Derived() {
        (void)typeid(*this); // Violation
    }
    void vf() override {}
};

// Rule 12-1-3: single fundamental argument constructor should be explicit
class R12_1_3_Ctor {
public:
    R12_1_3_Ctor(int x) : value_(x) {} // Violation
private:
    int value_;
};

// Rule 12-1-2: constructors should explicitly initialize immediate base classes
class R12_1_2_Base {
public:
    R12_1_2_Base() {}
};
class R12_1_2_Derived : public R12_1_2_Base {
public:
    R12_1_2_Derived() {} // Violation (base ctor not explicit in initializer list)
};

// Rule 12-8-1: copy constructor shall only initialize bases and non-static members
class R12_8_1_CopyInit : public R12_1_2_Base {
public:
    int m_;
    static int s_;
    R12_8_1_CopyInit() : R12_1_2_Base(), m_(0) {}
    R12_8_1_CopyInit(const R12_8_1_CopyInit& rhs) : R12_1_2_Base(rhs), m_(rhs.m_), s_(0) {} // Violation
};
int R12_8_1_CopyInit::s_ = 0;

// Rule 12-8-2: copy assignment in abstract class should be protected/private
class R12_8_2_Abstract {
public:
    virtual void api() = 0;
    R12_8_2_Abstract& operator=(const R12_8_2_Abstract&) = default; // Violation
};

// Rule 14-7-2: explicit template instantiation
template<typename T>
struct R14_7_2_Box { T value; };
template struct R14_7_2_Box<int>; // Violation

// Rule 14-8-1: overloaded function template explicitly specialized
template<typename T>
int r14_8_1_over(T x) { return static_cast<int>(x); }
template<typename T>
int r14_8_1_over(T* p) { return p ? 1 : 0; }
template<>
int r14_8_1_over<int>(int x) { return x + 1; } // Violation
int r14_8_2_mixed_call() {
    return r14_8_1_over<int>(5); // Rule 14-8-2 violation
}

// Rule 14-7-1: template shall be instantiated at least once
template<typename T>
struct R14_7_1_UnusedTemplate {
    T value;
}; // Violation (never instantiated in this TU)

// Rule 14-5-1: non-member generic function in global namespace
template<typename T>
T r14_5_1_global_generic(T v) { // Violation
    return v;
}

// Rule 14-7-3: specialization without primary template in same file
template<>
int r14_7_3_missing_primary<int>(int x) { // Violation
    return x + 42;
}

// Rule 14-6-1: dependent-base name should be qualified (this-> or Base<T>::)
template<typename T>
struct R14_6_1_Base {
    void do_work() {}
};
template<typename T>
struct R14_6_1_Derived : R14_6_1_Base<T> {
    void run() {
        do_work(); // Violation 14-6-1
    }
};

// Rule 14-6-2: called function in generic function should depend on generic parameter type
inline int r14_6_2_non_dependent_helper(int x) { return x + 1; }
template<typename T>
int r14_6_2_generic(T v) {
    (void)v;
    return r14_6_2_non_dependent_helper(1); // Violation 14-6-2
}

// Rule 14-5-2: copy ctor should be declared if template ctor exists
template<typename T>
class R14_5_2_MissingCopyCtor {
public:
    template<typename U>
    explicit R14_5_2_MissingCopyCtor(const U& u) : value_(static_cast<T>(u)) {} // Violation
private:
    T value_;
};

// Rule 14-5-3: copy assignment should be declared if template assignment exists
template<typename T>
class R14_5_3_MissingCopyAssign {
public:
    R14_5_3_MissingCopyAssign() : value_() {}
    template<typename U>
    R14_5_3_MissingCopyAssign& operator=(const U& u) { // Violation
        value_ = static_cast<T>(u);
        return *this;
    }
private:
    T value_;
};

// Rule 15-0-2 / 15-1-2 / 15-1-1: throw expression forms
void r15_throw_forms() {
    int* p = nullptr;
    throw p;      // 15-0-2
    throw NULL;   // 15-1-2
    throw r6_step(); // 15-1-1 (throw operand contains call)
}
void r15_throw_nullptr() {
    throw nullptr; // 15-1-2
}

// Rule 15-1-3: empty throw outside catch
void r15_bad_rethrow() {
    throw; // 15-1-3
}

// Rule 15-0-3: control shall not jump into try/catch by goto
void r15_goto_into_try() {
    goto in_try; // Violation 15-0-3
    try {
in_try:
        (void)0;
    } catch (...) {
    }
}

// Rule 15-5-1: destructor exits via exception
class R15_DtorThrow {
public:
    ~R15_DtorThrow() {
        throw 1; // 15-5-1
    }
};

// Rule 15-3-2/4/5/6/7: catch style, catch-all, and order
struct R15_BaseEx {};
struct R15_DerivedEx : R15_BaseEx {};
void r15_catch_rules() {
    try {
        throw R15_DerivedEx();
    } catch (R15_BaseEx b) {   // 15-3-4, 15-3-5, order base before derived
        (void)b;
    } catch (R15_DerivedEx& d) { // 15-3-7 / 15-3-6 by ordering
        (void)d;
    }
}

// Rule 15-3-3: function-try-block handler in ctor/dtor shall not reference non-static members
class R15_3_3_CtorTry {
public:
    int member_;
    R15_3_3_CtorTry() try : member_(0) {
        throw 1;
    } catch (...) {
        member_ = 1; // Violation 15-3-3
    }
};

// Rule 15-4-1: declarations with exception-specification shall match
int r15_4_1_decl(int) throw(int);
int r15_4_1_decl(int) throw(double); // Violation 15-4-1
int r15_4_1_decl(int v) throw(int) {
    return v;
}

// Rule 15-5-2: thrown exception type shall match declaration exception-specification
int r15_5_2_bad() throw(int) {
    throw 1.0; // Violation 15-5-2 (and 15-5-3)
}

// Rule 15-5-3: terminate() shall not be called implicitly
void r15_5_3_bad() throw() {
    throw 1; // Violation 15-5-3 (and 15-5-2)
}

// Rule 16-0-2: macro definition in non-global scope
void r16_0_2_non_global_macro() {
#define R16_LOCAL_MACRO 1
    int x = R16_LOCAL_MACRO;
    (void)x;
}

// Rule 16-1-1: invalid defined operator form
#if defined + R16_1_1_FLAG
int r16_1_1_bad_defined = 1;
#endif

// Rule 16-2-6: malformed include form
#include BAD_INCLUDE_TOKEN

// Rule 16-6-1: undocumented pragma
#pragma pack(push, 1)
#pragma once

// Rule 17-0-1 / 17-0-3: standard-library macro/name shall not be (re)defined/undefined/reused
#define errno 0
#undef errno

// Rule 17-0-2: standard-library object/function names shall not be reused
namespace r17_reuse {
struct StdNames {
    int qsort;          // Violation
    void getenv() {}    // Violation
};
int atoi = 0;           // Violation
}

// Rule 18-0-5 / 18-2-1 / 19-3-1
struct R18_2_1_Off { int a; char b; };
void r18_19_misc() {
    char dst[8] = {0};
    const char* src = "abc";
    (void)strcpy(dst, src); // 18-0-5
    int off = offsetof(R18_2_1_Off, b); // 18-2-1
    errno = off; // 19-3-1
}

// Rule 16-1-2: unmatched conditional directives
#if 1

int rule_cpp2008_extra_unit_anchor() {
    return 0;
}
