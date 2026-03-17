/*
 * Extra snippets to trigger cross-translation-unit and C++:2023 rules.
 */

#include <cstring>
#include <cstddef>
#include <cctype>
#include <cwctype>
#include <cassert>
#include <cerrno>
#include <clocale>
#include <locale>
#include <cstdlib>
#include <memory>
#include <utility>
#include <cstdio>
#include <vector>
#include <algorithm>
#include <string>
#include <memory>
#include <typeinfo>
#include <initializer_list>
#include <cstdint>
#include "no_guard.hpp" // Violation 19.2.1
#include "unnamed_namespace.hpp" // Violation 10.3.1

extern int rule_6_0_2_unsized[]; // Violation 6.0.2
int rule_6_7_2_global = 0; // Violation 6.0.3, 6.7.2

#pragma message("rule_19_6_1_bad") // Rule 19.6.1 violation

// Legacy 8-0-1: external object/function should be declared once in one file
extern int rule_8_0_1_multi_decl;

// Legacy 2-10-4: tag names should be unique
namespace r2_10_4_a { struct DupTag {}; }
namespace r2_10_4_b { struct DupTag {}; } // Violation

// Legacy 2-10-2: inner declarations should not hide outer declarations
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

// Legacy 0-1-9 / Rule 11.6.1: unused local variable
void r0_1_9_unused_local() {
    int local_unused = 5; // Violation
    int set_only;
    set_only = 1; // Violation
}

// Legacy 8-5-1: use before set
int r8_5_1_uninitialized(bool cond) {
    int x;
    if (cond) {
        x = 1;
    }
    return x; // Violation
}

// Legacy 0-2-1: overlapping copy
union R0_2_1_U {
    int a;
    float b;
};
void r0_2_1_overlap() {
    R0_2_1_U u;
    u = u; // Violation
    ::memcpy(&u, &u, sizeof(u)); // Violation
}

// Rule 24.5.1: character handling functions from <cctype>/<cwctype> shall not be used
void rule_24_5_1_bad() {
    int c = std::isalpha('a'); // Violation
    int w = std::iswalpha(L'a'); // Violation
    (void)c;
    (void)w;
}

// Rule 24.5.2: memcpy/memmove/memcmp from <cstring> shall not be used
void rule_24_5_2_bad() {
    char a[4] = {0};
    char b[4] = {1, 2, 3, 4};
    std::memcpy(a, b, sizeof(a)); // Violation
    std::memmove(a + 1, a, 2); // Violation
    (void)std::memcmp(a, b, sizeof(a)); // Violation
}

// Rule 22.3.1: assert shall not be used with constant-expression
void rule_22_3_1_bad() {
    assert(1); // Violation
}

// Rule 22.4.1: only zero may be assigned to errno
void rule_22_4_1_bad() {
    errno = 5; // Violation
}

// Rule 25.5.1: setlocale and std::locale::global shall not be called
void rule_25_5_1_bad() {
    (void)setlocale(LC_ALL, "C"); // Violation
    std::locale::global(std::locale::classic()); // Violation
}

// Rule 25.5.2: pointers returned by localeconv/getenv/setlocale/strerror must be used as const
void rule_25_5_2_bad() {
    char* p = std::strerror(1); // Violation
    p[0] = 'X';
}

// Rule 25.5.3: returned pointer shall not be used after subsequent same-function call
void rule_25_5_3_bad() {
    std::time_t t = 0;
    std::tm* a = std::localtime(&t);
    std::tm* b = std::localtime(&t);
    int y = a->tm_year; // Violation
    (void)b;
    (void)y;
}

// Rule 21.2.2: string handling functions from cstring/cstdlib/cwchar/cinttypes shall not be used
void rule_21_2_2_bad() {
    char dst[8] = {0};
    char src[8] = "abc";
    (void)std::strcpy(dst, src); // Violation
}

// Rule 21.2.4: offsetof shall not be used
void rule_21_2_4_bad() {
    struct S { int a; double b; };
    std::size_t o = offsetof(S, b); // Violation
    (void)o;
}

// Rule 21.6.1: dynamic memory should not be used
void rule_21_6_1_bad() {
    int* p = new int(1); // Violation
    void* q = std::malloc(4); // Violation
    delete p;
    std::free(q);
}

// Rule 18.5.2: program-terminating functions should not be used
void rule_18_5_2_bad() {
    std::exit(2); // Violation
}

// Rule 21.6.2: dynamic memory shall be managed automatically
void rule_21_6_2_bad() {
    int* p = new int(7); // Violation
    delete p;
}

// Rule 21.6.3: advanced memory management shall not be used
void rule_21_6_3_bad() {
    void* p = std::malloc(8);
    p = std::realloc(p, 16); // Violation
    std::free(p);
}

// Rule 23.11.1: raw pointer constructors of shared_ptr/unique_ptr should not be used
void rule_23_11_1_bad() {
    std::shared_ptr<int> sp(new int(1)); // Violation
    std::unique_ptr<int> up(new int(2)); // Violation
    (void)sp;
    (void)up;
}

// Rule 26.3.1: std::vector<bool> specialization should not be used
void rule_26_3_1_bad() {
    std::vector<bool> flags(4, false); // Violation
    (void)flags;
}

// Rule 28.6.4: result of remove/remove_if/unique/empty shall be used
void rule_28_6_4_bad() {
    std::vector<int> v = {1, 2, 2, 3};
    std::remove(v.begin(), v.end(), 2); // Violation
    std::unique(v.begin(), v.end()); // Violation
    v.empty(); // Violation
}

// Rule 21.6.5: pointer to incomplete class type shall not be deleted
class R21_6_5_Incomplete;
void rule_21_6_5_bad() {
    R21_6_5_Incomplete* p = nullptr;
    delete p; // Violation
}

// Rule 28.6.1: argument to std::move shall be non-const lvalue
void rule_28_6_1_bad() {
    const int a = 7;
    int b = std::move(a); // Violation
    (void)b;
}

// Rule 30.0.2: mixed read/write on same stream without reposition
void rule_30_0_2_bad() {
    std::FILE* fp = std::fopen("tmp_rule_30_0_2.txt", "w+");
    if (fp != nullptr) {
        std::fprintf(fp, "abc");
        char buf[4] = {0};
        std::fscanf(fp, "%3s", buf); // Violation
        std::fclose(fp);
    }
}

// Rule 21.6.4: if sized/unsized global delete is defined, both shall be defined
void operator delete(void* ptr) noexcept { // Violation (sized variant missing)
    std::free(ptr);
}

template <typename T>
void rule_28_6_2_sink(T&& value) { // Violation: forwarding ref used without std::forward
    (void)value;
}

// Rule 28.6.3: object shall not be used in potentially moved-from state
void rule_28_6_3_bad() {
    std::string src = "abc";
    std::string dst = std::move(src);
    if (!src.empty()) { // Violation
        (void)dst;
    }
}

// Rule 4.1.2: deprecated features should not be used
void rule_4_1_2_bad() {
    std::auto_ptr<int> p(new int(1)); // Violation
    (void)p;
}

// Rule 5.13.6: long long literals shall not use a single L/l suffix
long long rule_5_13_6_bad = 1234567890123L; // Violation

// Rule 7.11.1: nullptr shall be the only null-pointer-constant
int* rule_7_11_1_bad = NULL; // Violation

// Rule 5.0.1: trigraph-like sequences should not be used
const char* rule_5_0_1_bad = "??="; // Violation

// Rule 9.2.1: explicit conversion shall not be an expression statement
void rule_9_2_1_bad() {
    static_cast<void>(0); // Violation
}

// Rule 8.2.3: cast shall not remove cv-qualification from referenced type
void rule_8_2_3_bad() {
    const int c = 1;
    int* p = const_cast<int*>(&c); // Violation
    (void)p;
}

// Rule 8.2.5: reinterpret_cast shall not be used
void rule_8_2_5_bad() {
    int x = 0;
    float* p = reinterpret_cast<float*>(&x); // Violation
    (void)p;
}

// Rule 8.2.7: pointer-to-integral cast should not be used
void rule_8_2_7_bad() {
    int x = 0;
    long v = reinterpret_cast<long>(&x); // Violation
    (void)v;
}

// Rule 6.7.1: local variables shall not have static storage duration
void rule_6_7_1_bad() {
    static int counter = 0; // Violation
    counter++;
}

// Rule 10.0.1: declaration should not declare more than one variable
void rule_10_0_1_bad() {
    int a = 0, b = 1; // Violation
    (void)a;
    (void)b;
}

// Rule 10.2.1: enumeration shall define explicit underlying type
enum Rule10_2_1_Bad {
    Rule10_2_1_A = 0, // Violation
    Rule10_2_1_B = 1
};

// Rule 10.1.1: pointer or lvalue reference parameter should be const-qualified
void rule_10_1_1_bad(int* p, int& r) { // Violation
    p[0] = r;
}

// Rule 10.1.2: volatile qualifier shall be used appropriately
void rule_10_1_2_bad() {
    volatile int v = 0; // Violation
    (void)v;
}

// Rule 10.2.2 / 10.2.3: unscoped enum and use of numeric value
enum Rule10_2_2_Bad { // Violation
    Rule10_2_2_A = 0,
    Rule10_2_2_B = 1
};
int rule_10_2_3_bad = Rule10_2_2_A; // Violation
enum Rule10_2_3_Line { Rule10_2_3_A = 7, Rule10_2_3_B = 9 }; // Violation
int rule_10_2_3_bad_line = Rule10_2_3_A; // Violation

// Rule 11.3.2: more than two levels of pointer indirection
int*** rule_11_3_2_bad = nullptr; // Violation

// Rule 7.0.1: conversion from bool shall not occur
void rule_7_0_1_bad() {
    bool b = true;
    int x = b; // Violation
    (void)x;
}

// Rule 7.0.2: conversion to bool shall not occur
void rule_7_0_2_bad() {
    int x = 1;
    bool b = x; // Violation
    (void)b;
}

// Rule 7.11.2: array argument shall not decay to pointer
void rule_7_11_2_sink(int* p);
void rule_7_11_2_bad() {
    int arr[3] = {1, 2, 3};
    rule_7_11_2_sink(arr); // Violation
}

// Rule 7.11.3: conversion from function type to pointer-to-function type
int rule_7_11_3_func(int x) { return x; }
void rule_7_11_3_bad() {
    int (*p)(int) = static_cast<int (*)(int)>(rule_7_11_3_func); // Violation
    (void)p;
}

// Rule 7.0.4: bitwise/shift operands shall be appropriate
void rule_7_0_4_bad() {
    bool b = true;
    int x = 1;
    int y = b << x; // Violation
    (void)y;
}

// Rule 7.0.5: arithmetic conversions should not change signedness category
void rule_7_0_5_bad() {
    unsigned int u = 1U;
    int s = -1;
    int m = u + s; // Violation
    (void)m;
}

// Rule 7.0.6: assignment between numeric types shall be appropriate
void rule_7_0_6_bad() {
    int i = 0;
    double d = 3.14;
    i = d; // Violation
}

// Rule 8.0.1: expression meaning should be explicit via parentheses
void rule_8_0_1_bad() {
    int a = 1;
    int b = 2;
    int c = 3;
    int x = a << b + c; // Violation
    (void)x;
}

// Rule 8.1.1 / 8.1.2: implicit this capture and non-explicit capture list in non-transient lambda
struct Rule8_1_Bad {
    int member;
    void run() {
        auto l = [=]() { return this->member; }; // Violation 8.1.1, 8.1.2
        (void)l;
    }
};

// Rule 8.3.2: unary + operator should not be used
void rule_8_3_2_bad() {
    int x = 1;
    int y = +x; // Violation
    (void)y;
}

// Rule 8.2.6: integral / void* object shall not be cast to pointer type
void rule_8_2_6_bad() {
    void* pv = nullptr;
    int iv = 0;
    int* a = static_cast<int*>(pv); // Violation
    int* b = reinterpret_cast<int*>(iv); // Violation
    (void)a;
    (void)b;
}

// Rule 8.2.8: pointer type shall not be cast to integral (except uintptr_t/intptr_t)
void rule_8_2_8_bad() {
    int x = 0;
    long v = reinterpret_cast<long>(&x); // Violation
    (void)v;
}

// Rule 8.2.1: virtual base cast to derived shall use dynamic_cast
struct Rule8_2_1_VBase { virtual ~Rule8_2_1_VBase() = default; };
struct Rule8_2_1_Derived : virtual Rule8_2_1_VBase {};
void rule_8_2_1_bad(Rule8_2_1_VBase* p) {
    Rule8_2_1_Derived* d = reinterpret_cast<Rule8_2_1_Derived*>(p); // Violation
    (void)d;
}

// Rule 11.3.1: variables of array type should not be declared
void rule_11_3_1_bad() {
    int local_arr[3] = {0}; // Violation
    (void)local_arr[0];
}

// Rule 5.13.4: unsigned literals should carry U/u suffix
unsigned int rule_5_13_4_bad = 10; // Violation

// Rule 5.13.7: string literals with different encoding prefixes shall not be concatenated
const char* rule_5_13_7_bad = u8"abc" L"def"; // Violation

// Rule 6.0.4: identifier 'main' should only denote global main function
void rule_6_0_4_bad() {
    int main = 1; // Violation
    (void)main;
}

// Rule 9.6.3: goto shall jump to a label declared later in the function body
void rule_9_6_3_bad() {
label_back:
    goto label_back; // Violation
}

// Rule 9.6.2: goto shall reference a label in a surrounding block
void rule_9_6_2_bad() {
    goto inner; // Violation
    {
inner:
        int x = 0;
        (void)x;
    }
}

// Rule 9.6.4: [[noreturn]] function shall not return
[[noreturn]] void rule_9_6_4_bad() {
    return; // Violation
}

// Rule 6.8.2: returning address/reference to automatic local object
int* rule_6_8_2_bad() {
    int local = 0;
    return &local; // Violation
}

// Rule 6.8.3: assignment operator stores address of local object with greater lifetime
struct Rule6_8_3_Bad {
    int* p;
    Rule6_8_3_Bad& operator=(const Rule6_8_3_Bad&) {
        int local = 0;
        this->p = &local; // Violation
        return *this;
    }
};

// Rule 11.6.1: all variables should be initialized
void rule_11_6_1_bad() {
    int uninit; // Violation
    (void)uninit;
}

// Rule 12.2.1 / 12.2.2 / 12.2.3: bit-field constraints
struct Rule12_2_Bad {
    int bad_signed_one : 1; // Violation 12.2.1, 12.2.3
    float bad_type : 2;     // Violation 12.2.1, 12.2.2
};

// Rule 15.1.3: single-argument constructor should be explicit
struct Rule15_1_3_Bad {
    Rule15_1_3_Bad(int v) : value(v) {} // Violation
    int value;
};

// Rule 16.5.1 / 16.5.2: overloaded operators
struct Rule16_5_Bad {
    bool operator&&(const Rule16_5_Bad&) const { return false; } // Violation 16.5.1
    Rule16_5_Bad* operator&() { return this; } // Violation 16.5.2
};

// Rule 16.6.1: symmetrical operators should be non-member
struct Rule16_6_1_Bad {
    int value;
    Rule16_6_1_Bad operator+(const Rule16_6_1_Bad& other) const { // Violation
        Rule16_6_1_Bad out{value + other.value};
        return out;
    }
};

// Rule 18.1.1 / 18.1.2 / 18.3.2: exception handling constraints
void rule_18_1_1_bad() {
    int* p = nullptr;
    throw p; // Violation 18.1.1
}

void rule_18_1_2_bad() {
    throw; // Violation 18.1.2
}

void rule_18_3_2_bad() {
    try {
        throw Rule15_1_3_Bad(1);
    } catch (Rule15_1_3_Bad e) { // Violation 18.3.2
        (void)e;
    }
}

// Rule 18.3.1: at least one catch-all handler should be present
void rule_18_3_1_bad() {
    try {
        throw 1;
    } catch (int) { // Violation
    }
}

// Rule 18.4.1: exception-unfriendly functions shall be noexcept
struct Rule18_4_1_Bad {
    Rule18_4_1_Bad() = default;
    Rule18_4_1_Bad(Rule18_4_1_Bad&&) {} // Violation
    Rule18_4_1_Bad& operator=(Rule18_4_1_Bad&&) { return *this; } // Violation
    void swap(Rule18_4_1_Bad&) {} // Violation
};

// Rule 18.3.3: ctor/dtor function-try-block handlers shall not use non-static members
struct Rule18_3_3_Bad {
    int member;
    Rule18_3_3_Bad() try : member(0) {
        throw 1;
    } catch (...) {
        member = 1; // Violation
    }
};

// Rule 18.5.1: noexcept function should not propagate exceptions
void rule_18_5_1_bad() noexcept {
    throw 1; // Violation
}

// Rule 8.2.9: typeid operand shall not be polymorphic class expression
struct Rule8_2_9_Poly {
    virtual ~Rule8_2_9_Poly() {}
};
void rule_8_2_9_bad() {
    Rule8_2_9_Poly p;
    (void)typeid(p); // Violation
}
struct Rule8_2_9_PolyLine { virtual ~Rule8_2_9_PolyLine() {} };
void rule_8_2_9_bad_line() {
    Rule8_2_9_PolyLine x;
    (void)typeid(x); // Violation
}

// Rule 8.2.11: arguments passed via ellipsis shall have an appropriate type
void rule_8_2_11_variadic(int, ...) {}
void rule_8_2_11_bad() {
    rule_8_2_11_variadic(1, 2.5f); // Violation
}

template <typename T>
int rule_17_8_1_templ(T v) {
    return static_cast<int>(v);
}
template <>
int rule_17_8_1_templ<int>(int v) { // Violation 17.8.1
    return v;
}

// Rule 7.0.3: numerical value of character shall not be used
void rule_7_0_3_bad() {
    char c = 'A';
    int n = c + 1; // Violation
    (void)n;
}

// Rule 8.3.1: unary minus should not be applied to unsigned expression
void rule_8_3_1_bad() {
    unsigned int u = 1U;
    int n = -u; // Violation
    (void)n;
}

// Rule 8.20.1: unsigned arithmetic with constant operands should not wrap
unsigned int rule_8_20_1_bad = 0xFFFFFFFFU + 1U; // Violation

// Rule 28.3.1: predicates shall not have persistent side effects
void rule_28_3_1_bad() {
    std::vector<int> v{1, 2, 3};
    int side = 0;
    (void)std::find_if(v.begin(), v.end(), [&](int x) { side++; return x > 0; }); // Violation
}

// Rule 14.1.1: non-static data members should be either all private or all public
class Rule14_1_1_Bad {
public:
    int a; // Violation (mixed visibility with private data member)
private:
    int b;
};

// Rule 13.1.1: classes should not be inherited virtually
struct Rule13_1_1_Base {};
struct Rule13_1_1_Bad : virtual public Rule13_1_1_Base { // Violation
    int x;
};

// Rule 13.1.2: same accessible base both virtual and non-virtual in hierarchy
struct Rule13_1_2_Left : public Rule13_1_1_Base {};
struct Rule13_1_2_Right : virtual public Rule13_1_1_Base {};
struct Rule13_1_2_Bad : public Rule13_1_2_Left, public Rule13_1_2_Right { // Violation
    int y;
};

// Rule 13.3.1: derived virtual member should use override/final appropriately
struct Rule13_3_1_Base {
    virtual void f();
};
struct Rule13_3_1_Bad : public Rule13_3_1_Base {
    virtual void f(); // Violation
};

// Rule 13.3.2: overriding virtual function shall not change default arguments
struct Rule13_3_2_Base {
    virtual void h(int x = 1);
};
struct Rule13_3_2_Bad : public Rule13_3_2_Base {
    void h(int x = 2) override; // Violation
};

// Rule 13.3.3: parameter names in declarations/overrides should match
struct Rule13_3_3_Bad {
    void g(int lhs, int rhs);
    void g(int a, int b); // Violation
};

// Rule 13.3.4: pointer-to-member-function comparison only with nullptr
struct Rule13_3_4_Bad {
    void m1();
    void m2();
};
void rule_13_3_4_bad() {
    void (Rule13_3_4_Bad::*pmf1)() = &Rule13_3_4_Bad::m1;
    void (Rule13_3_4_Bad::*pmf2)() = &Rule13_3_4_Bad::m2;
    if (pmf1 == pmf2) { // Violation
    }
}

// Rule 15.1.1: dynamic type shall not be used from ctor/dtor
struct Rule15_1_1_Bad {
    Rule15_1_1_Bad() {
        (void)typeid(*this); // Violation
    }
};

// Rule 15.1.2: constructor should explicitly initialize immediate/virtual bases
struct Rule15_1_2_Base {
    Rule15_1_2_Base(int) {}
};
struct Rule15_1_2_Bad : public Rule15_1_2_Base {
    Rule15_1_2_Bad() {} // Violation
};

// Rule 15.1.4: all direct non-static data members should be initialized
struct Rule15_1_4_Bad {
    int a;
    int b;
    Rule15_1_4_Bad() : a(1) {} // Violation (b not initialized)
};

// Rule 15.0.2: user-provided copy/move member functions should have appropriate signatures
struct Rule15_0_2_Bad {
    Rule15_0_2_Bad() = default;
    Rule15_0_2_Bad(Rule15_0_2_Bad& other) { (void)other; } // Violation
    void operator=(const Rule15_0_2_Bad&) {} // Violation
};

// Rule 15.1.5: initializer-list constructor shall be the only constructor
struct Rule15_1_5_Bad {
    Rule15_1_5_Bad(std::initializer_list<int>) {} // Violation
    Rule15_1_5_Bad(int) {} // Violation
};

// Rule 15.0.1: special member functions should be provided appropriately
class Rule15_0_1_Bad {
public:
    ~Rule15_0_1_Bad() {} // Violation (partial special-member set)
    int v;
};

// Rule 19.0.2: function-like macro shall not be defined
#define RULE_19_0_2_BAD(x) ((x) + 1) // Violation

// Rule 19.3.3: mixed-use macro parameter argument shall not be further expandable
#define RULE_19_3_3_ARG 7
#define RULE_19_3_3_BAD(x) (#x + (x)) // Violation (mixed use)
int rule_19_3_3_use = RULE_19_3_3_BAD(RULE_19_3_3_ARG); // Violation

// Rule 19.0.4: #undef should only target macros defined earlier in same file
#undef RULE_19_0_4_UNKNOWN // Violation

// Rule 19.2.2: #include must be followed by <filename> or "filename"
#include BAD_HEADER_TOKEN // Violation

// Legacy 6-4-3: code before first case/default in switch
void r6_4_3_bad_switch(int n) {
    switch (n) {
        n = n + 1; // Violation
        case 1:
            break;
        default:
            break;
    }
}

// Legacy 6-4-4: nested switch label placement
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

// Legacy 0-3-2: ignored error information
void r0_3_2_ignored_error() {
    fopen("x.txt", "r"); // Violation
}

// Legacy 5-3-4: sizeof operand with side effect
void r5_3_4_sizeof_side_effect() {
    int i = 0;
    (void)sizeof(i++); // Violation
}

// Legacy 3-2-1 / 3-9-1: declarations shall be compatible / token-identical
extern int rule_8_4_2(double); // Conflicts with int rule_8_4_2(int) in misra_cpp_2008.cpp

// Legacy 3-2-3: entity should be declared only once in one TU
int r3_2_3_dup_decl();
int r3_2_3_dup_decl(); // Violation

// Legacy 3-9-2: use typedefs indicating size/signedness
int r3_9_2_plain_int = 0; // Violation

// Legacy 3-9-3: underlying bit representation of floating point shall not be used
void r3_9_3_float_bits() {
    float f = 1.0f;
    unsigned int* bits = reinterpret_cast<unsigned int*>(&f); // Violation
    (void)bits;
}

// Legacy 4-5-1: bool expressions should not be arithmetic operands
void r4_5_1_bool_operand() {
    bool flag = true;
    int x = flag + 1; // Violation
    (void)x;
}

// Legacy 4-5-2: enum expressions should not be built-in operator operands (except subscript)
enum R4_5_2_E { R4_5_2_A = 0, R4_5_2_B = 1 };
void r4_5_2_enum_operand() {
    R4_5_2_E e = R4_5_2_A;
    int x = e + 1; // Violation
    (void)x;
}

// Legacy 4-5-3: plain char / wchar_t expressions should not be built-in operator operands
void r4_5_3_char_operand() {
    char c = 'a';
    wchar_t wc = L'b';
    int x = c + 1;  // Violation
    int y = wc + 1; // Violation
    (void)x;
    (void)y;
}

// Legacy 4-10-1: NULL shall not be used as an integer value
int r4_10_1_null_int = NULL; // Violation

// Legacy 5-0-14: first operand of conditional operator shall be bool
int r5_0_14_conditional() {
    int cond = 1;
    return cond ? 1 : 0; // Violation
}

// Legacy 5-0-16/17/18: pointer arithmetic/comparison constraints
void r5_0_16_17_18() {
    int a[4] = {0};
    int b[4] = {0};
    int* p = a;
    int* q = b;
    int* oob = a + 10; // Legacy 5-0-16
    int diff = q - p;  // Legacy 5-0-17
    bool rel = q > p;  // Legacy 5-0-18
    (void)oob;
    (void)diff;
    (void)rel;
}

// Legacy 5-0-13: conditions should have bool type
void r5_0_13_condition_int() {
    int c = 1;
    if (c) { // Violation
        c++;
    }
}

// Legacy 5-0-19: no more than two levels of pointer indirection
void r5_0_19_ptr_nesting() {
    int x = 0;
    int* p1 = &x;
    int** p2 = &p1;
    int*** p3 = &p2; // Violation
    (void)p3;
}

// Legacy 5-0-20: bitwise non-constant operands should have same underlying type
void r5_0_20_bitwise_types() {
    unsigned int u = 1U;
    int s = 2;
    unsigned int r = u & s; // Violation
    (void)r;
}

// Legacy 5-3-1: logical operands should be bool
void r5_3_1_logical_non_bool() {
    int a = 1;
    int b = 2;
    if (a && b) { // Violation
        a++;
    }
}

// Legacy 5-0-4/5/6: implicit conversions (signedness, float<->int, narrowing)
void r5_0_4_5_6_implicit() {
    int si = -1;
    unsigned int ui = si; // 5-0-4
    float f = 3.5f;
    int i = f;            // 5-0-5 / 5-0-6
    short s = ui;         // 5-0-6
    (void)i;
    (void)s;
}

// Legacy 5-0-7/8/9: explicit conversions (float->int, signedness, narrowing)
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

// Legacy 5-0-10: shift of small operand without required cast
void r5_0_10_shift_small() {
    unsigned char uc = 1U;
    unsigned int x = uc << 2; // 5-0-10
    (void)x;
}

// Legacy 5-0-11: plain char used as numeric value
void r5_0_11_plain_char_numeric() {
    char c = 1;
    int n = c + 2; // 5-0-11
    (void)n;
}

// Legacy 5-0-12: signed/unsigned char used as character value
void r5_0_12_signed_char_charlit() {
    signed char sc = 'A';   // 5-0-12
    unsigned char uc = 'B'; // 5-0-12
    (void)sc;
    (void)uc;
}

// Legacy 5-2-12: array identifier shall not decay to pointer as function argument
void r5_2_12_takes_ptr(int* p) {
    (void)p;
}
void r5_2_12_array_decay() {
    int arr[3] = {1, 2, 3};
    r5_2_12_takes_ptr(arr); // 5-2-12
}

// Legacy 5-3-3: unary & shall not be overloaded
struct R5_3_3_OverloadAddr {
    int v;
    R5_3_3_OverloadAddr* operator&() { // 5-3-3
        return this;
    }
};

// Legacy 5-2-1: each operand of && / || should be a postfix-expression
void r5_2_1_logical_operands() {
    int x = 1;
    bool flag = true;
    if ((x + 1) && (!flag)) { // 5-2-1
        x++;
    }
}

// Legacy 5-2-2: cast from virtual base pointer to derived should use dynamic_cast
struct R5_2_2_VBase {
    virtual ~R5_2_2_VBase() {}
};
struct R5_2_2_Mid : virtual R5_2_2_VBase {};
struct R5_2_2_Derived : R5_2_2_Mid {};
void r5_2_2_virtual_base_cast(R5_2_2_VBase* p) {
    R5_2_2_Derived* d = reinterpret_cast<R5_2_2_Derived*>(p); // 5-2-2
    (void)d;
}

// Legacy 5-2-3: base-to-derived cast on polymorphic type
struct R5_2_3_Base {
    virtual ~R5_2_3_Base() {}
};
struct R5_2_3_Derived : R5_2_3_Base {};
void r5_2_3_polymorphic_downcast(R5_2_3_Base* p) {
    R5_2_3_Derived* d = static_cast<R5_2_3_Derived*>(p); // 5-2-3
    (void)d;
}

// Legacy 5-2-8: integral/enum/void* shall not be cast to pointer type
void r5_2_8_invalid_to_pointer() {
    void* pv = 0;
    int* from_void = static_cast<int*>(pv); // 5-2-8
    int raw = 0x1234;
    int* from_int = reinterpret_cast<int*>(raw); // 5-2-8
    (void)from_void;
    (void)from_int;
}

// Legacy 5-19-1: constant unsigned wrap-around
unsigned int r5_19_1_wrap = 0xFFFFFFFFU + 1U; // Violation

// Legacy 3-4-1: visibility should be minimized (global used by one function)
int r3_4_1_global = 0; // Violation (should be block scope)
void r3_4_1_use() {
    r3_4_1_global++;
}

// Legacy 1-0-1: language extensions should not be used
int r1_0_1_extension() {
    int x = ({ int y = 1; y; }); // GNU statement-expression extension
    int n = 3;
    int arr[n]; // VLA extension in C++
    x += arr[0];
    return x;
}

// Rule 19.3.1: # / ## operators should not be used
#define R16_3_2_CAT(a, b) a ## b

// Legacy 16-0-6: macro expansion expressions should be parenthesized
#define R16_0_6_BAD(x) x + 1

// Rule 19.3.5: preprocessor-like tokens in macro argument
#define R16_0_5_WRAP(x) x
R16_0_5_WRAP(#define BAD_INSIDE_ARG 1)

// Rule 19.1.3: identifier in #if should be defined before evaluation
#if R16_0_7_UNDEFINED_FLAG
int r16_0_7_anchor = 1;
#endif

// Rule 19.1.1: defined operator shall be used appropriately
#if defined123
int r19_1_1_anchor = 1; // Violation
#endif

// Rule 19.0.3: include should only be preceded by preprocessor directives/comments
int r16_0_1_code_before_include = 0;
#include "bad\\header.h" // Rule 19.2.3 and Rule 19.0.3

// Rule-10.4.1 (mapped from 7-4-2): asm declaration shall not be used.
void r10_4_1_asm_usage() {
    asm("nop");
}

// Rule 9.5.2: for-range initializer shall contain at most one function call
static std::vector<int> r9_5_2_make_vec(int a, int b) {
    return std::vector<int>{a, b};
}
static int r9_5_2_f1() {
    return 1;
}
static int r9_5_2_f2() {
    return 2;
}
void r9_5_2_bad() {
    for (int v : r9_5_2_make_vec(r9_5_2_f1(), r9_5_2_f2())) { // 9.5.2
        (void)v;
    }
}

// Rule 9.5.1: legacy for statements should be simple
void r9_5_1_bad() {
    for (int i = 0, j = 0; i < 10; ++i, ++j) { // 9.5.1
        (void)j;
    }
}

// Rule 0.2.1 / 0.2.4: limited visibility entities should be used at least once
static int r0_2_1_never_used = 0; // 0.2.1
static void r0_2_4_never_called() { // 0.2.4
    int local = 1;
    (void)local;
}
struct R0_2_3_UnusedType {}; // 0.2.3

// Rule 4.6.1: operations on a memory location shall be sequenced appropriately
void r4_6_1_bad() {
    int i = 0;
    i = i++; // 4.6.1
}

// Rule 5.13.1 / 5.13.2: escape sequences shall be valid and terminated
void r5_13_1_2_bad() {
    const char* bad_escape = "bad\qescape"; // 5.13.1
    const char* bad_octal = "bad\1234escape"; // 5.13.2
    (void)bad_escape;
    (void)bad_octal;
}

// Rule 0.1.1: value should not be unnecessarily written to a local object
void r0_1_1_bad() {
    int v = 0;
    v = 1;
    v = 2; // 0.1.1
    (void)v;
}

// Rule 6.8.4: member function returning object reference should be ref-qualified
struct R6_8_4_SelfRef {
    R6_8_4_SelfRef& self();
};
R6_8_4_SelfRef& R6_8_4_SelfRef::self() { // 6.8.4
    return *this;
}

// Rule 5.10.1: user-defined identifiers shall have an appropriate form
int bad__identifier = 0; // 5.10.1

// Rule 4.1.3: undefined / critical unspecified behavior
void r4_1_3_bad() {
    int z = 1 / 0; // 4.1.3
    (void)z;
}

// Rule 6.0.1: block scope declarations shall not be visually ambiguous
void r6_0_1_bad() {
    int a, b; // 6.0.1
    (void)a;
    (void)b;
}

// Rule 6.2.1 / 6.2.3: duplicate definitions (ODR / multiple implementation)
int r6_2_dup() {
    return 1;
}
int r6_2_dup() { // 6.2.1, 6.2.3
    return 2;
}

// Rule 6.2.2: declarations shall have same type
int r6_2_2_mismatch();
float r6_2_2_mismatch(); // 6.2.2

// Rule 6.9.1: same aliases shall be used across declarations
using R6_9_A = int;
using R6_9_B = int;
R6_9_A r6_9_1_alias();
R6_9_B r6_9_1_alias(); // 6.9.1

// Rule 6.9.2: fixed-width signed/unsigned integer type names should not be used
std::int32_t r6_9_2_bad = 0; // 6.9.2

// Rule 6.4.2: derived class shall not conceal inherited functions
class R6_4_2_Base {
public:
    void hide();
};
class R6_4_2_Derived : public R6_4_2_Base {
public:
    void hide(int); // 6.4.2
};

// Rule 6.4.3: dependent-base names shall not be resolved by unqualified lookup
template <class T>
class R6_4_3_Derived : public T {
public:
    void call() {
        hidden(); // 6.4.3
    }
};

// Rule 6.5.1 / 6.5.2: linkage should be placed/specified appropriately
int r6_5_1_ext_missing_header() { // 6.5.1
    return 0;
}
void r6_5_1_use() {
    (void)r6_5_1_ext_missing_header();
    (void)r6_5_1_ext_missing_header();
}
int r6_5_2_local_only() { // 6.5.2
    return 1;
}

// Rule 6.8.1: object shall not be accessed outside its lifetime
void r6_8_1_bad() {
    int* p = new int(7);
    delete p;
    int x = *p; // 6.8.1
    (void)x;
}

// Rule 19.1.2: unmatched conditional directives
#if 1

int rule_cpp2008_extra_unit_anchor() {
    return 0;
}

// Rule 9.6.5: function with non-void return type shall return a value on all paths
int rule_9_6_5_missing_return(bool cond) {
    if (cond) {
        return 1;
    }
    // Violation: missing return on false path
}
