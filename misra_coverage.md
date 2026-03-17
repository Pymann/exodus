# MISRA Coverage Checklist (Exodus)

This document tracks the implementation status of the MISRA standards exposed by Exodus `analyze` profiles.
Rules that are implemented via Tree-sitter or Clang AST analysis are marked with `[x]`.

<a id="quick-navigation"></a>
## Quick Navigation

- [MISRA C:2012](#misra-c2012)
- [MISRA C++:2008](#misra-cpp2008)
- [MISRA C:2023](#misra-c2023)
- [MISRA C++:2023](#misra-cpp2023)

## Supported Profiles

| Profile key | Standard | Current state |
|---|---|---|
| `c2012` | MISRA C:2012 | Main coverage checklist in this document |
| `cpp2008` | MISRA C++:2008 | Main coverage checklist in this document |
| `c2023` | MISRA C:2023 | Official 2023 rule IDs listed below; analyzer coverage still mostly C:2012-equivalent |
| `cpp2023` | MISRA C++:2023 | Official 2023 rule IDs listed below; analyzer output still mostly C++:2008-style IDs |

<a id="misra-c2012"></a>
## MISRA C:2012 (143 Rules)
[Back to Quick Navigation](#quick-navigation)

### 1. Standard C Environment
* [-] **Rule 1.1**: The program shall contain no violations of the standard C syntax and constraints, and shall not exceed the implementation's translation limits. (Nicht vollständig automatisierbar in einem einzelnen statischen Analyzer-Lauf)
* [x] **Rule 1.2**: Language extensions should not be used. (Clang)
* [-] **Rule 1.3**: There shall be no occurrence of undefined or critical unspecified behaviour. (Nicht vollständig entscheidbar/abdeckbar durch statische Analyse allein)

### 2. Unused Code
* [x] **Rule 2.1**: A project shall not contain unreachable code. (Tree-sitter & Clang)
* [x] **Rule 2.2**: There shall be no dead code. (Clang)
* [x] **Rule 2.3**: A project should not contain unused type declarations. (Clang)
* [x] **Rule 2.4**: A project should not contain unused tag declarations. (Clang)
* [x] **Rule 2.5**: A project should not contain unused macro declarations. (Clang)
* [x] **Rule 2.6**: A function should not contain unused label declarations. (Clang)
* [x] **Rule 2.7**: There should be no unused parameters in functions. (Clang)

### 3. Comments
* [x] **Rule 3.1**: The character sequence `/*` shall not be used within a C-style comment. (Tree-sitter)
* [x] **Rule 3.2**: Line-splicing shall not be used in `//` comments. (Tree-sitter)

### 4. Character Sets and Lexical Conventions
* [x] **Rule 4.1**: Octal and hexadecimal escape sequences shall be terminated. (Tree-sitter)
* [x] **Rule 4.2**: Trigraphs shall not be used. (Tree-sitter & Clang)

### 5. Identifiers
* [x] **Rule 5.1**: External identifiers shall be distinct. (Clang)
* [x] **Rule 5.2**: Identifiers declared in the same scope and name space shall be distinct. (Clang)
* [x] **Rule 5.3**: An identifier declared in an inner scope shall not hide an identifier declared in an outer scope. (Clang)
* [x] **Rule 5.4**: Macro identifiers shall be distinct. (Cross-TU / Clang)
* [x] **Rule 5.5**: Identifiers shall be distinct from macro names. (Cross-TU / Clang)
* [x] **Rule 5.6**: A `typedef` name shall be a unique identifier. (Cross-TU / Clang)
* [x] **Rule 5.7**: A tag name shall be a unique identifier. (Cross-TU / Clang)
* [x] **Rule 5.8**: Identifiers that define objects or functions with external linkage shall be unique. (Cross-TU)
* [x] **Rule 5.9**: Identifiers that define objects or functions with internal linkage should be unique. (Cross-TU)

### 6. Types
* [x] **Rule 6.1**: Bit-fields shall only be declared with an appropriate type. (Tree-sitter)
* [x] **Rule 6.2**: Single-bit named bit fields shall not be of a signed type. (Tree-sitter)

### 7. Literals and Constants
* [x] **Rule 7.1**: Octal constants shall not be used. (Tree-sitter)
* [x] **Rule 7.2**: A `u` or `U` suffix shall be applied to all integer constants that are represented in an unsigned type. (Tree-sitter & Clang)
* [x] **Rule 7.3**: The lowercase character `l` shall not be used in a literal suffix. (Tree-sitter)
* [x] **Rule 7.4**: A string literal shall not be assigned to an object unless the object's type is "pointer to `const`-qualified character". (Clang)

### 8. Declarations and Definitions
* [x] **Rule 8.1**: Types shall be explicitly specified. (Clang)
* [x] **Rule 8.2**: Function types shall be in prototype form with named parameters. (Tree-sitter & Clang)
* [x] **Rule 8.3**: All declarations of an object or function shall use the same names and type qualifiers. (Cross-TU / Clang)
* [x] **Rule 8.4**: A compatible declaration shall be visible when an object or function with external linkage is defined. (Clang)
* [x] **Rule 8.5**: An external object or function shall be declared once in one and only one file. (Cross-TU)
* [x] **Rule 8.6**: An identifier with external linkage shall have exactly one external definition. (Cross-TU)
* [x] **Rule 8.7**: Functions and objects should not be defined with external linkage if they are referenced in only one translation unit. (Cross-TU)
* [x] **Rule 8.8**: The `static` storage class specifier shall be used in all declarations of objects and functions that have internal linkage. (Clang)
* [x] **Rule 8.9**: An object should be defined at block scope if its identifier only appears in a single function. (Clang)
* [x] **Rule 8.10**: An `inline` function shall be declared with the `static` storage class. (Tree-sitter)
* [x] **Rule 8.11**: When an array with external linkage is declared, its size should be explicitly specified. (Clang)
* [x] **Rule 8.12**: Within an enumerator list, the value of an implicitly-specified enumeration constant shall be unique. (Clang)
* [x] **Rule 8.13**: A pointer should point to a const-qualified type whenever possible. (Clang)
* [x] **Rule 8.14**: The `restrict` type qualifier shall not be used. (Tree-sitter)

### 9. Initialization
* [x] **Rule 9.1**: The value of an object with automatic storage duration shall not be read before it has been set. (Clang)
* [x] **Rule 9.2**: The initializer for an aggregate or union shall be enclosed in braces. (Clang)
* [x] **Rule 9.3**: Arrays shall not be partially initialized. (Clang)
* [x] **Rule 9.4**: An element of an object shall not be initialized more than once. (Clang)
* [x] **Rule 9.5**: Where designated initializers are used to initialize an array object the size of the array shall be specified explicitly. (Clang)

### 10. The Essential Type Model
* [x] **Rule 10.1**: Operands shall not be of an inappropriate essential type. (Clang)
* [x] **Rule 10.2**: Expressions of essentially character type shall not be used inappropriately in addition and subtraction operations. (Clang)
* [x] **Rule 10.3**: The value of an expression shall not be assigned to an object with a narrower essential type or of a different essential type category. (Clang)
* [x] **Rule 10.4**: Both operands of an operator in which the usual arithmetic conversions are performed shall have the same essential type category. (Clang)
* [x] **Rule 10.5**: The value of an expression should not be cast to an inappropriate essential type. (Clang)
* [x] **Rule 10.6**: The value of a composite expression shall not be assigned to an object with wider essential type. (Clang)
* [x] **Rule 10.7**: If a composite expression is used as one operand of an operator in which the usual arithmetic conversions are performed then the other operand shall not have wider essential type. (Clang)
* [x] **Rule 10.8**: The value of a composite expression shall not be cast to a different essential type category or a wider essential type. (Clang)

### 11. Pointer Type Conversions
* [x] **Rule 11.1**: Conversions shall not be performed between a pointer to a function and any other type. (Clang)
* [x] **Rule 11.2**: Conversions shall not be performed between a pointer to an incomplete type and any other type. (Clang)
* [x] **Rule 11.3**: A cast shall not be performed between a pointer to object type and a pointer to a different object type. (Clang)
* [x] **Rule 11.4**: A conversion should not be performed between a pointer to object and an integer type. (Clang)
* [x] **Rule 11.5**: A conversion should not be performed from pointer to void into pointer to object. (Clang)
* [x] **Rule 11.6**: A cast shall not be performed between pointer to void and an arithmetic type. (Clang)
* [x] **Rule 11.7**: A cast shall not be performed between pointer to object and a non-integer arithmetic type. (Clang)
* [x] **Rule 11.8**: A cast shall not remove any `const` or `volatile` qualification from the type pointed to by a pointer. (Clang)
* [x] **Rule 11.9**: The macro NULL shall be the only permitted form of integer null pointer constant. (Clang)

### 12. Expressions
* [x] **Rule 12.1**: The precedence of operators within expressions should be made explicit. (Clang)
* [x] **Rule 12.2**: The right hand operand of a shift operator shall lie in the range zero to one less than the width in bits of the essential type of the left hand operand. (Clang)
* [x] **Rule 12.3**: The comma operator should not be used. (Clang)
* [x] **Rule 12.4**: Evaluation of constant expressions should not lead to unsigned integer wrap-around. (Clang)

### 13. Side Effects
* [x] **Rule 13.1**: Initializer lists shall not contain persistent side effects. (Clang)
* [x] **Rule 13.2**: The value of an expression and its persistent side effects shall be the same under all permitted evaluation orders. (Clang)
* [x] **Rule 13.3**: A full expression containing an increment `(++)` or decrement `(--)` operator should have no other potential side effects other than that caused by the increment or decrement operator. (Clang)
* [x] **Rule 13.4**: The result of an assignment operator should not be used. (Clang)
* [x] **Rule 13.5**: The right hand operand of a logical `&&` or `||` operator shall not contain persistent side effects. (Clang)
* [x] **Rule 13.6**: The operand of the `sizeof` operator shall not contain any expression which has potential side effects. (Tree-sitter)


### 14. Control Statement Expressions
* [x] **Rule 14.1**: A loop counter shall not have essentially floating type. (Clang)
* [x] **Rule 14.2**: A `for` loop shall be well-formed. (Clang)
* [x] **Rule 14.3**: Controlling expressions shall not be invariant. (Clang)
* [x] **Rule 14.4**: The controlling expression of an `if` statement and the controlling expression of an iteration-statement shall have essentially Boolean type. (Clang)

### 15. Control Flow
* [x] **Rule 15.1**: The `goto` statement should not be used. (Tree-sitter)
* [x] **Rule 15.2**: The `goto` statement shall jump to a label declared later in the same function. (Clang)
* [x] **Rule 15.3**: Any label referenced by a `goto` statement shall be declared in the same block, or in any block enclosing the `goto` statement. (Clang)
* [x] **Rule 15.4**: There should be no more than one `break` or `goto` statement used to terminate any iteration statement. (Clang)
* [x] **Rule 15.5**: A function should have a single point of exit at the end. (Tree-sitter)
* [x] **Rule 15.6**: The body of an iteration-statement or a selection-statement shall be a compound-statement. (Tree-sitter)
* [x] **Rule 15.7**: All `if ... else if` constructs shall be terminated with an `else` statement. (Tree-sitter)

### 16. Switch Statements
* [x] **Rule 16.1**: All `switch` statements shall be well-formed. (Clang)
* [x] **Rule 16.2**: A switch label shall only be used when the most closely-enclosing compound statement is the body of a `switch` statement. (Clang)
* [x] **Rule 16.3**: An unconditional `break` statement shall terminate every switch-clause. (Tree-sitter)
* [x] **Rule 16.4**: Every `switch` statement shall have a `default` label. (Tree-sitter)
* [x] **Rule 16.5**: A `default` label shall appear as either the first or the last switch label of a `switch` statement. (Tree-sitter)
* [x] **Rule 16.6**: Every `switch` statement shall have at least two switch-clauses. (Tree-sitter)
* [x] **Rule 16.7**: A switch-expression shall not have essentially Boolean type. (Clang)

### 17. Functions
* [x] **Rule 17.1**: The features of `<stdarg.h>` shall not be used. (Tree-sitter)
* [x] **Rule 17.2**: Functions shall not call themselves, either directly or indirectly. (Tree-sitter - Direct only)
* [x] **Rule 17.3**: A function shall not be declared implicitly. (Clang)
* [x] **Rule 17.4**: All exit paths from a function with non-void return type shall have an explicit `return` statement with an expression. (Clang)
* [x] **Rule 17.5**: The function argument corresponding to a parameter declared to have an array type shall have an appropriate number of elements. (Clang)
* [x] **Rule 17.6**: The declaration of an array parameter shall not contain the `static` keyword between the `[ ]`. (Clang)
* [x] **Rule 17.7**: The value returned by a function having non-void return type shall be used. (Clang)
* [x] **Rule 17.8**: A function parameter should not be modified. (Clang)

### 18. Pointers and Arrays
* [x] **Rule 18.1**: A pointer resulting from arithmetic on a pointer operand shall address an element of the same array as that pointer operand. (Clang)
* [x] **Rule 18.2**: Subtraction between pointers shall only be applied to pointers that address elements of the same array. (Clang)
* [x] **Rule 18.3**: The relational operators `>`, `>=`, `<` and `<=` shall not be applied to objects of pointer type except where they point into the same object. (Clang)
* [x] **Rule 18.4**: The `+`, `-`, `+=` and `-=` operators should not be applied to an expression of pointer type. (Clang)
* [x] **Rule 18.5**: Declarations should contain no more than two levels of pointer nesting. (Clang)
* [x] **Rule 18.6**: The address of an object with automatic storage shall not be copied to another object that persists after the first object has ceased to exist. (Clang)
* [x] **Rule 18.7**: Flexible array members shall not be declared. (Clang)
* [x] **Rule 18.8**: Variable-length array types shall not be used. (Tree-sitter/Clang)

### 19. Overlapping Storage
* [x] **Rule 19.1**: An object shall not be assigned or copied to an overlapping object. (Clang)
* [x] **Rule 19.2**: The `union` keyword should not be used. (Tree-sitter)

### 20. Preprocessing Directives
* [x] **Rule 20.1**: `#include` directives should only be preceded by preprocessor directives or comments. (Tree-sitter)
* [x] **Rule 20.2**: The `'`, `"` or `\` characters and the `/*` or `//` character sequences shall not occur in a header file name. (Tree-sitter)
* [x] **Rule 20.3**: The `\` character shall not be used to splice a macro definition across more than one line. (Tree-sitter)
* [x] **Rule 20.4**: A macro shall not be defined with the same name as a keyword. (Tree-sitter)
* [x] **Rule 20.5**: `#undef` should not be used. (Tree-sitter)
* [x] **Rule 20.6**: Tokens that look like a preprocessing directive shall not occur within a macro argument. (Clang)
* [x] **Rule 20.7**: Expressions resulting from the expansion of macro parameters shall be enclosed in parentheses. (Clang)
* [x] **Rule 20.8**: The controlling expression of a `#if` or `#elif` preprocessing directive shall evaluate to 0 or 1. (Tree-sitter/file scan heuristic)
* [x] **Rule 20.9**: All identifiers used in the controlling expression of `#if` or `#elif` preprocessing directives shall be `#define`'d before evaluation. (Tree-sitter/file scan heuristic)
* [x] **Rule 20.10**: The `#` and `##` preprocessor operators should not be used. (Clang)
* [x] **Rule 20.11**: A macro parameter immediately following a `#` operator shall not immediately be followed by a `##` operator. (Clang)
* [x] **Rule 20.12**: A macro parameter used as an operand to the `#` or `##` operators, which is itself subject to further macro replacement, shall only be used as an operand to these operators. (Clang heuristic)
* [x] **Rule 20.13**: A line whose first token is `#` shall be a valid preprocessing directive. (Tree-sitter)
* [x] **Rule 20.14**: All `#else`, `#elif` and `#endif` preprocessor directives shall reside in the same file as the `#if`, `#ifdef` or `#ifndef` directive to which they are related. (Tree-sitter)

### 21. Standard Libraries
* [x] **Rule 21.1**: `#define` and `#undef` shall not be used on a reserved identifier or reserved macro name. (Clang)
* [x] **Rule 21.2**: A reserved identifier or macro name shall not be declared. (Clang)
* [x] **Rule 21.3**: The memory allocation and deallocation functions of `<stdlib.h>` shall not be used. (Tree-sitter)
* [x] **Rule 21.4**: The standard header file `<setjmp.h>` shall not be used. (Tree-sitter)
* [x] **Rule 21.5**: The standard header file `<signal.h>` shall not be used. (Tree-sitter)
* [x] **Rule 21.6**: The Standard Library input/output functions shall not be used. (Tree-sitter)
* [x] **Rule 21.7**: The `atof`, `atoi`, `atol` and `atoll` functions of `<stdlib.h>` shall not be used. (Clang)
* [x] **Rule 21.8**: The library functions `abort`, `exit`, `getenv` and `system` of `<stdlib.h>` shall not be used. (Clang)
* [x] **Rule 21.9**: The library functions `bsearch` and `qsort` of `<stdlib.h>` shall not be used. (Clang)
* [x] **Rule 21.10**: The Standard Library time and date functions shall not be used. (Tree-sitter)
* [x] **Rule 21.11**: The standard header file `<tgmath.h>` shall not be used. (Tree-sitter)
* [x] **Rule 21.12**: The exception handling features of `<fenv.h>` should not be used. (Tree-sitter)

### 22. Resources
* [x] **Rule 22.1**: All resources obtained dynamically by means of Standard Library functions shall be explicitly released. (Clang heuristic)
* [x] **Rule 22.2**: A block of memory shall only be freed if it was allocated by means of a Standard Library function. (Clang heuristic)
* [x] **Rule 22.3**: The same file shall not be open for read and write access at the same time on different streams. (Clang heuristic)
* [x] **Rule 22.4**: There shall be no attempt to write to a stream which has been opened as read-only. (Clang heuristic)
* [x] **Rule 22.5**: A pointer to a `FILE` object shall not be dereferenced. (Clang)
* [x] **Rule 22.6**: The value of a pointer to a `FILE` shall not be used after the associated stream has been closed. (Clang heuristic)


---

<a id="misra-cpp2008"></a>
## MISRA C++:2008 (228 Rules)
[Back to Quick Navigation](#quick-navigation)

### 0. Language Independent Issues
* [x] **Rule 0-1-1**: A project shall not contain unreachable code. (Clang)
* [x] **Rule 0-1-2**: A project shall not contain infeasible paths. (Clang heuristic)
* [x] **Rule 0-1-3**: A project shall not contain unused variables. (Clang heuristic)
* [x] **Rule 0-1-4**: A project shall not contain non-volatile POD variables having only one use. (Clang heuristic)
* [x] **Rule 0-1-5**: A project shall not contain unused type declarations. (Clang)
* [x] **Rule 0-1-6**: A project shall not contain instances of undefined or critical unspecified behavior. (Clang diagnostic/heuristic)
* [x] **Rule 0-1-7**: The value of an expression shall be the same under any order of evaluation that standard permits. (Clang heuristic)
* [x] **Rule 0-1-8**: All functions with void return type shall have external side effect(s). (Clang heuristic)
* [x] **Rule 0-1-9**: There shall be no dead code. (Clang)
* [x] **Rule 0-1-10**: Every defined function shall be called at least once. (Clang heuristic)
* [x] **Rule 0-1-11**: There shall be no unused parameters in functions. (Clang)
* [x] **Rule 0-1-12**: There shall be no unused variables in functions. (Clang heuristic)
* [x] **Rule 0-2-1**: An object shall not be assigned to an overlapping object. (Clang)
* [-] **Rule 0-3-1**: Minimization of run-time failures shall be ensured by the use of static analysis or equivalent. (Process/compliance rule)
* [x] **Rule 0-3-2**: If a function generates error information, then that error information shall be tested. (Clang heuristic)

### 1. General
* [x] **Rule 1-0-1**: All code shall conform to ISO/IEC 14882:2003 "The C++ Standard" without extensions. (Clang)
* [-] **Rule 1-0-2**: Multiple compilers shall only be used if they have a common, defined interface. (Project/compliance rule)
* [x] **Rule 1-0-3**: The implementation of integer division in the chosen compiler shall be determined, documented and taken into account. (Project configuration rule)

### 2. Lexical Conventions
* [-] **Rule 2-2-1**: The character sets and corresponding encodings shall be documented. (Dokumentations-/Prozessregel)
* [x] **Rule 2-3-1**: Trigraphs shall not be used. (Clang)
* [x] **Rule 2-5-1**: Digraphs should not be used. (Tree-sitter/file scan heuristic)
* [x] **Rule 2-7-1**: The character sequence `/*` shall not be used within a C-style comment. (Tree-sitter)
* [x] **Rule 2-7-2**: Sections of code shall not be "commented out" using C-style comments. (Tree-sitter comment heuristic)
* [x] **Rule 2-7-3**: Sections of code should not be "commented out" using C++ comments. (Tree-sitter comment heuristic)
* [x] **Rule 2-10-1**: Different identifiers shall be typographically unambiguous. (Clang heuristic, configurable via ProjectConfig.misra_heuristics.rule_2_10_1)
* [x] **Rule 2-10-2**: Identifiers declared in an inner scope shall not hide an identifier in an outer scope. (Clang)
* [x] **Rule 2-10-3**: A typedef name shall be a unique identifier. (Clang)
* [x] **Rule 2-10-4**: A class, union or enum name shall be a unique identifier. (Clang)
* [x] **Rule 2-10-5**: The identifier name of a non-member object or function with static storage duration should not be reused. (Clang heuristic)
* [x] **Rule 2-10-6**: If an identifier refers to a type, it shall not also refer to an object or a function in the same scope. (Clang scope heuristic)
* [x] **Rule 2-13-1**: Only those escape sequences defined in the ISO C++ standard shall be used. (Tree-sitter literal heuristic)
* [x] **Rule 2-13-2**: Octal constants and octal escape sequences shall not be used. (Tree-sitter)
* [x] **Rule 2-13-3**: A "U" suffix shall be applied to all octal or hexadecimal constants of unsigned type. (Clang literal/type heuristic)
* [x] **Rule 2-13-4**: Literal suffixes shall be upper case. (Tree-sitter literal heuristic)

### 3. Basic Concepts
* [x] **Rule 3-1-1**: It shall be possible to include any header file in multiple translation units without violating the ODR. (Header content scan heuristic)
* [x] **Rule 3-1-2**: Functions shall not be declared at block scope. (Tree-sitter)
* [x] **Rule 3-1-3**: When an array is declared, its size shall be explicitly specified. (Tree-sitter)
* [x] **Rule 3-2-1**: All declarations of an object or function shall have compatible types. (Cross-TU signature compatibility heuristic)
* [x] **Rule 3-2-2**: The ODR shall not be violated. (Derived Cross-TU ODR inconsistency heuristic)
* [x] **Rule 3-2-3**: A type, object or function shall only be declared once in one translation unit. (Clang TU declaration-count heuristic)
* [x] **Rule 3-2-4**: An identifier with external linkage shall have exactly one definition. (Cross-TU)
* [x] **Rule 3-3-1**: Objects or functions with external linkage shall be declared in a header file. (Cross-TU declaration-location heuristic)
* [x] **Rule 3-3-2**: If a function has internal linkage then all re-declarations shall include the static keyword. (Clang via Rule 8.8 mapping)
* [x] **Rule 3-4-1**: An identifier declared to be an object or type shall be defined in a block that minimizes its visibility. (Clang via Rule 8.9 mapping)
* [x] **Rule 3-9-1**: The types used for an object, a function return type, or a function parameter shall be token-for-token identical. (Cross-TU token/type spelling heuristic)
* [x] **Rule 3-9-2**: `typedef`s that indicate size and signedness should be used in place of the basic numerical types. (Clang declaration-type heuristic)
* [x] **Rule 3-9-3**: The underlying bit representations of floating-point values shall not be used. (Clang cast-category heuristic)

### 4. Standard Conversions
* [x] **Rule 4-5-1**: Expressions with type bool shall not be used as operands to built-in operators other than the assignment operator. (Clang operator/type heuristic)
* [x] **Rule 4-5-2**: Expressions with type enum shall not be used as operands to built-in operators other than the subscript operator. (Clang operator/type heuristic)
* [x] **Rule 4-5-3**: Expressions with type "plain" char and `wchar_t` shall not be used as operands to built-in operators. (Clang operator/type heuristic)
* [x] **Rule 4-10-1**: NULL shall not be used as an integer value. (Clang declaration/expression token heuristic)
* [x] **Rule 4-10-2**: Literal zero shall not be used as the null-pointer-constant. (via Rule 11.9 mapping)

### 5. Expressions
* [x] **Rule 5-0-1**: The value of an expression shall be the same under any order of evaluation that standard permits. (Clang via Rule 13.2 mapping)
* [x] **Rule 5-0-2**: Reliance on C++ evaluation order constraints should not occur. (Clang evaluation-order heuristic)
* [x] **Rule 5-0-3**: A cvalue expression shall not be implicitly converted to a different underlying type. (Clang implicit-conversion heuristic)
* [x] **Rule 5-0-4**: An implicit integral conversion shall not change the signedness of the underlying type. (Clang implicit signedness-conversion heuristic)
* [x] **Rule 5-0-5**: There shall be no implicit conversions between floating-point and integer types. (Clang implicit float/integer-conversion heuristic)
* [x] **Rule 5-0-6**: An implicit conversion to a narrower type shall not occur. (Clang implicit narrowing heuristic)
* [x] **Rule 5-0-7**: There shall be no explicit floating point to integral conversions. (Clang explicit cast heuristic)
* [x] **Rule 5-0-8**: An explicit integral conversion shall not change the signedness of the underlying type. (Clang explicit signedness-conversion heuristic)
* [x] **Rule 5-0-9**: An explicit integral conversion shall not convert to a narrower type. (Clang explicit narrowing heuristic)
* [x] **Rule 5-0-10**: If the bitwise operators `~` and `<<` are applied to an operand with a smaller type, it shall be cast to its required underlying type. (Clang bitwise operand-width heuristic)
* [x] **Rule 5-0-11**: The plain char type shall only be used for the storage and use of character values. (Clang char-usage heuristic)
* [x] **Rule 5-0-12**: Signed and unsigned char type shall only be used for the storage and use of numeric values. (Clang char-usage heuristic)
* [x] **Rule 5-0-13**: The condition of an if-statement and the condition of an iteration-statement shall have type bool. (Clang condition-type heuristic)
* [x] **Rule 5-0-14**: The first operand of a conditional operator shall have type bool. (Clang conditional-operator heuristic)
* [x] **Rule 5-0-15**: Array indexing shall be the only acceptable form of pointer arithmetic. (Clang)
* [x] **Rule 5-0-16**: A pointer operand and any pointer resulting from pointer arithmetic shall both address elements of the same array. (Clang via Rule 18.1 mapping)
* [x] **Rule 5-0-17**: Subtraction between pointers shall only be applied to pointers that address elements of the same array. (Clang via Rule 18.2 mapping)
* [x] **Rule 5-0-18**: >, >=, <, <= shall not be applied to objects of pointer type except where they point to the same array. (Clang via Rule 18.3 mapping)
* [x] **Rule 5-0-19**: The declaration of objects shall contain no more than two levels of pointer indirection. (Clang via Rule 18.5 mapping)
* [x] **Rule 5-0-20**: Non-constant operands to a binary bitwise operator shall have the same underlying type. (Clang bitwise operand-type heuristic)
* [x] **Rule 5-0-21**: Bitwise operators shall only be applied to operands of unsigned underlying type. (Clang)
* [x] **Rule 5-2-1**: Each operand of a logical `&&` or `||` shall be a postfix-expression. (Clang logical-operand form heuristic)
* [x] **Rule 5-2-2**: A pointer to a virtual base class shall only be cast to a pointer to a derived class by means of `dynamic_cast`. (Clang virtual-base cast heuristic)
* [x] **Rule 5-2-3**: Casts from a base class to a derived class should not be performed on polymorphic types. (Clang downcast/polymorphism heuristic)
* [x] **Rule 5-2-4**: C-style casts and functional notation casts shall not be used. (Clang)
* [x] **Rule 5-2-5**: A cast shall not remove any `const` or `volatile` qualification. (Clang)
* [x] **Rule 5-2-6**: A cast shall not convert a pointer to a function to any other pointer type. (Clang)
* [x] **Rule 5-2-7**: An object with pointer type shall not be converted to an unrelated pointer type. (Clang)
* [x] **Rule 5-2-8**: An object with integral, enumerated, or pointer to void type shall not be cast to a pointer type. (Clang cast-source type heuristic)
* [x] **Rule 5-2-9**: A cast should not convert a pointer type to an integral type. (Clang)
* [x] **Rule 5-2-10**: The increment/decrement operators shall not be mixed with other operators in an expression. (Clang via Rule 13.3 mapping/heuristic)
* [x] **Rule 5-2-11**: The comma operator shall not be used. (Clang comma-operator heuristic)
* [x] **Rule 5-2-12**: An identifier with array type passed as a function argument shall not decay to a pointer. (Clang array-decay heuristic)
* [x] **Rule 5-3-1**: Each operand of the `!` operator, the logical `&&`, or `||` shall have type bool. (Clang logical-operand type heuristic)
* [x] **Rule 5-3-2**: The unary minus operator shall not be applied to an expression whose underlying type is unsigned. (Clang unary-operator type heuristic)
* [x] **Rule 5-3-3**: The unary `&` operator shall not be overloaded. (Clang operator-overload heuristic)
* [x] **Rule 5-3-4**: Evaluation of the operand to the sizeof operator shall not contain side effects. (Tree-sitter)
* [x] **Rule 5-8-1**: The right hand operand of a shift operator shall lie between zero and one less than the width in bits of the left hand operand. (Clang)
* [x] **Rule 5-14-1**: The right hand operand of a logical `&&` or `||` operator shall not contain side effects. (Clang)
* [x] **Rule 5-18-1**: The comma operator shall not be used. (Clang)
* [x] **Rule 5-19-1**: Evaluation of constant unsigned integer expressions should not lead to wrap-around. (Clang via Rule 12.4 mapping)

### 6. Statements
* [x] **Rule 6-2-1**: Assignment operators shall not be used in sub-expressions. (Clang)
* [x] **Rule 6-2-2**: Floating-point expressions shall not be tested for equality or inequality. (Clang comparison/type heuristic)
* [x] **Rule 6-2-3**: A null statement shall only occur on a line by itself. (Clang null-statement line heuristic)
* [x] **Rule 6-3-1**: The statement forming the body of a switch, while, do ... while or for statement shall be a compound statement. (Tree-sitter)
* [x] **Rule 6-4-1**: An `if ... else if` construct shall be terminated with an `else` clause. (Tree-sitter)
* [x] **Rule 6-4-2**: All `switch` statements shall be well-formed. (Clang switch-structure heuristic)
* [x] **Rule 6-4-3**: A `switch` statement shall be a well-formed switch statement. (Clang)
* [x] **Rule 6-4-4**: A switch-label shall only be used when the most closely-enclosing compound statement is the body of a switch. (Clang)
* [x] **Rule 6-4-5**: An unconditional `break` statement shall terminate every non-empty switch-clause. (Tree-sitter)
* [x] **Rule 6-4-6**: The final clause of a switch statement shall be the default clause. (Tree-sitter)
* [x] **Rule 6-4-7**: The condition of a switch statement shall not have bool type. (Clang)
* [x] **Rule 6-4-8**: Every switch statement shall have at least one `case`. (Tree-sitter)
* [x] **Rule 6-5-1**: A `for` loop shall contain a single loop-counter. (Clang for-header heuristic)
* [x] **Rule 6-5-2**: If loop-counter is not modified by `--` or `++`, it shall only be incremented or decremented by a compile-time constant. (Clang update-expression heuristic)
* [x] **Rule 6-5-3**: The loop-counter shall not be modified within condition or statement. (Clang condition-update heuristic)
* [x] **Rule 6-5-4**: The loop-counter shall be modified by one of: `--`, `++`, `-=n`, or `+=n`. (Clang update-form heuristic)
* [x] **Rule 6-5-5**: A loop-control-variable other than the loop-counter shall not be modified within condition or statement. (Clang loop-control-variable heuristic)
* [x] **Rule 6-5-6**: A loop-control-variable other than the loop-counter which is modified in statement shall have bool type. (Clang loop-control-variable type heuristic)
* [x] **Rule 6-6-1**: Any label referenced by a `goto` statement shall be declared in the same block, or in a block enclosing the `goto`. (Tree-sitter)
* [x] **Rule 6-6-2**: The `goto` statement shall jump to a label declared later in the same function body. (Tree-sitter)
* [x] **Rule 6-6-3**: The `continue` statement shall only be used within a well-formed `for` loop. (Clang loop-context heuristic)
* [x] **Rule 6-6-4**: For any iteration statement there shall be no more than one `break` or `goto` used for loop termination. (Clang)
* [x] **Rule 6-6-5**: A function shall have a single point of exit at the end of the function. (Clang)

### 7. Declarations
* [x] **Rule 7-1-1**: A variable which is not modified shall be `const` qualified. (Clang local-mutation heuristic)
* [x] **Rule 7-1-2**: A pointer or reference parameter in a function shall be declared as pointer to const or reference to const if the function is not modifying the object. (Clang)
* [x] **Rule 7-2-1**: An expression with enum underlying type shall only have values corresponding to the enumerators. (Clang enum-value heuristic)
* [x] **Rule 7-3-1**: The global namespace shall only contain `main`, namespace declarations and `extern "C"` declarations. (Clang translation-unit scope heuristic)
* [x] **Rule 7-3-2**: The identifier `main` shall not be used for a function other than the global function `main`. (Clang scope check)
* [x] **Rule 7-3-3**: There shall be no unnamed namespaces in header files. (Clang header namespace heuristic)
* [x] **Rule 7-3-4**: using-directives shall not be used. (Clang AST)
* [x] **Rule 7-3-5**: Multiple declarations for an identifier in the same namespace shall not straddle a using-declaration for that identifier. (Clang namespace declaration-order heuristic)
* [x] **Rule 7-3-6**: using-directives and using-declarations (excluding class scope or function scope) shall not be used in header files. (Clang header-scope heuristic)
* [x] **Rule 7-4-1**: All usage of assembler shall be documented. (Clang asm-line documentation heuristic)
* [x] **Rule 7-4-2**: Assembler instructions shall only be introduced using the `asm` declaration. (Clang asm-statement detection)
* [x] **Rule 7-4-3**: Assembly language shall be encapsulated and isolated. (Clang per-function asm isolation heuristic)
* [x] **Rule 7-5-1**: A function shall not return a reference or pointer to an automatic variable defined within the function. (Clang return-flow heuristic)
* [x] **Rule 7-5-2**: The address of an object with automatic storage shall not be assigned to another object that may persist after the first object ends. (Clang persistent-address heuristic)
* [x] **Rule 7-5-3**: A function shall not return a reference or a pointer to a parameter that is passed by reference or pointer. (Clang return-flow heuristic)
* [x] **Rule 7-5-4**: Functions should not call themselves, either directly or indirectly. (Tree-sitter)

### 8. Declarators
* [x] **Rule 8-0-1**: An object or function shall not be defined with multiple declarations in the same translation unit. (Cross-TU)
* [x] **Rule 8-3-1**: Parameters in an overriding virtual function shall either use the same default arguments as the function they override, or else shall not specify default arguments. (Clang override/default-argument heuristic)
* [x] **Rule 8-4-1**: Functions shall not be defined using the ellipsis notation. (Tree-sitter)
* [x] **Rule 8-4-2**: The identifiers used for the parameters in a re-declaration of a function shall be identical to those in the declaration. (Cross-TU / Clang)
* [x] **Rule 8-4-3**: All exit paths from a function with non-void return type shall have an explicit return statement with an expression. (Clang)
* [x] **Rule 8-4-4**: A function identifier shall either be used to call the function or it shall be preceded by `&`. (Clang function-reference heuristic)
* [x] **Rule 8-5-1**: All variables shall have a defined value before they are used. (Clang)
* [x] **Rule 8-5-2**: Braces shall be used to indicate and match the structure in the non-zero initialization of arrays and structures. (Clang)
* [x] **Rule 8-5-3**: In an enumerator list, the `=` construct shall not be used to explicitly initialize members other than the first. (Clang enum-declaration heuristic)

### 9. Classes
* [x] **Rule 9-3-1**: `const` member functions shall not return non-const pointers or references to class-data. (Clang member-return heuristic)
* [x] **Rule 9-3-2**: Member functions shall not return non-const handles to class-data. (Clang member-return heuristic)
* [x] **Rule 9-3-3**: If a member function can be made `const`, it shall be made `const`. (Clang member-mutation heuristic)
* [x] **Rule 9-5-1**: Unions shall not be used. (Tree-sitter)
* [x] **Rule 9-6-1**: Bit-fields shall not be declared. (Clang FIELD_DECL bitfield detection)
* [x] **Rule 9-6-2**: Bit-fields shall have an explicitly specified `unsigned` type. (Clang bitfield type heuristic)
* [x] **Rule 9-6-3**: Bit-fields shall not have enum types. (Clang bitfield enum-type heuristic)
* [x] **Rule 9-6-4**: Named bit-fields with signed integer type shall have a length of more than one bit. (Clang bitfield-width heuristic)

### 10. Derived Classes
* [x] **Rule 10-1-1**: Classes should not be derived from virtual bases. (Clang hierarchy virtual-base heuristic)
* [x] **Rule 10-1-2**: A base class shall only be declared virtual if it is used in a multiple inheritance hierarchy. (Clang direct-base heuristic)
* [x] **Rule 10-1-3**: An accessible base class shall not be both virtual and non-virtual in the same hierarchy. (Clang ancestry-path heuristic)
* [x] **Rule 10-2-1**: All accessible entity names from a base class object shall be unambiguous. (Clang base-member collision heuristic)
* [x] **Rule 10-3-1**: There shall be no more than one definition of each virtual function on each path through the inheritance hierarchy. (Clang multi-base virtual-definition heuristic)
* [x] **Rule 10-3-2**: Each overriding virtual function shall be declared with the `virtual` keyword. (Clang override token heuristic)
* [x] **Rule 10-3-3**: A virtual function shall only be overridden by a pure virtual function if it is itself declared as pure virtual. (Clang pure-override hierarchy heuristic)

### 11. Member Access Control
* [x] **Rule 11-0-1**: Member data in non-POD class types shall be private. (Clang non-POD/member-access heuristic)

### 12. Special Member Functions
* [x] **Rule 12-1-1**: An object's dynamic type shall not be used from the body of its constructor or destructor. (Clang ctor/dtor dynamic-dispatch heuristic)
* [x] **Rule 12-1-2**: All constructors of a class should explicitly call a constructor for all of its immediate base classes and all virtual base classes. (Clang constructor-initializer/base coverage heuristic)
* [x] **Rule 12-1-3**: All constructors that are callable with a single argument of fundamental type shall be declared explicit. (Clang constructor-parameter/token heuristic)
* [x] **Rule 12-8-1**: A copy constructor shall only initialize its base classes and the non-static members of the class. (Clang copy-constructor initializer-target heuristic)
* [x] **Rule 12-8-2**: The copy assignment operator shall be declared protected or private in an abstract class. (Clang abstract-class copy-assignment heuristic)

### 14. Templates
* [x] **Rule 14-5-1**: A non-member generic function shall only be declared in a namespace that is not an associated namespace. (Source-scan non-member template scope heuristic)
* [x] **Rule 14-5-2**: A copy constructor shall be declared when there is a template constructor with a single parameter that is a generic parameter. (Clang class-template constructor heuristic)
* [x] **Rule 14-5-3**: A copy assignment operator shall be declared when there is a template assignment operator with a parameter that is a generic parameter. (Clang class-template assignment heuristic)
* [x] **Rule 14-6-1**: In a class template with a dependent base, any name that may be found in that base shall be referred to using a qualified name or `this->`. (Source-scan dependent-base unqualified-name heuristic)
* [x] **Rule 14-6-2**: The function called by a generic function shall depend on the type of a generic parameter. (Source-scan generic-call dependency heuristic)
* [x] **Rule 14-7-1**: All class templates, function templates, class template static members and class template member functions shall be instantiated at least once. (Source-scan TU-local template instantiation heuristic)
* [x] **Rule 14-7-2**: For any given template specialization, an explicit instantiation of the template shall not appear. (Source-scan explicit-instantiation heuristic)
* [x] **Rule 14-7-3**: All partial and explicit specializations for a template shall be declared in the same file as the declaration of their primary template. (Source-scan specialization-without-primary heuristic)
* [x] **Rule 14-8-1**: Overloaded function templates shall not be explicitly specialized. (Source-scan overload-specialization heuristic)
* [x] **Rule 14-8-2**: The viable function set for a function call should either contain no function specializations, or consist only of function specializations. (Source-scan mixed primary/specialization call heuristic)

### 15. Exception Handling
* [x] **Rule 15-0-1**: Exceptions shall only be used for error handling. (Clang throw-type heuristic for primitive/pointer exception objects)
* [x] **Rule 15-0-2**: An exception object should not have pointer type. (Clang throw-type heuristic)
* [x] **Rule 15-0-3**: Control shall not be transferred into a try or catch block using a goto or a switch statement. (Clang goto-into-try/catch extent heuristic)
* [x] **Rule 15-1-1**: The assignment expression of a throw statement shall not itself cause an exception to be thrown. (Clang throw-operand call heuristic)
* [x] **Rule 15-1-2**: NULL shall not be thrown explicitly. (Clang throw-token heuristic)
* [x] **Rule 15-1-3**: An empty `throw` (re-throw) shall only be used in the compound-statement of a `catch` handler. (Clang throw-context heuristic)
* [-] **Rule 15-3-1**: Exceptions shall be raised only after start-up and before termination. (Process/compliance rule)
* [x] **Rule 15-3-2**: There should be at least one exception handler to catch all otherwise unhandled exceptions. (Clang try/catch-all heuristic)
* [x] **Rule 15-3-3**: Handlers of a function-try-block implementation of a class constructor or destructor shall not reference non-static members. (Clang ctor/dtor function-try catch-member-reference heuristic)
* [x] **Rule 15-3-4**: Each exception handler shall catch by reference. (Clang catch-parameter heuristic)
* [x] **Rule 15-3-5**: A class type exception shall always be caught by reference or pointer. (Clang catch-type heuristic)
* [x] **Rule 15-3-6**: Where multiple handlers are provided, they shall appear in an order from most derived exception to least derived. (Clang handler-order hierarchy heuristic)
* [x] **Rule 15-3-7**: Where multiple handlers are provided, any handler for a base class shall not be followed by a handler for a derived class. (Clang handler-order hierarchy heuristic)
* [x] **Rule 15-4-1**: If a function is declared with an exception-specification, then all declarations of the same function shall be declared with the same set of type-ids. (Clang declaration exception-spec consistency heuristic)
* [x] **Rule 15-5-1**: A class destructor shall not exit with an exception. (Clang destructor-throw heuristic)
* [x] **Rule 15-5-2**: Where a function's declaration includes an exception-specification, the function shall only throw exceptions of the indicated type(s). (Clang throw-type vs exception-spec heuristic)
* [x] **Rule 15-5-3**: The terminate() function shall not be called implicitly. (Clang exception-spec mismatch -> implicit terminate heuristic)

### 16. Preprocessing
* [x] **Rule 16-0-1**: `#include` directives in a file shall only be preceded by other preprocessor directives or comments. (Tree-sitter)
* [x] **Rule 16-0-2**: Macros shall only be `#define`'d or `#undef`'d in the global namespace. (Source-scan brace-depth heuristic)
* [x] **Rule 16-0-3**: `#undef` shall not be used. (Clang)
* [x] **Rule 16-0-4**: Function-like macros shall not be defined. (Source-scan macro-definition heuristic)
* [x] **Rule 16-0-5**: Arguments to a function-like macro shall not contain tokens that look like preprocessing directives. (Clang)
* [x] **Rule 16-0-6**: In the definition of a function-like macro, each instance of a parameter shall be enclosed in parentheses. (Clang)
* [x] **Rule 16-0-7**: Undefined macro identifiers shall not be used in `#if` or `#elif` preprocessor directives. (via Rule 20.9 mapping)
* [x] **Rule 16-0-8**: If the `#` token appears as the first token on a line, then it shall be immediately followed by a preprocessing token. (via Rule 20.13 mapping/tree-sitter file scan)
* [x] **Rule 16-1-1**: The `defined` preprocessor operator shall only be used in one of the two standard forms. (Source-scan `#if/#elif` form heuristic)
* [x] **Rule 16-1-2**: All `#else`, `#elif` and `#endif` preprocessor directives shall reside in the same file as the `#if` or `#ifdef` they relate to. (Tree-sitter)
* [-] **Rule 16-2-1**: The pre-processor shall only be used for file inclusion and macro guards. (Policy-/Architekturregel, nur eingeschränkt automatisierbar)
* [-] **Rule 16-2-2**: C++ macros shall only be used for: include guards, type qualifiers, or alignment constants. (Policyregel, semantisch nur begrenzt statisch prüfbar)
* [x] **Rule 16-2-3**: Include guards shall be provided. (Source-scan local-header guard heuristic)
* [x] **Rule 16-2-4**: The `', "` or `\` characters and the `/*` or `//` character sequences shall not occur in a header file name. (Tree-sitter)
* [x] **Rule 16-2-5**: The `\` character should not be used in a `#include` directive string. (Source-scan include-string heuristic)
* [x] **Rule 16-2-6**: The `#include` directive shall be followed by either a `<filename>` or `"filename"` sequence. (Source-scan include-form heuristic)
* [x] **Rule 16-3-1**: There shall be at most one occurrence of the `#` or `##` preprocessor operators in a single macro definition. (Source-scan macro operator-count heuristic)
* [x] **Rule 16-3-2**: The `#` and `##` preprocessor operators should not be used. (Clang)
* [x] **Rule 16-6-1**: All uses of the `#pragma` directive shall be documented and explained. (Source-scan pragma-doc heuristic)

### 17. Standard Libraries
* [x] **Rule 17-0-1**: Reserved identifiers, macros and functions in the standard library, shall not be defined, redefined or undefined. (Source-scan preprocessor define/undef heuristic)
* [x] **Rule 17-0-2**: The names of standard library macros, objects and functions shall not be reused. (Clang declaration-name reuse heuristic)
* [x] **Rule 17-0-3**: The names of standard library macros, objects and functions shall not be reused. (Clang macro-name reuse heuristic)
* [-] **Rule 17-0-4**: All library code shall conform to MISRA C++. (Process/compliance rule)
* [x] **Rule 17-0-5**: The setjmp macro and the longjmp function shall not be used. (Tree-sitter)

### 18. Language Support Library
* [x] **Rule 18-0-1**: The C library shall not be used. (Source-scan C-library include heuristic)
* [x] **Rule 18-0-2**: The library functions `atof`, `atoi` and `atol` from `<cstdlib>` shall not be used. (Clang)
* [x] **Rule 18-0-3**: The library functions `abort`, `exit`, `getenv` and `system` from `<cstdlib>` shall not be used. (Clang)
* [x] **Rule 18-0-4**: The time handling functions of `<ctime>` shall not be used. (Tree-sitter)
* [x] **Rule 18-0-5**: The unbounded string handling functions of `<cstring>` shall not be used. (Clang call-name heuristic)
* [x] **Rule 18-2-1**: The macro offsetof shall not be used. (Source-scan macro-usage heuristic)
* [x] **Rule 18-4-1**: Dynamic heap memory allocation shall not be used. (Tree-sitter)
* [x] **Rule 18-7-1**: The signal handling facilities of `<csignal>` shall not be used. (Tree-sitter)

### 19. Diagnostics Library
* [x] **Rule 19-3-1**: The error indicator errno shall not be used. (Source-scan identifier heuristic)

### 27. Input/Output Library
* [x] **Rule 27-0-1**: The stream input/output library `<cstdio>` shall not be used. (Tree-sitter)

---

<a id="misra-c2023"></a>
## MISRA C:2023 (200 Rules, Profile c2023)
[Back to Quick Navigation](#quick-navigation)

### Official Rule IDs (MISRA C:2023)
### Chapter 1
* [x] **Rule-1.1**: The program shall contain no violations of the standard C syntax and constraints, and shall not exceed the implementation's translation limits
* [x] **Rule-1.2**: Language extensions should not be used
* [x] **Rule-1.3**: There shall be no occurrence of undefined or critical unspecified behaviour
* [x] **Rule-1.4**: Emergent language features shall not be used
* [x] **Rule-1.5**: Obsolescent language features shall not be used

### Chapter 2
* [x] **Rule-2.1**: A project shall not contain unreachable code
* [x] **Rule-2.2**: A project shall not contain dead code
* [x] **Rule-2.3**: A project should not contain unused type declarations
* [x] **Rule-2.4**: A project should not contain unused tag declarations
* [x] **Rule-2.5**: A project should not contain unused macro definitions
* [x] **Rule-2.6**: A function should not contain unused label declarations
* [x] **Rule-2.7**: A function should not contain unused parameters
* [x] **Rule-2.8**: A project should not contain unused object definitions

### Chapter 3
* [x] **Rule-3.1**: The character sequences /* and // shall not be used within a comment.
* [x] **Rule-3.2**: Line-splicing shall not be used in // comments.

### Chapter 4
* [x] **Rule-4.1**: Octal and hexadecimal escape sequences shall be terminated
* [x] **Rule-4.2**: Trigraphs should not be used

### Chapter 5
* [x] **Rule-5.1**: External identifiers shall be distinct
* [x] **Rule-5.2**: Identifiers declared in the same scope and name space shall be distinct
* [x] **Rule-5.3**: An identifier declared in an inner scope shall not hide an identifier declared in an outer scope
* [x] **Rule-5.4**: Macro identifiers shall be distinct
* [x] **Rule-5.5**: Identifiers shall be distinct from macro names
* [x] **Rule-5.6**: A typedef name shall be a unique identifier
* [x] **Rule-5.7**: A tag name shall be a unique identifier
* [x] **Rule-5.8**: Identifiers that define objects or functions with external linkage shall be unique
* [x] **Rule-5.9**: Identifiers that define objects or functions with internal linkage should be unique

### Chapter 6
* [x] **Rule-6.1**: Bit-fields shall only be declared with an appropriate type
* [x] **Rule-6.2**: Single-bit named bit fields shall not be of a signed type
* [x] **Rule-6.3**: A bit field shall not be declared as a member of a union

### Chapter 7
* [x] **Rule-7.1**: Octal constants shall not be used
* [x] **Rule-7.2**: A "u" or "U" suffix shall be applied to all integer constants that are represented in an unsigned type
* [x] **Rule-7.3**: The lowercase character "l" shall not be used in a literal suffix
* [x] **Rule-7.4**: A string literal shall not be assigned to an object unless the object's type is "pointer to const-qualified char"
* [x] **Rule-7.5**: The argument of an integer-constant macro shall have an appropriate form
* [x] **Rule-7.6**: The small integer variants of the minimum-width integer constant macros shall not be used

### Chapter 8
* [x] **Rule-8.1**: Types shall be explicitly specified
* [x] **Rule-8.2**: Function types shall be in prototype form with named parameters
* [x] **Rule-8.3**: All declarations of an object or function shall use the same names and type qualifiers
* [x] **Rule-8.4**: A compatible declaration shall be visible when an object or function with external linkage is defined
* [x] **Rule-8.5**: An external object or function shall be declared once in one and only one file
* [x] **Rule-8.6**: An identifier with external linkage shall have exactly one external definition
* [x] **Rule-8.7**: Functions and objects should not be defined with external linkage if they are referenced in only one translation unit
* [x] **Rule-8.8**: The static storage class specifier shall be used in all declarations of objects and functions that have internal linkage
* [x] **Rule-8.9**: An object should be declared at block scope if its identifier only appears in a single function
* [x] **Rule-8.10**: An inline function shall be declared with the static storage class
* [x] **Rule-8.11**: When an array with external linkage is declared, its size should be explicitly specified
* [x] **Rule-8.12**: Within an enumerator list, the value of an implicitly-specified enumeration constant shall be unique
* [x] **Rule-8.13**: A pointer should point to a const-qualified type whenever possible
* [x] **Rule-8.14**: The restrict type qualifier shall not be used
* [x] **Rule-8.15**: All declarations of an object with an explicit alignment specification shall specify the same alignment.
* [x] **Rule-8.16**: The alignment specification of zero should not appear in an object declaration.
* [x] **Rule-8.17**: At most one explicit alignment specifier should appear in an object declaration.

### Chapter 9
* [x] **Rule-9.1**: The value of an object with automatic storage duration shall not be read before it has been set
* [x] **Rule-9.2**: The initializer for an aggregate or union shall be enclosed in braces
* [x] **Rule-9.3**: Arrays shall not be partially initialized
* [x] **Rule-9.4**: An element of an object shall not be initialized more than once
* [x] **Rule-9.5**: Where designated initializers are used to initialize an array object the size of the array shall be specified explicitly
* [x] **Rule-9.6**: An initializer using chained designators shall not contain initializers without designators
* [x] **Rule-9.7**: Atomic objects shall be appropriately initialized before being accessed

### Chapter 10
* [x] **Rule-10.1**: Operands shall not be of an inappropriate essential type.
* [x] **Rule-10.2**: Expressions of essentially character type shall not be used inappropriately in addition and subtraction operations
* [x] **Rule-10.3**: The value of an expression shall not be assigned to an object with a narrower essential type or of a different essential type category.
* [x] **Rule-10.4**: Both operands of an operator in which the usual arithmetic conversions are performed shall have the same essential type category
* [x] **Rule-10.5**: The value of an expression should not be cast to an inappropriate essential type
* [x] **Rule-10.6**: The value of a composite expression shall not be assigned to an object with wider essential type
* [x] **Rule-10.7**: If a composite expression is used as one operand of an operator in which the usual arithmetic conversions are performed then the other operand shall not have wider essential type
* [x] **Rule-10.8**: The value of a composite expression shall not be cast to a different essential type category or a wider essential type

### Chapter 11
* [x] **Rule-11.1**: Conversions shall not be performed between a pointer to a function and any other type
* [x] **Rule-11.2**: Conversions shall not be performed between a pointer to an incomplete type and any other type
* [x] **Rule-11.3**: A conversion shall not be performed between a pointer to object type and a pointer to a different object type
* [x] **Rule-11.4**: A conversion should not be performed between a pointer to object and an integer type
* [x] **Rule-11.5**: A conversion should not be performed from pointer to void into pointer to object
* [x] **Rule-11.6**: A cast shall not be performed between pointer to void and an arithmetic type
* [x] **Rule-11.7**: A cast shall not be performed between pointer to object and a non-integer arithmetic type
* [x] **Rule-11.8**: A cast shall not remove any const or volatile qualification from the type pointed to by a pointer
* [x] **Rule-11.9**: The macro NULL shall be the only permitted form of integer null pointer constant
* [x] **Rule-11.10**: The _Atomic qualifier shall not be applied to the incomplete type void.

### Chapter 12
* [x] **Rule-12.1**: The precedence of operators within expressions should be made explicit
* [x] **Rule-12.2**: The right hand operand of a shift operator shall lie in the range zero to one less than the width in bits of the essential type of the left hand operand
* [x] **Rule-12.3**: The comma operator should not be used
* [x] **Rule-12.4**: Evaluation of constant expressions should not lead to unsigned integer wrap-around
* [x] **Rule-12.5**: The sizeof operator shall not have an operand which is a function parameter declared as 'array of type'
* [x] **Rule-12.6**: Structure and union members of atomic objects shall not be directly accessed.

### Chapter 13
* [x] **Rule-13.1**: Initializer lists shall not contain persistent side-effects
* [x] **Rule-13.2**: The value of an expression and its persistent side-effects shall be the same under all permitted evaluation orders and shall be independent from thread interleaving
* [x] **Rule-13.3**: A full expression containing an increment (++) or decrement (--) operator should have no other potential side effects other than that caused by the increment or decrement operator
* [x] **Rule-13.4**: The result of an assignment operator should not be used
* [x] **Rule-13.5**: The right hand operand of a logical && or || operator shall not contain persistent side effects
* [x] **Rule-13.6**: The operand of the sizeof operator shall not contain any expression which has potential side-effects

### Chapter 14
* [x] **Rule-14.1**: A loop counter shall not have essentially floating type
* [x] **Rule-14.2**: A for loop shall be well-formed
* [x] **Rule-14.3**: Controlling expressions shall not be invariant
* [x] **Rule-14.4**: The controlling expression of an if-statement and the controlling expression of an iteration-statement shall have essentially Boolean type

### Chapter 15
* [x] **Rule-15.1**: The goto statement should not be used
* [x] **Rule-15.2**: The goto statement shall jump to a label declared later in the same function
* [x] **Rule-15.3**: Any label referenced by a goto statement shall be declared in the same block, or in any block enclosing the goto statement
* [x] **Rule-15.4**: There should be no more than one break or goto statement used to terminate any iteration statement
* [x] **Rule-15.5**: A function should have a single point of exit at the end
* [x] **Rule-15.6**: The body of an iteration-statement or a selection-statement shall be a compound-statement
* [x] **Rule-15.7**: All if ... else if constructs shall be terminated with an else statement

### Chapter 16
* [x] **Rule-16.1**: All switch statements shall be well-formed
* [x] **Rule-16.2**: A switch label shall only be used when the most closely-enclosing compound statement is the body of a switch statement
* [x] **Rule-16.3**: An unconditional break statement shall terminate every switch-clause
* [x] **Rule-16.4**: Every switch statement shall have a default label
* [x] **Rule-16.5**: A default label shall appear as either the first or the last switch label of a switch statement
* [x] **Rule-16.6**: Every switch statement shall have at least two switch-clauses
* [x] **Rule-16.7**: A switch-expression shall not have essentially Boolean type

### Chapter 17
* [x] **Rule-17.1**: The standard header file <stdarg.h> shall not be used
* [x] **Rule-17.2**: Functions shall not call themselves, either directly or indirectly
* [x] **Rule-17.3**: A function shall not be declared implicitly
* [x] **Rule-17.4**: All exit paths from a function with non-void return type shall have an explicit return statement with an expression
* [x] **Rule-17.5**: The function argument corresponding to a parameter declared to have an array type shall have an appropriate number of elements
* [x] **Rule-17.6**: The declaration of an array parameter shall not contain the static keyword between the [ ]
* [x] **Rule-17.7**: The value returned by a function having non-void return type shall be used
* [x] **Rule-17.8**: A function parameter should not be modified
* [x] **Rule-17.9**: A function declared with a _Noreturn function specifier shall not return to its caller
* [x] **Rule-17.10**: A function declared with a _Noreturn function specifier shall have void return type
* [x] **Rule-17.11**: A function that never returns should be declared with a _Noreturn function specifier
* [x] **Rule-17.12**: A function identifier should only be used with either a preceding &, or with a parenthesised parameter list
* [x] **Rule-17.13**: A function type shall not be type qualified

### Chapter 18
* [x] **Rule-18.1**: A pointer resulting from arithmetic on a pointer operand shall address an element of the same array as that pointer operand
* [x] **Rule-18.2**: Subtraction between pointers shall only be applied to pointers that address elements of the same array
* [x] **Rule-18.3**: The relational operators >, >=, < and <= shall not be applied to expressions of pointer type except where they point into the same object
* [x] **Rule-18.4**: The +, -, += and -= operators should not be applied to an expression of pointer type
* [x] **Rule-18.5**: Declarations should contain no more than two levels of pointer nesting
* [x] **Rule-18.6**: The address of an object with automatic or thread-local storage shall not be copied to another object that persists after the first object has ceased to exist
* [x] **Rule-18.7**: Flexible array members shall not be declared
* [x] **Rule-18.8**: Variable-length arrays shall not be used
* [x] **Rule-18.9**: An object with temporary lifetime shall not undergo array-to-pointer conversion
* [x] **Rule-18.10**: Pointers to variably-modified array types shall not be used

### Chapter 19
* [x] **Rule-19.1**: An object shall not be assigned or copied to an overlapping object
* [x] **Rule-19.2**: The union keyword should not be used

### Chapter 20
* [x] **Rule-20.1**: #include directives should only be preceded by preprocessor directives or comments
* [x] **Rule-20.2**: The ', " or \ characters and the /* or // character sequences shall not occur in a header file name
* [x] **Rule-20.3**: The #include directive shall be followed by either a <filename> or "filename" sequence
* [x] **Rule-20.4**: A macro shall not be defined with the same name as a keyword
* [x] **Rule-20.5**: #undef should not be used
* [x] **Rule-20.6**: Tokens that look like a preprocessing directive shall not occur within a macro argument
* [x] **Rule-20.7**: Expressions resulting from the expansion of macro parameters shall be enclosed in parentheses
* [x] **Rule-20.8**: The controlling expression of a #if or #elif preprocessing directive shall evaluate to 0 or 1
* [x] **Rule-20.9**: All identifiers used in the controlling expression of #if or #elif preprocessing directives shall be #define'd before evaluation
* [x] **Rule-20.10**: The # and ## preprocessor operators should not be used
* [x] **Rule-20.11**: A macro parameter immediately following a # operator shall not immediately be followed by a ## operator
* [x] **Rule-20.12**: A macro parameter used as an operand to the # or ## operators, which is itself subject to further macro replacement, shall only be used as an operand to these operators
* [x] **Rule-20.13**: A line whose first token is # shall be a valid preprocessing directive
* [x] **Rule-20.14**: All #else, #elif and #endif preprocessor directives shall reside in the same file as the #if, #ifdef or #ifndef directive to which they are related

### Chapter 21
* [x] **Rule-21.1**: #define and #undef shall not be used on a reserved identifier or reserved macro name
* [x] **Rule-21.2**: A reserved identifier or reserved macro name shall not be declared
* [x] **Rule-21.3**: The memory allocation and deallocation functions of <stdlib.h> shall not be used
* [x] **Rule-21.4**: The standard header file <setjmp.h> shall not be used
* [x] **Rule-21.5**: The standard header file <signal.h> shall not be used
* [x] **Rule-21.6**: The Standard Library input/output functions shall not be used
* [x] **Rule-21.7**: The Standard Library functions atof, atoi, atol and atoll of <stdlib.h> shall not be used
* [x] **Rule-21.8**: The Standard Library functions abort, exit, getenv and system of <stdlib.h> shall not be used
* [x] **Rule-21.9**: The Standard Library functions bsearch and qsort of <stdlib.h> shall not be used
* [x] **Rule-21.10**: The Standard Library time and date functions shall not be used
* [x] **Rule-21.11**: The standard header file <tgmath.h> should not be used
* [x] **Rule-21.12**: The standard header file <fenv.h> shall not be used
* [x] **Rule-21.13**: Any value passed to a function in <ctype.h> shall be representable as an unsigned char or be the value EOF
* [x] **Rule-21.14**: The Standard Library function memcmp shall not be used to compare null terminated strings
* [x] **Rule-21.15**: The pointer arguments to the Standard Library functions memcpy, memmove and memcmp shall be pointers to qualified or unqualified versions of compatible types
* [x] **Rule-21.16**: The pointer arguments to the Standard Library function memcmp shall point to either a pointer type, an essentially signed type, an essentially unsigned type, an essentially Boolean type or an essentially enum type
* [x] **Rule-21.17**: Use of the string handling functions from <string.h> shall not result in accesses beyond the bounds of the objects referenced by their pointer parameters
* [x] **Rule-21.18**: The size_t argument passed to any function in <string.h> shall have an appropriate value
* [x] **Rule-21.19**: The pointers returned by the Standard Library functions localeconv, getenv, setlocale or strerror shall only be used as if they have pointer to const-qualified type
* [x] **Rule-21.20**: The pointer returned by the Standard Library functions asctime, ctime, gmtime, localtime, localeconv, getenv, setlocale, or strerror shall not be used following a subsequent call to the same function
* [x] **Rule-21.21**: The Standard Library system of <stdlib.h> shall not be used
* [x] **Rule-21.22**: All operand arguments to any type-generic macros declared in <tgmath.h> shall have an appropriate essential type
* [x] **Rule-21.23**: All operand arguments to any multi-argument type-generic macros declared in <tgmath.h> shall have the same standard type
* [x] **Rule-21.24**: The random number generator functions of <stdlib.h> shall not be used.
* [x] **Rule-21.25**: All memory synchronization operations shall be executed in sequentially consistent order.
* [x] **Rule-21.26**: The Standard Library function mtx_timedlock() shall only be invoked on mutex objects of appropriate mutex type

### Chapter 22
* [x] **Rule-22.1**: All resources obtained dynamically by means of Standard Library functions shall be explicitly released
* [x] **Rule-22.2**: A block of memory shall only be freed if it was allocated by means of a Standard Library function
* [x] **Rule-22.3**: The same file shall not be open for read and write access at the same time on different streams
* [x] **Rule-22.4**: There shall be no attempt to write to a stream which has been opened as read-only
* [x] **Rule-22.5**: A pointer to a FILE object shall not be dereferenced
* [x] **Rule-22.6**: The value of a pointer to a FILE shall not be used after the associated stream has been closed
* [x] **Rule-22.7**: The macro EOF shall only be compared with the unmodified return value from any Standard Library function capable of returning EOF
* [x] **Rule-22.8**: The value of errno shall be set to zero prior to a call to an errno-setting-function
* [x] **Rule-22.9**: The value of errno shall be tested against zero after calling an errno-setting-function
* [x] **Rule-22.10**: The value of errno shall only be tested when the last function to be called was an errno-setting-function
* [x] **Rule-22.11**: A thread that was previously either joined or detached shall not be subsequently joined nor detached
* [x] **Rule-22.12**: Thread objects, thread synchronization objects, and thread-specific storage pointers shall only be accessed by the appropriate Standard Library functions
* [x] **Rule-22.13**: Thread objects, thread synchronization objects and thread-specific storage pointers shall have appropriate storage duration
* [x] **Rule-22.14**: Thread synchronization objects shall be initialized before being accessed
* [x] **Rule-22.15**: Thread synchronization objects and thread-specific storage pointers shall not be destroyed until after all threads accessing them have terminated
* [x] **Rule-22.16**: All mutex objects locked by a thread shall be explicitly unlocked by the same thread
* [x] **Rule-22.17**: No thread shall unlock a mutex or call cnd_wait() or cnd_timedwait() for a mutex it has not locked before
* [x] **Rule-22.18**: Non-recursive mutexes shall not be recursively locked
* [x] **Rule-22.19**: A condition variable shall be associated with at most one mutex object
* [x] **Rule-22.20**: Thread-specific storage pointers shall be created before being accessed

### Chapter 23
* [x] **Rule-23.1**: A generic selection should only be expanded from a macro
* [x] **Rule-23.2**: A generic selection that is not expanded from a macro shall not contain potential side effects in the controlling expression
* [x] **Rule-23.3**: A generic selection should contain at least one non-default association
* [x] **Rule-23.4**: A generic association shall list an appropriate type
* [x] **Rule-23.5**: A generic selection should not depend on implicit pointer type conversion
* [x] **Rule-23.6**: The controlling expression of a generic selection shall have an essential type that matches its standard type
* [x] **Rule-23.7**: A generic selection that is expanded from a macro should evaluate its argument only once
* [x] **Rule-23.8**: A default association shall appear as either the first or the last association of a generic selection

---

<a id="misra-cpp2023"></a>
## MISRA C++:2023 (175 Rules, Profile cpp2023)
[Back to Quick Navigation](#quick-navigation)

### Official Rule IDs (MISRA C++:2023)
### Chapter 0
* [x] **Rule-0.0.1**: A function shall not contain unreachable statements
* [x] **Rule-0.0.2**: Controlling expressions should not be invariant
* [x] **Rule-0.1.1**: A value should not be unnecessarily written to a local object
* [x] **Rule-0.1.2**: The value returned by a function shall be used
* [x] **Rule-0.2.1**: Variables with limited visibility should be used at least once
* [x] **Rule-0.2.2**: A named function parameter shall be used at least once
* [x] **Rule-0.2.3**: Types with limited visibility should be used at least once
* [x] **Rule-0.2.4**: Functions with limited visibility should be used at least once

### Chapter 4
* [x] **Rule-4.1.1**: A program shall conform to ISO/IEC 14882:2017 (C++17)
* [x] **Rule-4.1.2**: Deprecated features should not be used
* [x] **Rule-4.1.3**: There shall be no occurrence of //undefined// or //critical unspecified behaviour//
* [x] **Rule-4.6.1**: Operations on a memory location shall be sequenced appropriately

### Chapter 5
* [x] **Rule-5.0.1**: Trigraph-like sequences should not be used
* [x] **Rule-5.7.1**: The character sequence /* shall not be used within a C-style comment
* [x] **Rule-5.7.3**: Line-splicing shall not be used in // comments
* [x] **Rule-5.10.1**: User-defined identifiers shall have an appropriate form
* [x] **Rule-5.13.1**: Within character literals and non raw-string literals, \ shall only be used to form a defined escape sequence or universal character name
* [x] **Rule-5.13.2**: Octal escape sequences, hexadecimal escape sequences and universal character names shall be terminated
* [x] **Rule-5.13.3**: Octal constants shall not be used
* [x] **Rule-5.13.4**: Unsigned integer literals shall be appropriately suffixed
* [x] **Rule-5.13.5**: The lowercase form of "L" shall not be used as the first character in a literal suffix
* [x] **Rule-5.13.6**: An integer-literal of type long long shall not use a single L or l in any suffix
* [x] **Rule-5.13.7**: String literals with different encoding prefixes shall not be concatenated

### Chapter 6
* [x] **Rule-6.0.1**: Block scope declarations shall not be visually ambiguous
* [x] **Rule-6.0.2**: When an array with external linkage is declared, its size should be explicitly specified
* [x] **Rule-6.0.3**: The only declarations in the global namespace should be main, namespace declarations and extern "C" declarations
* [x] **Rule-6.0.4**: The identifier main shall not be used for a function other than the global function main
* [x] **Rule-6.2.1**: The one-definition rule shall not be violated
* [x] **Rule-6.2.2**: All declarations of a variable or function shall have the same type
* [x] **Rule-6.2.3**: The source code used to implement an entity shall appear only once
* [x] **Rule-6.2.4**: A header file shall not contain definitions of functions or objects that are non-inline and have external linkage
* [x] **Rule-6.4.1**: A variable declared in an inner scope shall not hide a variable declared in an outer scope
* [x] **Rule-6.4.2**: Derived classes shall not conceal functions that are inherited from their bases
* [x] **Rule-6.4.3**: A name that is present in a dependent base shall not be resolved by unqualified lookup
* [x] **Rule-6.5.1**: A function or object with external linkage should be introduced in a header file
* [x] **Rule-6.5.2**: Internal linkage should be specified appropriately
* [x] **Rule-6.7.1**: Local variables shall not have static storage duration
* [x] **Rule-6.7.2**: Global variables shall not be used
* [x] **Rule-6.8.1**: An object shall not be accessed outside of its lifetime
* [x] **Rule-6.8.2**: A function must not return a reference or a pointer to a local variable with automatic storage duration
* [x] **Rule-6.8.3**: An assignment operator shall not assign the address of an object with automatic storage duration to an object with a greater lifetime
* [x] **Rule-6.8.4**: Member functions returning references to their object should be ref-qualified appropriately
* [x] **Rule-6.9.1**: The same type aliases shall be used in all declarations of the same entity
* [x] **Rule-6.9.2**: The names of the standard signed integer types and standard unsigned integer types should not be used

### Chapter 7
* [x] **Rule-7.0.1**: There shall be no conversion from type bool
* [x] **Rule-7.0.2**: There shall be no conversion to type bool
* [x] **Rule-7.0.3**: The numerical value of a character shall not be used
* [x] **Rule-7.0.4**: The operands of bitwise operators and shift operators shall be appropriate
* [x] **Rule-7.0.5**: Integral promotion and the usual arithmetic conversions shall not change the signedness or the type category of an operand
* [x] **Rule-7.0.6**: Assignment between numeric types shall be appropriate
* [x] **Rule-7.11.1**: nullptr shall be the only form of the null-pointer-constant
* [x] **Rule-7.11.2**: An array passed as a function argument shall not decay to a pointer
* [x] **Rule-7.11.3**: A conversion from function type to pointer-to-function type shall only occur in appropriate contexts

### Chapter 8
* [x] **Rule-8.0.1**: Parentheses should be used to make the meaning of an expression appropriately explicit
* [x] **Rule-8.1.1**: A non-transient lambda shall not implicitly capture this
* [x] **Rule-8.1.2**: Variables should be captured explicitly in a non-transient lambda
* [x] **Rule-8.2.1**: A virtual base class shall only be cast to a derived class by means of dynamic_cast
* [x] **Rule-8.2.2**: C-style casts and functional notation casts shall not be used
* [x] **Rule-8.2.3**: A cast shall not remove any const or volatile qualification from the type accessed via a pointer or by reference
* [x] **Rule-8.2.4**: Casts shall not be performed between a pointer to a function and any other type
* [x] **Rule-8.2.5**: reinterpret_cast shall not be used
* [x] **Rule-8.2.6**: An object with integral, enumerated, or pointer to void type shall not be cast to a pointer type
* [x] **Rule-8.2.7**: A cast should not convert a pointer type to an integral type
* [x] **Rule-8.2.8**: An object pointer type shall not be cast to an integral type other than std::uintptr_t or std::intptr_t
* [x] **Rule-8.2.9**: The operand to typeid shall not be an expression of polymorphic class type
* [x] **Rule-8.2.10**: Functions shall not call themselves, either directly or indirectly
* [x] **Rule-8.2.11**: An argument passed via ellipsis shall have an appropriate type
* [x] **Rule-8.3.1**: The built-in unary - operator should not be applied to an expression of unsigned type
* [x] **Rule-8.3.2**: The built-in unary + operator should not be used
* [x] **Rule-8.7.1**: Pointer arithmetic shall not form an invalid pointer
* [x] **Rule-8.7.2**: Subtraction between pointers shall only be applied to pointers that address elements of the same array
* [x] **Rule-8.9.1**: The built-in relational operators >, >=, < and <= shall not be applied to objects of pointer type, except where they point to elements of the same array
* [x] **Rule-8.14.1**: The right-hand operand of a logical && or || operator should not contain persistent side effects
* [x] **Rule-8.18.1**: An object or sub-object must not be copied to an overlapping object
* [x] **Rule-8.18.2**: The result of an assignment operator should not be used
* [x] **Rule-8.19.1**: The comma operator should not be used
* [x] **Rule-8.20.1**: An unsigned arithmetic operation with constant operands should not wrap

### Chapter 9
* [x] **Rule-9.2.1**: An Explicit type conversion shall not be an expression statement
* [x] **Rule-9.3.1**: The body of an iteration-statement or a selection-statement shall be a compound-statement
* [x] **Rule-9.4.1**: All if ... else if constructs shall be terminated with an else statement
* [x] **Rule-9.4.2**: The structure of a switch statement shall be appropriate
* [x] **Rule-9.5.1**: Legacy for statements should be simple
* [x] **Rule-9.5.2**: A for-range-initializer shall contain at most one function call
* [x] **Rule-9.6.1**: The goto statement should not be used
* [x] **Rule-9.6.2**: A goto statement shall reference a label in a surrounding block
* [x] **Rule-9.6.3**: The goto statement shall jump to a label declared later in the function body
* [x] **Rule-9.6.4**: A function declared with the [[noreturn]] attribute shall not return
* [x] **Rule-9.6.5**: A function with non-void return type shall return a value on all paths

### Chapter 10
* [x] **Rule-10.0.1**: A declaration should not declare more than one variable or member variable
* [x] **Rule-10.1.1**: The target type of a pointer or lvalue reference parameter should be const-qualified appropriately
* [x] **Rule-10.1.2**: The volatile qualifier shall be used appropriately
* [x] **Rule-10.2.1**: An enumeration shall be defined with an explicit underlying type
* [x] **Rule-10.2.2**: Unscoped enumerations should not be declared
* [x] **Rule-10.2.3**: The numeric value of an unscoped enumeration with no fixed underlying type shall not be used
* [x] **Rule-10.3.1**: There should be no unnamed namespaces in header files
* [x] **Rule-10.4.1**: The asm declaration shall not be used

### Chapter 11
* [x] **Rule-11.3.1**: Variables of array type should not be declared
* [x] **Rule-11.3.2**: The declaration of an object should contain no more than two levels of pointer indirection
* [x] **Rule-11.6.1**: All variables should be initialized
* [x] **Rule-11.6.2**: The value of an object must not be read before it has been set
* [x] **Rule-11.6.3**: Within an enumerator list, the value of an implicitly specified enumeration constant shall be unique

### Chapter 12
* [x] **Rule-12.2.1**: Bit-fields should not be declared
* [x] **Rule-12.2.2**: Bit-fields shall have an appropriate type
* [x] **Rule-12.2.3**: A named bit-field with signed integer type shall not have a length of one bit
* [x] **Rule-12.3.1**: The union keyword shall not be used

### Chapter 13
* [x] **Rule-13.1.1**: Classes should not be inherited virtually
* [x] **Rule-13.1.2**: An accessible base class shall not be both virtual and non-virtual in the same hierarchy
* [x] **Rule-13.3.1**: User-declared member functions shall use the virtual, override and final specifiers appropriately
* [x] **Rule-13.3.2**: Parameters in an overriding virtual function shall not specify different default arguments
* [x] **Rule-13.3.3**: The parameters in all declarations or overrides of a function shall either be unnamed or have identical names
* [x] **Rule-13.3.4**: A comparison of a potentially virtual pointer to member function shall only be with nullptr

### Chapter 14
* [x] **Rule-14.1.1**: Non-static data members should be either all private or all public

### Chapter 15
* [x] **Rule-15.0.1**: Special member functions shall be provided appropriately
* [x] **Rule-15.0.2**: User-provided copy and move member functions of a class should have appropriate signatures
* [x] **Rule-15.1.1**: An object's dynamic type shall not be used from within its constructor or destructor
* [x] **Rule-15.1.2**: All constructors of a class should explicitly initialize all of its virtual base classes and immediate base classes
* [x] **Rule-15.1.3**: Conversion operators and constructors that are callable with a single argument shall be explicit
* [x] **Rule-15.1.4**: All direct, non-static data members of a class should be initialized before the class object is accessible
* [x] **Rule-15.1.5**: A class shall only define an initializer-list constructor when it is the only constructor

### Chapter 16
* [x] **Rule-16.5.1**: The logical AND and logical OR operators shall not be overloaded
* [x] **Rule-16.5.2**: The address-of operator shall not be overloaded
* [x] **Rule-16.6.1**: Symmetrical operators should only be implemented as non-member functions

### Chapter 17
* [x] **Rule-17.8.1**: Function templates shall not be explicitly specialized

### Chapter 18
* [x] **Rule-18.1.1**: An exception object shall not have pointer type
* [x] **Rule-18.1.2**: An empty throw shall only occur within the compound-statement of a catch handler
* [x] **Rule-18.3.1**: There should be at least one exception handler to catch all otherwise unhandled exceptions
* [x] **Rule-18.3.2**: An exception of class type shall be caught by const reference or reference
* [x] **Rule-18.3.3**: Handlers for a function-try-block of a constructor or destructor shall not use non-static members from their class or its bases
* [x] **Rule-18.4.1**: Exception-unfriendly functions shall be noexcept
* [x] **Rule-18.5.1**: A noexcept function should not attempt to propagate an exception to the calling function
* [x] **Rule-18.5.2**: Program-terminating functions should not be used

### Chapter 19
* [x] **Rule-19.0.1**: A line whose first token is # shall be a valid preprocessing directive
* [x] **Rule-19.0.2**: Function-like macros shall not be defined
* [x] **Rule-19.0.3**: #include directives should only be preceded by preprocessor directives or comments
* [x] **Rule-19.0.4**: #undef should only be used for macros defined previously in the same file
* [x] **Rule-19.1.1**: The defined preprocessor operator shall be used appropriately
* [x] **Rule-19.1.2**: All #else, #elif and #endif preprocessor directives shall reside in the same file as the #if, #ifdef or #ifndef directive to which they are related
* [x] **Rule-19.1.3**: All identifiers used in the controlling expression of #if or #elif preprocessing directives shall be defined prior to evaluation
* [x] **Rule-19.2.1**: Precautions shall be taken in order to prevent the contents of a header file being included more than once
* [x] **Rule-19.2.2**: The #include directive shall be followed by either a <filename> or "filename" sequence
* [x] **Rule-19.2.3**: The ', " or \ characters and the /* or // character sequences shall not occur in a header file name
* [x] **Rule-19.3.1**: The # and ## preprocessor operators should not be used
* [x] **Rule-19.3.2**: A macro parameter immediately following a # operator shall not be immediately followed by a ## operator
* [x] **Rule-19.3.3**: The argument to a mixed-use macro parameter shall not be subject to further expansion
* [x] **Rule-19.3.4**: Parentheses shall be used to ensure macro arguments are expanded appropriately
* [x] **Rule-19.3.5**: Tokens that look like a preprocessing directive shall not occur within a macro argument
* [x] **Rule-19.6.1**: The #pragma directive and the _Pragma operator should not be used

### Chapter 21
* [x] **Rule-21.2.1**: The library functions atof, atoi, atol and atoll from <cstdlib> shall not be used
* [x] **Rule-21.2.2**: The string handling functions from <cstring>, <cstdlib>, <cwchar> and <cinttypes> shall not be used
* [x] **Rule-21.2.3**: The library function system from <cstdlib> shall not be used
* [x] **Rule-21.2.4**: The macro offsetof shall not be used
* [x] **Rule-21.6.1**: Dynamic memory should not be used
* [x] **Rule-21.6.2**: Dynamic memory shall be managed automatically
* [x] **Rule-21.6.3**: Advanced memory management shall not be used
* [x] **Rule-21.6.4**: If a project defines either a sized or unsized version of a global delete operator, then both shall be defined
* [x] **Rule-21.6.5**: A pointer to an incomplete class type shall not be deleted
* [x] **Rule-21.10.1**: The features of <cstdarg> shall not be used
* [x] **Rule-21.10.2**: The standard header file <csetjmp> shall not be used
* [x] **Rule-21.10.3**: The facilities provided by the standard header file <csignal> shall not be used

### Chapter 22
* [x] **Rule-22.3.1**: The assert macro shall not be used with a constant-expression
* [x] **Rule-22.4.1**: The literal value zero shall be the only value assigned to errno

### Chapter 23
* [x] **Rule-23.11.1**: The raw pointer constructors of std::shared_ptr and std::unique_ptr should not be used

### Chapter 24
* [x] **Rule-24.5.1**: The character handling functions from <cctype> and <cwctype> shall not be used
* [x] **Rule-24.5.2**: The C++ Standard Library functions memcpy, memmove and memcmp from <cstring> shall not be used

### Chapter 25
* [x] **Rule-25.5.1**: The setlocale and std::locale::global functions shall not be called
* [x] **Rule-25.5.2**: The pointers returned by the C++ Standard Library functions localeconv, getenv, setlocale or strerror must only be used as if they have pointer to const-qualified type
* [x] **Rule-25.5.3**: The pointer returned by the C Standard Library functions asctime, ctime, gmtime, localtime, localeconv, getenv, setlocale or strerror must not be used following a subsequent call to the same function

### Chapter 26
* [x] **Rule-26.3.1**: std::vector should not be specialized with bool

### Chapter 28
* [x] **Rule-28.3.1**: Predicates shall not have persistent side effects
* [x] **Rule-28.6.1**: The argument to std::move shall be a non-const lvalue
* [x] **Rule-28.6.2**: Forwarding references and std::forward shall be used together
* [x] **Rule-28.6.3**: An object shall not be used while in a potentially moved-from state
* [x] **Rule-28.6.4**: The result of std::remove, std::remove_if, std::unique and empty shall be used

### Chapter 30
* [x] **Rule-30.0.1**: The C Library input/output functions shall not be used
* [x] **Rule-30.0.2**: Reads and writes on the same file stream shall be separated by a positioning operation

### Source
* MISRA C:2023 enforcement list (M3CM)
* MISRA C++:2023 enforcement list (M2CPP)
