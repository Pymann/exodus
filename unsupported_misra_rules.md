# Unsupported MISRA Rules by Tree-Sitter

## Current Coverage
At present, `exodus analyze` relies purely on `tree-sitter` for static AST matching. 
* **MISRA C:2012** defines **143** rules.
* **MISRA C++:2008** defines **228** rules.

We have currently implemented **10 structural rules** (e.g., Goto, Octal constants, missing `default`, `malloc`/`free`, restricted headers, unreachable code, `restrict`, `union`, brace formatting).

**Overall Coverage Estimations:**
* **C:2012**: ~7.0% (10 out of 143 rules)
* **C++:2008**: ~4.3% (10 out of 228 rules)

**Theoretical limit for pure AST checking**: Tree-sitter might be able to implement at most ~15-20% of all MISRA rules using pure AST structural queries without semantic insight.

---

Tree-sitter is a fast, robust syntax parser, which makes it excellent for structural static analysis (e.g., finding `goto` statements, missing braces, or usage of forbidden standard library functions). However, it does not build a full symbol table, track data flow, or evaluate expression types across files.

Therefore, the following MISRA C:2012 / C++:2008 rules cannot be reliably implemented out-of-the-box with pure Tree-sitter queries without a significant external semantic analysis engine engine (like Clang-Tidy):

## Data Flow and Execution Path Analysis
* **Rule 2.2**: Dead code. (Requires knowing if a value is ever read/used).
* **Rule 9.1**: Uninitialized memory read. (Requires control flow and data flow).
* **Rule 13.2 / 13.3 / 13.5 / 13.6**: Persistent side effects and order of evaluation.
* **Rule 14.3**: Invariant controlling expressions. (Requires value range analysis).
* **Rule 22.1 / 22.2 / 22.3 / 22.4 / 22.6**: Resources and Streams (open/close files, malloc/free mismatches, read-only writing).

## Type and Semantic Analysis
* **Rule 1.1 / 1.2**: Standard syntax constraints and extensions.
* **Rule 5.1 - 5.9 / 8.x**: Identifier shadowing, visibility, external/internal linkage uniqueness across multiple translation units.
* **Rule 10.1 - 10.8**: Essential type category conversions (e.g., bitwise operations on floats, implicit narrowing).
* **Rule 11.1 - 11.9**: Pointer conversions and casts that depend on the actual types being pointed to.
* **Rule 12.1 - 12.4**: Operator precedence, shift out of bounds, constant expression wrap-around.
* **Rule 14.1**: Loop counter types (requires resolving `typedefs` to see if it's float).
* **Rule 18.1 - 18.x**: Pointer arithmetic out of array bounds.

## C++ Specific (Semantic)
* **Rule 5-0-4**: Implicit integral conversions changing signedness.
* **Rule 9-3-1**: Const member functions returning non-const references (requires resolving member vs non-member and const-ness).

To implement these, a deeper static analysis backend (utilizing a compiler frontend like Clang) would be required to complement the Tree-sitter AST scanning.
