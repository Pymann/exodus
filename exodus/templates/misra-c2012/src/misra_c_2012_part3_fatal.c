/*
 * Exhaustive MISRA C:2012 Violation Templates - Part 3 (Fatal Preprocessor Errors)
 * 
 * This file contains violations that cause Clang's AST parser to fail completely 
 * or stop processing the file. They are isolated here so they don't prevent
 * the analysis of other rules.
 */

// Rule 20.4: A macro shall not be defined with the same name as a keyword
#define int my_int // Violation

// Rule 20.13: A line whose first token is # shall be a valid preprocessing directive
# invalid_directive // Violation
