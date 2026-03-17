#include <iostream>
#include <stdarg.h> // Rule 8-4-1: <stdarg.h> shall not be used
#include <cstdarg>  // Rule 8-4-1
#include <stdio.h>  // Rule 27-0-1: The standard header file <stdio.h> shall not be used
#include <stdlib.h> // Rule 18-0-1: The C library shall not be used

// Intentionally defined at global scope without a preceding declaration.
void external_func_without_decl() {
}

// Uses a GNU/C-style extension in a C++ template fixture.
void restrict_example(int * restrict p) {
    *p = 1;
}

// Rule 0-1-11: Unused parameters
void do_something(int unused_param) {
    int value = 0123; // Rule 2-13-2: Octal constants shall not be used
    
    if (1) {
        char c = '\x12';
    }
    
    goto label;
    
    value = 5;
    
label:
    value++;
}

void check_switch(int type) {
    switch (type) { // Rule 6-4-6: Every switch statement shall have a default label
        case 1:
            do_something(0);
            // Rule 6-4-5: An unterminated case clause shall be used only for empty case clauses
        case 2:
            std::cout << "Case 2" << std::endl;
            break;
        // Missing default
    }
}

int return_value_func() {
    return 42;
}

int main() {
    // Rule 18-4-1: Dynamic heap memory allocation (malloc, free) shall not be used
    int* ptr1 = (int*)malloc(10 * sizeof(int));
    if (ptr1) {
        free(ptr1);
    }
    
    // Rule 18-4-1: Dynamic heap memory allocation (new, delete) shall not be used
    int* ptr2 = new int(5);
    delete ptr2;
    
    check_switch(010); // Rule 2-13-2: Octal constant
    
    // Identifier shadowing fixture.
    int i = 0;
    {
        int i = 1; 
    }
    
    // Reads an automatic variable before initialization.
    int uninitialized_var;
    int a = uninitialized_var;
    
    // Rule 5-0-5: Implicit conversions between floating-point and integer types
    int b = 5;
    float c = 5.0f;
    int d = b & c; // Bitwise AND on float
    
    // Rule 5-2-6: A cast shall not convert a pointer to a function to any other pointer type
    void (*func_ptr)() = &external_func_without_decl;
    void *void_ptr = (void*)func_ptr; 
    
    // Rule 5-2-9: A cast should not convert a pointer type to an integral type
    int addr = (int)&b;
    
    // Rule 6-2-1: The result of an assignment operator should not be used
    int x;
    if (x = 5) { // Assignment in if condition
    }
    
    // Rule 5-0-13: The controlling expression of an if statement shall have essentially Boolean type
    int int_condition = 5;
    if (int_condition) { // int used as boolean
    }
    
    // Uses stdio in a C++ translation unit.
    printf("Using printf\n");
    
    return_value_func();
    
    // Rule 6-6-4: There should be no more than one break or goto statement used to terminate any iteration statement
    for (int j = 0; j < 10; ++j) {
        if (j == 2) break;
        if (j == 5) break; 
    }
    
    return 0;
}
