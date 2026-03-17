#include <iostream>
#include <stdarg.h> // Rule 21.10.1: <stdarg.h> shall not be used
#include <cstdarg>  // Rule 21.10.1
#include <stdio.h>  // Rule 30.0.1: The standard header file <stdio.h> shall not be used
#include <stdlib.h> // C library fixture

// Global-scope fixture without a preceding declaration.
void external_func_without_decl() {
}

// Legacy C++2008 fixture using a GNU/C-style extension.
void restrict_example(int * restrict p) {
    *p = 1;
}

// Rule 0.2.2: Unused parameters
void do_something(int unused_param) {
    int value = 0123; // Rule 5.13.3: Octal constants shall not be used
    
    // Rule 0.0.2: Controlling expressions shall not be invariant
    if (1) {
        char c = '\x12';
    }
    
    goto label; // Rule 9.6.1: goto statement should not be used
    
    value = 5;
    
label:
    value++;
}

void check_switch(int type) {
    switch (type) {
        case 1:
            do_something(0);
            // Missing break on purpose.
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
    // Rule 21.6.1: Dynamic memory should not be used
    int* ptr1 = (int*)malloc(10 * sizeof(int));
    if (ptr1) {
        free(ptr1);
    }
    
    // Rule 18.4.1: Dynamic heap memory allocation shall not be used
    int* ptr2 = new int(5);
    delete ptr2;
    
    check_switch(010); // Rule 5.13.3: Octal constant
    
    // Shadowing fixture.
    int i = 0;
    {
        int i = 1; 
    }
    
    // Rule 11.6.2: Read before set
    int uninitialized_var;
    int a = uninitialized_var;
    
    // Rule 7.0.4: Bitwise operands shall be appropriate
    int b = 5;
    float c = 5.0f;
    int d = b & c; // Bitwise AND on float
    
    // Rule 8.2.4: Function pointers shall not be cast to unrelated types
    void (*func_ptr)() = &external_func_without_decl;
    void *void_ptr = (void*)func_ptr; 
    
    // Pointer-to-integer cast fixture.
    int addr = (int)&b;
    
    // Rule 8.18.2: The result of an assignment operator should not be used
    int x;
    if (x = 5) { // Assignment in if condition
    }
    
    // Non-bool controlling-expression fixture.
    int int_condition = 5;
    if (int_condition) { // int used as boolean
    }
    
    // Rule 0.1.2: Return value shall be used
    printf("Using printf\n");
    
    return_value_func();
    
    // Rule 9.3.1: Single-statement bodies without braces
    for (int j = 0; j < 10; ++j) {
        if (j == 2) break;
        if (j == 5) break; 
    }
    
    return 0;
}
