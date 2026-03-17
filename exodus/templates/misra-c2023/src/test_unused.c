#define UNUSED_MACRO 42

void test_func(void) {
    typedef int unused_typedef;
    struct unused_struct { int a; };
    enum unused_enum { A, B };
    
    int x = 0;
    goto my_label;
my_label:
    x++;
    
unused_label:
    x++;
}
