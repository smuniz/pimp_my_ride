/* A very simple function to return a constant 0x123. */
#include "stdio.h"

int test0 ();

int test0 ( ) {
    return 0x123;
}

int caller() {
    return test0() + 1;
}

int main(void) {
    return caller();
}
