#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

int add_loop(int a, int b) {
    return a + b;
}

int multiply_loop(int a, int b) {
    return a * b;
}

int main(){
    int pid = getpid();
    printf("Process ID: %d\n", pid);
    printf("add_loop addr: %p\n", (void*)add_loop);
    printf("multiply_loop addr: %p\n", (void*)multiply_loop);
    while(1){
        int add_result = add_loop(1, 2);
        int multiply_result = multiply_loop(1, 2);

        printf("Add Result: %d\n", add_result);
        printf("Multiply Result: %d\n", multiply_result);
        sleep(1);
    }
}