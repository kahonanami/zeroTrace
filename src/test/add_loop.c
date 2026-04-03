#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

int add_loop(int a, int b) {
    return a + b;
}

int main(){
    int pid = getpid();
    printf("Process ID: %d\n", pid);
    printf("add_lopp addr: %p\n", (void*)add_loop);
    while(1){
        int result = add_loop(1, 2);
        printf("Result: %d\n", result);
        sleep(1);
    }
}