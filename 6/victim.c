#include <stdio.h>
#include <stdlib.h>

void hacked() {
    puts("Hacked!");
}
void hello() {
    char str[5000];
    gets(str);
    printf("Hello, %s!\n", str);
}
int main(){
    hello();
    return 0;
}
