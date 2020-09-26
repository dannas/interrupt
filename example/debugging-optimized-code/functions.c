#include <stddef.h>
int add1(int x) {
    return x + 1;
}

int sum(int a[], size_t N) {
    int s = 0;
    for (size_t i = 0; i < N; ++i) {
        s += a[i];
    }
    return s;
}

