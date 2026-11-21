// Test ELF fixture kaynağı: bilinen yapıda fonksiyonlar
// (if/else + döngü + çağrı grafiği + veri referansları)
__attribute__((noinline)) int add_numbers(int a, int b) { return a + b; }

__attribute__((noinline)) int loop_sum(int n) {
    int total = 0;
    for (int i = 1; i <= n; i++)
        total += i;
    return total;
}

__attribute__((noinline)) int choose(int x) {
    if (x > 100)
        return loop_sum(x);
    else if (x > 10)
        return add_numbers(x, 5);
    return 0;
}

const char* god_message = "GODTIER_FIXTURE_STRING";

int fixture_main(void) {
    int a = add_numbers(0x37, 5);      // 60 = 0x3c
    int b = loop_sum(10);              // 55
    int c = choose(200);
    return a + b + c + god_message[0];
}
int main(void) { return fixture_main(); }
