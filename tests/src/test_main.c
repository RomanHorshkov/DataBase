#include <stdio.h>

/* Each suite exposes a single entrypoint */
int run_test_func(int argc, char** argv);
int run_test_load(int argc, char** argv);

int main(int argc, char** argv)
{
    int rc1 = run_test_func(argc, argv);
    int rc2 = run_test_load(argc, argv);
    return (rc1 || rc2) ? 1 : 0;
}