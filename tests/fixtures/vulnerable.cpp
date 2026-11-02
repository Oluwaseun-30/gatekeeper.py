#include <cstring>
#include <cstdio>
#include <cstdlib>

void process_user_input(const char* user_data) {
    char buffer[64];
    // Vulnerable to buffer overflow (CWE-120)
    strcpy(buffer, user_data);

    // Vulnerable to format string attack (CWE-134)
    printf(buffer);

    // Safe commented line that should be ignored:
    // system("rm -rf /");
}
