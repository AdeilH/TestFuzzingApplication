#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CMD 8192        // Increased buffer size
#define MAX_INPUT 4096      // Max input size
#define SCRIPT_PATH "//wsl.localhost/Ubuntu/home/adeel/frid/basics/afl_rpc.js"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    // Read input file
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Failed to open input file\n");
        return 1;
    }
    
    char buffer[MAX_INPUT];
    size_t n = fread(buffer, 1, sizeof(buffer)-1, f);
    fclose(f);
    buffer[n] = 0;

    // Remove newlines and escape quotes
    for (size_t i = 0; i < n; i++) {
        if (buffer[i] == '\n' || buffer[i] == '\r') {
            buffer[i] = ' ';
        }
    }
// /mnt/c/Windows/System32/cmd.exe /C "frida -U -l "//wsl.localhost/Ubuntu/home/adeel/frid/basics/afl_rpc.js" FuzzingApplication --eval rpc.exports.fuzzer(\"test\")"
    // Build command
    char cmd[MAX_CMD];
    int ret = snprintf(cmd, sizeof(cmd),
        "cd /mnt/c && cmd.exe /C \"frida -U -l "
        "\"//wsl.localhost/Ubuntu/home/adeel/frid/basics/afl_rpc.js\" "
        "FuzzingApplication --eval rpc.exports.fuzzer(\\\"%s\\\") --eval exit \"",
        buffer);

    if (ret < 0 || ret >= sizeof(cmd)) {
        fprintf(stderr, "Command too long\n");
        return 1;
    }

    printf("Executing command:\n%s\n", cmd);
    return system(cmd);
} 