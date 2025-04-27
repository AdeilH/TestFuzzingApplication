#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define MAX_CMD 8192
#define MAX_INPUT 4096
#define SCRIPT_PATH "//wsl.localhost/Ubuntu/home/adeel/frid/basics/persistent_rpc.js"
// /mnt/c/Windows/System32/cmd.exe /C "frida -U -l "//wsl.localhost/Ubuntu/home/adeel/frid/basics/afl_rpc.js" FuzzingApplication --eval rpc.exports.fuzzer(\"test\")"

static FILE* frida_repl = NULL;

// Start Frida REPL
int start_frida_repl() {
    char cmd[MAX_CMD];
    snprintf(cmd, sizeof(cmd),
        "cd /mnt/c && cmd.exe /C \"frida -U -l "
        "\"%s\" FuzzingApplication\"",
        SCRIPT_PATH);
    
    printf("Starting Frida REPL:\n%s\n", cmd);
    
    // Open a pipe to the Frida REPL
    frida_repl = popen(cmd, "w");
    if (!frida_repl) {
        fprintf(stderr, "Failed to start Frida REPL: %s\n", strerror(errno));
        return 1;
    }
    
    // Wait for Frida to initialize
    sleep(2);
    return 0;
}

// Send command to REPL
int send_to_repl(const char* input) {
    char cmd[MAX_CMD];
    snprintf(cmd, sizeof(cmd), 
        "rpc.exports.fuzzer(\"%s\")\n", 
        input);
    
    fprintf(frida_repl, "%s", cmd);
    fflush(frida_repl);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    // Start REPL if not running
    if (!frida_repl && start_frida_repl() != 0) {
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

    // Remove newlines
    for (size_t i = 0; i < n; i++) {
        if (buffer[i] == '\n' || buffer[i] == '\r') {
            buffer[i] = ' ';
        }
    }

    // Send to REPL
    return send_to_repl(buffer);
} 