console.log("[*] Starting Persistent Frida Fuzzer");

let mainActivity = null;

// Initialize once and keep the instance
Java.perform(() => {
    Java.choose("com.example.fuzzingapplication.MainActivity", {
        onMatch: function(instance) {
            console.log("[+] Found MainActivity");
            mainActivity = instance;
        },
        onComplete: function() {}
    });
});

// Export RPC interface
rpc.exports = {
    fuzzer: function(payload) {
        return Java.perform(() => {
            try {
                if (!mainActivity) {
                    console.log("[-] MainActivity not found");
                    return 1;
                }

                console.log(`[*] Testing input: ${payload}`);
                mainActivity.processAndLogText(payload);
                console.log("[+] Payload sent successfully");
                return 0;
            } catch(e) {
                console.log(`[-] Crash: ${e}`);
                return 1;
            }
        });
    }
};

// // Make fuzzer function globally available
// global.fuzzer = rpc.exports.fuzzer;

// // Keep script alive
// Process.on('detached', () => {
//     console.log("[*] Detached from process");
// }); 