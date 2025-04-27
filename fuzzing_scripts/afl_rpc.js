console.log("[*] Starting AFL++ RPC handler");

let mainActivity = null;

// Initialize once
Java.perform(() => {
    Java.choose("com.example.fuzzingapplication.MainActivity", {
        onMatch: function(instance) {
            console.log("[+] Found MainActivity");
            mainActivity = instance;
        },
        onComplete: function() {}
    });
});

rpc.exports = {
    // AFL++ will call this function
    fuzzer: function(payload) {
        console.log("[*] Fuzzer called with:", payload);
        return Java.perform(() => {
            try {
                if (!mainActivity) {
                    console.log("[-] MainActivity not found");
                    return 1;
                }

                // Send to app
                mainActivity.processAndLogText(payload);
                console.log("[+] Payload sent successfully");
                
                return 0; // Tell AFL++ test passed
            } catch(e) {
                console.log(`[-] Crash: ${e}`);
                return 1; // Tell AFL++ test crashed
            }
        });
    },

    // Optional: initialize fuzzing session
    init: function() {
        console.log("[*] Initializing fuzzer");
        return mainActivity !== null;
    }
}; 