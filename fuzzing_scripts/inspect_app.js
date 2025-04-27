Java.perform(function() {
    console.log("[*] Enumerating MainActivity methods...");
    
    try {
        var MainActivity = Java.use("com.example.fuzzingapplication.MainActivity");
        console.log("[+] Successfully hooked MainActivity");
        
        // Get all methods
        var methods = MainActivity.class.getDeclaredMethods();
        console.log("[*] Available methods:");
        methods.forEach(function(method) {
            console.log("  - " + method.toString());
        });
        
        // Try to find our specific method
        console.log("\n[*] Looking for processAndLogText method...");
        var processMethod = MainActivity.processAndLogText;
        if (processMethod) {
            console.log("[+] Found processAndLogText method!");
            console.log("    Implementation: " + processMethod.implementation);
        }
        
    } catch(e) {
        console.log("[!] Error: " + e);
    }
}); 