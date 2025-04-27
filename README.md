Basic start up guide of the fuzzing application:

1. Install the app on your android device
2. Run the app
3. Set up AFL and Frida:
   ```bash
   # Install AFL++ if not already installed
   git clone https://github.com/AFLplusplus/AFLplusplus
   cd AFLplusplus
   make
   sudo make install

   # Push Frida server to Android device
   adb root # If your device is rooted
   adb push frida-server /data/local/tmp/
   adb shell "chmod 755 /data/local/tmp/frida-server"
   adb shell "/data/local/tmp/frida-server &"
   ```

4. About the Frida inspection script:
   - The script (inspect_app.py) connects to the Android device via USB
   - It attaches to the running FuzzingApplication process
   - Uses inspect_app.js to hook into the MainActivity class
   - Enumerates and inspects available methods
   - Specifically looks for the `processAndLogText` method which is our fuzzing target

5. Target Function Details:
   - Function: `processAndLogText` in MainActivity
   - Purpose: Processes text input and performs logging operations
   - This is our fuzzing target as it handles user input and may be vulnerable to malformed data

6. Run the inspection script to verify everything is set up:
   ```bash
   python inspect_app.py
   ```
   You should see output showing the available methods and confirmation that the target method was found.

7. AFL RPC Integration:
   - The `afl_rpc_wrapper.c` acts as a bridge between AFL++ and Frida
   - `afl_rpc.js` contains the actual fuzzing logic that runs via Frida
   - Together they allow AFL++ to fuzz the Android app through Frida's instrumentation

8. Compile the AFL RPC wrapper:
   ```bash
   # Compile with AFL compiler
   gcc afl_rpc_wrapper.c -o afl_rpc_wrapper
   ```

9. Create input corpus:
   ```bash
   # Make directory for input corpus
   mkdir corpus_in
   # Add some initial test cases
   echo "test" > corpus_in/test1
   echo "Hello World!" > corpus_in/test2
   ```

10. Start fuzzing:
    ```bash
    # Make sure Frida server is running on device
    adb shell "/data/local/tmp/frida-server &"
    
    # Start AFL fuzzing
    afl-fuzz -n -i corpus_in -o findings -- ./afl_rpc_wrapper @@
    ```

    The command breakdown:
    - `-n`: Run AFL in non-instrumented mode (since instrumentation happens via Frida)
    - `-i corpus_in`: Directory containing initial test cases
    - `-o findings`: Directory where AFL will store results
    - `@@`: Placeholder that AFL uses to insert test cases

11. Monitor the fuzzing progress:
    - AFL will show its status screen with execution stats
    - Check the `findings` directory for crashes and hangs
    - The `afl_rpc.js` script will log any interesting behaviors to help with debugging


