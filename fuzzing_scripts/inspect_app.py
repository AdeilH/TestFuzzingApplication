import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(f"[!] Error: {message['description']}")

def main():
    print("[*] Attaching to application...")
    
    # Connect to device
    device = frida.get_usb_device()
    
    # List available processes
    print("[*] Available processes:")
    for process in device.enumerate_processes():
        print(f"    - {process.name} (pid: {process.pid})")
    
    # Try to find our app
    target = None
    for process in device.enumerate_processes():
        if "fuzzing" in process.name.lower():
            target = process
            break
    
    if not target:
        print("[!] Target app not found. Please make sure it's running.")
        return
    
    print(f"[+] Found target app: {target.name} (pid: {target.pid})")
    
    # Attach to the process
    session = device.attach(target.pid)
    print("[+] Attached to process")
    
    # Load the inspection script
    with open("inspect_app.js") as f:
        script_content = f.read()
    
    script = session.create_script(script_content)
    script.on('message', on_message)
    print("[*] Script loaded, starting inspection...")
    script.load()
    
    # Keep the script running
    print("[*] Press Enter to exit...")
    input()
    
if __name__ == "__main__":
    main() 