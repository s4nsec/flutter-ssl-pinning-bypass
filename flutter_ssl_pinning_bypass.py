#!/usr/bin/env python3
"""
Flutter APK SSL Certificate Validation Disabler

This script disables SSL certificate validation in a Flutter application
by analyzing the APK file and injecting a Frida hook. This is useful for
authorized security testing where you need to bypass SSL pinning.
"""

import argparse
import os
import re
import subprocess
import sys
import urllib.request


DECOMPILED_APK_PATH = "/tmp/apk_decompiled"
DISASSEMBLY_FILE_PATH = "/tmp/disassembly.txt"
FRIDA_VERSION = "16.3.3"
FRIDA_SERVER_URL = f"https://github.com/frida/frida/releases/download/{FRIDA_VERSION}/frida-server-{FRIDA_VERSION}-android-x86_64.xz"


def run_command(cmd, capture_output=True, check=True, shell=False):
    """Run a shell command and return the result."""
    print(f"+ {cmd if isinstance(cmd, str) else ' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        capture_output=capture_output,
        text=True,
        check=check,
        shell=shell,
    )
    return result


def decompile_apk(apk_path, apktool_path):
    """Decompile the APK using apktool."""
    run_command([
        "java", "-jar", apktool_path, "d", apk_path,
        "-o", DECOMPILED_APK_PATH, "-f"
    ])


def find_ssl_addresses(so_file):
    """Find SSL client and server addresses in the shared library."""
    result = run_command(["strings", "-a", "-t", "x", so_file])

    ssl_client_address = None
    ssl_server_address = None

    for line in result.stdout.splitlines():
        if "ssl_client" in line:
            ssl_client_address = line.split()[0]
        if "ssl_server" in line:
            ssl_server_address = line.split()[0]

    return ssl_client_address, ssl_server_address


def disassemble_library(so_file):
    """Disassemble the shared library using objdump."""
    result = run_command(["objdump", "-d", so_file])
    with open(DISASSEMBLY_FILE_PATH, "w") as f:
        f.write(result.stdout)


def find_ssl_offset(ssl_client_address, ssl_server_address):
    """Find the SSL function offset from the disassembly."""
    pattern = f"{ssl_client_address}|{ssl_server_address}"

    with open(DISASSEMBLY_FILE_PATH, "r") as f:
        for line in f:
            if re.search(pattern, line):
                # Extract the offset (first field before the colon)
                ssl_offset = line.split()[0]
                print(ssl_offset)
                return ssl_offset

    return None


def calculate_ssl_function_address(ssl_offset, so_file):
    """Calculate the SSL function start address and offset from JNI_OnLoad."""
    # Remove trailing colon and convert to hex
    ssl_offset_hex = int(ssl_offset.rstrip(":"), 16)
    ssl_function_start_offset = -0x10a

    print(f"0x{ssl_offset_hex:x} {ssl_function_start_offset}")

    ssl_function_start_address = ssl_offset_hex + ssl_function_start_offset

    print(f"ssl_function_start_address: 0x{ssl_function_start_address:x}")

    # Get JNI_OnLoad address from objdump -T
    result = run_command(["objdump", "-T", so_file])
    lines = result.stdout.strip().splitlines()

    # Get address from tail -n 3 | awk '{print $1}'
    jni_onload_line = lines[-3] if len(lines) >= 3 else lines[-1]
    jni_onload_address = int(jni_onload_line.split()[0], 16)

    print(f"jni_onload_address: 0x{jni_onload_address:x}")

    ssl_function_offset = ssl_function_start_address - jni_onload_address

    print(f"ssl_function_offset: 0x{ssl_function_offset:x}")

    return ssl_function_offset


def generate_frida_script(ssl_function_offset):
    """Generate the Frida script for SSL bypass."""
    script_content = f"""function hook_ssl_crypto_x509_session_verify_cert_chain(address){{
  Interceptor.attach(address, {{
    onEnter: function(args) {{ console.log("Disabling SSL certificate validation") }},
    onLeave: function(retval) {{ console.log("Retval: " + retval); retval.replace(0x1);}}
  }});
}}
function disable_certificate_validation(){{
 var m = Process.findModuleByName("libflutter.so");
 console.log("libflutter.so loaded at ", m.base);
 var jni_onload_addr = m.enumerateExports()[0].address;
 console.log("jni_onload_address: ", jni_onload_addr);
// Adding the offset between
// ssl_crypto_x509_session_verify_cert_chain and JNI_Onload = 0x{ssl_function_offset:x}
 let addr = ptr(jni_onload_addr).add(0x{ssl_function_offset:x});
 console.log("ssl_crypto_x509_session_verify_cert_chain_addr: ", addr);
 let buf = Memory.readByteArray(addr, 12);
 console.log(hexdump(buf, {{ offset: 0, length: 64, header: false, ansi: false}}));
 hook_ssl_crypto_x509_session_verify_cert_chain(addr);

}}
setTimeout(disable_certificate_validation, 1000)
"""

    with open("script.js", "w") as f:
        f.write(script_content)

    print("Generated script.js")


def setup_frida_server():
    """Download and setup Frida server on the Android device."""
    frida_server_xz = "frida-server.xz"
    frida_server = "frida-server"

    print(f"+ Downloading Frida server from {FRIDA_SERVER_URL}")
    urllib.request.urlretrieve(FRIDA_SERVER_URL, frida_server_xz)

    run_command(["unxz", "-f", frida_server_xz])
    run_command(["adb", "root"])
    run_command(["adb", "push", frida_server, "/data/local/tmp/"])
    run_command(["adb", "shell", "chmod 755 /data/local/tmp/frida-server"])
    run_command([
        "adb", "shell",
        "/data/local/tmp/frida-server > /dev/null 2>&1 & echo $!"
    ])


def run_frida(app_package_name):
    """Run Frida with the generated script."""
    run_command(
        ["frida", "-U", "-f", app_package_name, "-l", "script.js"],
        capture_output=False,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Flutter APK SSL Certificate Validation Disabler"
    )
    parser.add_argument("apk_path", help="Path to the APK file")
    parser.add_argument("apktool_path", help="Path to the apktool JAR file")
    parser.add_argument("app_package_name", help="Package name of the application")

    args = parser.parse_args()

    # Step 1: Decompile the APK
    decompile_apk(args.apk_path, args.apktool_path)

    # Step 2: Find SSL addresses
    so_file = os.path.join(DECOMPILED_APK_PATH, "lib", "x86_64", "libflutter.so")
    ssl_client_address, ssl_server_address = find_ssl_addresses(so_file)

    if not ssl_client_address or not ssl_server_address:
        print("Error: Could not find SSL client or server addresses", file=sys.stderr)
        sys.exit(1)

    print(f"SSL Client Address: {ssl_client_address}")
    print(f"SSL Server Address: {ssl_server_address}")

    # Step 3: Disassemble the library
    disassemble_library(so_file)

    # Step 4: Find SSL offset
    ssl_offset = find_ssl_offset(ssl_client_address, ssl_server_address)

    if not ssl_offset:
        print("Error: Could not find SSL offset in disassembly", file=sys.stderr)
        sys.exit(1)

    # Step 5: Calculate SSL function address
    ssl_function_offset = calculate_ssl_function_address(ssl_offset, so_file)

    # Step 6: Generate Frida script
    generate_frida_script(ssl_function_offset)

    # Step 7: Setup Frida server
    setup_frida_server()

    # Step 8: Run Frida
    run_frida(args.app_package_name)


if __name__ == "__main__":
    main()
