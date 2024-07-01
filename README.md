# Flutter APK SSL Certificate Validation Disabler

This script disables SSL certificate validation in a Flutter application by modifying the APK file and injecting a Frida hook. This can be useful for testing purposes where you need to bypass SSL pinning.

## Prerequisites

- `apktool`: Tool to decompile and recompile APK files.
- `strings`: Command to extract printable strings from a binary.
- `objdump`: Command to display information from object files.
- `adb`: Android Debug Bridge, a versatile command-line tool for interacting with Android devices.
- `frida`: Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.

## Usage

### Arguments

1. `APK_PATH`: Path to the APK file to be decompiled and modified.
2. `APKTOOL_PATH`: Path to the `apktool` JAR file.
3. `APP_PACKAGE_NAME`: Package name of the application to be tested.

### Example

```sh
./flutter_ssl_pinning_bypass.sh /path/to/app.apk /path/to/apktool.jar com.example.app
```

## Script Details

1. **Setup and Variables:**
    - The script sets the options `-e` (exit on error) and `-x` (print commands).
    - Variables are initialized for paths and filenames.

2. **Decompile the APK:**
    - Uses `apktool` to decompile the APK to a temporary directory.

3. **Find SSL Client and Server Addresses:**
    - Extracts SSL client and server addresses from the `libflutter.so` file using `strings`.

4. **Disassemble the Shared Library:**
    - Disassembles the `libflutter.so` file to a text file.

5. **Calculate SSL Function Offset:**
    - Extracts the offset of the SSL function start address and converts it to a hexadecimal format.
    - Calculates the offset between the SSL function and the `JNI_OnLoad` function.

6. **Generate Frida Script:**
    - Creates a Frida script (`script.js`) to hook and disable SSL certificate validation.

7. **Download and Setup Frida Server:**
    - Downloads the Frida server for Android and sets it up on the device.

8. **Run Frida with the Script:**
    - Uses Frida to inject the script into the specified application.

## Notes

- Ensure your Android device is connected and ADB is set up properly.
- Running this script requires root access on the Android device.
- This script is intended for testing and educational purposes only. Use responsibly.
