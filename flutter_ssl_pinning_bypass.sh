#!/bin/bash

set -e
set -x

APK_PATH=$1
APKTOOL_PATH=$2
APP_PACKAGE_NAME=$3

DECOMPILED_APK_PATH="/tmp/apk_decompiled"

java -jar $APKTOOL_PATH d $APK_PATH -o $DECOMPILED_APK_PATH -f

SO_FILE="${DECOMPILED_APK_PATH}/lib/x86_64/libflutter.so"

SSL_CLIENT_ADDRESS=$(strings -a -t x ${SO_FILE} | grep -E "ssl_client" | awk -F' ' '{print $1}')
SSL_SERVER_ADDRESS=$(strings -a -t x ${SO_FILE} | grep -E "ssl_server" | awk -F' ' '{print $1}')

DISSASEMBLY_FILE_PATH="/tmp/disassembly.txt"

(objdump -d $SO_FILE > $DISSASEMBLY_FILE_PATH)

ssl_offset=$(grep -E "${SSL_CLIENT_ADDRESS}|${SSL_SERVER_ADDRESS}" $DISSASEMBLY_FILE_PATH | head -1| awk -F ' ' '{print $1}')
echo $ssl_offset

ssl_offset_hex="0x${ssl_offset%:}"
ssl_function_start_offset="-0x10a"

echo ${ssl_offset_hex} $ssl_function_start_offset

ssl_function_start_address_decimal=$(($((ssl_offset_hex))+$((ssl_function_start_offset))))
ssl_function_start_address=$(printf "0x%x\n" $ssl_function_start_address_decimal)

jni_onload_address=0x$(objdump -T ${SO_FILE} | tail -n 3 | awk -F' ' '{print $1}')

ssl_function_offset_decimal=$(($((ssl_function_start_address))-$((jni_onload_address))))
ssl_function_offset=$(printf "0x%x\n" $ssl_function_offset_decimal)
echo $ssl_function_offset

cat <<EOF > script.js
function hook_ssl_crypto_x509_session_verify_cert_chain(address){
  Interceptor.attach(address, {
    onEnter: function(args) { console.log("Disabling SSL certificate validation") },
    onLeave: function(retval) { console.log("Retval: " + retval); retval.replace(0x1);}
  });
}
function disable_certificate_validation(){
 var m = Process.findModuleByName("libflutter.so");
 console.log("libflutter.so loaded at ", m.base);
 var jni_onload_addr = m.enumerateExports()[0].address;
 console.log("jni_onload_address: ", jni_onload_addr);
// Adding the offset between
// ssl_crypto_x509_session_verify_cert_chain and JNI_Onload = $ssl_function_offset
 let addr = ptr(jni_onload_addr).add($ssl_function_offset);
 console.log("ssl_crypto_x509_session_verify_cert_chain_addr: ", addr);
 let buf = Memory.readByteArray(addr, 12);
 console.log(hexdump(buf, { offset: 0, length: 64, header: false, ansi: false}));
 hook_ssl_crypto_x509_session_verify_cert_chain(addr);

}
setTimeout(disable_certificate_validation, 1000)
EOF

curl -L -o frida-server.xz https://github.com/frida/frida/releases/download/16.3.3/frida-server-16.3.3-android-x86_64.xz
unxz -f frida-server.xz
adb root
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

frida -U -f $APP_PACKAGE_NAME -l script.js
