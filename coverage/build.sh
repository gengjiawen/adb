OUTPUT_DIR=$(dirname "$0")
. "$OUTPUT_DIR"/include.sh
export CLANG_COVERAGE=true
export NATIVE_COVERAGE_PATHS=packages/modules/adb

. "$ANDROID_BUILD_TOP"/build/envsetup.sh
m com.android.adbd $ADB_TESTS
adb push $ANDROID_PRODUCT_OUT/data/nativetest64 /data
adb install $ANDROID_PRODUCT_OUT/system/apex/com.android.adbd.apex
adb reboot
