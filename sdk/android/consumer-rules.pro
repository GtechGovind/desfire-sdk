-keep class com.desfire.ev3.Native { *; }
-keep class com.desfire.ev3.NativeRuntime { *; }
-keep class com.desfire.ev3.ProviderBridge { *; }
-keep class com.desfire.ev3.raw.RawNative { *; }
-keep class com.desfire.ev3.offline.OfflineNative { *; }
-keep class com.desfire.ev3.DesfireException { *; }
-keepclassmembers class * implements com.desfire.ev3.CardTransport {
    public byte[] exchange(byte[], int);
    public void cancel();
    public void reset();
}
