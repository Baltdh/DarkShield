# DarkShield release optimizer rules.
# Keep Android entry points referenced from the manifest while allowing R8
# to optimize the rest of the application.
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod

# Keep custom Views that Android may instantiate by class name.
-keep public class * extends android.view.View {
    public <init>(android.content.Context);
    public <init>(android.content.Context, android.util.AttributeSet);
    public <init>(android.content.Context, android.util.AttributeSet, int);
}

# Preserve useful source information in crash traces without retaining
# unnecessary application code.
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable
