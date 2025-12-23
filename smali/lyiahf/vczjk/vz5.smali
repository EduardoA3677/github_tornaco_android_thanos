.class public Llyiahf/vczjk/vz5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/qg5;
.implements Llyiahf/vczjk/vs;
.implements Llyiahf/vczjk/eg9;
.implements Lgithub/tornaco/android/thanos/core/profile/handle/IAudio;
.implements Llyiahf/vczjk/dw0;
.implements Llyiahf/vczjk/tp0;
.implements Llyiahf/vczjk/nl1;
.implements Llyiahf/vczjk/yn0;
.implements Llyiahf/vczjk/u96;
.implements Llyiahf/vczjk/dx;
.implements Llyiahf/vczjk/wx0;
.implements Llyiahf/vczjk/du2;
.implements Llyiahf/vczjk/ho0;
.implements Llyiahf/vczjk/qh1;
.implements Llyiahf/vczjk/sj8;


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/vz5;

.field public static final OooOOOo:[Ljava/lang/String;

.field public static final OooOOo0:Llyiahf/vczjk/vz5;


# instance fields
.field public OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/vz5;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/vz5;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/vz5;->OooOOOO:Llyiahf/vczjk/vz5;

    const-string v0, "decelerate"

    const-string v1, "linear"

    const-string v2, "standard"

    const-string v3, "accelerate"

    filled-new-array {v2, v3, v0, v1}, [Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/vz5;->OooOOOo:[Ljava/lang/String;

    new-instance v0, Llyiahf/vczjk/vz5;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Llyiahf/vczjk/vz5;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/vz5;->OooOOo0:Llyiahf/vczjk/vz5;

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Llyiahf/vczjk/vz5;->OooOOO0:I

    sparse-switch p1, :sswitch_data_0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-string p1, "identity"

    iput-object p1, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    return-void

    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Llyiahf/vczjk/ws5;

    const/16 v0, 0x10

    new-array v0, v0, [Llyiahf/vczjk/js4;

    invoke-direct {p1, v0}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    return-void

    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Llyiahf/vczjk/ld9;

    invoke-direct {p1, p0}, Llyiahf/vczjk/ld9;-><init>(Llyiahf/vczjk/vz5;)V

    iput-object p1, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    return-void

    :sswitch_2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void

    nop

    :sswitch_data_0
    .sparse-switch
        0x2 -> :sswitch_2
        0x15 -> :sswitch_1
        0x18 -> :sswitch_0
    .end sparse-switch
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/view/GestureDetector$SimpleOnGestureListener;Landroid/os/Handler;)V
    .locals 1

    const/16 v0, 0x14

    iput v0, p0, Llyiahf/vczjk/vz5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Landroid/view/GestureDetector;

    invoke-direct {v0, p1, p2, p3}, Landroid/view/GestureDetector;-><init>(Landroid/content/Context;Landroid/view/GestureDetector$OnGestureListener;Landroid/os/Handler;)V

    iput-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/widget/EditText;)V
    .locals 1

    const/16 v0, 0x11

    iput v0, p0, Llyiahf/vczjk/vz5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/a27;

    invoke-direct {v0, p1}, Llyiahf/vczjk/a27;-><init>(Landroid/widget/EditText;)V

    iput-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/vz5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Lorg/mvel2/ParserContext;)V
    .locals 1

    const/16 v0, 0x19

    iput v0, p0, Llyiahf/vczjk/vz5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1, p2}, Lorg/mvel2/MVEL;->compileExpression(Ljava/lang/String;Lorg/mvel2/ParserContext;)Ljava/io/Serializable;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/util/regex/Matcher;)V
    .locals 1

    const/16 v0, 0x16

    iput v0, p0, Llyiahf/vczjk/vz5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iput-object p1, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/uz5;Llyiahf/vczjk/xj0;)V
    .locals 0

    const/4 p2, 0x0

    iput p2, p0, Llyiahf/vczjk/vz5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public static OooOO0(Landroid/content/Context;)Landroid/hardware/fingerprint/FingerprintManager;
    .locals 2

    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v0

    const-string v1, "android.hardware.fingerprint"

    invoke-virtual {v0, v1}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_0

    const-class v0, Landroid/hardware/fingerprint/FingerprintManager;

    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Landroid/hardware/fingerprint/FingerprintManager;

    return-object p0

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public static OooOO0o(Ljava/lang/String;)Llyiahf/vczjk/vz5;
    .locals 21

    move-object/from16 v0, p0

    const/4 v1, 0x3

    const/4 v2, -0x1

    const/4 v3, 0x0

    const/4 v4, 0x2

    const/4 v5, 0x1

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    const-string v6, "cubic"

    invoke-virtual {v0, v6}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v6

    if-eqz v6, :cond_1

    new-instance v1, Llyiahf/vczjk/hk2;

    invoke-direct {v1, v0}, Llyiahf/vczjk/hk2;-><init>(Ljava/lang/String;)V

    return-object v1

    :cond_1
    const-string v6, "spline"

    invoke-virtual {v0, v6}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v6

    const/16 v7, 0x2c

    const/16 v8, 0x28

    if-eqz v6, :cond_5

    new-instance v6, Llyiahf/vczjk/l59;

    invoke-direct {v6, v5}, Llyiahf/vczjk/vz5;-><init>(I)V

    iput-object v0, v6, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v9

    div-int/2addr v9, v4

    new-array v9, v9, [D

    invoke-virtual {v0, v8}, Ljava/lang/String;->indexOf(I)I

    move-result v8

    add-int/2addr v8, v5

    invoke-virtual {v0, v7, v8}, Ljava/lang/String;->indexOf(II)I

    move-result v10

    move v11, v3

    :goto_0
    if-eq v10, v2, :cond_2

    invoke-virtual {v0, v8, v10}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v8}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v8

    add-int/lit8 v12, v11, 0x1

    invoke-static {v8}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    move-result-wide v13

    aput-wide v13, v9, v11

    add-int/lit8 v8, v10, 0x1

    invoke-virtual {v0, v7, v8}, Ljava/lang/String;->indexOf(II)I

    move-result v10

    move v11, v12

    goto :goto_0

    :cond_2
    const/16 v2, 0x29

    invoke-virtual {v0, v2, v8}, Ljava/lang/String;->indexOf(II)I

    move-result v2

    invoke-virtual {v0, v8, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v0

    add-int/lit8 v2, v11, 0x1

    invoke-static {v0}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    move-result-wide v7

    aput-wide v7, v9, v11

    invoke-static {v9, v2}, Ljava/util/Arrays;->copyOf([DI)[D

    move-result-object v0

    array-length v2, v0

    mul-int/2addr v2, v1

    sub-int/2addr v2, v4

    array-length v1, v0

    sub-int/2addr v1, v5

    int-to-double v7, v1

    const-wide/high16 v9, 0x3ff0000000000000L    # 1.0

    div-double v7, v9, v7

    new-array v11, v4, [I

    aput v5, v11, v5

    aput v2, v11, v3

    sget-object v12, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    invoke-static {v12, v11}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;[I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, [[D

    new-array v2, v2, [D

    move v12, v3

    :goto_1
    array-length v13, v0

    if-ge v12, v13, :cond_4

    aget-wide v13, v0, v12

    add-int v15, v12, v1

    aget-object v16, v11, v15

    aput-wide v13, v16, v3

    move/from16 v16, v3

    move/from16 v17, v4

    int-to-double v3, v12

    mul-double/2addr v3, v7

    aput-wide v3, v2, v15

    if-lez v12, :cond_3

    mul-int/lit8 v15, v1, 0x2

    add-int/2addr v15, v12

    aget-object v18, v11, v15

    add-double v19, v13, v9

    aput-wide v19, v18, v16

    add-double v18, v3, v9

    aput-wide v18, v2, v15

    add-int/lit8 v15, v12, -0x1

    aget-object v18, v11, v15

    sub-double/2addr v13, v9

    sub-double/2addr v13, v7

    aput-wide v13, v18, v16

    const-wide/high16 v13, -0x4010000000000000L    # -1.0

    add-double/2addr v3, v13

    sub-double/2addr v3, v7

    aput-wide v3, v2, v15

    :cond_3
    add-int/2addr v12, v5

    move/from16 v3, v16

    move/from16 v4, v17

    goto :goto_1

    :cond_4
    new-instance v0, Llyiahf/vczjk/wn5;

    invoke-direct {v0, v2, v11}, Llyiahf/vczjk/wn5;-><init>([D[[D)V

    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, " 0 "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    const-wide/16 v3, 0x0

    invoke-virtual {v0, v3, v4}, Llyiahf/vczjk/wn5;->Ooooo0o(D)D

    move-result-wide v3

    invoke-virtual {v2, v3, v4}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, " 1 "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v9, v10}, Llyiahf/vczjk/wn5;->Ooooo0o(D)D

    move-result-wide v3

    invoke-virtual {v2, v3, v4}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    iput-object v0, v6, Llyiahf/vczjk/l59;->OooOOo:Llyiahf/vczjk/wn5;

    return-object v6

    :cond_5
    move/from16 v16, v3

    move/from16 v17, v4

    const-string v3, "Schlick"

    invoke-virtual {v0, v3}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v3

    if-eqz v3, :cond_6

    new-instance v1, Llyiahf/vczjk/w88;

    invoke-direct {v1, v5}, Llyiahf/vczjk/vz5;-><init>(I)V

    iput-object v0, v1, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    invoke-virtual {v0, v8}, Ljava/lang/String;->indexOf(I)I

    move-result v2

    invoke-virtual {v0, v7, v2}, Ljava/lang/String;->indexOf(II)I

    move-result v3

    add-int/2addr v2, v5

    invoke-virtual {v0, v2, v3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v2

    invoke-static {v2}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    move-result-wide v8

    iput-wide v8, v1, Llyiahf/vczjk/w88;->OooOOo:D

    add-int/2addr v3, v5

    invoke-virtual {v0, v7, v3}, Ljava/lang/String;->indexOf(II)I

    move-result v2

    invoke-virtual {v0, v3, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    move-result-wide v2

    iput-wide v2, v1, Llyiahf/vczjk/w88;->OooOOoo:D

    return-object v1

    :cond_6
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    move-result v3

    sparse-switch v3, :sswitch_data_0

    :goto_2
    move v1, v2

    goto :goto_3

    :sswitch_0
    const-string v3, "standard"

    invoke-virtual {v0, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_a

    goto :goto_2

    :sswitch_1
    const-string v1, "linear"

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_7

    goto :goto_2

    :cond_7
    move/from16 v1, v17

    goto :goto_3

    :sswitch_2
    const-string v1, "decelerate"

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_8

    goto :goto_2

    :cond_8
    move v1, v5

    goto :goto_3

    :sswitch_3
    const-string v1, "accelerate"

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_9

    goto :goto_2

    :cond_9
    move/from16 v1, v16

    :cond_a
    :goto_3
    packed-switch v1, :pswitch_data_0

    sget-object v0, Ljava/lang/System;->err:Ljava/io/PrintStream;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "transitionEasing syntax error syntax:transitionEasing=\"cubic(1.0,0.5,0.0,0.6)\" or "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    sget-object v2, Llyiahf/vczjk/vz5;->OooOOOo:[Ljava/lang/String;

    invoke-static {v2}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/vz5;->OooOOOO:Llyiahf/vczjk/vz5;

    return-object v0

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/hk2;

    const-string v1, "cubic(0.4, 0.0, 0.2, 1)"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hk2;-><init>(Ljava/lang/String;)V

    return-object v0

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/hk2;

    const-string v1, "cubic(1, 1, 0, 0)"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hk2;-><init>(Ljava/lang/String;)V

    return-object v0

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/hk2;

    const-string v1, "cubic(0.0, 0.0, 0.2, 0.95)"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hk2;-><init>(Ljava/lang/String;)V

    return-object v0

    :pswitch_3
    new-instance v0, Llyiahf/vczjk/hk2;

    const-string v1, "cubic(0.4, 0.05, 0.8, 0.7)"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hk2;-><init>(Ljava/lang/String;)V

    return-object v0

    nop

    :sswitch_data_0
    .sparse-switch
        -0x50bb8523 -> :sswitch_3
        -0x4b5653c4 -> :sswitch_2
        -0x41b970db -> :sswitch_1
        0x4e3d1ebd -> :sswitch_0
    .end sparse-switch

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method private final OooOOOO(Llyiahf/vczjk/sg5;)V
    .locals 0

    return-void
.end method


# virtual methods
.method public OooO(D)D
    .locals 0

    const-wide/high16 p1, 0x3ff0000000000000L    # 1.0

    return-wide p1
.end method

.method public OooO00o(Llyiahf/vczjk/kr1;)Llyiahf/vczjk/kr1;
    .locals 2

    instance-of v0, p1, Llyiahf/vczjk/co7;

    if-eqz v0, :cond_0

    return-object p1

    :cond_0
    new-instance v0, Llyiahf/vczjk/p1;

    iget-object v1, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/le5;

    invoke-virtual {v1}, Llyiahf/vczjk/le5;->OooOO0O()F

    move-result v1

    neg-float v1, v1

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/p1;-><init>(FLlyiahf/vczjk/kr1;)V

    return-object v0
.end method

.method public OooO0O0(Llyiahf/vczjk/v98;Ljava/lang/Float;Ljava/lang/Float;Llyiahf/vczjk/su8;Llyiahf/vczjk/vu8;)Ljava/lang/Object;
    .locals 6

    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    move-result v1

    invoke-virtual {p3}, Ljava/lang/Number;->floatValue()F

    move-result p2

    const/4 p3, 0x0

    const/16 v0, 0x1c

    invoke-static {p3, p2, v0}, Llyiahf/vczjk/tg0;->OooO0OO(FFI)Llyiahf/vczjk/xl;

    move-result-object v2

    iget-object p2, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    move-object v3, p2

    check-cast v3, Llyiahf/vczjk/t02;

    move-object v0, p1

    move-object v4, p4

    move-object v5, p5

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/bv8;->OooO00o(Llyiahf/vczjk/v98;FLlyiahf/vczjk/xl;Llyiahf/vczjk/t02;Llyiahf/vczjk/su8;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    check-cast p1, Llyiahf/vczjk/dl;

    return-object p1
.end method

.method public OooO0OO(Llyiahf/vczjk/uqa;Llyiahf/vczjk/zp0;Llyiahf/vczjk/tg7;)V
    .locals 6

    const/4 v0, 0x0

    if-eqz p2, :cond_1

    monitor-enter p2

    :try_start_0
    iget-object v1, p2, Llyiahf/vczjk/zp0;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Landroid/os/CancellationSignal;

    if-nez v1, :cond_0

    new-instance v1, Landroid/os/CancellationSignal;

    invoke-direct {v1}, Landroid/os/CancellationSignal;-><init>()V

    iput-object v1, p2, Llyiahf/vczjk/zp0;->OooO0Oo:Ljava/lang/Object;

    iget-boolean v2, p2, Llyiahf/vczjk/zp0;->OooO00o:Z

    if-eqz v2, :cond_0

    invoke-virtual {v1}, Landroid/os/CancellationSignal;->cancel()V

    goto :goto_0

    :catchall_0
    move-exception v0

    move-object p1, v0

    goto :goto_1

    :cond_0
    :goto_0
    iget-object v1, p2, Llyiahf/vczjk/zp0;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Landroid/os/CancellationSignal;

    monitor-exit p2

    move-object v2, v1

    goto :goto_2

    :goto_1
    monitor-exit p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p1

    :cond_1
    move-object v2, v0

    :goto_2
    iget-object p2, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast p2, Landroid/content/Context;

    invoke-static {p2}, Llyiahf/vczjk/vz5;->OooOO0(Landroid/content/Context;)Landroid/hardware/fingerprint/FingerprintManager;

    move-result-object p2

    if-eqz p2, :cond_6

    if-nez p1, :cond_2

    goto :goto_3

    :cond_2
    iget-object v1, p1, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Ljavax/crypto/Cipher;

    if-eqz v1, :cond_4

    new-instance v0, Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;

    invoke-direct {v0, v1}, Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;-><init>(Ljavax/crypto/Cipher;)V

    :cond_3
    :goto_3
    move-object v1, v0

    goto :goto_4

    :cond_4
    iget-object v1, p1, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v1, Ljava/security/Signature;

    if-eqz v1, :cond_5

    new-instance v0, Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;

    invoke-direct {v0, v1}, Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;-><init>(Ljava/security/Signature;)V

    goto :goto_3

    :cond_5
    iget-object p1, p1, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Ljavax/crypto/Mac;

    if-eqz p1, :cond_3

    new-instance v0, Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;

    invoke-direct {v0, p1}, Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;-><init>(Ljavax/crypto/Mac;)V

    goto :goto_3

    :goto_4
    new-instance v4, Llyiahf/vczjk/n13;

    invoke-direct {v4, p3}, Llyiahf/vczjk/n13;-><init>(Llyiahf/vczjk/tg7;)V

    const/4 v3, 0x0

    const/4 v5, 0x0

    move-object v0, p2

    invoke-virtual/range {v0 .. v5}, Landroid/hardware/fingerprint/FingerprintManager;->authenticate(Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;Landroid/os/CancellationSignal;ILandroid/hardware/fingerprint/FingerprintManager$AuthenticationCallback;Landroid/os/Handler;)V

    :cond_6
    return-void
.end method

.method public OooO0Oo(Landroid/graphics/drawable/Drawable;)V
    .locals 0

    return-void
.end method

.method public OooO0o(Landroid/graphics/drawable/Drawable;)V
    .locals 2

    new-instance v0, Llyiahf/vczjk/a00;

    iget-object v1, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/j00;

    if-eqz p1, :cond_0

    invoke-virtual {v1, p1}, Llyiahf/vczjk/j00;->OooOO0(Landroid/graphics/drawable/Drawable;)Llyiahf/vczjk/un6;

    move-result-object p1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    invoke-direct {v0, p1}, Llyiahf/vczjk/a00;-><init>(Llyiahf/vczjk/un6;)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/j00;->OooOO0O(Llyiahf/vczjk/c00;)V

    return-void
.end method

.method public OooO0o0(Landroid/graphics/drawable/Drawable;)V
    .locals 0

    return-void
.end method

.method public OooO0oO(Landroid/content/Context;Ljava/lang/String;Ljava/io/InputStream;Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/d95;
    .locals 6

    if-nez p4, :cond_0

    const-string p4, "application/json"

    :cond_0
    const-string v0, "application/zip"

    invoke-virtual {p4, v0}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/uz5;

    const/4 v2, 0x0

    if-nez v0, :cond_6

    const-string v0, "application/x-zip"

    invoke-virtual {p4, v0}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v0

    if-nez v0, :cond_6

    const-string v0, "application/x-zip-compressed"

    invoke-virtual {p4, v0}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v0

    if-nez v0, :cond_6

    const-string v0, "\\?"

    invoke-virtual {p2, v0}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v3

    const/4 v4, 0x0

    aget-object v3, v3, v4

    const-string v5, ".lottie"

    invoke-virtual {v3, v5}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    move-result v3

    if-eqz v3, :cond_1

    goto :goto_1

    :cond_1
    const-string p1, "application/gzip"

    invoke-virtual {p4, p1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result p1

    if-nez p1, :cond_4

    const-string p1, "application/x-gzip"

    invoke-virtual {p4, p1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result p1

    if-nez p1, :cond_4

    invoke-virtual {p2, v0}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object p1

    aget-object p1, p1, v4

    const-string p4, ".tgs"

    invoke-virtual {p1, p4}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    move-result p1

    if-eqz p1, :cond_2

    goto :goto_0

    :cond_2
    invoke-static {}, Llyiahf/vczjk/p55;->OooO00o()V

    sget-object p1, Llyiahf/vczjk/gy2;->OooOOO0:Llyiahf/vczjk/gy2;

    if-eqz p5, :cond_3

    invoke-virtual {v1, p2, p3, p1}, Llyiahf/vczjk/uz5;->OooooOo(Ljava/lang/String;Ljava/io/InputStream;Llyiahf/vczjk/gy2;)Ljava/io/File;

    move-result-object p3

    new-instance p4, Ljava/io/FileInputStream;

    invoke-virtual {p3}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object p3

    invoke-direct {p4, p3}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V

    invoke-static {p4, p2}, Llyiahf/vczjk/e85;->OooO0Oo(Ljava/io/InputStream;Ljava/lang/String;)Llyiahf/vczjk/d95;

    move-result-object p3

    goto :goto_4

    :cond_3
    invoke-static {p3, v2}, Llyiahf/vczjk/e85;->OooO0Oo(Ljava/io/InputStream;Ljava/lang/String;)Llyiahf/vczjk/d95;

    move-result-object p3

    goto :goto_4

    :cond_4
    :goto_0
    invoke-static {}, Llyiahf/vczjk/p55;->OooO00o()V

    sget-object p1, Llyiahf/vczjk/gy2;->OooOOOO:Llyiahf/vczjk/gy2;

    if-eqz p5, :cond_5

    invoke-virtual {v1, p2, p3, p1}, Llyiahf/vczjk/uz5;->OooooOo(Ljava/lang/String;Ljava/io/InputStream;Llyiahf/vczjk/gy2;)Ljava/io/File;

    move-result-object p3

    new-instance p4, Ljava/util/zip/GZIPInputStream;

    new-instance v0, Ljava/io/FileInputStream;

    invoke-direct {v0, p3}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V

    invoke-direct {p4, v0}, Ljava/util/zip/GZIPInputStream;-><init>(Ljava/io/InputStream;)V

    invoke-static {p4, p2}, Llyiahf/vczjk/e85;->OooO0Oo(Ljava/io/InputStream;Ljava/lang/String;)Llyiahf/vczjk/d95;

    move-result-object p3

    goto :goto_4

    :cond_5
    new-instance p4, Ljava/util/zip/GZIPInputStream;

    invoke-direct {p4, p3}, Ljava/util/zip/GZIPInputStream;-><init>(Ljava/io/InputStream;)V

    invoke-static {p4, v2}, Llyiahf/vczjk/e85;->OooO0Oo(Ljava/io/InputStream;Ljava/lang/String;)Llyiahf/vczjk/d95;

    move-result-object p3

    goto :goto_4

    :cond_6
    :goto_1
    invoke-static {}, Llyiahf/vczjk/p55;->OooO00o()V

    sget-object p4, Llyiahf/vczjk/gy2;->OooOOO:Llyiahf/vczjk/gy2;

    if-eqz p5, :cond_7

    invoke-virtual {v1, p2, p3, p4}, Llyiahf/vczjk/uz5;->OooooOo(Ljava/lang/String;Ljava/io/InputStream;Llyiahf/vczjk/gy2;)Ljava/io/File;

    move-result-object p3

    new-instance v0, Ljava/util/zip/ZipInputStream;

    new-instance v2, Ljava/io/FileInputStream;

    invoke-direct {v2, p3}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V

    invoke-direct {v0, v2}, Ljava/util/zip/ZipInputStream;-><init>(Ljava/io/InputStream;)V

    invoke-static {p1, v0, p2}, Llyiahf/vczjk/e85;->OooO0oO(Landroid/content/Context;Ljava/util/zip/ZipInputStream;Ljava/lang/String;)Llyiahf/vczjk/d95;

    move-result-object p1

    :goto_2
    move-object p3, p1

    goto :goto_3

    :cond_7
    new-instance v0, Ljava/util/zip/ZipInputStream;

    invoke-direct {v0, p3}, Ljava/util/zip/ZipInputStream;-><init>(Ljava/io/InputStream;)V

    invoke-static {p1, v0, v2}, Llyiahf/vczjk/e85;->OooO0oO(Landroid/content/Context;Ljava/util/zip/ZipInputStream;Ljava/lang/String;)Llyiahf/vczjk/d95;

    move-result-object p1

    goto :goto_2

    :goto_3
    move-object p1, p4

    :goto_4
    if-eqz p5, :cond_8

    iget-object p4, p3, Llyiahf/vczjk/d95;->OooO00o:Llyiahf/vczjk/z75;

    if-eqz p4, :cond_8

    const/4 p4, 0x1

    invoke-static {p2, p1, p4}, Llyiahf/vczjk/uz5;->OoooOOo(Ljava/lang/String;Llyiahf/vczjk/gy2;Z)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/io/File;

    invoke-virtual {v1}, Llyiahf/vczjk/uz5;->OoooOoO()Ljava/io/File;

    move-result-object p4

    invoke-direct {p2, p4, p1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {p2}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object p1

    const-string p4, ".temp"

    const-string p5, ""

    invoke-virtual {p1, p4, p5}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    move-result-object p1

    new-instance p4, Ljava/io/File;

    invoke-direct {p4, p1}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p4}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    move-result p1

    invoke-virtual {p4}, Ljava/lang/Object;->toString()Ljava/lang/String;

    invoke-static {}, Llyiahf/vczjk/p55;->OooO00o()V

    if-nez p1, :cond_8

    new-instance p1, Ljava/lang/StringBuilder;

    const-string p5, "Unable to rename cache file "

    invoke-direct {p1, p5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p2, " to "

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p4}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p2, "."

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/p55;->OooO0O0(Ljava/lang/String;)V

    :cond_8
    return-object p3
.end method

.method public OooO0oo(D)D
    .locals 0

    return-wide p1
.end method

.method public OooOO0O()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;

    invoke-virtual {v0}, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;->getCollapsedPadding()I

    move-result v0

    return v0
.end method

.method public OooOOO(Ljava/lang/String;)V
    .locals 3

    new-instance v0, Llyiahf/vczjk/kd5;

    iget-object v1, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v1, Lnow/fortuitous/thanos/apps/AppDetailsActivity;

    invoke-direct {v0, v1}, Llyiahf/vczjk/kd5;-><init>(Landroid/content/Context;)V

    iget-object v2, v0, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s3;

    iput-object p1, v2, Llyiahf/vczjk/s3;->OooO0o:Ljava/lang/CharSequence;

    const/4 p1, 0x1

    iput-boolean p1, v2, Llyiahf/vczjk/s3;->OooOOO0:Z

    const p1, 0x104000a

    const/4 v2, 0x0

    invoke-virtual {v0, p1, v2}, Llyiahf/vczjk/kd5;->OooOo00(ILandroid/content/DialogInterface$OnClickListener;)V

    invoke-virtual {v0}, Llyiahf/vczjk/w3;->OooOOOO()Llyiahf/vczjk/x3;

    iget-object p1, v1, Lnow/fortuitous/thanos/apps/AppDetailsActivity;->OoooO00:Llyiahf/vczjk/dl5;

    invoke-virtual {p1}, Llyiahf/vczjk/dl5;->OooO00o()V

    return-void
.end method

.method public OooOOO0(FFFF)V
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/uqa;

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v1

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOo00()J

    move-result-wide v2

    const/16 v4, 0x20

    shr-long/2addr v2, v4

    long-to-int v2, v2

    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    add-float/2addr p3, p1

    sub-float/2addr v2, p3

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOo00()J

    move-result-wide v5

    const-wide v7, 0xffffffffL

    and-long/2addr v5, v7

    long-to-int p3, v5

    invoke-static {p3}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p3

    add-float/2addr p4, p2

    sub-float/2addr p3, p4

    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p4

    int-to-long v2, p4

    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p3

    int-to-long p3, p3

    shl-long/2addr v2, v4

    and-long/2addr p3, v7

    or-long/2addr p3, v2

    shr-long v2, p3, v4

    long-to-int v2, v2

    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    const/4 v3, 0x0

    cmpl-float v2, v2, v3

    if-ltz v2, :cond_0

    and-long v4, p3, v7

    long-to-int v2, v4

    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    cmpl-float v2, v2, v3

    if-ltz v2, :cond_0

    const/4 v2, 0x1

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    :goto_0
    if-nez v2, :cond_1

    const-string v2, "Width and height must be greater than or equal to zero"

    invoke-static {v2}, Llyiahf/vczjk/oz3;->OooO00o(Ljava/lang/String;)V

    :cond_1
    invoke-virtual {v0, p3, p4}, Llyiahf/vczjk/uqa;->Oooo0(J)V

    invoke-interface {v1, p1, p2}, Llyiahf/vczjk/eq0;->OooOOOo(FF)V

    return-void
.end method

.method public OooOOOo(FJ)V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/uqa;

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v0

    const/16 v1, 0x20

    shr-long v1, p2, v1

    long-to-int v1, v1

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    const-wide v3, 0xffffffffL

    and-long/2addr p2, v3

    long-to-int p2, p2

    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p3

    invoke-interface {v0, v2, p3}, Llyiahf/vczjk/eq0;->OooOOOo(FF)V

    invoke-interface {v0, p1}, Llyiahf/vczjk/eq0;->OooO0Oo(F)V

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p1

    neg-float p1, p1

    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p2

    neg-float p2, p2

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/eq0;->OooOOOo(FF)V

    return-void
.end method

.method public OooOOo(FF)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/uqa;

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v0

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/eq0;->OooOOOo(FF)V

    return-void
.end method

.method public OooOOo0(FFJ)V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/uqa;

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v0

    const/16 v1, 0x20

    shr-long v1, p3, v1

    long-to-int v1, v1

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    const-wide v3, 0xffffffffL

    and-long/2addr p3, v3

    long-to-int p3, p3

    invoke-static {p3}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p4

    invoke-interface {v0, v2, p4}, Llyiahf/vczjk/eq0;->OooOOOo(FF)V

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/eq0;->OooO00o(FF)V

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p1

    neg-float p1, p1

    invoke-static {p3}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p2

    neg-float p2, p2

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/eq0;->OooOOOo(FF)V

    return-void
.end method

.method public OooOOoo()Ljava/lang/reflect/Type;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/lang/reflect/Type;

    return-object v0
.end method

.method public OooOo(Landroid/graphics/Typeface;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/r11;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r11;->OooOoO(Landroid/graphics/Typeface;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r11;->OooOO0o(Z)V

    :cond_0
    return-void
.end method

.method public OooOo0O(Llyiahf/vczjk/sg5;Landroid/view/MenuItem;)Z
    .locals 4

    iget p1, p0, Llyiahf/vczjk/vz5;->OooOOO0:I

    packed-switch p1, :pswitch_data_0

    iget-object p1, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast p1, Lcom/google/android/material/navigation/NavigationView;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x0

    return p1

    :pswitch_0
    iget-object p1, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast p1, Landroidx/appcompat/widget/ActionMenuView;

    iget-object p1, p1, Landroidx/appcompat/widget/ActionMenuView;->Oooo0o:Llyiahf/vczjk/oO0OoOO0;

    const/4 v0, 0x0

    if-eqz p1, :cond_4

    check-cast p1, Llyiahf/vczjk/fk7;

    iget-object p1, p1, Llyiahf/vczjk/fk7;->OooOOO0:Ljava/lang/Object;

    check-cast p1, Landroidx/appcompat/widget/Toolbar;

    iget-object v1, p1, Landroidx/appcompat/widget/Toolbar;->OoooO0O:Llyiahf/vczjk/ed5;

    iget-object v1, v1, Llyiahf/vczjk/ed5;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Ljava/util/concurrent/CopyOnWriteArrayList;

    invoke-virtual {v1}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    const/4 v3, 0x1

    if-eqz v2, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/uc3;

    iget-object v2, v2, Llyiahf/vczjk/uc3;->OooO00o:Landroidx/fragment/app/oo000o;

    invoke-virtual {v2, p2}, Landroidx/fragment/app/oo000o;->OooOOOo(Landroid/view/MenuItem;)Z

    move-result v2

    if-eqz v2, :cond_0

    move v1, v3

    goto :goto_0

    :cond_1
    move v1, v0

    :goto_0
    if-eqz v1, :cond_2

    move p1, v3

    goto :goto_1

    :cond_2
    iget-object p1, p1, Landroidx/appcompat/widget/Toolbar;->OoooOO0:Llyiahf/vczjk/vw9;

    if-eqz p1, :cond_3

    invoke-interface {p1, p2}, Llyiahf/vczjk/vw9;->onMenuItemClick(Landroid/view/MenuItem;)Z

    move-result p1

    goto :goto_1

    :cond_3
    move p1, v0

    :goto_1
    if-eqz p1, :cond_4

    move v0, v3

    :cond_4
    return v0

    nop

    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method

.method public OooOoO(Llyiahf/vczjk/sg5;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/vz5;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroidx/appcompat/widget/ActionMenuView;

    iget-object v0, v0, Landroidx/appcompat/widget/ActionMenuView;->Oooo00o:Llyiahf/vczjk/qg5;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, Llyiahf/vczjk/qg5;->OooOoO(Llyiahf/vczjk/sg5;)V

    :cond_0
    return-void

    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method

.method public OooOooO()Landroid/view/ViewGroup$LayoutParams;
    .locals 3

    new-instance v0, Landroid/view/ViewGroup$LayoutParams;

    iget-object v1, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v1, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;

    invoke-virtual {v1}, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;->getCollapsedSize()I

    move-result v2

    invoke-virtual {v1}, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;->getCollapsedSize()I

    move-result v1

    invoke-direct {v0, v2, v1}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    return-object v0
.end method

.method public OooOooo(Llyiahf/vczjk/wn0;Ljava/lang/Throwable;)V
    .locals 1

    const-string v0, "call"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/yp0;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    return-void
.end method

.method public Oooo0o()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;

    invoke-virtual {v0}, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;->getCollapsedPadding()I

    move-result v0

    return v0
.end method

.method public Oooo0oO(Landroid/view/View;Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;
    .locals 6

    const/4 p1, 0x1

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;

    iget-object v1, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->OooOoO:Llyiahf/vczjk/ioa;

    invoke-static {v1, p2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_5

    iput-object p2, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->OooOoO:Llyiahf/vczjk/ioa;

    invoke-virtual {p2}, Llyiahf/vczjk/ioa;->OooO0Oo()I

    move-result v1

    const/4 v2, 0x0

    if-lez v1, :cond_0

    move v1, p1

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    iput-boolean v1, v0, Landroidx/coordinatorlayout/widget/CoordinatorLayout;->OooOoOO:Z

    if-nez v1, :cond_1

    invoke-virtual {v0}, Landroid/view/View;->getBackground()Landroid/graphics/drawable/Drawable;

    move-result-object v1

    if-nez v1, :cond_1

    move v1, p1

    goto :goto_1

    :cond_1
    move v1, v2

    :goto_1
    invoke-virtual {v0, v1}, Landroid/view/View;->setWillNotDraw(Z)V

    iget-object v1, p2, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-virtual {v1}, Llyiahf/vczjk/foa;->OooOOOO()Z

    move-result v3

    if-eqz v3, :cond_2

    goto :goto_3

    :cond_2
    invoke-virtual {v0}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v3

    :goto_2
    if-ge v2, v3, :cond_4

    invoke-virtual {v0, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/xfa;->OooO00o:Ljava/util/WeakHashMap;

    invoke-virtual {v4}, Landroid/view/View;->getFitsSystemWindows()Z

    move-result v5

    if-eqz v5, :cond_3

    invoke-virtual {v4}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v4

    check-cast v4, Landroidx/coordinatorlayout/widget/OooO0OO;

    iget-object v4, v4, Landroidx/coordinatorlayout/widget/OooO0OO;->OooO00o:Landroidx/coordinatorlayout/widget/CoordinatorLayout$Behavior;

    if-eqz v4, :cond_3

    invoke-virtual {v1}, Llyiahf/vczjk/foa;->OooOOOO()Z

    move-result v4

    if-eqz v4, :cond_3

    goto :goto_3

    :cond_3
    add-int/2addr v2, p1

    goto :goto_2

    :cond_4
    :goto_3
    invoke-virtual {v0}, Landroid/view/View;->requestLayout()V

    :cond_5
    return-object p2
.end method

.method public Oooo0oo(Llyiahf/vczjk/wn0;Llyiahf/vczjk/hs7;)V
    .locals 1

    const-string v0, "call"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p2, Llyiahf/vczjk/hs7;->OooO00o:Llyiahf/vczjk/is7;

    invoke-virtual {p1}, Llyiahf/vczjk/is7;->OooO0oO()Z

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yp0;

    if-eqz p1, :cond_0

    iget-object p1, p2, Llyiahf/vczjk/hs7;->OooO0O0:Ljava/lang/Object;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    return-void

    :cond_0
    new-instance p1, Llyiahf/vczjk/zq3;

    invoke-direct {p1, p2}, Llyiahf/vczjk/zq3;-><init>(Llyiahf/vczjk/hs7;)V

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    return-void
.end method

.method public OoooOO0(Llyiahf/vczjk/c96;)Ljava/lang/Object;
    .locals 3

    new-instance v0, Llyiahf/vczjk/z51;

    invoke-direct {v0, p1}, Llyiahf/vczjk/z51;-><init>(Llyiahf/vczjk/c96;)V

    new-instance v1, Llyiahf/vczjk/uz5;

    const/16 v2, 0xd

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/uz5;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/c96;->OooOOOO(Llyiahf/vczjk/ho0;)V

    return-object v0
.end method

.method public Oooooo0(Llyiahf/vczjk/hy0;)Llyiahf/vczjk/vx0;
    .locals 3

    const-string v0, "classId"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/lh6;

    iget-object v1, p1, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-static {v0, v1}, Llyiahf/vczjk/kh6;->Oooo0oO(Llyiahf/vczjk/lh6;Llyiahf/vczjk/hc3;)Ljava/util/ArrayList;

    move-result-object v0

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/hh6;

    instance-of v2, v1, Llyiahf/vczjk/hk0;

    if-eqz v2, :cond_0

    check-cast v1, Llyiahf/vczjk/hk0;

    iget-object v1, v1, Llyiahf/vczjk/hk0;->OooOo:Llyiahf/vczjk/pb7;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/pb7;->Oooooo0(Llyiahf/vczjk/hy0;)Llyiahf/vczjk/vx0;

    move-result-object v1

    if-eqz v1, :cond_0

    return-object v1

    :cond_1
    const/4 p1, 0x0

    return-object p1
.end method

.method public accept(Ljava/lang/Object;)V
    .locals 0

    check-cast p1, Llyiahf/vczjk/nc2;

    iget-object p1, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/t41;

    iget-object p1, p1, Llyiahf/vczjk/t41;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    invoke-virtual {p1}, Landroidx/databinding/ObservableArrayList;->clear()V

    return-void
.end method

.method public evaluate(Llyiahf/vczjk/gv2;)Z
    .locals 1

    invoke-virtual {p1}, Llyiahf/vczjk/gv2;->OooO00o()Ljava/util/HashMap;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/io/Serializable;

    invoke-static {v0, p1}, Lorg/mvel2/MVEL;->executeExpression(Ljava/lang/Object;Ljava/util/Map;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    return p1
.end method

.method public getHeight()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;

    invoke-virtual {v0}, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;->getCollapsedSize()I

    move-result v0

    return v0
.end method

.method public getRingerMode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOo0O:Llyiahf/vczjk/p10;

    iget-object v0, v0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/ServicesKt;->getAudioManager(Landroid/content/Context;)Landroid/media/AudioManager;

    move-result-object v0

    invoke-virtual {v0}, Landroid/media/AudioManager;->getRingerMode()I

    move-result v0

    return v0
.end method

.method public getWidth()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;

    invoke-virtual {v0}, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;->getCollapsedSize()I

    move-result v0

    return v0
.end method

.method public setRingerMode(I)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOo0O:Llyiahf/vczjk/p10;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/oOOOOo0O;

    const/4 v2, 0x2

    invoke-direct {v1, p1, v2, v0}, Llyiahf/vczjk/oOOOOo0O;-><init>(IILjava/lang/Object;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/td9;->OooO0o(Ljava/lang/Runnable;)V

    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/vz5;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/lang/String;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
