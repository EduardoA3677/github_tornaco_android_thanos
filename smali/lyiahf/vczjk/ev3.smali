.class public final synthetic Llyiahf/vczjk/ev3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/uqa;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/uqa;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ev3;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ev3;->OooOOO:Llyiahf/vczjk/uqa;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 8

    const/4 v0, 0x0

    iget v1, p0, Llyiahf/vczjk/ev3;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ev3;->OooOOO:Llyiahf/vczjk/uqa;

    sget-object v1, Llyiahf/vczjk/op3;->Oooo00o:Llyiahf/vczjk/op3;

    iget-object v0, v0, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroid/content/Context;

    monitor-enter v1

    :try_start_0
    sget-object v2, Llyiahf/vczjk/op3;->Oooo0:Llyiahf/vczjk/ci7;

    if-nez v2, :cond_1

    new-instance v2, Llyiahf/vczjk/xb2;

    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    sget-object v3, Llyiahf/vczjk/ez2;->OooO00o:Llyiahf/vczjk/we4;

    iput-object v3, v2, Llyiahf/vczjk/xb2;->OooO0O0:Llyiahf/vczjk/we4;

    const-wide v3, 0x3f947ae147ae147bL    # 0.02

    iput-wide v3, v2, Llyiahf/vczjk/xb2;->OooO0OO:D

    const-wide/32 v3, 0xa00000

    iput-wide v3, v2, Llyiahf/vczjk/xb2;->OooO0Oo:J

    const-wide/32 v3, 0xfa00000

    iput-wide v3, v2, Llyiahf/vczjk/xb2;->OooO0o0:J

    sget-object v3, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v3, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    iput-object v3, v2, Llyiahf/vczjk/xb2;->OooO0o:Llyiahf/vczjk/m22;

    sget-object v3, Llyiahf/vczjk/OooOOO0;->OooO00o:Landroid/graphics/Bitmap$Config;

    invoke-virtual {v0}, Landroid/content/Context;->getCacheDir()Ljava/io/File;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/io/File;->mkdirs()Z

    invoke-static {v0}, Llyiahf/vczjk/d03;->ooOO(Ljava/io/File;)Ljava/io/File;

    move-result-object v0

    sget-object v3, Llyiahf/vczjk/zp6;->OooOOO:Ljava/lang/String;

    invoke-static {v0}, Llyiahf/vczjk/xj0;->OooOOo0(Ljava/io/File;)Llyiahf/vczjk/zp6;

    move-result-object v0

    iput-object v0, v2, Llyiahf/vczjk/xb2;->OooO00o:Llyiahf/vczjk/zp6;

    invoke-virtual {v2}, Llyiahf/vczjk/xb2;->OooO00o()Llyiahf/vczjk/ci7;

    move-result-object v2

    sput-object v2, Llyiahf/vczjk/op3;->Oooo0:Llyiahf/vczjk/ci7;

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v2, "cacheDir == null"

    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_1
    :goto_0
    monitor-exit v1

    return-object v2

    :goto_1
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v0

    :pswitch_0
    const-class v1, Landroid/app/ActivityManager;

    iget-object v2, p0, Llyiahf/vczjk/ev3;->OooOOO:Llyiahf/vczjk/uqa;

    iget-object v2, v2, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v2, Landroid/content/Context;

    sget-object v3, Llyiahf/vczjk/OooOOO0;->OooO00o:Landroid/graphics/Bitmap$Config;

    const-wide v3, 0x3fc999999999999aL    # 0.2

    :try_start_2
    invoke-virtual {v2, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v5, Landroid/app/ActivityManager;

    invoke-virtual {v5}, Landroid/app/ActivityManager;->isLowRamDevice()Z

    move-result v5
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    if-eqz v5, :cond_2

    const-wide v3, 0x3fc3333333333333L    # 0.15

    :catch_0
    :cond_2
    new-instance v5, Llyiahf/vczjk/w3;

    const/16 v6, 0xa

    invoke-direct {v5, v6, v0}, Llyiahf/vczjk/w3;-><init>(IZ)V

    const-wide/16 v6, 0x0

    cmpl-double v6, v3, v6

    if-lez v6, :cond_4

    sget-object v0, Llyiahf/vczjk/OooOOO0;->OooO00o:Landroid/graphics/Bitmap$Config;

    :try_start_3
    invoke-virtual {v2, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v0, Landroid/app/ActivityManager;

    invoke-virtual {v2}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    move-result-object v1

    iget v1, v1, Landroid/content/pm/ApplicationInfo;->flags:I

    const/high16 v2, 0x100000

    and-int/2addr v1, v2

    if-eqz v1, :cond_3

    invoke-virtual {v0}, Landroid/app/ActivityManager;->getLargeMemoryClass()I

    move-result v0

    goto :goto_2

    :cond_3
    invoke-virtual {v0}, Landroid/app/ActivityManager;->getMemoryClass()I

    move-result v0
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_1

    goto :goto_2

    :catch_1
    const/16 v0, 0x100

    :goto_2
    int-to-double v0, v0

    mul-double/2addr v3, v0

    const/16 v0, 0x400

    int-to-double v0, v0

    mul-double/2addr v3, v0

    mul-double/2addr v3, v0

    double-to-int v0, v3

    :cond_4
    if-lez v0, :cond_5

    new-instance v1, Llyiahf/vczjk/n62;

    invoke-direct {v1, v0, v5}, Llyiahf/vczjk/n62;-><init>(ILlyiahf/vczjk/w3;)V

    goto :goto_3

    :cond_5
    new-instance v1, Llyiahf/vczjk/tqa;

    const/16 v0, 0x10

    invoke-direct {v1, v5, v0}, Llyiahf/vczjk/tqa;-><init>(Ljava/lang/Object;I)V

    :goto_3
    new-instance v0, Llyiahf/vczjk/mi7;

    invoke-direct {v0, v1, v5}, Llyiahf/vczjk/mi7;-><init>(Llyiahf/vczjk/k79;Llyiahf/vczjk/w3;)V

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
