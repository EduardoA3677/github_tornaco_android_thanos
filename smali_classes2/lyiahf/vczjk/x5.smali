.class public final synthetic Llyiahf/vczjk/x5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/x5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/x5;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/x5;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/x5;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ah5;)V
    .locals 1

    const/4 v0, 0x6

    iput v0, p0, Llyiahf/vczjk/x5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/x5;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/x5;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/x5;->OooOOOo:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/le3;Llyiahf/vczjk/ul4;Landroid/content/Context;)V
    .locals 0

    const/16 p3, 0x9

    iput p3, p0, Llyiahf/vczjk/x5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/x5;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/x5;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/x5;->OooOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 11

    const-string v0, "runningAppState"

    const/4 v1, 0x0

    const/4 v2, 0x1

    const/4 v3, 0x3

    const/4 v4, 0x0

    sget-object v5, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v6, p0, Llyiahf/vczjk/x5;->OooOOO:Ljava/lang/Object;

    iget-object v7, p0, Llyiahf/vczjk/x5;->OooOOOO:Ljava/lang/Object;

    iget-object v8, p0, Llyiahf/vczjk/x5;->OooOOOo:Ljava/lang/Object;

    iget v9, p0, Llyiahf/vczjk/x5;->OooOOO0:I

    packed-switch v9, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/xo9;

    check-cast v8, Llyiahf/vczjk/zl8;

    invoke-direct {v0, v8, v4}, Llyiahf/vczjk/xo9;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/yo1;)V

    check-cast v7, Llyiahf/vczjk/xr1;

    invoke-static {v7, v4, v4, v0, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/gu6;

    check-cast v6, Llyiahf/vczjk/yo9;

    const/16 v2, 0x12

    invoke-direct {v1, v2, v8, v6}, Llyiahf/vczjk/gu6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/k84;->OoooO00(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/sc2;

    return-object v5

    :pswitch_0
    check-cast v7, Llyiahf/vczjk/oe3;

    check-cast v8, Llyiahf/vczjk/ur0;

    invoke-interface {v7, v8}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/qs5;

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-interface {v6, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    return-object v5

    :pswitch_1
    check-cast v7, Llyiahf/vczjk/oe3;

    check-cast v8, Llyiahf/vczjk/vw;

    invoke-interface {v7, v8}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/qs5;

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-interface {v6, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    return-object v5

    :pswitch_2
    check-cast v7, Llyiahf/vczjk/cm4;

    iget-boolean v0, v7, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz v0, :cond_0

    check-cast v8, Llyiahf/vczjk/zl9;

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zl9;->OooO00o(Ljava/lang/String;)V

    goto :goto_0

    :cond_0
    check-cast v6, Llyiahf/vczjk/yo9;

    invoke-virtual {v6, v2}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    :goto_0
    return-object v5

    :pswitch_3
    check-cast v7, Llyiahf/vczjk/cm4;

    iget-boolean v0, v7, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz v0, :cond_1

    check-cast v8, Llyiahf/vczjk/yg5;

    invoke-virtual {v8, v2}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    goto :goto_1

    :cond_1
    check-cast v6, Llyiahf/vczjk/yo9;

    invoke-virtual {v6, v2}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    :goto_1
    return-object v5

    :pswitch_4
    check-cast v6, Llyiahf/vczjk/qs5;

    invoke-interface {v6}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cm4;

    iget-boolean v0, v0, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz v0, :cond_2

    check-cast v7, Llyiahf/vczjk/hb8;

    invoke-virtual {v7, v2}, Llyiahf/vczjk/hb8;->OooO0Oo(Z)V

    check-cast v8, Llyiahf/vczjk/h48;

    invoke-virtual {v8}, Llyiahf/vczjk/h48;->OooO0oo()V

    goto :goto_2

    :cond_2
    sget-object v0, Llyiahf/vczjk/im4;->OooO00o:Llyiahf/vczjk/im4;

    invoke-virtual {v0}, Llyiahf/vczjk/im4;->OooO00o()V

    :goto_2
    return-object v5

    :pswitch_5
    check-cast v6, Llyiahf/vczjk/qs5;

    invoke-interface {v6}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/j28;

    iget-boolean v0, v0, Llyiahf/vczjk/j28;->OooO0OO:Z

    if-eqz v0, :cond_3

    check-cast v7, Llyiahf/vczjk/i48;

    invoke-virtual {v7}, Llyiahf/vczjk/i48;->OooO()V

    goto :goto_3

    :cond_3
    check-cast v8, Llyiahf/vczjk/le3;

    invoke-interface {v8}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :goto_3
    return-object v5

    :pswitch_6
    check-cast v6, Llyiahf/vczjk/qs5;

    invoke-interface {v6}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/i28;

    iget-boolean v0, v0, Llyiahf/vczjk/i28;->OooO00o:Z

    if-eqz v0, :cond_4

    check-cast v7, Llyiahf/vczjk/h48;

    invoke-virtual {v7}, Llyiahf/vczjk/h48;->OooO0oo()V

    goto :goto_4

    :cond_4
    check-cast v8, Llyiahf/vczjk/le3;

    invoke-interface {v8}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :goto_4
    return-object v5

    :pswitch_7
    new-instance v0, Llyiahf/vczjk/sz7;

    check-cast v8, Llyiahf/vczjk/i48;

    invoke-direct {v0, v8, v2}, Llyiahf/vczjk/sz7;-><init>(Llyiahf/vczjk/i48;I)V

    check-cast v7, Llyiahf/vczjk/cp8;

    invoke-virtual {v7, v0}, Llyiahf/vczjk/cp8;->OooO0oO(Llyiahf/vczjk/ze3;)V

    new-instance v0, Llyiahf/vczjk/e2;

    check-cast v6, Landroid/content/Context;

    const/16 v2, 0x1d

    invoke-direct {v0, v2, v6, v8}, Llyiahf/vczjk/e2;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    new-instance v2, Llyiahf/vczjk/bp8;

    invoke-direct {v2, v1, v7, v0}, Llyiahf/vczjk/bp8;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object v0, v7, Llyiahf/vczjk/cp8;->OooO00o:Llyiahf/vczjk/yo8;

    iput-object v2, v0, Llyiahf/vczjk/yo8;->OooO0OO:Llyiahf/vczjk/bp8;

    return-object v5

    :pswitch_8
    check-cast v7, Llyiahf/vczjk/cm4;

    iget-boolean v0, v7, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz v0, :cond_5

    check-cast v6, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v6}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v0

    check-cast v8, Llyiahf/vczjk/zl9;

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zl9;->OooO00o(Ljava/lang/String;)V

    goto :goto_5

    :cond_5
    sget-object v0, Llyiahf/vczjk/im4;->OooO00o:Llyiahf/vczjk/im4;

    invoke-virtual {v0}, Llyiahf/vczjk/im4;->OooO00o()V

    :goto_5
    return-object v5

    :pswitch_9
    check-cast v7, Llyiahf/vczjk/oy7;

    check-cast v8, Lnow/fortuitous/thanos/process/v2/RunningAppState;

    invoke-static {v8, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/on1;->OooO00o:Ljava/util/Set;

    check-cast v0, Ljava/lang/Iterable;

    instance-of v3, v0, Ljava/util/Collection;

    iget-object v4, v7, Llyiahf/vczjk/oy7;->OooO0o0:Landroid/content/Context;

    if-eqz v3, :cond_6

    move-object v3, v0

    check-cast v3, Ljava/util/Collection;

    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_6

    goto :goto_8

    :cond_6
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_7
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_9

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    :try_start_0
    new-instance v7, Ljava/io/File;

    invoke-virtual {v4}, Landroid/content/Context;->getDataDir()Ljava/io/File;

    move-result-object v9

    invoke-static {v3}, Lutil/EncryptUtils;->decrypt(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    invoke-direct {v7, v9, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v7}, Ljava/io/File;->exists()Z

    move-result v3

    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_6

    :catchall_0
    move-exception v3

    invoke-static {v3}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v3

    :goto_6
    invoke-static {v3}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v7

    if-nez v7, :cond_8

    goto :goto_7

    :cond_8
    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    :goto_7
    check-cast v3, Ljava/lang/Boolean;

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    if-eqz v3, :cond_7

    goto :goto_9

    :cond_9
    :goto_8
    const-string v0, "getDataDir(...)"

    invoke-static {v4, v0}, Llyiahf/vczjk/u81;->OooOo0o(Landroid/content/Context;Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_a

    :goto_9
    move v1, v2

    :cond_a
    const-string v0, "Required value was null."

    const-string v2, "39M5DC32-B17D-4370-AB98-A9L809256685"

    if-eqz v1, :cond_c

    invoke-static {}, Lcom/tencent/mmkv/MMKV;->OooO0Oo()Lcom/tencent/mmkv/MMKV;

    move-result-object v1

    invoke-virtual {v1, v2}, Lcom/tencent/mmkv/MMKV;->OooO0OO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_b

    invoke-static {v1}, Lcom/tencent/mmkv/MMKV;->OooO(Ljava/lang/String;)Lcom/tencent/mmkv/MMKV;

    move-result-object v1

    invoke-static {v4}, Llyiahf/vczjk/on1;->OooO0O0(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v3}, Lcom/tencent/mmkv/MMKV;->OooO0o0(Ljava/lang/String;)V

    goto :goto_a

    :cond_b
    new-instance v1, Ljava/lang/IllegalArgumentException;

    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_c
    :goto_a
    sget-object v1, Llyiahf/vczjk/on1;->OooO00o:Ljava/util/Set;

    check-cast v1, Ljava/util/Collection;

    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_e

    invoke-static {v4}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v3

    if-eqz v3, :cond_e

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v3

    invoke-static {}, Lcom/tencent/mmkv/MMKV;->OooO0Oo()Lcom/tencent/mmkv/MMKV;

    move-result-object v7

    invoke-virtual {v7, v2}, Lcom/tencent/mmkv/MMKV;->OooO0OO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_d

    invoke-static {v2}, Lcom/tencent/mmkv/MMKV;->OooO(Ljava/lang/String;)Lcom/tencent/mmkv/MMKV;

    move-result-object v0

    invoke-static {v4}, Llyiahf/vczjk/on1;->OooO0O0(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Lcom/tencent/mmkv/MMKV;->OooO0O0(Ljava/lang/String;)I

    move-result v0

    const-string v2, "github.tornaco.android.thanos"

    invoke-static {v2, v0}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->newPkg(Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v0

    invoke-virtual {v3, v0}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getAppInfo(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v0

    if-eqz v0, :cond_e

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v0

    iget-object v1, v8, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v1

    const-string v2, "RunningApp detail UI forceStop"

    invoke-virtual {v0, v1, v2}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->forceStopPackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;Ljava/lang/String;)V

    goto :goto_b

    :cond_d
    new-instance v1, Ljava/lang/IllegalArgumentException;

    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_e
    :goto_b
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    check-cast v6, Llyiahf/vczjk/oe3;

    invoke-interface {v6, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v5

    :pswitch_a
    check-cast v7, Llyiahf/vczjk/ny7;

    check-cast v8, Ltornaco/apps/thanox/running/RunningAppState;

    invoke-static {v8, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v7}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/iy7;

    invoke-direct {v1, v8, v4}, Llyiahf/vczjk/iy7;-><init>(Ltornaco/apps/thanox/running/RunningAppState;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v4, v4, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    check-cast v6, Llyiahf/vczjk/oe3;

    invoke-interface {v6, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v5

    :pswitch_b
    new-instance v0, Llyiahf/vczjk/vy7;

    check-cast v8, Landroidx/appcompat/app/AppCompatActivity;

    check-cast v6, Lnow/fortuitous/thanos/process/v2/RunningProcessState;

    invoke-direct {v0, v8, v6, v4}, Llyiahf/vczjk/vy7;-><init>(Landroidx/appcompat/app/AppCompatActivity;Lnow/fortuitous/thanos/process/v2/RunningProcessState;Llyiahf/vczjk/yo1;)V

    check-cast v7, Llyiahf/vczjk/xr1;

    invoke-static {v7, v4, v4, v0, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-object v5

    :pswitch_c
    check-cast v7, Llyiahf/vczjk/km6;

    invoke-virtual {v7}, Llyiahf/vczjk/km6;->OooO0oo()I

    move-result v0

    sget-object v1, Llyiahf/vczjk/mb6;->OooO00o:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    sub-int/2addr v1, v2

    if-eq v0, v1, :cond_f

    new-instance v0, Llyiahf/vczjk/lb6;

    invoke-direct {v0, v7, v4}, Llyiahf/vczjk/lb6;-><init>(Llyiahf/vczjk/km6;Llyiahf/vczjk/yo1;)V

    check-cast v8, Llyiahf/vczjk/xr1;

    invoke-static {v8, v4, v4, v0, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_c

    :cond_f
    check-cast v6, Llyiahf/vczjk/le3;

    invoke-interface {v6}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :goto_c
    return-object v5

    :pswitch_d
    check-cast v7, Llyiahf/vczjk/zl8;

    iget-object v0, v7, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    iget-object v0, v0, Llyiahf/vczjk/c9;->OooO0Oo:Llyiahf/vczjk/oe3;

    sget-object v1, Llyiahf/vczjk/am8;->OooOOO:Llyiahf/vczjk/am8;

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_10

    new-instance v0, Llyiahf/vczjk/rk5;

    check-cast v6, Llyiahf/vczjk/zl8;

    invoke-direct {v0, v6, v4}, Llyiahf/vczjk/rk5;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/yo1;)V

    check-cast v8, Llyiahf/vczjk/xr1;

    invoke-static {v8, v4, v4, v0, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_10
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object v0

    :pswitch_e
    new-instance v0, Llyiahf/vczjk/b55;

    check-cast v8, Llyiahf/vczjk/dw4;

    check-cast v6, Llyiahf/vczjk/qs5;

    invoke-direct {v0, v8, v6, v4}, Llyiahf/vczjk/b55;-><init>(Llyiahf/vczjk/dw4;Llyiahf/vczjk/p29;Llyiahf/vczjk/yo1;)V

    check-cast v7, Llyiahf/vczjk/xr1;

    invoke-static {v7, v4, v4, v0, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-object v5

    :pswitch_f
    sget v0, Llyiahf/vczjk/xl4;->OooO00o:I

    new-instance v0, Llyiahf/vczjk/rl4;

    const-wide/16 v9, 0x0

    check-cast v8, Llyiahf/vczjk/le3;

    invoke-direct {v0, v9, v10, v8, v4}, Llyiahf/vczjk/rl4;-><init>(JLlyiahf/vczjk/le3;Llyiahf/vczjk/yo1;)V

    check-cast v7, Llyiahf/vczjk/xr1;

    invoke-static {v7, v4, v4, v0, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    const-string v0, "context"

    check-cast v6, Landroid/content/Context;

    invoke-static {v6, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Llyiahf/vczjk/xl4;->OooO00o:I

    add-int/2addr v0, v2

    sput v0, Llyiahf/vczjk/xl4;->OooO00o:I

    return-object v5

    :pswitch_10
    check-cast v7, Llyiahf/vczjk/oe3;

    check-cast v8, Llyiahf/vczjk/w03;

    invoke-interface {v7, v8}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/qs5;

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-interface {v6, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    return-object v5

    :pswitch_11
    check-cast v7, Llyiahf/vczjk/oj2;

    invoke-virtual {v7, v1}, Llyiahf/vczjk/oj2;->OooO00o(Z)V

    check-cast v8, Llyiahf/vczjk/oe3;

    check-cast v6, Llyiahf/vczjk/gj2;

    invoke-interface {v8, v6}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v5

    :pswitch_12
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    check-cast v6, Llyiahf/vczjk/qs5;

    invoke-interface {v6, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    check-cast v7, Llyiahf/vczjk/oe3;

    check-cast v8, Llyiahf/vczjk/ah5;

    invoke-interface {v7, v8}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v5

    :pswitch_13
    check-cast v7, Llyiahf/vczjk/oe3;

    invoke-interface {v7, v8}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/zh1;

    invoke-virtual {v6, v1}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    return-object v5

    :pswitch_14
    new-instance v0, Llyiahf/vczjk/c4;

    check-cast v8, Llyiahf/vczjk/dj8;

    const/16 v2, 0xe

    invoke-direct {v0, v8, v2}, Llyiahf/vczjk/c4;-><init>(Ljava/lang/Object;I)V

    check-cast v7, Llyiahf/vczjk/cp8;

    invoke-virtual {v7, v0}, Llyiahf/vczjk/cp8;->OooO0oO(Llyiahf/vczjk/ze3;)V

    new-instance v0, Llyiahf/vczjk/e2;

    check-cast v6, Landroid/content/Context;

    const/16 v2, 0x9

    invoke-direct {v0, v2, v6, v8}, Llyiahf/vczjk/e2;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    new-instance v2, Llyiahf/vczjk/bp8;

    invoke-direct {v2, v1, v7, v0}, Llyiahf/vczjk/bp8;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object v0, v7, Llyiahf/vczjk/cp8;->OooO00o:Llyiahf/vczjk/yo8;

    iput-object v2, v0, Llyiahf/vczjk/yo8;->OooO0OO:Llyiahf/vczjk/bp8;

    return-object v5

    :pswitch_15
    sget v0, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OoooO0O:I

    check-cast v6, Llyiahf/vczjk/qs5;

    invoke-interface {v6}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cr5;

    iget-boolean v0, v0, Llyiahf/vczjk/cr5;->OooO00o:Z

    if-eqz v0, :cond_12

    check-cast v7, Llyiahf/vczjk/t81;

    :cond_11
    iget-object v0, v7, Llyiahf/vczjk/t81;->OooO0oo:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/cr5;

    sget-object v4, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v3, Llyiahf/vczjk/cr5;

    invoke-direct {v3, v4, v1}, Llyiahf/vczjk/cr5;-><init>(Ljava/util/Set;Z)V

    invoke-virtual {v0, v2, v3}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_11

    goto :goto_d

    :cond_12
    check-cast v8, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;

    invoke-virtual {v8}, Landroid/app/Activity;->finish()V

    :goto_d
    return-object v5

    :pswitch_16
    sget v0, Lnow/fortuitous/thanos/launchother/AllowListActivity;->OoooO0O:I

    check-cast v6, Llyiahf/vczjk/qs5;

    invoke-interface {v6}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/t6;

    iget-object v0, v0, Llyiahf/vczjk/t6;->OooO0O0:Ljava/util/List;

    new-instance v1, Ljava/util/ArrayList;

    const/16 v2, 0xa

    invoke-static {v0, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_e
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_13

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v2}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_e

    :cond_13
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    sget v1, Lgithub/tornaco/android/thanos/picker/AppPickerActivity;->o000oOoO:I

    new-instance v1, Landroid/content/Intent;

    const-class v2, Lgithub/tornaco/android/thanos/picker/AppPickerActivity;

    check-cast v8, Landroid/content/Context;

    invoke-direct {v1, v8, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    new-instance v2, Landroid/os/Bundle;

    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    const-string v3, "github.tornaco.android.thanos.picker.extra.EXTRA_EXCLUDE_PKGS"

    invoke-virtual {v2, v3, v0}, Landroid/os/Bundle;->putParcelableArrayList(Ljava/lang/String;Ljava/util/ArrayList;)V

    invoke-virtual {v1, v2}, Landroid/content/Intent;->putExtras(Landroid/os/Bundle;)Landroid/content/Intent;

    check-cast v7, Llyiahf/vczjk/wa5;

    invoke-virtual {v7, v1}, Llyiahf/vczjk/wa5;->OooO00o(Ljava/lang/Object;)V

    return-object v5

    :pswitch_17
    check-cast v6, Llyiahf/vczjk/qs5;

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-interface {v6, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    check-cast v7, Llyiahf/vczjk/oe3;

    check-cast v8, Llyiahf/vczjk/ww2;

    invoke-interface {v7, v8}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v5

    :pswitch_18
    check-cast v6, Llyiahf/vczjk/qs5;

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-interface {v6, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    check-cast v7, Llyiahf/vczjk/xn6;

    invoke-virtual {v7}, Llyiahf/vczjk/xn6;->OooO0Oo()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/oe3;

    check-cast v8, Landroidx/appcompat/app/AppCompatActivity;

    invoke-interface {v0, v8}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v5

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
