.class public final synthetic Llyiahf/vczjk/r07;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/r07;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    const/4 v0, 0x1

    const-string v1, ""

    const/4 v2, 0x0

    const-string v3, "getString(...)"

    const/4 v4, 0x0

    sget-object v5, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const-string v6, "it"

    iget v7, p0, Llyiahf/vczjk/r07;->OooOOO0:I

    packed-switch v7, :pswitch_data_0

    check-cast p1, Landroid/os/ParcelFileDescriptor;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/km8;->OooO00o:Llyiahf/vczjk/km8;

    invoke-static {}, Llyiahf/vczjk/km8;->OooO00o()Llyiahf/vczjk/nm8;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/nm8;->OooO0O0:Lgithub/tornaco/android/thanos/core/IThanosLite;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, Lgithub/tornaco/android/thanos/core/IThanosLite;->writeLogsTo(Landroid/os/ParcelFileDescriptor;)V

    :cond_0
    return-object v5

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/z8a;

    const-string p1, "Dark mode"

    return-object p1

    :pswitch_1
    check-cast p1, Ljava/lang/String;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_2
    check-cast p1, Ljava/lang/String;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_3
    check-cast p1, Ljava/lang/String;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v5

    :pswitch_4
    check-cast p1, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;

    if-eqz p1, :cond_1

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;->getTitle()Ljava/lang/String;

    move-result-object v2

    :cond_1
    if-nez v2, :cond_2

    goto :goto_0

    :cond_2
    move-object v1, v2

    :goto_0
    return-object v1

    :pswitch_5
    if-nez p1, :cond_3

    goto :goto_1

    :cond_3
    move v0, v4

    :goto_1
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    :pswitch_6
    return-object p1

    :pswitch_7
    check-cast p1, Llyiahf/vczjk/wf8;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Llyiahf/vczjk/wf8;->iterator()Ljava/util/Iterator;

    move-result-object p1

    return-object p1

    :pswitch_8
    check-cast p1, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getVersionName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getState()I

    move-result v2

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result p1

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_9
    check-cast p1, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getVersionName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getState()I

    move-result v2

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result p1

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_a
    check-cast p1, Llyiahf/vczjk/nw7;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v5

    :pswitch_b
    check-cast p1, Llyiahf/vczjk/nw7;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :pswitch_c
    check-cast p1, Ljava/lang/String;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v5

    :pswitch_d
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/db/profile/RuleDao_Impl;->OooO0OO(Llyiahf/vczjk/j48;)Ljava/util/List;

    move-result-object p1

    return-object p1

    :pswitch_e
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/db/profile/RuleDao_Impl;->OooO0O0(Llyiahf/vczjk/j48;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_f
    check-cast p1, Ljava/lang/String;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "["

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, "]"

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_10
    check-cast p1, Llyiahf/vczjk/jd5;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/jd5;->OooO00o:Ljava/util/regex/Matcher;

    invoke-virtual {p1}, Ljava/util/regex/Matcher;->group()Ljava/lang/String;

    move-result-object p1

    const-string v0, "group(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "globalVarOf$"

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/g79;->Oooo000(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_11
    check-cast p1, Ljava/lang/Float;

    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    move-result p1

    mul-float v0, p1, p1

    mul-float/2addr v0, p1

    mul-float/2addr v0, p1

    mul-float/2addr v0, p1

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p1

    return-object p1

    :pswitch_12
    check-cast p1, Ljava/lang/Float;

    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    move-result p1

    int-to-float v0, v0

    sub-float p1, v0, p1

    mul-float v1, p1, p1

    mul-float/2addr v1, p1

    mul-float/2addr v1, p1

    sub-float/2addr v0, v1

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p1

    return-object p1

    :pswitch_13
    check-cast p1, Ljava/lang/String;

    sget v0, Lnow/fortuitous/thanos/recovery/RecoveryUtilsActivity;->OoooO0O:I

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_14
    check-cast p1, Llyiahf/vczjk/uj4;

    const/16 v0, 0x1770

    iput v0, p1, Llyiahf/vczjk/uj4;->OooO00o:I

    const/high16 v1, 0x42b40000    # 90.0f

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    const/16 v3, 0x12c

    invoke-virtual {p1, v3, v2}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/cp5;->OooO0O0:Llyiahf/vczjk/cu1;

    iput-object v3, v2, Llyiahf/vczjk/tj4;->OooO0O0:Llyiahf/vczjk/ik2;

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    const/16 v2, 0x5dc

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    const/high16 v1, 0x43340000    # 180.0f

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    const/16 v3, 0x708

    invoke-virtual {p1, v3, v2}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    const/16 v2, 0xbb8

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    const/high16 v1, 0x43870000    # 270.0f

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    const/16 v3, 0xce4

    invoke-virtual {p1, v3, v2}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    const/16 v2, 0x1194

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    const/high16 v1, 0x43b40000    # 360.0f

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    const/16 v3, 0x12c0

    invoke-virtual {p1, v3, v2}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    return-object v5

    :pswitch_15
    check-cast p1, Llyiahf/vczjk/nw7;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Llyiahf/vczjk/nw7;->getName()Ljava/lang/String;

    move-result-object p1

    const-string v0, "addRuleIfNotExists, ignore: "

    invoke-static {v0, p1}, Llyiahf/vczjk/u81;->OooOo0(Ljava/lang/String;Ljava/lang/String;)V

    return-object v5

    :pswitch_16
    check-cast p1, Llyiahf/vczjk/v74;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :try_start_0
    invoke-interface {p1, v2}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_2

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    :goto_2
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    instance-of v1, p1, Llyiahf/vczjk/ts7;

    if-eqz v1, :cond_4

    move-object p1, v0

    :cond_4
    check-cast p1, Ljava/lang/Boolean;

    return-object p1

    :pswitch_17
    check-cast p1, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v5

    :pswitch_18
    check-cast p1, Ljava/lang/Throwable;

    invoke-static {p1}, Landroid/util/Log;->getStackTraceString(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    return-object v5

    :pswitch_19
    check-cast p1, Lgithub/tornaco/android/thanos/core/app/AppResources;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-array v0, v4, [Ljava/lang/Object;

    const-string v1, "service_app_set_3rd"

    invoke-virtual {p1, v1, v0}, Lgithub/tornaco/android/thanos/core/app/AppResources;->getString(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_1a
    check-cast p1, Lgithub/tornaco/android/thanos/core/app/AppResources;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-array v0, v4, [Ljava/lang/Object;

    const-string v1, "service_app_set_white_listed"

    invoke-virtual {p1, v1, v0}, Lgithub/tornaco/android/thanos/core/app/AppResources;->getString(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_1b
    check-cast p1, Lgithub/tornaco/android/thanos/core/app/AppResources;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-array v0, v4, [Ljava/lang/Object;

    const-string v1, "service_app_set_system"

    invoke-virtual {p1, v1, v0}, Lgithub/tornaco/android/thanos/core/app/AppResources;->getString(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_1c
    check-cast p1, Lgithub/tornaco/android/thanos/core/app/AppResources;

    invoke-static {p1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-array v0, v4, [Ljava/lang/Object;

    const-string v1, "service_app_set_shortcut_proxy"

    invoke-virtual {p1, v1, v0}, Lgithub/tornaco/android/thanos/core/app/AppResources;->getString(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
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
