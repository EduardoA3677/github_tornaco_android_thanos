.class public final synthetic Llyiahf/vczjk/xm8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/xm8;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    const-string v0, "%02d"

    const/4 v1, 0x0

    const-string v2, "it"

    const/4 v3, 0x1

    sget-object v4, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget v5, p0, Llyiahf/vczjk/xm8;->OooOOO0:I

    packed-switch v5, :pswitch_data_0

    check-cast p1, Ljava/util/List;

    new-instance v0, Llyiahf/vczjk/kx9;

    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    invoke-interface {p1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    move-result v2

    const/4 v3, 0x2

    invoke-interface {p1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    invoke-direct {v0, v1, v2, p1}, Llyiahf/vczjk/kx9;-><init>(FFF)V

    return-object v0

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/af8;

    invoke-static {p1, v3}, Llyiahf/vczjk/ye8;->OooO0o(Llyiahf/vczjk/af8;I)V

    return-object v4

    :pswitch_1
    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    invoke-static {v0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_2
    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    invoke-static {v0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :pswitch_3
    check-cast p1, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :pswitch_4
    check-cast p1, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :pswitch_5
    check-cast p1, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1

    :pswitch_6
    check-cast p1, Landroid/content/Context;

    sget v0, Lnow/fortuitous/thanos/ThanosApp;->OooOOOO:I

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/support/subscribe/SubscribeActivity;->OoooO0O:I

    new-instance v0, Landroid/content/Intent;

    const-class v1, Lgithub/tornaco/android/thanos/support/subscribe/SubscribeActivity;

    invoke-direct {v0, p1, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    invoke-virtual {p1, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    return-object v4

    :pswitch_7
    check-cast p1, Ljava/lang/Throwable;

    sget v0, Lnow/fortuitous/thanos/ThanosApp;->OooOOOO:I

    const-string v0, "\n"

    invoke-static {v0}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    const-string v1, "==== App un-handled error, please file a bug ===="

    invoke-static {v1}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Oooo0oO(Ljava/lang/Throwable;)V

    invoke-static {v0}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    return-object v4

    :pswitch_8
    check-cast p1, Llyiahf/vczjk/mm9;

    sget-object p1, Llyiahf/vczjk/gm9;->OooO00o:Llyiahf/vczjk/jh1;

    return-object v4

    :pswitch_9
    check-cast p1, Ljava/lang/String;

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result p1

    if-lez p1, :cond_0

    move v1, v3

    :cond_0
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/xn6;

    const-string v1, ""

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    return-object v0

    :pswitch_a
    check-cast p1, Llyiahf/vczjk/af8;

    sget-object v0, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v0, Llyiahf/vczjk/ve8;->OooOO0o:Llyiahf/vczjk/ze8;

    sget-object v1, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/4 v2, 0x5

    aget-object v1, v1, v2

    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    return-object v4

    :pswitch_b
    check-cast p1, Ljava/lang/String;

    const-string p1, "Pay"

    return-object p1

    :pswitch_c
    check-cast p1, Llyiahf/vczjk/iu0;

    sget v0, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/stats/StatsActivity;->OoooO0O:I

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v4

    :pswitch_d
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;->OooO0oO(Llyiahf/vczjk/j48;)Ljava/util/List;

    move-result-object p1

    return-object p1

    :pswitch_e
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;->OooO0o(Llyiahf/vczjk/j48;)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :pswitch_f
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;->OooO0oo(Llyiahf/vczjk/j48;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_10
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;->OooO00o(Llyiahf/vczjk/j48;)Ljava/util/List;

    move-result-object p1

    return-object p1

    :pswitch_11
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;->OooO0o0(Llyiahf/vczjk/j48;)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :pswitch_12
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;->OooO0OO(Llyiahf/vczjk/j48;)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :pswitch_13
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;->OooOOo0(Llyiahf/vczjk/j48;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_14
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;->OooO(Llyiahf/vczjk/j48;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_15
    check-cast p1, Llyiahf/vczjk/af8;

    invoke-static {p1, v1}, Llyiahf/vczjk/ye8;->OooO0o(Llyiahf/vczjk/af8;I)V

    return-object v4

    :pswitch_16
    check-cast p1, Llyiahf/vczjk/af8;

    invoke-static {p1, v1}, Llyiahf/vczjk/ye8;->OooO0o(Llyiahf/vczjk/af8;I)V

    return-object v4

    :pswitch_17
    check-cast p1, Lde/robv/android/xposed/XC_MethodHook$MethodHookParam;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/xposed/hooks/s/pm/ShortcutHook;->OooO0oo(Lde/robv/android/xposed/XC_MethodHook$MethodHookParam;)Llyiahf/vczjk/z8a;

    move-result-object p1

    return-object p1

    :pswitch_18
    check-cast p1, Ljava/lang/String;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/xposed/hooks/s/pm/ShortcutHook;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/z8a;

    move-result-object p1

    return-object p1

    :pswitch_19
    check-cast p1, Lde/robv/android/xposed/XC_MethodHook$MethodHookParam;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/xposed/hooks/s/pm/ShortcutHook;->OooO0O0(Lde/robv/android/xposed/XC_MethodHook$MethodHookParam;)Llyiahf/vczjk/z8a;

    move-result-object p1

    return-object p1

    :pswitch_1a
    check-cast p1, Ljava/lang/String;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/xposed/hooks/s/pm/ShortcutHook;->OooO0Oo(Ljava/lang/String;)Llyiahf/vczjk/z8a;

    move-result-object p1

    return-object p1

    :pswitch_1b
    check-cast p1, Lde/robv/android/xposed/XC_MethodHook$MethodHookParam;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/xposed/hooks/s/pm/ShortcutHook;->OooO0OO(Lde/robv/android/xposed/XC_MethodHook$MethodHookParam;)Llyiahf/vczjk/z8a;

    move-result-object p1

    return-object p1

    :pswitch_1c
    check-cast p1, Ljava/lang/String;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/services/xposed/hooks/s/pm/ShortcutHook;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/z8a;

    move-result-object p1

    return-object p1

    nop

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
