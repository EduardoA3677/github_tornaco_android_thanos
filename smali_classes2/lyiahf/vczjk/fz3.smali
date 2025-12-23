.class public final synthetic Llyiahf/vczjk/fz3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/fz3;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/fz3;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 6

    const/4 v0, 0x0

    const/4 v1, 0x1

    const/4 v2, 0x3

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v4, p0, Llyiahf/vczjk/fz3;->OooOOO:Ljava/lang/Object;

    iget v5, p0, Llyiahf/vczjk/fz3;->OooOOO0:I

    packed-switch v5, :pswitch_data_0

    sget v0, Lnow/fortuitous/thanos/recovery/RecoveryUtilsActivity;->OoooO0O:I

    check-cast v4, Lnow/fortuitous/thanos/recovery/RecoveryUtilsActivity;

    invoke-virtual {v4}, Landroid/app/Activity;->finish()V

    return-object v3

    :pswitch_0
    sget v0, Lgithub/tornaco/thanos/android/module/profile/example/ProfileExampleActivity;->OoooO0O:I

    check-cast v4, Lgithub/tornaco/thanos/android/module/profile/example/ProfileExampleActivity;

    invoke-virtual {v4}, Landroid/app/Activity;->finish()V

    return-object v3

    :pswitch_1
    check-cast v4, Llyiahf/vczjk/a77;

    invoke-virtual {v4}, Llyiahf/vczjk/a77;->OooO()V

    return-object v3

    :pswitch_2
    check-cast v4, Lnow/fortuitous/thanos/process/v2/ProcessManageActivityV2;

    invoke-virtual {v4}, Landroid/app/Activity;->finish()V

    return-object v3

    :pswitch_3
    sget v0, Ltornaco/apps/thanox/picker/PkgPickerActivity;->OoooO0O:I

    check-cast v4, Ltornaco/apps/thanox/picker/PkgPickerActivity;

    invoke-virtual {v4}, Landroid/app/Activity;->finish()V

    return-object v3

    :pswitch_4
    check-cast v4, Llyiahf/vczjk/pu6;

    iget-object v0, v4, Llyiahf/vczjk/pu6;->OooO0o0:Landroid/content/Context;

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    return-object v0

    :pswitch_5
    sget v0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PinSettingsActivity;->OoooO0O:I

    check-cast v4, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PinSettingsActivity;

    invoke-virtual {v4}, Landroid/app/Activity;->finish()V

    return-object v3

    :pswitch_6
    check-cast v4, Llyiahf/vczjk/vr6;

    iget-object v0, v4, Llyiahf/vczjk/vr6;->OooO0o0:Landroid/content/Context;

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    return-object v0

    :pswitch_7
    sget v0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PatternSettingsActivity;->OoooO0O:I

    check-cast v4, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PatternSettingsActivity;

    invoke-virtual {v4}, Landroid/app/Activity;->finish()V

    return-object v3

    :pswitch_8
    check-cast v4, Llyiahf/vczjk/cf6;

    iget-object v0, v4, Llyiahf/vczjk/cf6;->OooO0O0:Landroid/content/Context;

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getOpsManager()Lgithub/tornaco/android/thanos/core/ops/OpsManager;

    move-result-object v0

    return-object v0

    :pswitch_9
    check-cast v4, Llyiahf/vczjk/ue6;

    invoke-virtual {v4}, Llyiahf/vczjk/td9;->OooOOO0()Landroid/content/Context;

    move-result-object v0

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/ServicesKt;->getAppOpsManager(Landroid/content/Context;)Landroid/app/AppOpsManager;

    move-result-object v0

    return-object v0

    :pswitch_a
    sget v0, Lgithub/tornaco/thanos/android/ops2/byop/Ops2Activity;->OoooO0O:I

    check-cast v4, Lgithub/tornaco/thanos/android/ops2/byop/Ops2Activity;

    invoke-virtual {v4}, Landroid/app/Activity;->finish()V

    return-object v3

    :pswitch_b
    new-instance v0, Lgithub/tornaco/android/thanos/core/app/AppResources;

    check-cast v4, Llyiahf/vczjk/rc6;

    iget-object v1, v4, Llyiahf/vczjk/rc6;->OooO00o:Landroid/content/Context;

    const-string v2, "github.tornaco.android.thanos"

    invoke-direct {v0, v1, v2}, Lgithub/tornaco/android/thanos/core/app/AppResources;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    return-object v0

    :pswitch_c
    check-cast v4, Llyiahf/vczjk/ec6;

    iget-object v0, v4, Llyiahf/vczjk/ec6;->OooO00o:Landroid/content/Context;

    new-instance v0, Llyiahf/vczjk/d96;

    invoke-direct {v0}, Llyiahf/vczjk/d96;-><init>()V

    new-instance v3, Llyiahf/vczjk/um0;

    invoke-direct {v3, v2}, Llyiahf/vczjk/um0;-><init>(I)V

    iget-object v2, v0, Llyiahf/vczjk/d96;->OooO0OO:Ljava/util/ArrayList;

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v2, Llyiahf/vczjk/e96;

    invoke-direct {v2, v0}, Llyiahf/vczjk/e96;-><init>(Llyiahf/vczjk/d96;)V

    new-instance v0, Llyiahf/vczjk/pb7;

    invoke-direct {v0, v1}, Llyiahf/vczjk/pb7;-><init>(I)V

    const-string v3, "https://api.github.com"

    invoke-virtual {v0, v3}, Llyiahf/vczjk/pb7;->OooO(Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/pk3;->OooO0OO()Llyiahf/vczjk/pk3;

    move-result-object v3

    invoke-virtual {v0, v3}, Llyiahf/vczjk/pb7;->OooO0O0(Llyiahf/vczjk/pk3;)V

    new-instance v3, Llyiahf/vczjk/a61;

    invoke-direct {v3, v1}, Llyiahf/vczjk/a61;-><init>(I)V

    iget-object v1, v0, Llyiahf/vczjk/pb7;->OooOOo0:Ljava/lang/Object;

    check-cast v1, Ljava/util/ArrayList;

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iput-object v2, v0, Llyiahf/vczjk/pb7;->OooOOO:Ljava/lang/Object;

    invoke-virtual {v0}, Llyiahf/vczjk/pb7;->OooOO0()Llyiahf/vczjk/mi;

    move-result-object v0

    const-class v1, Llyiahf/vczjk/fc6;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/mi;->OooO0oO(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v0

    const-string v1, "create(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/fc6;

    return-object v0

    :pswitch_d
    sget v0, Lgithub/tornaco/thanos/android/module/profile/online/OnlineProfileActivity;->OoooO0O:I

    check-cast v4, Lgithub/tornaco/thanos/android/module/profile/online/OnlineProfileActivity;

    invoke-virtual {v4}, Landroid/app/Activity;->finish()V

    return-object v3

    :pswitch_e
    sget v0, Lnow/fortuitous/thanos/main/OneKeyBoostSettingsActivity;->Oooo0oo:I

    check-cast v4, Lnow/fortuitous/thanos/main/OneKeyBoostSettingsActivity;

    invoke-virtual {v4}, Landroid/app/Activity;->finish()V

    return-object v3

    :pswitch_f
    sget v0, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;->OoooO00:I

    check-cast v4, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;

    new-instance v0, Llyiahf/vczjk/r36;

    invoke-direct {v0, v4, v4}, Llyiahf/vczjk/r36;-><init>(Lgithub/tornaco/android/thanox/module/notification/recorder/ui/NotificationRecordActivity;Llyiahf/vczjk/h68;)V

    return-object v0

    :pswitch_10
    sget v0, Lgithub/tornaco/thanos/android/module/profile/engine/NewRegularIntervalActivity;->OoooO0O:I

    check-cast v4, Lgithub/tornaco/thanos/android/module/profile/engine/NewRegularIntervalActivity;

    invoke-virtual {v4}, Landroid/app/Activity;->finish()V

    return-object v3

    :pswitch_11
    check-cast v4, Ljava/lang/String;

    new-instance v0, Llyiahf/vczjk/yu5;

    invoke-direct {v0, v4}, Llyiahf/vczjk/yu5;-><init>(Ljava/lang/String;)V

    return-object v0

    :pswitch_12
    check-cast v4, Llyiahf/vczjk/ku5;

    iget-object v0, v4, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    iget-boolean v1, v0, Llyiahf/vczjk/mu5;->OooO:Z

    if-eqz v1, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/mu5;->OooOO0:Llyiahf/vczjk/wy4;

    iget-object v1, v1, Llyiahf/vczjk/wy4;->OooO0Oo:Llyiahf/vczjk/jy4;

    sget-object v2, Llyiahf/vczjk/jy4;->OooOOO0:Llyiahf/vczjk/jy4;

    if-eq v1, v2, :cond_0

    iget-object v1, v0, Llyiahf/vczjk/mu5;->OooOOO0:Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/hha;

    iget-object v0, v0, Llyiahf/vczjk/mu5;->OooO00o:Llyiahf/vczjk/ku5;

    const/4 v2, 0x4

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/uk2;->o0000oo(Llyiahf/vczjk/lha;Llyiahf/vczjk/hha;I)Llyiahf/vczjk/tg7;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    const-class v2, Llyiahf/vczjk/lu5;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/tg7;->OooOoOO(Llyiahf/vczjk/gf4;)Llyiahf/vczjk/dha;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/lu5;

    iget-object v0, v0, Llyiahf/vczjk/lu5;->OooO0O0:Llyiahf/vczjk/x58;

    return-object v0

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "You cannot access the NavBackStackEntry\'s SavedStateHandle after the NavBackStackEntry is destroyed."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "You cannot access the NavBackStackEntry\'s SavedStateHandle until it is added to the NavController\'s back stack (i.e., the Lifecycle of the NavBackStackEntry reaches the CREATED state)."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :pswitch_13
    check-cast v4, Llyiahf/vczjk/yj5;

    iget-object v0, v4, Llyiahf/vczjk/yj5;->OooOOOo:Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    return-object v3

    :pswitch_14
    check-cast v4, Llyiahf/vczjk/xn6;

    invoke-virtual {v4}, Llyiahf/vczjk/xn6;->OooO0Oo()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    return-object v3

    :pswitch_15
    check-cast v4, Llyiahf/vczjk/ua5;

    invoke-static {v4}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/ia5;

    const/4 v5, 0x0

    invoke-direct {v1, v4, v5}, Llyiahf/vczjk/ia5;-><init>(Llyiahf/vczjk/ua5;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v5, v5, v1, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-object v3

    :pswitch_16
    sget v0, Lgithub/tornaco/thanos/android/module/profile/LogActivity;->OoooO0O:I

    check-cast v4, Lgithub/tornaco/thanos/android/module/profile/LogActivity;

    invoke-virtual {v4}, Landroid/app/Activity;->finish()V

    return-object v3

    :pswitch_17
    const-string v1, "LiveDanmu onEmpty"

    invoke-static {v1}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    check-cast v4, Llyiahf/vczjk/i25;

    iget-boolean v1, v4, Llyiahf/vczjk/i25;->OooOOOO:Z

    if-eqz v1, :cond_2

    invoke-virtual {v4}, Landroid/view/View;->isAttachedToWindow()Z

    move-result v1

    if-eqz v1, :cond_2

    const-string v1, "LiveDanmu detach"

    invoke-static {v1}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    :try_start_0
    iput-boolean v0, v4, Llyiahf/vczjk/i25;->OooOOOO:Z

    iget-object v0, v4, Llyiahf/vczjk/i25;->OooOOO:Landroid/view/WindowManager;

    invoke-interface {v0, v4}, Landroid/view/WindowManager;->removeViewImmediate(Landroid/view/View;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    const-string v1, "LiveDanmu, fail detach: "

    invoke-static {v1, v0}, Llyiahf/vczjk/zsa;->Oooo0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    :cond_2
    :goto_0
    return-object v3

    :pswitch_18
    sget v0, Lnow/fortuitous/thanos/launchother/LaunchOtherAppRuleActivity;->OoooO0O:I

    check-cast v4, Lnow/fortuitous/thanos/launchother/LaunchOtherAppRuleActivity;

    invoke-virtual {v4}, Landroid/app/Activity;->finish()V

    return-object v3

    :pswitch_19
    sget v0, Lnow/fortuitous/thanos/launchother/LaunchOtherAppAskActivity;->Oooo0oO:I

    check-cast v4, Lnow/fortuitous/thanos/launchother/LaunchOtherAppAskActivity;

    invoke-static {v4}, Llyiahf/vczjk/yh1;->OooO00o(Landroid/app/Activity;)V

    const/4 v0, -0x1

    invoke-virtual {v4, v0}, Landroid/app/Activity;->setResult(I)V

    invoke-virtual {v4}, Landroid/app/Activity;->finish()V

    return-object v3

    :pswitch_1a
    sget v0, Lgithub/tornaco/android/thanos/support/subscribe/LVLCheckActivity;->OoooO0O:I

    check-cast v4, Lgithub/tornaco/android/thanos/support/subscribe/LVLCheckActivity;

    invoke-virtual {v4}, Landroid/app/Activity;->finish()V

    return-object v3

    :pswitch_1b
    check-cast v4, Lgithub/tornaco/android/thanos/core/app/infinite/IEnableCallback;

    if-eqz v4, :cond_3

    const-string v1, "Fail create user profile."

    invoke-interface {v4, v1, v0}, Lgithub/tornaco/android/thanos/core/app/infinite/IEnableCallback;->onError(Ljava/lang/String;I)V

    :cond_3
    return-object v3

    :pswitch_1c
    check-cast v4, Lgithub/tornaco/android/thanos/core/app/infinite/IRemovePackageCallback;

    if-eqz v4, :cond_4

    invoke-interface {v4}, Lgithub/tornaco/android/thanos/core/app/infinite/IRemovePackageCallback;->onSuccess()V

    :cond_4
    return-object v3

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
