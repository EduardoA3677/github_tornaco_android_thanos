.class public final Llyiahf/vczjk/pq;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/qa6;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Landroidx/appcompat/app/AppCompatActivity;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/app/AppCompatActivity;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/pq;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Landroidx/activity/ComponentActivity;)V
    .locals 2

    iget p1, p0, Llyiahf/vczjk/pq;->OooO00o:I

    packed-switch p1, :pswitch_data_0

    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Ltornaco/apps/thanox/Hilt_ThanosShizukuMainActivity;

    iget-boolean v0, p1, Ltornaco/apps/thanox/Hilt_ThanosShizukuMainActivity;->OoooO0:Z

    if-nez v0, :cond_0

    const/4 v0, 0x1

    iput-boolean v0, p1, Ltornaco/apps/thanox/Hilt_ThanosShizukuMainActivity;->OoooO0:Z

    invoke-virtual {p1}, Ltornaco/apps/thanox/Hilt_ThanosShizukuMainActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/vo9;

    check-cast p1, Ltornaco/apps/thanox/ThanosShizukuMainActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_0
    return-void

    :pswitch_0
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/android/thanos/support/subscribe/Hilt_SubscribeActivity;

    iget-boolean v0, p1, Lgithub/tornaco/android/thanos/support/subscribe/Hilt_SubscribeActivity;->OoooO0:Z

    if-nez v0, :cond_1

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/android/thanos/support/subscribe/Hilt_SubscribeActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/support/subscribe/Hilt_SubscribeActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/i89;

    check-cast p1, Lgithub/tornaco/android/thanos/support/subscribe/SubscribeActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_1
    return-void

    :pswitch_1
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/stats/Hilt_StatsActivity;

    iget-boolean v0, p1, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/stats/Hilt_StatsActivity;->OoooO0:Z

    if-nez v0, :cond_2

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/stats/Hilt_StatsActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/stats/Hilt_StatsActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/q39;

    check-cast p1, Lgithub/tornaco/android/thanox/module/notification/recorder/ui/stats/StatsActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_2
    return-void

    :pswitch_2
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lnow/fortuitous/thanos/sf/Hilt_SFActivity;

    iget-boolean v0, p1, Lnow/fortuitous/thanos/sf/Hilt_SFActivity;->OoooO0:Z

    if-nez v0, :cond_3

    const/4 v0, 0x1

    iput-boolean v0, p1, Lnow/fortuitous/thanos/sf/Hilt_SFActivity;->OoooO0:Z

    invoke-virtual {p1}, Lnow/fortuitous/thanos/sf/Hilt_SFActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/oz7;

    check-cast p1, Lnow/fortuitous/thanos/sf/SFActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_3
    return-void

    :pswitch_3
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lnow/fortuitous/thanos/process/v2/Hilt_RunningAppStateDetailsActivity;

    iget-boolean v0, p1, Lnow/fortuitous/thanos/process/v2/Hilt_RunningAppStateDetailsActivity;->OoooO0:Z

    if-nez v0, :cond_4

    const/4 v0, 0x1

    iput-boolean v0, p1, Lnow/fortuitous/thanos/process/v2/Hilt_RunningAppStateDetailsActivity;->OoooO0:Z

    invoke-virtual {p1}, Lnow/fortuitous/thanos/process/v2/Hilt_RunningAppStateDetailsActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ry7;

    check-cast p1, Lnow/fortuitous/thanos/process/v2/RunningAppStateDetailsActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_4
    return-void

    :pswitch_4
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Ltornaco/apps/thanox/running/detail/Hilt_RunningAppStateDetailsActivity;

    iget-boolean v0, p1, Ltornaco/apps/thanox/running/detail/Hilt_RunningAppStateDetailsActivity;->OoooO0:Z

    if-nez v0, :cond_5

    const/4 v0, 0x1

    iput-boolean v0, p1, Ltornaco/apps/thanox/running/detail/Hilt_RunningAppStateDetailsActivity;->OoooO0:Z

    invoke-virtual {p1}, Ltornaco/apps/thanox/running/detail/Hilt_RunningAppStateDetailsActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/qy7;

    check-cast p1, Ltornaco/apps/thanox/running/detail/RunningAppStateDetailsActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_5
    return-void

    :pswitch_5
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lnow/fortuitous/thanos/recovery/Hilt_RecoveryUtilsActivity;

    iget-boolean v0, p1, Lnow/fortuitous/thanos/recovery/Hilt_RecoveryUtilsActivity;->OoooO0:Z

    if-nez v0, :cond_6

    const/4 v0, 0x1

    iput-boolean v0, p1, Lnow/fortuitous/thanos/recovery/Hilt_RecoveryUtilsActivity;->OoooO0:Z

    invoke-virtual {p1}, Lnow/fortuitous/thanos/recovery/Hilt_RecoveryUtilsActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/uj7;

    check-cast p1, Lnow/fortuitous/thanos/recovery/RecoveryUtilsActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_6
    return-void

    :pswitch_6
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/example/Hilt_ProfileExampleActivity;

    iget-boolean v0, p1, Lgithub/tornaco/thanos/android/module/profile/example/Hilt_ProfileExampleActivity;->OoooO0:Z

    if-nez v0, :cond_7

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/thanos/android/module/profile/example/Hilt_ProfileExampleActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/thanos/android/module/profile/example/Hilt_ProfileExampleActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/a87;

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/example/ProfileExampleActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_7
    return-void

    :pswitch_7
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lnow/fortuitous/thanos/process/v2/Hilt_ProcessManageActivityV2;

    iget-boolean v0, p1, Lnow/fortuitous/thanos/process/v2/Hilt_ProcessManageActivityV2;->OoooO0:Z

    if-nez v0, :cond_8

    const/4 v0, 0x1

    iput-boolean v0, p1, Lnow/fortuitous/thanos/process/v2/Hilt_ProcessManageActivityV2;->OoooO0:Z

    invoke-virtual {p1}, Lnow/fortuitous/thanos/process/v2/Hilt_ProcessManageActivityV2;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/h57;

    check-cast p1, Lnow/fortuitous/thanos/process/v2/ProcessManageActivityV2;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_8
    return-void

    :pswitch_8
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Ltornaco/apps/thanox/picker/Hilt_PkgPickerActivity;

    iget-boolean v0, p1, Ltornaco/apps/thanox/picker/Hilt_PkgPickerActivity;->OoooO0:Z

    if-nez v0, :cond_9

    const/4 v0, 0x1

    iput-boolean v0, p1, Ltornaco/apps/thanox/picker/Hilt_PkgPickerActivity;->OoooO0:Z

    invoke-virtual {p1}, Ltornaco/apps/thanox/picker/Hilt_PkgPickerActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/wv6;

    check-cast p1, Ltornaco/apps/thanox/picker/PkgPickerActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_9
    return-void

    :pswitch_9
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/Hilt_PinSettingsActivity;

    iget-boolean v0, p1, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/Hilt_PinSettingsActivity;->OoooO0:Z

    if-nez v0, :cond_a

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/Hilt_PinSettingsActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/Hilt_PinSettingsActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ju6;

    check-cast p1, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PinSettingsActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_a
    return-void

    :pswitch_a
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/Hilt_PatternSettingsActivity;

    iget-boolean v0, p1, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/Hilt_PatternSettingsActivity;->OoooO0:Z

    if-nez v0, :cond_b

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/Hilt_PatternSettingsActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/Hilt_PatternSettingsActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/pr6;

    check-cast p1, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PatternSettingsActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_b
    return-void

    :pswitch_b
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/thanos/android/ops2/byop/Hilt_Ops2Activity;

    iget-boolean v0, p1, Lgithub/tornaco/thanos/android/ops2/byop/Hilt_Ops2Activity;->OoooO0:Z

    if-nez v0, :cond_c

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/thanos/android/ops2/byop/Hilt_Ops2Activity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/thanos/android/ops2/byop/Hilt_Ops2Activity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/je6;

    check-cast p1, Lgithub/tornaco/thanos/android/ops2/byop/Ops2Activity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_c
    return-void

    :pswitch_c
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/online/Hilt_OnlineProfileActivity;

    iget-boolean v0, p1, Lgithub/tornaco/thanos/android/module/profile/online/Hilt_OnlineProfileActivity;->OoooO0:Z

    if-nez v0, :cond_d

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/thanos/android/module/profile/online/Hilt_OnlineProfileActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/thanos/android/module/profile/online/Hilt_OnlineProfileActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/bc6;

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/online/OnlineProfileActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_d
    return-void

    :pswitch_d
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;

    iget-boolean v0, p1, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;->OoooO0:Z

    if-nez v0, :cond_e

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/a16;

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/engine/NewRegularIntervalActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_e
    return-void

    :pswitch_e
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lnow/fortuitous/thanos/main/Hilt_NavActivity;

    iget-boolean v0, p1, Lnow/fortuitous/thanos/main/Hilt_NavActivity;->OoooO0:Z

    if-nez v0, :cond_f

    const/4 v0, 0x1

    iput-boolean v0, p1, Lnow/fortuitous/thanos/main/Hilt_NavActivity;->OoooO0:Z

    invoke-virtual {p1}, Lnow/fortuitous/thanos/main/Hilt_NavActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ju5;

    check-cast p1, Lnow/fortuitous/thanos/main/NavActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_f
    return-void

    :pswitch_f
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/Hilt_LogActivity;

    iget-boolean v0, p1, Lgithub/tornaco/thanos/android/module/profile/Hilt_LogActivity;->OoooO0:Z

    if-nez v0, :cond_10

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/thanos/android/module/profile/Hilt_LogActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/thanos/android/module/profile/Hilt_LogActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/e55;

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/LogActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_10
    return-void

    :pswitch_10
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lnow/fortuitous/thanos/launchother/Hilt_LaunchOtherAppRuleActivity;

    iget-boolean v0, p1, Lnow/fortuitous/thanos/launchother/Hilt_LaunchOtherAppRuleActivity;->OoooO0:Z

    if-nez v0, :cond_11

    const/4 v0, 0x1

    iput-boolean v0, p1, Lnow/fortuitous/thanos/launchother/Hilt_LaunchOtherAppRuleActivity;->OoooO0:Z

    invoke-virtual {p1}, Lnow/fortuitous/thanos/launchother/Hilt_LaunchOtherAppRuleActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ln4;

    check-cast p1, Lnow/fortuitous/thanos/launchother/LaunchOtherAppRuleActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_11
    return-void

    :pswitch_11
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/android/thanos/support/subscribe/Hilt_LVLCheckActivity;

    iget-boolean v0, p1, Lgithub/tornaco/android/thanos/support/subscribe/Hilt_LVLCheckActivity;->OoooO0:Z

    if-nez v0, :cond_12

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/android/thanos/support/subscribe/Hilt_LVLCheckActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/support/subscribe/Hilt_LVLCheckActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ll4;

    check-cast p1, Lgithub/tornaco/android/thanos/support/subscribe/LVLCheckActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_12
    return-void

    :pswitch_12
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_DateTimeEngineActivity;

    iget-boolean v0, p1, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_DateTimeEngineActivity;->OoooO0:Z

    if-nez v0, :cond_13

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_DateTimeEngineActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_DateTimeEngineActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xz1;

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/engine/DateTimeEngineActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_13
    return-void

    :pswitch_13
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/engine/danmu/Hilt_DanmuUISettingsActivity;

    iget-boolean v0, p1, Lgithub/tornaco/thanos/android/module/profile/engine/danmu/Hilt_DanmuUISettingsActivity;->OoooO0:Z

    if-nez v0, :cond_14

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/thanos/android/module/profile/engine/danmu/Hilt_DanmuUISettingsActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/thanos/android/module/profile/engine/danmu/Hilt_DanmuUISettingsActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ew1;

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/engine/danmu/DanmuUISettingsActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_14
    return-void

    :pswitch_14
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/Hilt_ConsoleActivity;

    iget-boolean v0, p1, Lgithub/tornaco/thanos/android/module/profile/Hilt_ConsoleActivity;->OoooO0:Z

    if-nez v0, :cond_15

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/thanos/android/module/profile/Hilt_ConsoleActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/thanos/android/module/profile/Hilt_ConsoleActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/bj1;

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/ConsoleActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_15
    return-void

    :pswitch_15
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lnow/fortuitous/thanos/start/chart/Hilt_ComposeStartChartActivity;

    iget-boolean v0, p1, Lnow/fortuitous/thanos/start/chart/Hilt_ComposeStartChartActivity;->OoooO0:Z

    if-nez v0, :cond_16

    const/4 v0, 0x1

    iput-boolean v0, p1, Lnow/fortuitous/thanos/start/chart/Hilt_ComposeStartChartActivity;->OoooO0:Z

    invoke-virtual {p1}, Lnow/fortuitous/thanos/start/chart/Hilt_ComposeStartChartActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/me1;

    check-cast p1, Lnow/fortuitous/thanos/start/chart/ComposeStartChartActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_16
    return-void

    :pswitch_16
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/thanos/module/component/manager/redesign/Hilt_ComponentsActivity;

    iget-boolean v0, p1, Lgithub/tornaco/thanos/module/component/manager/redesign/Hilt_ComponentsActivity;->OoooO0:Z

    if-nez v0, :cond_17

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/thanos/module/component/manager/redesign/Hilt_ComponentsActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/thanos/module/component/manager/redesign/Hilt_ComponentsActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/m81;

    check-cast p1, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_17
    return-void

    :pswitch_17
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lnow/fortuitous/thanos/main/Hilt_ChooserActivity;

    iget-boolean v0, p1, Lnow/fortuitous/thanos/main/Hilt_ChooserActivity;->OoooO0:Z

    if-nez v0, :cond_18

    const/4 v0, 0x1

    iput-boolean v0, p1, Lnow/fortuitous/thanos/main/Hilt_ChooserActivity;->OoooO0:Z

    invoke-virtual {p1}, Lnow/fortuitous/thanos/main/Hilt_ChooserActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/rw0;

    check-cast p1, Lnow/fortuitous/thanos/main/ChooserActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_18
    return-void

    :pswitch_18
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/android/thanos/module/compose/common/infra/Hilt_BaseAppListFilterActivity;

    iget-boolean v0, p1, Lgithub/tornaco/android/thanos/module/compose/common/infra/Hilt_BaseAppListFilterActivity;->OoooO0:Z

    if-nez v0, :cond_19

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/android/thanos/module/compose/common/infra/Hilt_BaseAppListFilterActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/module/compose/common/infra/Hilt_BaseAppListFilterActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/d60;

    check-cast p1, Lgithub/tornaco/android/thanos/module/compose/common/infra/BaseAppListFilterActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_19
    return-void

    :pswitch_19
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/thanos/android/ops2/byapp/Hilt_AppOpsListActivity;

    iget-boolean v0, p1, Lgithub/tornaco/thanos/android/ops2/byapp/Hilt_AppOpsListActivity;->OoooO0:Z

    if-nez v0, :cond_1a

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/thanos/android/ops2/byapp/Hilt_AppOpsListActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/thanos/android/ops2/byapp/Hilt_AppOpsListActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/mv;

    check-cast p1, Lgithub/tornaco/thanos/android/ops2/byapp/AppOpsListActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_1a
    return-void

    :pswitch_1a
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lgithub/tornaco/thanos/android/ops2/byop/Hilt_AppListActivity;

    iget-boolean v0, p1, Lgithub/tornaco/thanos/android/ops2/byop/Hilt_AppListActivity;->OoooO0:Z

    if-nez v0, :cond_1b

    const/4 v0, 0x1

    iput-boolean v0, p1, Lgithub/tornaco/thanos/android/ops2/byop/Hilt_AppListActivity;->OoooO0:Z

    invoke-virtual {p1}, Lgithub/tornaco/thanos/android/ops2/byop/Hilt_AppListActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/vu;

    check-cast p1, Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_1b
    return-void

    :pswitch_1b
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    check-cast p1, Lnow/fortuitous/thanos/launchother/Hilt_AllowListActivity;

    iget-boolean v0, p1, Lnow/fortuitous/thanos/launchother/Hilt_AllowListActivity;->OoooO0:Z

    if-nez v0, :cond_1c

    const/4 v0, 0x1

    iput-boolean v0, p1, Lnow/fortuitous/thanos/launchother/Hilt_AllowListActivity;->OoooO0:Z

    invoke-virtual {p1}, Lnow/fortuitous/thanos/launchother/Hilt_AllowListActivity;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/s6;

    check-cast p1, Lnow/fortuitous/thanos/launchother/AllowListActivity;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_1c
    return-void

    :pswitch_1c
    iget-object p1, p0, Llyiahf/vczjk/pq;->OooO0O0:Landroidx/appcompat/app/AppCompatActivity;

    invoke-virtual {p1}, Landroidx/appcompat/app/AppCompatActivity;->OooOo0O()Llyiahf/vczjk/xq;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/xq;->OooO00o()V

    iget-object p1, p1, Landroidx/activity/ComponentActivity;->OooOOOo:Llyiahf/vczjk/f68;

    iget-object p1, p1, Llyiahf/vczjk/f68;->OooO0O0:Llyiahf/vczjk/e68;

    const-string v1, "androidx:appcompat"

    invoke-virtual {p1, v1}, Llyiahf/vczjk/e68;->OooO00o(Ljava/lang/String;)Landroid/os/Bundle;

    invoke-virtual {v0}, Llyiahf/vczjk/xq;->OooO0Oo()V

    return-void

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
