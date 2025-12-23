.class public final synthetic Llyiahf/vczjk/c4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/c4;->OooOOO0:I

    iput-object p3, p0, Llyiahf/vczjk/c4;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/c4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/c4;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/a91;I)V
    .locals 0

    const/4 p2, 0x0

    iput p2, p0, Llyiahf/vczjk/c4;->OooOOO0:I

    sget p2, Llyiahf/vczjk/j4;->OooO00o:F

    sget p2, Llyiahf/vczjk/j4;->OooO00o:F

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/c4;->OooOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    const/4 v0, 0x3

    const-string v1, "file"

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x1

    sget-object v5, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v6, p0, Llyiahf/vczjk/c4;->OooOOO:Ljava/lang/Object;

    iget v7, p0, Llyiahf/vczjk/c4;->OooOOO0:I

    packed-switch v7, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lgithub/tornaco/thanos/android/module/profile/LogActivity;->OoooO0O:I

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Lgithub/tornaco/thanos/android/module/profile/LogActivity;

    invoke-virtual {v6, p2, p1}, Lgithub/tornaco/thanos/android/module/profile/LogActivity;->OooOoOO(ILlyiahf/vczjk/rf1;)V

    return-object v5

    :pswitch_0
    check-cast p2, Landroid/view/View;

    const-string v0, "data"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "view"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v6, Llyiahf/vczjk/i25;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v0, p2, Llyiahf/vczjk/wq0;

    if-eqz v0, :cond_3

    instance-of v0, p1, Llyiahf/vczjk/cw1;

    if-eqz v0, :cond_3

    const v0, 0x1020007

    invoke-virtual {p2, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/ImageView;

    const/16 v1, 0x8

    invoke-virtual {v0, v1}, Landroid/widget/ImageView;->setVisibility(I)V

    check-cast p1, Llyiahf/vczjk/cw1;

    invoke-virtual {v6}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    const-string v4, "getContext(...)"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v4, p1, Llyiahf/vczjk/cw1;->OooO00o:Ljava/lang/String;

    if-nez v4, :cond_0

    goto :goto_0

    :cond_0
    const-string v6, "app://"

    invoke-static {v4, v6, v2}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v7

    if-eqz v7, :cond_1

    invoke-static {v4, v6}, Llyiahf/vczjk/z69;->OoooOoo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    invoke-static {v1, v3}, Lgithub/tornaco/android/thanos/core/util/ApkUtil;->loadIconByPkgName(Landroid/content/Context;Ljava/lang/String;)Landroid/graphics/drawable/Drawable;

    move-result-object v3

    :cond_1
    :goto_0
    if-eqz v3, :cond_2

    invoke-virtual {v0, v2}, Landroid/widget/ImageView;->setVisibility(I)V

    invoke-virtual {v0, v3}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    :cond_2
    const v0, 0x1020014

    invoke-virtual {p2, v0}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object p2

    check-cast p2, Landroid/widget/TextView;

    iget-object p1, p1, Llyiahf/vczjk/cw1;->OooO0O0:Ljava/lang/String;

    invoke-virtual {p2, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    :cond_3
    return-object v5

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lnow/fortuitous/thanos/launchother/LaunchOtherAppRuleActivity;->OoooO0O:I

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Lnow/fortuitous/thanos/launchother/LaunchOtherAppRuleActivity;

    invoke-virtual {v6, p2, p1}, Lnow/fortuitous/thanos/launchother/LaunchOtherAppRuleActivity;->OooOoOO(ILlyiahf/vczjk/rf1;)V

    return-object v5

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lgithub/tornaco/android/thanos/support/subscribe/LVLCheckActivity;->OoooO0O:I

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Lgithub/tornaco/android/thanos/support/subscribe/LVLCheckActivity;

    invoke-virtual {v6, p2, p1}, Lgithub/tornaco/android/thanos/support/subscribe/LVLCheckActivity;->OooOoOO(ILlyiahf/vczjk/rf1;)V

    return-object v5

    :pswitch_3
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lnow/fortuitous/thanos/settings/FeatureToggleActivity;->Oooo0oo:I

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Lnow/fortuitous/thanos/settings/FeatureToggleActivity;

    invoke-virtual {v6, p2, p1}, Lnow/fortuitous/thanos/settings/FeatureToggleActivity;->OooOoOO(ILlyiahf/vczjk/rf1;)V

    return-object v5

    :pswitch_4
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lgithub/tornaco/android/thanos/module/compose/common/widget/FeatureDescriptionAndroidView;->OooOo:I

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Lgithub/tornaco/android/thanos/module/compose/common/widget/FeatureDescriptionAndroidView;

    invoke-virtual {v6, p2, p1}, Lgithub/tornaco/android/thanos/module/compose/common/widget/FeatureDescriptionAndroidView;->OooO00o(ILlyiahf/vczjk/rf1;)V

    return-object v5

    :pswitch_5
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lgithub/tornaco/android/thanos/module/compose/common/widget/ExperimentalFeatureWarningMessageAndroidView;->OooOo0:I

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Lgithub/tornaco/android/thanos/module/compose/common/widget/ExperimentalFeatureWarningMessageAndroidView;

    invoke-virtual {v6, p2, p1}, Lgithub/tornaco/android/thanos/module/compose/common/widget/ExperimentalFeatureWarningMessageAndroidView;->OooO00o(ILlyiahf/vczjk/rf1;)V

    return-object v5

    :pswitch_6
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Llyiahf/vczjk/ps9;

    invoke-static {v6, p1, p2}, Llyiahf/vczjk/zsa;->OooOo0(Llyiahf/vczjk/ps9;Llyiahf/vczjk/rf1;I)V

    return-object v5

    :pswitch_7
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Llyiahf/vczjk/p97;

    invoke-static {v6, p1, p2}, Llyiahf/vczjk/zsa;->OooOOO(Llyiahf/vczjk/p97;Llyiahf/vczjk/rf1;I)V

    return-object v5

    :pswitch_8
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Llyiahf/vczjk/za2;

    invoke-static {v6, p1, p2}, Llyiahf/vczjk/qqa;->OooO0Oo(Llyiahf/vczjk/za2;Llyiahf/vczjk/rf1;I)V

    return-object v5

    :pswitch_9
    check-cast p1, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;

    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    const-string v0, "record"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;->getAlarm()Lgithub/tornaco/android/thanos/core/alarm/Alarm;

    move-result-object p1

    check-cast v6, Llyiahf/vczjk/k02;

    const-string v0, "alarm"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, v6, Llyiahf/vczjk/k02;->OooO0OO:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v0

    invoke-virtual {v0, p1, p2}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->setAlarmEnabled(Lgithub/tornaco/android/thanos/core/alarm/Alarm;Z)V

    invoke-virtual {v6}, Llyiahf/vczjk/k02;->OooO0o()V

    return-object v5

    :pswitch_a
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Llyiahf/vczjk/ov5;

    invoke-static {v6, p1, p2}, Llyiahf/vczjk/bua;->OooO0oo(Llyiahf/vczjk/ov5;Llyiahf/vczjk/rf1;I)V

    return-object v5

    :pswitch_b
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Llyiahf/vczjk/v21;

    invoke-static {v6, p1, p2}, Llyiahf/vczjk/os9;->OooO0OO(Llyiahf/vczjk/v21;Llyiahf/vczjk/rf1;I)V

    return-object v5

    :pswitch_c
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lgithub/tornaco/thanos/android/module/profile/ConsoleActivity;->OoooO0O:I

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Lgithub/tornaco/thanos/android/module/profile/ConsoleActivity;

    invoke-virtual {v6, p2, p1}, Lgithub/tornaco/thanos/android/module/profile/ConsoleActivity;->OooOoOO(ILlyiahf/vczjk/rf1;)V

    return-object v5

    :pswitch_d
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lnow/fortuitous/thanos/start/chart/ComposeStartChartActivity;->OoooO0O:I

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Lnow/fortuitous/thanos/start/chart/ComposeStartChartActivity;

    invoke-virtual {v6, p2, p1}, Lnow/fortuitous/thanos/start/chart/ComposeStartChartActivity;->OooOoOO(ILlyiahf/vczjk/rf1;)V

    return-object v5

    :pswitch_e
    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    check-cast p2, Llyiahf/vczjk/jd2;

    invoke-static {p2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v6, Llyiahf/vczjk/dj8;

    iget-object v1, v6, Llyiahf/vczjk/vo1;->OooO0o:Landroid/content/Context;

    const/16 v4, 0x2706

    if-eq p1, v4, :cond_6

    const/16 v2, 0x2707

    if-eq p1, v2, :cond_4

    goto/16 :goto_3

    :cond_4
    invoke-static {p2, v1}, Llyiahf/vczjk/t51;->OoooO0O(Llyiahf/vczjk/jd2;Landroid/content/Context;)Ljava/io/OutputStream;

    move-result-object p1

    if-nez p1, :cond_5

    invoke-static {v6}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/ti8;

    invoke-direct {p2, v6, v3}, Llyiahf/vczjk/ti8;-><init>(Llyiahf/vczjk/dj8;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v3, v3, p2, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto/16 :goto_3

    :cond_5
    :try_start_0
    new-instance v2, Llyiahf/vczjk/di8;

    const/4 v4, 0x2

    invoke-direct {v2, v6, v4}, Llyiahf/vczjk/di8;-><init>(Llyiahf/vczjk/dj8;I)V

    invoke-static {v1, v2}, Llyiahf/vczjk/l4a;->OooOo00(Landroid/content/Context;Llyiahf/vczjk/oe3;)Ljava/io/File;

    move-result-object v1

    invoke-static {v1, p1}, Llyiahf/vczjk/wr6;->OooOO0(Ljava/io/File;Ljava/io/OutputStream;)V

    invoke-static {v6}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/vi8;

    invoke-direct {v1, v6, p2, v3}, Llyiahf/vczjk/vi8;-><init>(Llyiahf/vczjk/dj8;Llyiahf/vczjk/jd2;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v3, v3, v1, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    :goto_1
    invoke-static {p1}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object p1

    if-eqz p1, :cond_9

    invoke-static {v6}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p2

    new-instance v1, Llyiahf/vczjk/xi8;

    invoke-direct {v1, v6, p1, v3}, Llyiahf/vczjk/xi8;-><init>(Llyiahf/vczjk/dj8;Ljava/lang/Throwable;Llyiahf/vczjk/yo1;)V

    invoke-static {p2, v3, v3, v1, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto/16 :goto_3

    :cond_6
    const-string p1, "backup, create new file failed. "

    new-instance v4, Ljava/lang/StringBuilder;

    const-string v7, "backup: "

    invoke-direct {v4, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    invoke-static {p2, v1}, Llyiahf/vczjk/t51;->OoooO0O(Llyiahf/vczjk/jd2;Landroid/content/Context;)Ljava/io/OutputStream;

    move-result-object v4

    if-nez v4, :cond_7

    invoke-static {v6}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/pi8;

    invoke-direct {v1, v6, p2, v3}, Llyiahf/vczjk/pi8;-><init>(Llyiahf/vczjk/dj8;Llyiahf/vczjk/jd2;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v3, v3, v1, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto/16 :goto_3

    :cond_7
    new-instance v7, Ljava/io/File;

    invoke-virtual {v1}, Landroid/content/Context;->getCacheDir()Ljava/io/File;

    move-result-object v1

    const-string v8, "backup"

    invoke-direct {v7, v1, v8}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v8, "backup, backupTmpDir: "

    invoke-direct {v1, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v8

    invoke-static {v8, v9}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatForFileName(J)Ljava/lang/String;

    move-result-object v1

    const-string v8, "Thanox-Backup-"

    invoke-static {v8, v1}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const-string v8, ".zip"

    invoke-static {v1, v8}, Llyiahf/vczjk/u81;->OooOO0o(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    new-instance v8, Ljava/io/File;

    invoke-direct {v8, v7, v1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    :try_start_1
    invoke-static {v7}, Llyiahf/vczjk/d03;->Oooooo0(Ljava/io/File;)Z

    invoke-virtual {v7}, Ljava/io/File;->mkdirs()Z

    invoke-virtual {v8}, Ljava/lang/Object;->toString()Ljava/lang/String;

    invoke-virtual {v8}, Ljava/io/File;->createNewFile()Z

    move-result v1

    if-eqz v1, :cond_8

    const/high16 p1, 0x30000000

    invoke-static {v8, p1}, Landroid/os/ParcelFileDescriptor;->open(Ljava/io/File;I)Landroid/os/ParcelFileDescriptor;

    move-result-object p1

    invoke-static {p1}, Ljava/util/Objects;->toString(Ljava/lang/Object;)Ljava/lang/String;

    invoke-virtual {v6}, Llyiahf/vczjk/dj8;->OooO0oo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getBackupAgent()Lgithub/tornaco/android/thanos/core/backup/BackupAgent;

    move-result-object v1

    invoke-virtual {v1, p1}, Lgithub/tornaco/android/thanos/core/backup/BackupAgent;->performBackup(Landroid/os/ParcelFileDescriptor;)V

    invoke-static {v8, v4}, Llyiahf/vczjk/wr6;->OooOO0(Ljava/io/File;Ljava/io/OutputStream;)V

    invoke-static {v6}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/qi8;

    invoke-direct {v1, v6, p2, v3}, Llyiahf/vczjk/qi8;-><init>(Llyiahf/vczjk/dj8;Llyiahf/vczjk/jd2;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v3, v3, v1, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_3

    :catchall_1
    move-exception p1

    goto :goto_2

    :cond_8
    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :goto_2
    const-string p2, "Backup fail"

    new-array v1, v2, [Ljava/lang/Object;

    invoke-static {p2, v1, p1}, Llyiahf/vczjk/zsa;->Oooo0o(Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    invoke-static {v6}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p2

    new-instance v1, Llyiahf/vczjk/ri8;

    invoke-direct {v1, v6, p1, v8, v3}, Llyiahf/vczjk/ri8;-><init>(Llyiahf/vczjk/dj8;Ljava/lang/Throwable;Ljava/io/File;Llyiahf/vczjk/yo1;)V

    invoke-static {p2, v3, v3, v1, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_9
    :goto_3
    return-object v5

    :pswitch_f
    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    check-cast p2, Llyiahf/vczjk/jd2;

    invoke-static {p2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v6, Llyiahf/vczjk/cj8;

    iget-object p1, v6, Llyiahf/vczjk/vo1;->OooO0o:Landroid/content/Context;

    invoke-static {p2, p1}, Llyiahf/vczjk/t51;->OoooO0O(Llyiahf/vczjk/jd2;Landroid/content/Context;)Ljava/io/OutputStream;

    move-result-object v1

    if-nez v1, :cond_a

    invoke-static {v6}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/si8;

    invoke-direct {p2, v6, v3}, Llyiahf/vczjk/si8;-><init>(Llyiahf/vczjk/cj8;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v3, v3, p2, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_6

    :cond_a
    :try_start_2
    new-instance v2, Llyiahf/vczjk/r07;

    const/16 v4, 0x1d

    invoke-direct {v2, v4}, Llyiahf/vczjk/r07;-><init>(I)V

    invoke-static {p1, v2}, Llyiahf/vczjk/l4a;->OooOo00(Landroid/content/Context;Llyiahf/vczjk/oe3;)Ljava/io/File;

    move-result-object p1

    new-instance v2, Ljava/io/FileInputStream;

    invoke-direct {v2, p1}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    :try_start_3
    invoke-static {v2, v1}, Llyiahf/vczjk/ng0;->OooOo00(Ljava/io/InputStream;Ljava/io/OutputStream;)J
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    :try_start_4
    invoke-interface {v1}, Ljava/io/Closeable;->close()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_5

    :try_start_5
    invoke-virtual {v2}, Ljava/io/FileInputStream;->close()V

    invoke-static {v6}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/ui8;

    invoke-direct {v1, v6, p2, v3}, Llyiahf/vczjk/ui8;-><init>(Llyiahf/vczjk/cj8;Llyiahf/vczjk/jd2;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v3, v3, v1, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    goto :goto_5

    :catchall_2
    move-exception p1

    goto :goto_4

    :catchall_3
    move-exception p1

    :try_start_6
    throw p1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_4

    :catchall_4
    move-exception p2

    :try_start_7
    invoke-static {v1, p1}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw p2
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_5

    :catchall_5
    move-exception p1

    :try_start_8
    throw p1
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_6

    :catchall_6
    move-exception p2

    :try_start_9
    invoke-static {v2, p1}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw p2
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    :goto_4
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    :goto_5
    invoke-static {p1}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object p1

    if-eqz p1, :cond_b

    invoke-static {v6}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p2

    new-instance v1, Llyiahf/vczjk/wi8;

    invoke-direct {v1, v6, p1, v3}, Llyiahf/vczjk/wi8;-><init>(Llyiahf/vczjk/cj8;Ljava/lang/Throwable;Llyiahf/vczjk/yo1;)V

    invoke-static {p2, v3, v3, v1, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_b
    :goto_6
    return-object v5

    :pswitch_10
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Llyiahf/vczjk/g71;

    invoke-static {v6, p1, p2}, Llyiahf/vczjk/zsa;->OooOOOO(Llyiahf/vczjk/g71;Llyiahf/vczjk/rf1;I)V

    return-object v5

    :pswitch_11
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;

    invoke-static {v6, p1, p2}, Llyiahf/vczjk/zsa;->OooO0O0(Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;Llyiahf/vczjk/rf1;I)V

    return-object v5

    :pswitch_12
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;

    invoke-static {v6, p1, p2}, Llyiahf/vczjk/zsa;->OooO(Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;Llyiahf/vczjk/rf1;I)V

    return-object v5

    :pswitch_13
    check-cast p1, Llyiahf/vczjk/b71;

    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    const-string v0, "componentGroup"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v6, Llyiahf/vczjk/t81;

    invoke-virtual {v6, p1, p2}, Llyiahf/vczjk/t81;->OooO0oo(Llyiahf/vczjk/b71;Z)V

    return-object v5

    :pswitch_14
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OoooO0O:I

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;

    invoke-virtual {v6, p2, p1}, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OooOoOO(ILlyiahf/vczjk/rf1;)V

    return-object v5

    :pswitch_15
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Llyiahf/vczjk/qz0;

    invoke-virtual {v6, p2, p1}, Llyiahf/vczjk/qz0;->OooO00o(ILlyiahf/vczjk/rf1;)V

    return-object v5

    :pswitch_16
    check-cast p1, Llyiahf/vczjk/z8a;

    check-cast p2, Ljava/lang/String;

    const-string p1, "id"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v6, Llyiahf/vczjk/oe3;

    invoke-interface {v6, p2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v5

    :pswitch_17
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Llyiahf/vczjk/i40;

    invoke-static {v6, p1, p2}, Llyiahf/vczjk/jp8;->OooO0O0(Llyiahf/vczjk/i40;Llyiahf/vczjk/rf1;I)V

    return-object v5

    :pswitch_18
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lgithub/tornaco/thanos/android/ops2/byapp/AppOpsListActivity;->OoooO0O:I

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Lgithub/tornaco/thanos/android/ops2/byapp/AppOpsListActivity;

    invoke-virtual {v6, p2, p1}, Lgithub/tornaco/thanos/android/ops2/byapp/AppOpsListActivity;->OooOoOO(ILlyiahf/vczjk/rf1;)V

    return-object v5

    :pswitch_19
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;->OoooO0O:I

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;

    invoke-virtual {v6, p2, p1}, Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;->OooOoOO(ILlyiahf/vczjk/rf1;)V

    return-object v5

    :pswitch_1a
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Llyiahf/vczjk/yo9;

    invoke-static {v6, p1, p2}, Llyiahf/vczjk/dn8;->OooOOo(Llyiahf/vczjk/yo9;Llyiahf/vczjk/rf1;I)V

    return-object v5

    :pswitch_1b
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lnow/fortuitous/thanos/launchother/AllowListActivity;->OoooO0O:I

    invoke-static {v4}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v6, Lnow/fortuitous/thanos/launchother/AllowListActivity;

    invoke-virtual {v6, p2, p1}, Lnow/fortuitous/thanos/launchother/AllowListActivity;->OooOoOO(ILlyiahf/vczjk/rf1;)V

    return-object v5

    :pswitch_1c
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p2, 0x1b7

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    sget v0, Llyiahf/vczjk/j4;->OooO00o:F

    sget v0, Llyiahf/vczjk/j4;->OooO00o:F

    check-cast v6, Llyiahf/vczjk/a91;

    invoke-static {v6, p1, p2}, Llyiahf/vczjk/j4;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    return-object v5

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
