.class public final synthetic Llyiahf/vczjk/oo0oO0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/oo0oO0;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/pu5;Llyiahf/vczjk/ku5;Z)V
    .locals 0

    const/16 p3, 0x13

    iput p3, p0, Llyiahf/vczjk/oo0oO0;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 18

    move-object/from16 v1, p0

    const/4 v0, -0x1

    const/4 v2, 0x3

    const/4 v3, 0x0

    const/4 v4, 0x1

    const/4 v5, 0x0

    iget v6, v1, Llyiahf/vczjk/oo0oO0;->OooOOO0:I

    packed-switch v6, :pswitch_data_0

    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/oe3;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Ltornaco/apps/thanox/running/RunningAppState;

    invoke-interface {v0, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_0
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/oe3;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Lnow/fortuitous/thanos/process/v2/RunningAppState;

    invoke-interface {v0, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_1
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/w17;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-boolean v2, v0, Llyiahf/vczjk/w17;->OooO0OO:Z

    if-eqz v2, :cond_0

    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v2

    xor-int/2addr v2, v4

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v2

    invoke-interface {v0, v2}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    iget-boolean v2, v0, Llyiahf/vczjk/w17;->OooO0o0:Z

    xor-int/2addr v2, v4

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v2

    iget-object v0, v0, Llyiahf/vczjk/w17;->OooO0o:Llyiahf/vczjk/oe3;

    invoke-interface {v0, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :goto_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/t27;

    iget-object v4, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/x17;

    invoke-direct {v0, v4, v3}, Llyiahf/vczjk/t27;-><init>(Llyiahf/vczjk/x17;Llyiahf/vczjk/yo1;)V

    iget-object v4, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/xr1;

    invoke-static {v4, v3, v3, v0, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_3
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ot6;

    iget-object v0, v0, Llyiahf/vczjk/ot6;->OooO0O0:Ljava/util/List;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/oe3;

    invoke-interface {v2, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_4
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    invoke-virtual {v2}, Ljava/lang/String;->length()I

    move-result v2

    if-lez v2, :cond_2

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/qs5;

    invoke-static {v2, v5}, Llyiahf/vczjk/fu6;->OooO0OO(Llyiahf/vczjk/qs5;Z)V

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    const-string v3, "<this>"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2}, Ljava/lang/String;->length()I

    move-result v3

    sub-int/2addr v3, v4

    if-gez v3, :cond_1

    goto :goto_1

    :cond_1
    move v5, v3

    :goto_1
    invoke-static {v5, v2}, Llyiahf/vczjk/z69;->o00Ooo(ILjava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-interface {v0, v2}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    :cond_2
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_5
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cc6;

    iget-object v0, v0, Llyiahf/vczjk/cc6;->OooO0O0:Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Landroidx/appcompat/app/AppCompatActivity;

    invoke-static {v2, v0, v5, v4}, Lgithub/tornaco/thanos/android/module/profile/RuleEditorActivity;->OooOoo(Landroid/content/Context;Lgithub/tornaco/android/thanos/core/profile/RuleInfo;IZ)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_6
    sget v0, Lnow/fortuitous/thanos/onboarding/OnBoardingActivity;->Oooo0oo:I

    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroid/content/Context;

    invoke-static {v0}, Llyiahf/vczjk/n27;->OooO00o(Landroid/content/Context;)Landroid/content/SharedPreferences;

    move-result-object v2

    invoke-interface {v2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v2

    const-string v3, "PREF_KEY_ON_BOARDING"

    invoke-interface {v2, v3, v4}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    move-result-object v2

    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->apply()V

    const-class v2, Lnow/fortuitous/thanos/main/NavActivity;

    invoke-static {v0, v2}, Llyiahf/vczjk/bua;->Oooo(Landroid/content/Context;Ljava/lang/Class;)V

    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Lnow/fortuitous/thanos/onboarding/OnBoardingActivity;

    invoke-virtual {v0}, Landroid/app/Activity;->finish()V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_7
    new-instance v0, Llyiahf/vczjk/c46;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/g46;

    iget-object v2, v2, Llyiahf/vczjk/g46;->OooO00o:Landroid/content/Context;

    iget-object v3, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Ljava/lang/String;

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/c46;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    return-object v0

    :pswitch_8
    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ld9;

    iget-object v3, v2, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    mul-int/lit16 v3, v3, 0xe10

    int-to-long v3, v3

    const-wide/16 v5, 0x3e8

    mul-long/2addr v3, v5

    iget-object v7, v2, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/qs5;

    check-cast v7, Llyiahf/vczjk/fw8;

    invoke-virtual {v7}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Ljava/lang/Number;

    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    move-result v7

    mul-int/lit8 v7, v7, 0x3c

    int-to-long v7, v7

    mul-long/2addr v7, v5

    add-long/2addr v7, v3

    iget-object v3, v2, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->longValue()J

    move-result-wide v3

    mul-long/2addr v3, v5

    add-long/2addr v3, v7

    new-instance v5, Landroid/content/Intent;

    invoke-direct {v5}, Landroid/content/Intent;-><init>()V

    new-instance v6, Lgithub/tornaco/thanos/android/module/profile/engine/NewRegularIntervalResult;

    iget-object v2, v2, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/qs5;

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    invoke-direct {v6, v3, v4, v2}, Lgithub/tornaco/thanos/android/module/profile/engine/NewRegularIntervalResult;-><init>(JLjava/lang/String;)V

    const-string v2, "res"

    invoke-virtual {v5, v2, v6}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    move-result-object v2

    iget-object v3, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Lgithub/tornaco/thanos/android/module/profile/engine/NewRegularIntervalActivity;

    invoke-virtual {v3, v0, v2}, Landroid/app/Activity;->setResult(ILandroid/content/Intent;)V

    invoke-virtual {v3}, Landroid/app/Activity;->finish()V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_9
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pu5;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ku5;

    iget-object v4, v0, Llyiahf/vczjk/pu5;->OooO00o:Llyiahf/vczjk/qp3;

    monitor-enter v4

    :try_start_0
    iget-object v0, v0, Llyiahf/vczjk/pu5;->OooO0O0:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Iterable;

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :goto_2
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_4

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    move-object v8, v7

    check-cast v8, Llyiahf/vczjk/ku5;

    invoke-static {v8, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :catchall_0
    move-exception v0

    goto :goto_4

    :cond_4
    :goto_3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0, v3, v6}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v4

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :goto_4
    monitor-exit v4

    throw v0

    :pswitch_a
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yg5;

    invoke-virtual {v0, v5}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    iget-object v2, v0, Llyiahf/vczjk/yg5;->OooO0o:Ljava/lang/Object;

    iget-object v3, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/wg5;

    iget-object v3, v3, Llyiahf/vczjk/wg5;->OooO00o:Ljava/lang/String;

    iget-object v0, v0, Llyiahf/vczjk/yg5;->OooO0o0:Llyiahf/vczjk/ze3;

    invoke-interface {v0, v2, v3}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_b
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ua5;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Ljava/util/List;

    invoke-virtual {v0, v2, v4}, Llyiahf/vczjk/ua5;->OooO(Ljava/util/List;Z)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_c
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/q95;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/gv2;

    invoke-static {v0, v2}, Llyiahf/vczjk/q95;->OooO00o(Llyiahf/vczjk/q95;Llyiahf/vczjk/gv2;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_d
    sget v0, Lgithub/tornaco/thanos/android/module/profile/LogActivity;->OoooO0O:I

    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/j55;

    iget-boolean v0, v0, Llyiahf/vczjk/j55;->OooO0OO:Z

    xor-int/lit8 v8, v0, 0x1

    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/l55;

    iget-object v0, v0, Llyiahf/vczjk/l55;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    move-object v5, v2

    check-cast v5, Llyiahf/vczjk/j55;

    const/4 v6, 0x0

    const/16 v10, 0xb

    const/4 v7, 0x0

    const/4 v9, 0x0

    invoke-static/range {v5 .. v10}, Llyiahf/vczjk/j55;->OooO00o(Llyiahf/vczjk/j55;ZZZLjava/util/List;I)Llyiahf/vczjk/j55;

    move-result-object v2

    invoke-virtual {v0, v3, v2}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_e
    new-instance v0, Llyiahf/vczjk/a55;

    iget-object v4, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/dw4;

    invoke-direct {v0, v4, v3}, Llyiahf/vczjk/a55;-><init>(Llyiahf/vczjk/dw4;Llyiahf/vczjk/yo1;)V

    iget-object v4, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/xr1;

    invoke-static {v4, v3, v3, v0, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_f
    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/i25;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v3, Llyiahf/vczjk/wq0;

    const/16 v4, 0x14

    invoke-static {v4}, Llyiahf/vczjk/ru6;->OooOOOo(I)I

    move-result v4

    iget-object v6, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v6, Landroid/content/Context;

    invoke-direct {v3, v6, v4}, Llyiahf/vczjk/wq0;-><init>(Landroid/content/Context;I)V

    iget-object v4, v2, Llyiahf/vczjk/i25;->OooOOO0:Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getBackgroundColor()I

    move-result v7

    const/high16 v8, -0x1000000

    const-string v9, "getContext(...)"

    if-ne v7, v0, :cond_6

    invoke-virtual {v2}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v7

    invoke-static {v7, v9}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v7}, Llyiahf/vczjk/ru6;->OooOoO0(Landroid/content/Context;)Z

    move-result v7

    if-eqz v7, :cond_5

    invoke-virtual {v3, v8}, Llyiahf/vczjk/wq0;->setCardBackgroundColor(I)V

    goto :goto_5

    :cond_5
    invoke-virtual {v3, v0}, Llyiahf/vczjk/wq0;->setCardBackgroundColor(I)V

    goto :goto_5

    :cond_6
    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getBackgroundColor()I

    move-result v7

    invoke-virtual {v3, v7}, Llyiahf/vczjk/wq0;->setCardBackgroundColor(I)V

    :goto_5
    new-instance v7, Landroid/view/ViewGroup$LayoutParams;

    const/4 v10, -0x2

    invoke-direct {v7, v10, v10}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    invoke-virtual {v3, v7}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    new-instance v7, Landroid/widget/LinearLayout;

    invoke-direct {v7, v6}, Landroid/widget/LinearLayout;-><init>(Landroid/content/Context;)V

    new-instance v11, Landroid/widget/LinearLayout$LayoutParams;

    invoke-direct {v11, v10, v10}, Landroid/widget/LinearLayout$LayoutParams;-><init>(II)V

    invoke-virtual {v7, v5}, Landroid/widget/LinearLayout;->setOrientation(I)V

    const/16 v12, 0x11

    iput v12, v11, Landroid/widget/LinearLayout$LayoutParams;->gravity:I

    invoke-virtual {v7, v11}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    new-instance v11, Landroid/widget/ImageView;

    invoke-direct {v11, v6}, Landroid/widget/ImageView;-><init>(Landroid/content/Context;)V

    new-instance v13, Landroid/widget/LinearLayout$LayoutParams;

    const/16 v14, 0x18

    invoke-static {v14}, Llyiahf/vczjk/ru6;->OooOOOo(I)I

    move-result v15

    invoke-static {v14}, Llyiahf/vczjk/ru6;->OooOOOo(I)I

    move-result v14

    invoke-direct {v13, v15, v14}, Landroid/widget/LinearLayout$LayoutParams;-><init>(II)V

    iput v12, v13, Landroid/widget/LinearLayout$LayoutParams;->gravity:I

    const/16 v12, 0xc

    invoke-static {v12}, Llyiahf/vczjk/ru6;->OooOOOo(I)I

    move-result v14

    const/4 v15, 0x2

    move/from16 v16, v12

    invoke-static {v15}, Llyiahf/vczjk/ru6;->OooOOOo(I)I

    move-result v12

    move/from16 v17, v15

    invoke-static/range {v16 .. v16}, Llyiahf/vczjk/ru6;->OooOOOo(I)I

    move-result v15

    invoke-static/range {v17 .. v17}, Llyiahf/vczjk/ru6;->OooOOOo(I)I

    move-result v5

    invoke-virtual {v13, v14, v12, v15, v5}, Landroid/view/ViewGroup$MarginLayoutParams;->setMargins(IIII)V

    const v5, 0x1020007

    invoke-virtual {v11, v5}, Landroid/view/View;->setId(I)V

    invoke-virtual {v11, v13}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    new-instance v5, Landroid/widget/TextView;

    invoke-direct {v5, v6}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getTextColor()I

    move-result v6

    if-ne v6, v0, :cond_8

    invoke-virtual {v2}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v2

    invoke-static {v2, v9}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2}, Llyiahf/vczjk/ru6;->OooOoO0(Landroid/content/Context;)Z

    move-result v2

    if-eqz v2, :cond_7

    invoke-virtual {v5, v0}, Landroid/widget/TextView;->setTextColor(I)V

    goto :goto_6

    :cond_7
    invoke-virtual {v5, v8}, Landroid/widget/TextView;->setTextColor(I)V

    goto :goto_6

    :cond_8
    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getTextColor()I

    move-result v0

    invoke-virtual {v5, v0}, Landroid/widget/TextView;->setTextColor(I)V

    :goto_6
    new-instance v0, Landroid/widget/LinearLayout$LayoutParams;

    invoke-direct {v0, v10, v10}, Landroid/widget/LinearLayout$LayoutParams;-><init>(II)V

    const v2, 0x800013

    iput v2, v0, Landroid/widget/LinearLayout$LayoutParams;->gravity:I

    invoke-virtual {v5, v2}, Landroid/widget/TextView;->setGravity(I)V

    const/4 v2, 0x0

    invoke-virtual {v5, v2}, Landroid/view/View;->setFocusable(Z)V

    invoke-virtual {v5, v2}, Landroid/view/View;->setClickable(Z)V

    const/4 v2, 0x4

    invoke-virtual {v5, v2}, Landroid/widget/TextView;->setMaxLines(I)V

    sget-object v2, Landroid/text/TextUtils$TruncateAt;->END:Landroid/text/TextUtils$TruncateAt;

    invoke-virtual {v5, v2}, Landroid/widget/TextView;->setEllipsize(Landroid/text/TextUtils$TruncateAt;)V

    const v2, 0x1020014

    invoke-virtual {v5, v2}, Landroid/view/View;->setId(I)V

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getTextSizeSp()I

    move-result v2

    int-to-float v2, v2

    move/from16 v4, v17

    invoke-virtual {v5, v4, v2}, Landroid/widget/TextView;->setTextSize(IF)V

    invoke-virtual {v5, v0}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    invoke-virtual {v7, v11, v13}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    invoke-virtual {v7, v5, v0}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    invoke-virtual {v3, v7}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    return-object v3

    :pswitch_10
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ul4;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Landroid/content/Context;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/ul4;->OooO0o0(Landroid/content/Context;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_11
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/za2;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ku5;

    const/4 v3, 0x0

    invoke-virtual {v0, v2, v3}, Llyiahf/vczjk/za2;->OooO0o0(Llyiahf/vczjk/ku5;Z)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_12
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cf0;

    iget-object v0, v0, Llyiahf/vczjk/cf0;->OooO0OO:Ljava/lang/String;

    new-instance v2, Llyiahf/vczjk/nt;

    iget-object v3, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ov5;

    invoke-direct {v2, v3, v4}, Llyiahf/vczjk/nt;-><init>(Llyiahf/vczjk/ov5;I)V

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v3, v3, Llyiahf/vczjk/ov5;->OooO0O0:Llyiahf/vczjk/su5;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v2}, Llyiahf/vczjk/mc4;->OoooO0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/bw5;

    move-result-object v2

    invoke-virtual {v3, v0, v2}, Llyiahf/vczjk/su5;->OooOOO0(Ljava/lang/String;Llyiahf/vczjk/bw5;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_13
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v21;

    const/4 v2, 0x0

    invoke-virtual {v0, v2}, Llyiahf/vczjk/v21;->OooO00o(Z)V

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/qs5;

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    iget-object v0, v0, Llyiahf/vczjk/v21;->OooO0O0:Llyiahf/vczjk/oe3;

    invoke-interface {v0, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_14
    new-instance v0, Llyiahf/vczjk/c4;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/cj8;

    const/16 v3, 0xd

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/c4;-><init>(Ljava/lang/Object;I)V

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/cp8;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/cp8;->OooO0oO(Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_15
    sget v0, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OoooO0O:I

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ze3;

    iget-object v3, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/e71;

    invoke-interface {v2, v3, v0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_16
    sget v0, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OoooO0O:I

    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/t81;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_9
    iget-object v2, v0, Llyiahf/vczjk/t81;->OooO0o0:Llyiahf/vczjk/s29;

    invoke-virtual {v2}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Ljava/lang/String;

    const-string v4, ""

    invoke-virtual {v2, v3, v4}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_9

    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/hb8;

    invoke-virtual {v0}, Llyiahf/vczjk/hb8;->OooO00o()V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_17
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/p51;

    iget-object v2, v0, Llyiahf/vczjk/p51;->OooO0O0:Llyiahf/vczjk/oe3;

    iget-object v3, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/qs5;

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    invoke-interface {v2, v3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v2, 0x0

    invoke-virtual {v0, v2}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_18
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/qz0;

    iget-object v0, v0, Llyiahf/vczjk/qz0;->OooO00o:Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/dq;

    const/4 v2, 0x0

    invoke-virtual {v0, v2}, Llyiahf/vczjk/dq;->OooO00o(Z)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_19
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/xn6;

    invoke-virtual {v0}, Llyiahf/vczjk/xn6;->OooO0Oo()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/oe3;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/xw;

    invoke-interface {v0, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_1a
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/tv7;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/rs0;

    invoke-interface {v2, v0}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_1b
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Landroid/content/Intent;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/a;

    const-string v3, "stopServiceInternal, connRecords count: "

    const-string v4, "stopServiceInternal, serviceRecords count: "

    :try_start_1
    const-string v5, "uid"
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    const/4 v6, 0x0

    :try_start_2
    invoke-virtual {v0, v5, v6}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    move-result v5
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_4

    :try_start_3
    const-string v6, "stopServiceInternal: uid: %s name: %s"

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-virtual {v0}, Landroid/content/Intent;->getComponent()Landroid/content/ComponentName;

    move-result-object v8

    filled-new-array {v7, v8}, [Ljava/lang/Object;

    move-result-object v7

    invoke-static {v6, v7}, Llyiahf/vczjk/zsa;->o0ooOoO(Ljava/lang/String;[Ljava/lang/Object;)V

    if-nez v5, :cond_a

    const/4 v5, 0x0

    goto/16 :goto_9

    :cond_a
    new-instance v6, Ljava/util/concurrent/atomic/AtomicBoolean;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    const/4 v7, 0x0

    :try_start_4
    invoke-direct {v6, v7}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    :try_start_5
    iget-object v2, v2, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v2, v2, Llyiahf/vczjk/fo9;->OooOOO:Llyiahf/vczjk/kg;

    iget-object v2, v2, Llyiahf/vczjk/kg;->OooOOO0:Llyiahf/vczjk/era;

    iget-object v2, v2, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/oO00o00O;

    if-eqz v2, :cond_b

    invoke-virtual {v2, v0, v5}, Llyiahf/vczjk/oO00o00O;->o0000O0(Landroid/content/Intent;I)Ljava/util/ArrayList;

    move-result-object v7

    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    move-result v8

    new-instance v9, Ljava/lang/StringBuilder;

    invoke-direct {v9, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v9, v8}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    new-instance v4, Llyiahf/vczjk/oOO0O0O;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    const/4 v8, 0x0

    :try_start_6
    invoke-direct {v4, v8, v2, v6}, Llyiahf/vczjk/oOO0O0O;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-static {v7, v4}, Lutil/CollectionUtils;->consumeRemaining(Ljava/util/Collection;Lutil/Consumer;)V

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/util/PkgUtils;->packageNameOf(Landroid/content/Intent;)Ljava/lang/String;

    move-result-object v0

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    iget-object v7, v2, Llyiahf/vczjk/l21;->OooOOO:Ljava/lang/Object;

    const-string v9, "mServiceConnections"

    invoke-static {v7, v9}, Lutil/XposedHelpers;->getObjectField(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Landroid/util/ArrayMap;

    invoke-virtual {v7}, Landroid/util/ArrayMap;->values()Ljava/util/Collection;

    move-result-object v7

    new-instance v9, Llyiahf/vczjk/oO00O0oO;

    invoke-direct {v9, v0, v5, v4}, Llyiahf/vczjk/oO00O0oO;-><init>(Ljava/lang/String;ILjava/util/ArrayList;)V

    invoke-interface {v7, v9}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    move-result v0

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/oOO0OO0O;

    invoke-direct {v0, v2, v6}, Llyiahf/vczjk/oOO0OO0O;-><init>(Llyiahf/vczjk/oO00o00O;Ljava/util/concurrent/atomic/AtomicBoolean;)V

    invoke-static {v4, v0}, Lutil/CollectionUtils;->consumeRemaining(Ljava/util/Collection;Lutil/Consumer;)V

    goto :goto_7

    :catchall_1
    move-exception v0

    goto :goto_8

    :catchall_2
    move-exception v0

    const/4 v8, 0x0

    goto :goto_8

    :cond_b
    const/4 v8, 0x0

    :goto_7
    invoke-virtual {v6}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v5
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    goto :goto_9

    :catchall_3
    move-exception v0

    move v8, v7

    goto :goto_8

    :catchall_4
    move-exception v0

    move v8, v6

    :goto_8
    const-string v2, "stopServiceInternal error"

    invoke-static {v2, v0}, Llyiahf/vczjk/zsa;->Oooo0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    move v5, v8

    :goto_9
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0

    :pswitch_1c
    iget-object v0, v1, Llyiahf/vczjk/oo0oO0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/d25;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, v1, Llyiahf/vczjk/oo0oO0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Landroid/view/accessibility/AccessibilityManager;

    invoke-virtual {v2, v0}, Landroid/view/accessibility/AccessibilityManager;->removeAccessibilityStateChangeListener(Landroid/view/accessibility/AccessibilityManager$AccessibilityStateChangeListener;)Z

    iget-object v0, v0, Llyiahf/vczjk/d25;->OooOOO:Llyiahf/vczjk/c25;

    if-eqz v0, :cond_c

    invoke-virtual {v2, v0}, Landroid/view/accessibility/AccessibilityManager;->removeTouchExplorationStateChangeListener(Landroid/view/accessibility/AccessibilityManager$TouchExplorationStateChangeListener;)Z

    :cond_c
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

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
