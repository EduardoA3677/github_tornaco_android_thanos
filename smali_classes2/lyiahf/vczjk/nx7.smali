.class public Llyiahf/vczjk/nx7;
.super Llyiahf/vczjk/ph;
.source "SourceFile"


# instance fields
.field public final OooO0OO:Landroidx/databinding/ObservableBoolean;

.field public final OooO0Oo:Llyiahf/vczjk/cg1;

.field public final OooO0o:Lgithub/tornaco/android/thanos/core/app/ThanosManager;

.field public final OooO0o0:Landroidx/databinding/ObservableArrayList;

.field public final OooO0oO:Llyiahf/vczjk/lx7;

.field public final OooO0oo:Llyiahf/vczjk/mx7;


# direct methods
.method public constructor <init>(Landroid/app/Application;)V
    .locals 2

    invoke-direct {p0, p1}, Llyiahf/vczjk/ph;-><init>(Landroid/app/Application;)V

    new-instance v0, Landroidx/databinding/ObservableBoolean;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Landroidx/databinding/ObservableBoolean;-><init>(Z)V

    iput-object v0, p0, Llyiahf/vczjk/nx7;->OooO0OO:Landroidx/databinding/ObservableBoolean;

    new-instance v0, Llyiahf/vczjk/cg1;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/cg1;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/nx7;->OooO0Oo:Llyiahf/vczjk/cg1;

    new-instance v0, Landroidx/databinding/ObservableArrayList;

    invoke-direct {v0}, Landroidx/databinding/ObservableArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/nx7;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    new-instance v0, Llyiahf/vczjk/lx7;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/lx7;-><init>(Llyiahf/vczjk/nx7;I)V

    iput-object v0, p0, Llyiahf/vczjk/nx7;->OooO0oO:Llyiahf/vczjk/lx7;

    new-instance v0, Llyiahf/vczjk/mx7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/mx7;-><init>(Llyiahf/vczjk/nx7;)V

    iput-object v0, p0, Llyiahf/vczjk/nx7;->OooO0oo:Llyiahf/vczjk/mx7;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/nx7;->OooO0o:Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object p1

    invoke-virtual {p1, v0}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->registerRuleChangeListener(Lgithub/tornaco/android/thanos/core/profile/RuleChangeListener;)V

    :cond_0
    return-void
.end method


# virtual methods
.method public final OooO0Oo()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/nx7;->OooO0Oo:Llyiahf/vczjk/cg1;

    invoke-virtual {v0}, Llyiahf/vczjk/cg1;->OooO0OO()V

    iget-object v0, p0, Llyiahf/vczjk/nx7;->OooO0o:Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/nx7;->OooO0oo:Llyiahf/vczjk/mx7;

    invoke-virtual {v0, v1}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->unRegisterRuleChangeListener(Lgithub/tornaco/android/thanos/core/profile/RuleChangeListener;)V

    :cond_0
    return-void
.end method

.method public final OooO0o()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/nx7;->OooO0o:Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/nx7;->OooO0OO:Landroidx/databinding/ObservableBoolean;

    invoke-virtual {v0}, Landroidx/databinding/ObservableBoolean;->get()Z

    move-result v1

    if-eqz v1, :cond_1

    :goto_0
    return-void

    :cond_1
    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Landroidx/databinding/ObservableBoolean;->set(Z)V

    new-instance v0, Llyiahf/vczjk/lx7;

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/lx7;-><init>(Llyiahf/vczjk/nx7;I)V

    new-instance v1, Llyiahf/vczjk/lp8;

    const/4 v2, 0x0

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/lp8;-><init>(Ljava/lang/Object;I)V

    new-instance v0, Llyiahf/vczjk/oOO0O00O;

    const/16 v2, 0x10

    invoke-direct {v0, v2}, Llyiahf/vczjk/oOO0O00O;-><init>(I)V

    new-instance v2, Llyiahf/vczjk/qp8;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/qp8;-><init>(Llyiahf/vczjk/jp8;Llyiahf/vczjk/af3;)V

    sget-object v0, Llyiahf/vczjk/s88;->OooO0OO:Llyiahf/vczjk/i88;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/o76;->OooO0o(Llyiahf/vczjk/i88;)Llyiahf/vczjk/u76;

    move-result-object v0

    invoke-static {}, Llyiahf/vczjk/wf;->OooO00o()Llyiahf/vczjk/i88;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/o76;->OooO0O0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/c86;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/lx7;

    const/4 v2, 0x2

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/lx7;-><init>(Llyiahf/vczjk/nx7;I)V

    sget-object v2, Llyiahf/vczjk/v34;->OooO0Oo:Llyiahf/vczjk/up3;

    new-instance v3, Llyiahf/vczjk/v76;

    invoke-direct {v3, v0, v1, v2}, Llyiahf/vczjk/v76;-><init>(Llyiahf/vczjk/o76;Llyiahf/vczjk/nl1;Llyiahf/vczjk/o0oo0000;)V

    new-instance v0, Llyiahf/vczjk/lx7;

    const/4 v1, 0x3

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/lx7;-><init>(Llyiahf/vczjk/nx7;I)V

    sget-object v1, Lgithub/tornaco/android/thanos/core/util/Rxs;->ON_ERROR_LOGGING:Llyiahf/vczjk/nl1;

    new-instance v2, Llyiahf/vczjk/lx7;

    const/4 v4, 0x4

    invoke-direct {v2, p0, v4}, Llyiahf/vczjk/lx7;-><init>(Llyiahf/vczjk/nx7;I)V

    invoke-virtual {v3, v0, v1, v2}, Llyiahf/vczjk/o76;->OooO0OO(Llyiahf/vczjk/nl1;Llyiahf/vczjk/nl1;Llyiahf/vczjk/o0oo0000;)Llyiahf/vczjk/sm4;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/nx7;->OooO0Oo:Llyiahf/vczjk/cg1;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/cg1;->OooO0O0(Llyiahf/vczjk/nc2;)Z

    return-void
.end method

.method public final OooO0oO(Lgithub/tornaco/android/thanos/core/profile/RuleInfo;)Llyiahf/vczjk/vx7;
    .locals 10

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getRuleString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "su.exe("

    invoke-virtual {v0, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/nx7;->OooO0o:Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    if-eqz v0, :cond_0

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->isShellSuSupportInstalled()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/ph;->OooO0o0()Landroid/app/Application;

    move-result-object v0

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->module_profile_should_enable_su:I

    invoke-virtual {v0, v1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/vx7;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/vx7;-><init>(Lgithub/tornaco/android/thanos/core/profile/RuleInfo;Ljava/lang/String;)V

    return-object v1

    :cond_0
    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getRuleString()Ljava/lang/String;

    move-result-object v0

    const-string v2, "fcmPushMessageArrived"

    invoke-virtual {v0, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->isProfileEnginePushEnabled()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/ph;->OooO0o0()Landroid/app/Application;

    move-result-object v0

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->module_profile_should_enable_push:I

    invoke-virtual {v0, v1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/vx7;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/vx7;-><init>(Lgithub/tornaco/android/thanos/core/profile/RuleInfo;Ljava/lang/String;)V

    return-object v1

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/ph;->OooO0o0()Landroid/app/Application;

    move-result-object v0

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getRuleString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->getAllGlobalRuleVarNames()[Ljava/lang/String;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :try_start_0
    const-string v0, "globalVarOf$"

    if-eqz v1, :cond_5

    invoke-static {v1}, Llyiahf/vczjk/z69;->OoooOO0(Ljava/lang/CharSequence;)Z

    move-result v4

    if-eqz v4, :cond_2

    goto :goto_0

    :cond_2
    const/4 v4, 0x0

    invoke-static {v1, v0, v4}, Llyiahf/vczjk/z69;->Oooo0OO(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_0

    :cond_3
    new-instance v0, Llyiahf/vczjk/on7;

    const-string v4, "globalVarOf\\$[^\\s.)=]+"

    invoke-direct {v0, v4}, Llyiahf/vczjk/on7;-><init>(Ljava/lang/String;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/on7;->OooO0OO(Llyiahf/vczjk/on7;Ljava/lang/String;)Llyiahf/vczjk/b62;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/r07;

    const/16 v4, 0xc

    invoke-direct {v1, v4}, Llyiahf/vczjk/r07;-><init>(I)V

    invoke-static {v0, v1}, Llyiahf/vczjk/ag8;->Oooo0oo(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/jy9;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/ag8;->OoooO00(Llyiahf/vczjk/wf8;)Ljava/util/List;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/d21;->Ooooooo(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v1

    if-nez v1, :cond_4

    move-object v3, v0

    :cond_4
    check-cast v3, Ljava/util/List;

    :cond_5
    :goto_0
    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_6
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_7

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    move-object v3, v1

    check-cast v3, Ljava/lang/String;

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v2, v3}, Llyiahf/vczjk/sy;->Ooooooo([Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_6

    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_7
    invoke-virtual {v4}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_8

    invoke-virtual {p0}, Llyiahf/vczjk/ph;->OooO0o0()Landroid/app/Application;

    move-result-object v0

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->module_profile_miss_global_var:I

    invoke-static {}, Ljava/lang/System;->lineSeparator()Ljava/lang/String;

    move-result-object v5

    const-string v2, "splitter"

    invoke-static {v5, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v8, Llyiahf/vczjk/r07;

    const/16 v2, 0xd

    invoke-direct {v8, v2}, Llyiahf/vczjk/r07;-><init>(I)V

    const/4 v7, 0x0

    const/16 v9, 0x1e

    const/4 v6, 0x0

    invoke-static/range {v4 .. v9}, Llyiahf/vczjk/d21;->o0ooOoO(Ljava/lang/Iterable;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object v2

    filled-new-array {v2}, [Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Landroid/content/Context;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/vx7;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/vx7;-><init>(Lgithub/tornaco/android/thanos/core/profile/RuleInfo;Ljava/lang/String;)V

    return-object v1

    :cond_8
    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getRuleString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "Thread.sleep"

    invoke-virtual {v0, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_9

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getPriority()I

    move-result v0

    if-ltz v0, :cond_9

    invoke-virtual {p0}, Llyiahf/vczjk/ph;->OooO0o0()Landroid/app/Application;

    move-result-object v0

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->module_profile_block_thread:I

    invoke-virtual {v0, v1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/vx7;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/vx7;-><init>(Lgithub/tornaco/android/thanos/core/profile/RuleInfo;Ljava/lang/String;)V

    return-object v1

    :cond_9
    new-instance v0, Llyiahf/vczjk/vx7;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/vx7;-><init>(Lgithub/tornaco/android/thanos/core/profile/RuleInfo;Ljava/lang/String;)V

    return-object v0
.end method
