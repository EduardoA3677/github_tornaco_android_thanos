.class public final Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;
.super Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;
.source "SourceFile"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0007\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u00a8\u0006\u0004"
    }
    d2 = {
        "Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;",
        "Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;",
        "<init>",
        "()V",
        "app_prcRelease"
    }
    k = 0x1
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final synthetic OoooO:I


# instance fields
.field public Oooo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field public Oooo0oo:I

.field public final OoooO0:Llyiahf/vczjk/sc9;

.field public OoooO00:Llyiahf/vczjk/pc0;

.field public OoooO0O:I


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;-><init>()V

    new-instance v0, Llyiahf/vczjk/nea;

    const/4 v1, 0x2

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/nea;-><init>(Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;I)V

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object v0

    iput-object v0, p0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OoooO0:Llyiahf/vczjk/sc9;

    return-void
.end method


# virtual methods
.method public final OooOoOO(ILlyiahf/vczjk/rf1;)V
    .locals 11

    move-object v4, p2

    check-cast v4, Llyiahf/vczjk/zf1;

    const p2, 0x52c3fc3a

    invoke-virtual {v4, p2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v4, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    const/4 v0, 0x2

    if-eqz p2, :cond_0

    const/4 p2, 0x4

    goto :goto_0

    :cond_0
    move p2, v0

    :goto_0
    or-int/2addr p2, p1

    and-int/lit8 p2, p2, 0x3

    if-ne p2, v0, :cond_2

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p2

    if-nez p2, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_6

    :cond_2
    :goto_1
    const p2, 0x6e3c21fe

    invoke-virtual {v4, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p2

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/4 v2, 0x1

    const/4 v10, 0x0

    if-ne p2, v1, :cond_5

    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    move-result-object p2

    if-eqz p2, :cond_4

    const-string v3, "pkg"

    invoke-virtual {p2, v3}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    if-nez p2, :cond_3

    goto :goto_2

    :cond_3
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;

    move-result-object v3

    const-string v5, "request_code"

    const/high16 v6, -0x80000000

    invoke-virtual {v3, v5, v6}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    move-result v3

    iput v3, p0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->Oooo0oo:I

    invoke-static {p0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v3

    invoke-virtual {v3, p2}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getAppInfo(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object p2

    iput-object p2, p0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->Oooo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    if-eqz p2, :cond_4

    move p2, v2

    goto :goto_3

    :cond_4
    :goto_2
    move p2, v10

    :goto_3
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p2

    invoke-virtual {v4, p2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    if-eqz p2, :cond_14

    invoke-virtual {p0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOoo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object p2

    invoke-virtual {p2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object p2

    invoke-virtual {p2}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->getLockMethod()I

    move-result p2

    const/4 v3, 0x0

    const v5, 0x4c5de2

    if-ne p2, v2, :cond_9

    invoke-virtual {p0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOoo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object p2

    invoke-virtual {p2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object p2

    invoke-virtual {p2}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->getLockPattern()Ljava/lang/String;

    move-result-object p2

    if-eqz p2, :cond_9

    invoke-static {p2}, Llyiahf/vczjk/z69;->OoooOO0(Ljava/lang/CharSequence;)Z

    move-result p2

    if-eqz p2, :cond_6

    goto :goto_4

    :cond_6
    const p2, -0x7af86175

    invoke-virtual {v4, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v0, p0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->Oooo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    :try_start_0
    invoke-virtual {p0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOoo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object p2

    invoke-virtual {p2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object p2

    invoke-virtual {p2}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->getLockCustomHint()Ljava/lang/String;

    move-result-object v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :catchall_0
    move-object v2, v3

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez p2, :cond_7

    if-ne v3, v1, :cond_8

    :cond_7
    new-instance v3, Llyiahf/vczjk/mea;

    const/4 p2, 0x0

    invoke-direct {v3, p0, p2}, Llyiahf/vczjk/mea;-><init>(Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;I)V

    invoke-virtual {v4, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v3, Llyiahf/vczjk/oe3;

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v5, 0x0

    const/4 v1, 0x0

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/os9;->OooOO0o(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto/16 :goto_6

    :cond_9
    :goto_4
    invoke-virtual {p0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOoo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object p2

    invoke-virtual {p2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object p2

    invoke-virtual {p2}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->getLockMethod()I

    move-result p2

    if-ne p2, v0, :cond_11

    invoke-virtual {p0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOoo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object p2

    invoke-virtual {p2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object p2

    invoke-virtual {p2}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->getLockPin()Ljava/lang/String;

    move-result-object p2

    if-eqz p2, :cond_11

    invoke-static {p2}, Llyiahf/vczjk/z69;->OoooOO0(Ljava/lang/CharSequence;)Z

    move-result p2

    if-eqz p2, :cond_a

    goto/16 :goto_5

    :cond_a
    const p2, -0x7aefc495

    invoke-virtual {v4, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v0, p0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->Oooo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    :try_start_1
    invoke-virtual {p0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOoo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object p2

    invoke-virtual {p2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object p2

    invoke-virtual {p2}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->getLockCustomHint()Ljava/lang/String;

    move-result-object v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-object v2, v3

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez p2, :cond_b

    if-ne v3, v1, :cond_c

    :cond_b
    new-instance v3, Llyiahf/vczjk/mea;

    const/4 p2, 0x1

    invoke-direct {v3, p0, p2}, Llyiahf/vczjk/mea;-><init>(Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;I)V

    invoke-virtual {v4, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    check-cast v3, Llyiahf/vczjk/oe3;

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez p2, :cond_d

    if-ne v6, v1, :cond_e

    :cond_d
    new-instance v6, Llyiahf/vczjk/nea;

    const/4 p2, 0x0

    invoke-direct {v6, p0, p2}, Llyiahf/vczjk/nea;-><init>(Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;I)V

    invoke-virtual {v4, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    check-cast v6, Llyiahf/vczjk/le3;

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez p2, :cond_f

    if-ne v5, v1, :cond_10

    :cond_f
    new-instance v5, Llyiahf/vczjk/nea;

    const/4 p2, 0x1

    invoke-direct {v5, p0, p2}, Llyiahf/vczjk/nea;-><init>(Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;I)V

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_10
    check-cast v5, Llyiahf/vczjk/le3;

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v1, 0x0

    move-object v7, v4

    move-object v4, v6

    const/4 v6, 0x0

    const/4 v8, 0x0

    const/16 v9, 0xc2

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/fu6;->OooO0O0(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    move-object v4, v7

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_6

    :cond_11
    :goto_5
    const p2, -0x7ae736b9

    invoke-virtual {v4, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v0, :cond_12

    if-ne v2, v1, :cond_13

    :cond_12
    new-instance v2, Llyiahf/vczjk/pea;

    invoke-direct {v2, p0, v3}, Llyiahf/vczjk/pea;-><init>(Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v4, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    check-cast v2, Llyiahf/vczjk/ze3;

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {p2, v4, v2}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_6

    :cond_14
    const-string p2, "VerifyActivity, bad intent."

    invoke-static {p2}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    invoke-virtual {p0}, Landroid/app/Activity;->finish()V

    :goto_6
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_15

    new-instance v0, Llyiahf/vczjk/oea;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/oea;-><init>(Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;I)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_15
    return-void
.end method

.method public final OooOoo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;
    .locals 1

    iget-object v0, p0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OoooO0:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    return-object v0
.end method

.method public final OooOoo0()V
    .locals 3

    const-string v0, "cancelVerifyAndFinish..."

    invoke-static {v0}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    :try_start_0
    iget-object v0, p0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OoooO00:Llyiahf/vczjk/pc0;

    if-eqz v0, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/zc3;

    const-string v1, "BiometricPromptCompat"

    if-nez v0, :cond_0

    const-string v0, "Unable to start authentication. Client fragment manager was null."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_0

    :cond_0
    const-string v2, "androidx.biometric.BiometricFragment"

    invoke-virtual {v0, v2}, Landroidx/fragment/app/oo000o;->OooOooO(Ljava/lang/String;)Landroidx/fragment/app/Oooo0;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/jc0;

    if-nez v0, :cond_1

    const-string v0, "Unable to cancel authentication. BiometricFragment not found."

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_0

    :cond_1
    const/4 v1, 0x3

    invoke-virtual {v0, v1}, Llyiahf/vczjk/jc0;->OooO0oO(I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    :cond_2
    :goto_0
    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Landroid/app/Activity;->setResult(I)V

    invoke-virtual {p0}, Landroid/app/Activity;->finish()V

    return-void
.end method

.method public final OooOooO()V
    .locals 4

    invoke-virtual {p0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOoo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object v0

    iget v1, p0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->Oooo0oo:I

    const/4 v2, -0x3

    const/4 v3, 0x1

    invoke-virtual {v0, v1, v2, v3}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->setVerifyResult(III)V

    invoke-virtual {p0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOoo0()V

    return-void
.end method

.method public final OooOooo()V
    .locals 4

    invoke-virtual {p0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOoo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object v0

    iget v1, p0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->Oooo0oo:I

    const/4 v2, 0x1

    const/4 v3, 0x0

    invoke-virtual {v0, v1, v2, v3}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->setVerifyResult(III)V

    invoke-static {p0}, Llyiahf/vczjk/yh1;->OooO00o(Landroid/app/Activity;)V

    const/4 v0, -0x1

    invoke-virtual {p0, v0}, Landroid/app/Activity;->setResult(I)V

    invoke-virtual {p0}, Landroid/app/Activity;->finish()V

    return-void
.end method

.method public final onBackPressed()V
    .locals 4

    invoke-virtual {p0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOoo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object v0

    iget v1, p0, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->Oooo0oo:I

    const/4 v2, -0x3

    const/4 v3, -0x1

    invoke-virtual {v0, v1, v2, v3}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->setVerifyResult(III)V

    invoke-virtual {p0}, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/VerifyActivity;->OooOoo0()V

    return-void
.end method
