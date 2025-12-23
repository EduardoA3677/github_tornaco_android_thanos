.class public Llyiahf/vczjk/xi7;
.super Llyiahf/vczjk/n80;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/n80;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/String;)V
    .locals 1

    sget v0, Lgithub/tornaco/android/thanos/R$xml;->recent_task_blur_pref:I

    invoke-virtual {p0, v0, p1}, Llyiahf/vczjk/j27;->OooOO0(ILjava/lang/String;)V

    return-void
.end method

.method public final OooO0oo()V
    .locals 5

    invoke-virtual {p0}, Landroidx/fragment/app/Oooo0;->getContext()Landroid/content/Context;

    move-result-object v0

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v1

    const/4 v2, 0x0

    if-nez v1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/j27;->OooOOO:Llyiahf/vczjk/n27;

    iget-object v0, v0, Llyiahf/vczjk/n27;->OooO0oO:Landroidx/preference/PreferenceScreen;

    invoke-virtual {v0, v2}, Landroidx/preference/Preference;->OooOo0(Z)V

    return-void

    :cond_0
    sget v1, Lgithub/tornaco/android/thanos/R$string;->key_recent_task_blur_mode:I

    invoke-virtual {p0, v1}, Landroidx/fragment/app/Oooo0;->getString(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0, v1}, Llyiahf/vczjk/j27;->OooO0oO(Ljava/lang/CharSequence;)Landroidx/preference/Preference;

    move-result-object v1

    check-cast v1, Landroidx/preference/SwitchPreferenceCompat;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v3

    const-string v4, "android"

    invoke-static {v4}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->systemUserPkg(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v4

    invoke-virtual {v3, v4}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->getPkgRecentTaskBlurMode(Lgithub/tornaco/android/thanos/core/pm/Pkg;)I

    move-result v3

    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v4, 0x2

    if-ne v3, v4, :cond_1

    const/4 v2, 0x1

    :cond_1
    invoke-virtual {v1, v2}, Landroidx/preference/TwoStatePreference;->OooOoOO(Z)V

    new-instance v2, Llyiahf/vczjk/ob0;

    const/16 v3, 0x9

    invoke-direct {v2, v3, v0}, Llyiahf/vczjk/ob0;-><init>(ILgithub/tornaco/android/thanos/core/app/ThanosManager;)V

    iput-object v2, v1, Landroidx/preference/Preference;->OooOOo0:Llyiahf/vczjk/s17;

    return-void
.end method
