.class public Llyiahf/vczjk/et8;
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

    sget v0, Lgithub/tornaco/android/thanos/R$xml;->smart_standby_pref:I

    invoke-virtual {p0, v0, p1}, Llyiahf/vczjk/j27;->OooOO0(ILjava/lang/String;)V

    return-void
.end method

.method public final OooO0oo()V
    .locals 4

    invoke-virtual {p0}, Landroidx/fragment/app/Oooo0;->getContext()Landroid/content/Context;

    move-result-object v0

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v1

    if-nez v1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/j27;->OooOOO:Llyiahf/vczjk/n27;

    iget-object v0, v0, Llyiahf/vczjk/n27;->OooO0oO:Landroidx/preference/PreferenceScreen;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroidx/preference/Preference;->OooOo0(Z)V

    return-void

    :cond_0
    sget v1, Lgithub/tornaco/android/thanos/R$string;->key_smart_standby_stop_service:I

    invoke-virtual {p0, v1}, Landroidx/fragment/app/Oooo0;->getString(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0, v1}, Llyiahf/vczjk/j27;->OooO0oO(Ljava/lang/CharSequence;)Landroidx/preference/Preference;

    move-result-object v1

    check-cast v1, Landroidx/preference/SwitchPreferenceCompat;

    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isSmartStandByStopServiceEnabled()Z

    move-result v2

    invoke-virtual {v1, v2}, Landroidx/preference/TwoStatePreference;->OooOoOO(Z)V

    new-instance v2, Llyiahf/vczjk/h87;

    const/4 v3, 0x4

    invoke-direct {v2, v0, v3}, Llyiahf/vczjk/h87;-><init>(Ljava/lang/Object;I)V

    iput-object v2, v1, Landroidx/preference/Preference;->OooOOo0:Llyiahf/vczjk/s17;

    sget v1, Lgithub/tornaco/android/thanos/R$string;->key_smart_standby_unbind_service:I

    invoke-virtual {p0, v1}, Landroidx/fragment/app/Oooo0;->getString(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0, v1}, Llyiahf/vczjk/j27;->OooO0oO(Ljava/lang/CharSequence;)Landroidx/preference/Preference;

    move-result-object v1

    check-cast v1, Landroidx/preference/SwitchPreferenceCompat;

    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isSmartStandByUnbindServiceEnabled()Z

    move-result v2

    invoke-virtual {v1, v2}, Landroidx/preference/TwoStatePreference;->OooOoOO(Z)V

    new-instance v2, Llyiahf/vczjk/bh6;

    invoke-direct {v2, v0}, Llyiahf/vczjk/bh6;-><init>(Ljava/lang/Object;)V

    iput-object v2, v1, Landroidx/preference/Preference;->OooOOo0:Llyiahf/vczjk/s17;

    sget v1, Lgithub/tornaco/android/thanos/R$string;->key_smart_standby_set_inactive:I

    invoke-virtual {p0, v1}, Landroidx/fragment/app/Oooo0;->getString(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0, v1}, Llyiahf/vczjk/j27;->OooO0oO(Ljava/lang/CharSequence;)Landroidx/preference/Preference;

    move-result-object v1

    check-cast v1, Landroidx/preference/SwitchPreferenceCompat;

    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isSmartStandByInactiveEnabled()Z

    move-result v2

    invoke-virtual {v1, v2}, Landroidx/preference/TwoStatePreference;->OooOoOO(Z)V

    new-instance v2, Llyiahf/vczjk/gv7;

    invoke-direct {v2, v0}, Llyiahf/vczjk/gv7;-><init>(Ljava/lang/Object;)V

    iput-object v2, v1, Landroidx/preference/Preference;->OooOOo0:Llyiahf/vczjk/s17;

    sget v1, Lgithub/tornaco/android/thanos/R$string;->key_smart_standby_bypass_if_has_n:I

    invoke-virtual {p0, v1}, Landroidx/fragment/app/Oooo0;->getString(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0, v1}, Llyiahf/vczjk/j27;->OooO0oO(Ljava/lang/CharSequence;)Landroidx/preference/Preference;

    move-result-object v1

    check-cast v1, Landroidx/preference/SwitchPreferenceCompat;

    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isSmartStandByByPassIfHasNotificationEnabled()Z

    move-result v2

    invoke-virtual {v1, v2}, Landroidx/preference/TwoStatePreference;->OooOoOO(Z)V

    new-instance v2, Llyiahf/vczjk/wg7;

    invoke-direct {v2, v0}, Llyiahf/vczjk/wg7;-><init>(Ljava/lang/Object;)V

    iput-object v2, v1, Landroidx/preference/Preference;->OooOOo0:Llyiahf/vczjk/s17;

    sget v1, Lgithub/tornaco/android/thanos/R$string;->key_smart_standby_bypass_if_has_visible_windows:I

    invoke-virtual {p0, v1}, Landroidx/fragment/app/Oooo0;->getString(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0, v1}, Llyiahf/vczjk/j27;->OooO0oO(Ljava/lang/CharSequence;)Landroidx/preference/Preference;

    move-result-object v1

    check-cast v1, Landroidx/preference/SwitchPreferenceCompat;

    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isSmartStandByByPassIfHasVisibleWindows()Z

    move-result v2

    invoke-virtual {v1, v2}, Landroidx/preference/TwoStatePreference;->OooOoOO(Z)V

    new-instance v2, Llyiahf/vczjk/as7;

    invoke-direct {v2, v0}, Llyiahf/vczjk/as7;-><init>(Ljava/lang/Object;)V

    iput-object v2, v1, Landroidx/preference/Preference;->OooOOo0:Llyiahf/vczjk/s17;

    sget v1, Lgithub/tornaco/android/thanos/R$string;->key_smart_standby_block_bg_service_start:I

    invoke-virtual {p0, v1}, Landroidx/fragment/app/Oooo0;->getString(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0, v1}, Llyiahf/vczjk/j27;->OooO0oO(Ljava/lang/CharSequence;)Landroidx/preference/Preference;

    move-result-object v1

    check-cast v1, Landroidx/preference/SwitchPreferenceCompat;

    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isSmartStandByBlockBgServiceStartEnabled()Z

    move-result v2

    invoke-virtual {v1, v2}, Landroidx/preference/TwoStatePreference;->OooOoOO(Z)V

    new-instance v2, Llyiahf/vczjk/fk7;

    invoke-direct {v2, v0}, Llyiahf/vczjk/fk7;-><init>(Ljava/lang/Object;)V

    iput-object v2, v1, Landroidx/preference/Preference;->OooOOo0:Llyiahf/vczjk/s17;

    return-void
.end method
