.class public abstract Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;
.super Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/mg3;


# instance fields
.field public volatile Oooo:Llyiahf/vczjk/oO0O0O00;

.field public Oooo0oo:Llyiahf/vczjk/as7;

.field public OoooO0:Z

.field public final OoooO00:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;-><init>()V

    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;->OoooO00:Ljava/lang/Object;

    const/4 v0, 0x0

    iput-boolean v0, p0, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;->OoooO0:Z

    new-instance v0, Llyiahf/vczjk/pq;

    const/16 v1, 0xf

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/pq;-><init>(Landroidx/appcompat/app/AppCompatActivity;I)V

    invoke-virtual {p0, v0}, Landroidx/activity/ComponentActivity;->OooOOo0(Llyiahf/vczjk/qa6;)V

    return-void
.end method


# virtual methods
.method public final OooO0O0()Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;->OooOoo0()Llyiahf/vczjk/oO0O0O00;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/oO0O0O00;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final OooOoo0()Llyiahf/vczjk/oO0O0O00;
    .locals 2

    iget-object v0, p0, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;->Oooo:Llyiahf/vczjk/oO0O0O00;

    if-nez v0, :cond_1

    iget-object v0, p0, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;->OoooO00:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;->Oooo:Llyiahf/vczjk/oO0O0O00;

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/oO0O0O00;

    invoke-direct {v1, p0}, Llyiahf/vczjk/oO0O0O00;-><init>(Landroid/app/Activity;)V

    iput-object v1, p0, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;->Oooo:Llyiahf/vczjk/oO0O0O00;

    goto :goto_0

    :catchall_0
    move-exception v1

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit v0

    goto :goto_2

    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v1

    :cond_1
    :goto_2
    iget-object v0, p0, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;->Oooo:Llyiahf/vczjk/oO0O0O00;

    return-object v0
.end method

.method public final getDefaultViewModelProviderFactory()Llyiahf/vczjk/hha;
    .locals 1

    invoke-super {p0}, Landroidx/activity/ComponentActivity;->getDefaultViewModelProviderFactory()Llyiahf/vczjk/hha;

    move-result-object v0

    invoke-static {p0, v0}, Llyiahf/vczjk/mc4;->OooOooo(Landroidx/activity/ComponentActivity;Llyiahf/vczjk/hha;)Llyiahf/vczjk/sn3;

    move-result-object v0

    return-object v0
.end method

.method public final onCreate(Landroid/os/Bundle;)V
    .locals 1

    invoke-super {p0, p1}, Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;->onCreate(Landroid/os/Bundle;)V

    invoke-virtual {p0}, Landroid/app/Activity;->getApplication()Landroid/app/Application;

    move-result-object p1

    instance-of p1, p1, Llyiahf/vczjk/mg3;

    if-eqz p1, :cond_0

    invoke-virtual {p0}, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;->OooOoo0()Llyiahf/vczjk/oO0O0O00;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/oO0O0O00;->OooO0OO()Llyiahf/vczjk/as7;

    move-result-object p1

    iput-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;->Oooo0oo:Llyiahf/vczjk/as7;

    invoke-virtual {p1}, Llyiahf/vczjk/as7;->OooO0O0()Z

    move-result p1

    if-eqz p1, :cond_0

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;->Oooo0oo:Llyiahf/vczjk/as7;

    invoke-virtual {p0}, Landroidx/activity/ComponentActivity;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ir5;

    iput-object v0, p1, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    :cond_0
    return-void
.end method

.method public final onDestroy()V
    .locals 2

    invoke-super {p0}, Landroidx/appcompat/app/AppCompatActivity;->onDestroy()V

    iget-object v0, p0, Lgithub/tornaco/thanos/android/module/profile/engine/Hilt_NewRegularIntervalActivity;->Oooo0oo:Llyiahf/vczjk/as7;

    if-eqz v0, :cond_0

    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    :cond_0
    return-void
.end method
