.class public abstract Llyiahf/vczjk/vq7;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static OooO00o(Landroid/app/Activity;Llyiahf/vczjk/iy4;)V
    .locals 1

    const-string v0, "event"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p0, Llyiahf/vczjk/uy4;

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/uy4;

    invoke-interface {p0}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object p0

    instance-of v0, p0, Llyiahf/vczjk/wy4;

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/wy4;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/wy4;->OooO0o(Llyiahf/vczjk/iy4;)V

    :cond_0
    return-void
.end method

.method public static OooO0O0(Landroid/app/Activity;)V
    .locals 3

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1d

    if-lt v0, v1, :cond_0

    sget-object v0, Llyiahf/vczjk/xq7$OooO00o;->Companion:Llyiahf/vczjk/wq7;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/xq7$OooO00o;

    invoke-direct {v0}, Llyiahf/vczjk/xq7$OooO00o;-><init>()V

    invoke-static {p0, v0}, Llyiahf/vczjk/hp7;->OooOOO0(Landroid/app/Activity;Llyiahf/vczjk/xq7$OooO00o;)V

    :cond_0
    invoke-virtual {p0}, Landroid/app/Activity;->getFragmentManager()Landroid/app/FragmentManager;

    move-result-object p0

    const-string v0, "androidx.lifecycle.LifecycleDispatcher.report_fragment_tag"

    invoke-virtual {p0, v0}, Landroid/app/FragmentManager;->findFragmentByTag(Ljava/lang/String;)Landroid/app/Fragment;

    move-result-object v1

    if-nez v1, :cond_1

    invoke-virtual {p0}, Landroid/app/FragmentManager;->beginTransaction()Landroid/app/FragmentTransaction;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/xq7;

    invoke-direct {v2}, Llyiahf/vczjk/xq7;-><init>()V

    invoke-virtual {v1, v2, v0}, Landroid/app/FragmentTransaction;->add(Landroid/app/Fragment;Ljava/lang/String;)Landroid/app/FragmentTransaction;

    move-result-object v0

    invoke-virtual {v0}, Landroid/app/FragmentTransaction;->commit()I

    invoke-virtual {p0}, Landroid/app/FragmentManager;->executePendingTransactions()Z

    :cond_1
    return-void
.end method
