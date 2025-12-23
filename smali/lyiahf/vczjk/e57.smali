.class public final Llyiahf/vczjk/e57;
.super Llyiahf/vczjk/pm2;
.source "SourceFile"


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/f57;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f57;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/e57;->this$0:Llyiahf/vczjk/f57;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onActivityCreated(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 1

    const-string p2, "activity"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v0, 0x1d

    if-ge p2, v0, :cond_0

    sget p2, Llyiahf/vczjk/xq7;->OooOOO:I

    invoke-virtual {p1}, Landroid/app/Activity;->getFragmentManager()Landroid/app/FragmentManager;

    move-result-object p1

    const-string p2, "androidx.lifecycle.LifecycleDispatcher.report_fragment_tag"

    invoke-virtual {p1, p2}, Landroid/app/FragmentManager;->findFragmentByTag(Ljava/lang/String;)Landroid/app/Fragment;

    move-result-object p1

    const-string p2, "null cannot be cast to non-null type androidx.lifecycle.ReportFragment"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/xq7;

    iget-object p2, p0, Llyiahf/vczjk/e57;->this$0:Llyiahf/vczjk/f57;

    iget-object p2, p2, Llyiahf/vczjk/f57;->OooOo00:Llyiahf/vczjk/oO0OOo0o;

    iput-object p2, p1, Llyiahf/vczjk/xq7;->OooOOO0:Llyiahf/vczjk/oO0OOo0o;

    :cond_0
    return-void
.end method

.method public onActivityPaused(Landroid/app/Activity;)V
    .locals 3

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/e57;->this$0:Llyiahf/vczjk/f57;

    iget v0, p1, Llyiahf/vczjk/f57;->OooOOO:I

    add-int/lit8 v0, v0, -0x1

    iput v0, p1, Llyiahf/vczjk/f57;->OooOOO:I

    if-nez v0, :cond_0

    iget-object v0, p1, Llyiahf/vczjk/f57;->OooOOo0:Landroid/os/Handler;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object p1, p1, Llyiahf/vczjk/f57;->OooOOoo:Llyiahf/vczjk/xy3;

    const-wide/16 v1, 0x2bc

    invoke-virtual {v0, p1, v1, v2}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    :cond_0
    return-void
.end method

.method public onActivityPreCreated(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 1

    const-string p2, "activity"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p2, Llyiahf/vczjk/e57$OooO00o;

    iget-object v0, p0, Llyiahf/vczjk/e57;->this$0:Llyiahf/vczjk/f57;

    invoke-direct {p2, v0}, Llyiahf/vczjk/e57$OooO00o;-><init>(Llyiahf/vczjk/f57;)V

    invoke-static {p1, p2}, Llyiahf/vczjk/xo;->OooOOOo(Landroid/app/Activity;Llyiahf/vczjk/e57$OooO00o;)V

    return-void
.end method

.method public onActivityStopped(Landroid/app/Activity;)V
    .locals 2

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/e57;->this$0:Llyiahf/vczjk/f57;

    iget v0, p1, Llyiahf/vczjk/f57;->OooOOO0:I

    add-int/lit8 v0, v0, -0x1

    iput v0, p1, Llyiahf/vczjk/f57;->OooOOO0:I

    if-nez v0, :cond_0

    iget-boolean v0, p1, Llyiahf/vczjk/f57;->OooOOOO:Z

    if-eqz v0, :cond_0

    iget-object v0, p1, Llyiahf/vczjk/f57;->OooOOo:Llyiahf/vczjk/wy4;

    sget-object v1, Llyiahf/vczjk/iy4;->ON_STOP:Llyiahf/vczjk/iy4;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/wy4;->OooO0o(Llyiahf/vczjk/iy4;)V

    const/4 v0, 0x1

    iput-boolean v0, p1, Llyiahf/vczjk/f57;->OooOOOo:Z

    :cond_0
    return-void
.end method
