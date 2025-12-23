.class public final Llyiahf/vczjk/ey4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/u22;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/fy4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fy4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ey4;->OooOOO0:Llyiahf/vczjk/fy4;

    return-void
.end method


# virtual methods
.method public final OooO0oO(Llyiahf/vczjk/uy4;)V
    .locals 2

    const-string v0, "owner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/ey4;->OooOOO0:Llyiahf/vczjk/fy4;

    const-string v0, "onResume"

    iget-object v1, p1, Llyiahf/vczjk/fy4;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    invoke-virtual {v1, v0}, Lgithub/tornaco/android/thanos/core/Logger;->w(Ljava/lang/Object;)V

    invoke-virtual {p1}, Llyiahf/vczjk/fy4;->OooO0o()V

    return-void
.end method

.method public final onDestroy(Llyiahf/vczjk/uy4;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ey4;->OooOOO0:Llyiahf/vczjk/fy4;

    const-string v1, "onDestroy"

    iget-object v0, v0, Llyiahf/vczjk/fy4;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    invoke-virtual {v0, v1}, Lgithub/tornaco/android/thanos/core/Logger;->w(Ljava/lang/Object;)V

    invoke-interface {p1}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object p1

    invoke-virtual {p1, p0}, Llyiahf/vczjk/ky4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    return-void
.end method

.method public final onStop(Llyiahf/vczjk/uy4;)V
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/ey4;->OooOOO0:Llyiahf/vczjk/fy4;

    const-string v0, "onStop"

    iget-object v1, p1, Llyiahf/vczjk/fy4;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    invoke-virtual {v1, v0}, Lgithub/tornaco/android/thanos/core/Logger;->w(Ljava/lang/Object;)V

    invoke-virtual {p1}, Llyiahf/vczjk/fy4;->OooO0oO()V

    return-void
.end method
