.class public final Llyiahf/vczjk/g68;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/h68;

.field public final OooO0O0:Llyiahf/vczjk/ku7;

.field public final OooO0OO:Llyiahf/vczjk/rp3;

.field public final OooO0Oo:Ljava/util/LinkedHashMap;

.field public OooO0o:Landroid/os/Bundle;

.field public OooO0o0:Z

.field public OooO0oO:Z

.field public OooO0oo:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/h68;Llyiahf/vczjk/ku7;)V
    .locals 1

    const-string v0, "owner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/g68;->OooO00o:Llyiahf/vczjk/h68;

    iput-object p2, p0, Llyiahf/vczjk/g68;->OooO0O0:Llyiahf/vczjk/ku7;

    new-instance p1, Llyiahf/vczjk/rp3;

    const/16 p2, 0x19

    invoke-direct {p1, p2}, Llyiahf/vczjk/rp3;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/g68;->OooO0OO:Llyiahf/vczjk/rp3;

    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/g68;->OooO0Oo:Ljava/util/LinkedHashMap;

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/g68;->OooO0oo:Z

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/g68;->OooO00o:Llyiahf/vczjk/h68;

    invoke-interface {v0}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/ky4;->OooO0O0()Llyiahf/vczjk/jy4;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/jy4;->OooOOO:Llyiahf/vczjk/jy4;

    if-ne v1, v2, :cond_1

    iget-boolean v1, p0, Llyiahf/vczjk/g68;->OooO0o0:Z

    if-nez v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/g68;->OooO0O0:Llyiahf/vczjk/ku7;

    invoke-virtual {v1}, Llyiahf/vczjk/ku7;->OooO00o()Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/o0OO00o0;

    const/4 v2, 0x3

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/o0OO00o0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ky4;->OooO00o(Llyiahf/vczjk/ty4;)V

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/g68;->OooO0o0:Z

    return-void

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "SavedStateRegistry was already attached."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Restarter must be created only during owner\'s initialization stage"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
