.class public final Llyiahf/vczjk/k25;
.super Llyiahf/vczjk/l25;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sy4;


# instance fields
.field public final synthetic OooOOo:Llyiahf/vczjk/m25;

.field public final OooOOo0:Llyiahf/vczjk/uy4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/m25;Llyiahf/vczjk/uy4;Llyiahf/vczjk/k86;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/k25;->OooOOo:Llyiahf/vczjk/m25;

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/l25;-><init>(Llyiahf/vczjk/m25;Llyiahf/vczjk/k86;)V

    iput-object p2, p0, Llyiahf/vczjk/k25;->OooOOo0:Llyiahf/vczjk/uy4;

    return-void
.end method


# virtual methods
.method public final OooO0O0()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/k25;->OooOOo0:Llyiahf/vczjk/uy4;

    invoke-interface {v0}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v0

    invoke-virtual {v0, p0}, Llyiahf/vczjk/ky4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    return-void
.end method

.method public final OooO0OO(Llyiahf/vczjk/uy4;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/k25;->OooOOo0:Llyiahf/vczjk/uy4;

    if-ne v0, p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/uy4;Llyiahf/vczjk/iy4;)V
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/k25;->OooOOo0:Llyiahf/vczjk/uy4;

    invoke-interface {p1}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object p2

    invoke-virtual {p2}, Llyiahf/vczjk/ky4;->OooO0O0()Llyiahf/vczjk/jy4;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/jy4;->OooOOO0:Llyiahf/vczjk/jy4;

    if-ne p2, v0, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/k25;->OooOOo:Llyiahf/vczjk/m25;

    iget-object p2, p0, Llyiahf/vczjk/l25;->OooOOO0:Llyiahf/vczjk/k86;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/m25;->OooO0oo(Llyiahf/vczjk/k86;)V

    return-void

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eq v0, p2, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/k25;->OooO0o0()Z

    move-result v0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/l25;->OooO00o(Z)V

    invoke-interface {p1}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ky4;->OooO0O0()Llyiahf/vczjk/jy4;

    move-result-object v0

    move-object v1, v0

    move-object v0, p2

    move-object p2, v1

    goto :goto_0

    :cond_1
    return-void
.end method

.method public final OooO0o0()Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/k25;->OooOOo0:Llyiahf/vczjk/uy4;

    invoke-interface {v0}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ky4;->OooO0O0()Llyiahf/vczjk/jy4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/jy4;->OooOOOo:Llyiahf/vczjk/jy4;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/jy4;->OooO00o(Llyiahf/vczjk/jy4;)Z

    move-result v0

    return v0
.end method
