.class public final Llyiahf/vczjk/cj4;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bj4;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/oe3;

.field public OooOoo0:Llyiahf/vczjk/rm4;


# virtual methods
.method public final OooO0oO(Landroid/view/KeyEvent;)Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/cj4;->OooOoo0:Llyiahf/vczjk/rm4;

    if-eqz v0, :cond_0

    new-instance v1, Llyiahf/vczjk/vi4;

    invoke-direct {v1, p1}, Llyiahf/vczjk/vi4;-><init>(Landroid/view/KeyEvent;)V

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooOOo(Landroid/view/KeyEvent;)Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/cj4;->OooOoOO:Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_0

    new-instance v1, Llyiahf/vczjk/vi4;

    invoke-direct {v1, p1}, Llyiahf/vczjk/vi4;-><init>(Landroid/view/KeyEvent;)V

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method
