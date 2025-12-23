.class public abstract Landroidx/compose/ui/layout/OooO00o;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final OooO00o(Llyiahf/vczjk/ef5;)Ljava/lang/Object;
    .locals 2

    invoke-interface {p0}, Llyiahf/vczjk/ef5;->OooOoo()Ljava/lang/Object;

    move-result-object p0

    instance-of v0, p0, Llyiahf/vczjk/ao4;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/ao4;

    goto :goto_0

    :cond_0
    move-object p0, v1

    :goto_0
    if-eqz p0, :cond_1

    iget-object p0, p0, Llyiahf/vczjk/ao4;->OooOoOO:Ljava/lang/Object;

    return-object p0

    :cond_1
    return-object v1
.end method

.method public static final OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;
    .locals 1

    new-instance v0, Landroidx/compose/ui/layout/LayoutElement;

    invoke-direct {v0, p1}, Landroidx/compose/ui/layout/LayoutElement;-><init>(Llyiahf/vczjk/bf3;)V

    invoke-interface {p0, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0OO(Llyiahf/vczjk/kl5;Ljava/lang/Object;)Llyiahf/vczjk/kl5;
    .locals 1

    new-instance v0, Landroidx/compose/ui/layout/LayoutIdElement;

    invoke-direct {v0, p1}, Landroidx/compose/ui/layout/LayoutIdElement;-><init>(Ljava/lang/Object;)V

    invoke-interface {p0, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;
    .locals 1

    new-instance v0, Landroidx/compose/ui/layout/OnGloballyPositionedElement;

    invoke-direct {v0, p1}, Landroidx/compose/ui/layout/OnGloballyPositionedElement;-><init>(Llyiahf/vczjk/oe3;)V

    invoke-interface {p0, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;
    .locals 1

    new-instance v0, Landroidx/compose/ui/layout/OnSizeChangedModifier;

    invoke-direct {v0, p1}, Landroidx/compose/ui/layout/OnSizeChangedModifier;-><init>(Llyiahf/vczjk/oe3;)V

    invoke-interface {p0, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method
