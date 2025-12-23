.class public abstract Landroidx/compose/foundation/selection/OooO00o;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static final OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/rr5;ZLlyiahf/vczjk/gu7;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;
    .locals 6

    new-instance v0, Landroidx/compose/foundation/selection/SelectableElement;

    move v1, p1

    move-object v2, p2

    move v3, p3

    move-object v4, p4

    move-object v5, p5

    invoke-direct/range {v0 .. v5}, Landroidx/compose/foundation/selection/SelectableElement;-><init>(ZLlyiahf/vczjk/rr5;ZLlyiahf/vczjk/gu7;Llyiahf/vczjk/le3;)V

    invoke-interface {p0, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0O0(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/du7;ZLlyiahf/vczjk/gu7;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;
    .locals 8

    if-eqz p3, :cond_0

    new-instance v0, Landroidx/compose/foundation/selection/ToggleableElement;

    move v1, p1

    move-object v2, p2

    move-object v3, p3

    move v4, p4

    move-object v5, p5

    move-object v6, p6

    invoke-direct/range {v0 .. v6}, Landroidx/compose/foundation/selection/ToggleableElement;-><init>(ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/px3;ZLlyiahf/vczjk/gu7;Llyiahf/vczjk/oe3;)V

    goto :goto_0

    :cond_0
    move v2, p1

    move-object v3, p2

    move-object p2, p3

    move v5, p4

    move-object v6, p5

    move-object v7, p6

    if-nez p2, :cond_1

    new-instance v1, Landroidx/compose/foundation/selection/ToggleableElement;

    const/4 v4, 0x0

    invoke-direct/range {v1 .. v7}, Landroidx/compose/foundation/selection/ToggleableElement;-><init>(ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/px3;ZLlyiahf/vczjk/gu7;Llyiahf/vczjk/oe3;)V

    move-object v0, v1

    goto :goto_0

    :cond_1
    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    if-eqz v3, :cond_2

    invoke-static {v0, v3, p2}, Landroidx/compose/foundation/OooO0o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/n24;Llyiahf/vczjk/lx3;)Llyiahf/vczjk/kl5;

    move-result-object p1

    new-instance v1, Landroidx/compose/foundation/selection/ToggleableElement;

    const/4 v4, 0x0

    invoke-direct/range {v1 .. v7}, Landroidx/compose/foundation/selection/ToggleableElement;-><init>(ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/px3;ZLlyiahf/vczjk/gu7;Llyiahf/vczjk/oe3;)V

    invoke-interface {p1, v1}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    goto :goto_0

    :cond_2
    new-instance p1, Landroidx/compose/foundation/selection/OooO0O0;

    move p3, v2

    move p4, v5

    move-object p5, v6

    move-object p6, v7

    invoke-direct/range {p1 .. p6}, Landroidx/compose/foundation/selection/OooO0O0;-><init>(Llyiahf/vczjk/du7;ZZLlyiahf/vczjk/gu7;Llyiahf/vczjk/oe3;)V

    invoke-static {v0, p1}, Llyiahf/vczjk/ng0;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object v0

    :goto_0
    invoke-interface {p0, v0}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0OO(Llyiahf/vczjk/le3;Llyiahf/vczjk/du7;Llyiahf/vczjk/gu7;Llyiahf/vczjk/gt9;Z)Llyiahf/vczjk/kl5;
    .locals 7

    const/4 v2, 0x0

    if-eqz p1, :cond_0

    new-instance v0, Landroidx/compose/foundation/selection/TriStateToggleableElement;

    move-object v6, p0

    move-object v3, p1

    move-object v5, p2

    move-object v1, p3

    move v4, p4

    invoke-direct/range {v0 .. v6}, Landroidx/compose/foundation/selection/TriStateToggleableElement;-><init>(Llyiahf/vczjk/gt9;Llyiahf/vczjk/rr5;Llyiahf/vczjk/px3;ZLlyiahf/vczjk/gu7;Llyiahf/vczjk/le3;)V

    return-object v0

    :cond_0
    move-object v6, p0

    move-object v3, p1

    move-object v5, p2

    move-object v1, p3

    move v4, p4

    if-nez v3, :cond_1

    new-instance v0, Landroidx/compose/foundation/selection/TriStateToggleableElement;

    const/4 v3, 0x0

    invoke-direct/range {v0 .. v6}, Landroidx/compose/foundation/selection/TriStateToggleableElement;-><init>(Llyiahf/vczjk/gt9;Llyiahf/vczjk/rr5;Llyiahf/vczjk/px3;ZLlyiahf/vczjk/gu7;Llyiahf/vczjk/le3;)V

    return-object v0

    :cond_1
    sget-object p0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    move-object v2, v6

    move v6, v4

    move-object v4, v5

    move-object v5, v1

    new-instance v1, Landroidx/compose/foundation/selection/OooO0OO;

    invoke-direct/range {v1 .. v6}, Landroidx/compose/foundation/selection/OooO0OO;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/du7;Llyiahf/vczjk/gu7;Llyiahf/vczjk/gt9;Z)V

    invoke-static {p0, v1}, Llyiahf/vczjk/ng0;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method
