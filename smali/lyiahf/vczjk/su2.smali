.class public abstract Llyiahf/vczjk/su2;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static OooO00o(Llyiahf/vczjk/zoa;Landroidx/window/extensions/layout/FoldingFeature;)Llyiahf/vczjk/nm3;
    .locals 6

    const-string v0, "windowMetrics"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Landroidx/window/extensions/layout/FoldingFeature;->getType()I

    move-result v0

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v2, :cond_1

    if-eq v0, v1, :cond_0

    goto/16 :goto_2

    :cond_0
    sget-object v0, Llyiahf/vczjk/mm3;->OooO0Oo:Llyiahf/vczjk/mm3;

    goto :goto_0

    :cond_1
    sget-object v0, Llyiahf/vczjk/mm3;->OooO0OO:Llyiahf/vczjk/mm3;

    :goto_0
    invoke-virtual {p1}, Landroidx/window/extensions/layout/FoldingFeature;->getState()I

    move-result v3

    if-eq v3, v2, :cond_3

    if-eq v3, v1, :cond_2

    goto :goto_2

    :cond_2
    sget-object v1, Llyiahf/vczjk/tqa;->OooOOOo:Llyiahf/vczjk/tqa;

    goto :goto_1

    :cond_3
    sget-object v1, Llyiahf/vczjk/tqa;->OooOOOO:Llyiahf/vczjk/tqa;

    :goto_1
    new-instance v2, Llyiahf/vczjk/ug0;

    invoke-virtual {p1}, Landroidx/window/extensions/layout/FoldingFeature;->getBounds()Landroid/graphics/Rect;

    move-result-object v3

    const-string v4, "getBounds(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v2, v3}, Llyiahf/vczjk/ug0;-><init>(Landroid/graphics/Rect;)V

    iget-object p0, p0, Llyiahf/vczjk/zoa;->OooO00o:Llyiahf/vczjk/ug0;

    invoke-virtual {p0}, Llyiahf/vczjk/ug0;->OooO0OO()Landroid/graphics/Rect;

    move-result-object p0

    invoke-virtual {v2}, Llyiahf/vczjk/ug0;->OooO00o()I

    move-result v3

    if-nez v3, :cond_4

    invoke-virtual {v2}, Llyiahf/vczjk/ug0;->OooO0O0()I

    move-result v3

    if-nez v3, :cond_4

    goto :goto_2

    :cond_4
    invoke-virtual {v2}, Llyiahf/vczjk/ug0;->OooO0O0()I

    move-result v3

    invoke-virtual {p0}, Landroid/graphics/Rect;->width()I

    move-result v5

    if-eq v3, v5, :cond_5

    invoke-virtual {v2}, Llyiahf/vczjk/ug0;->OooO00o()I

    move-result v3

    invoke-virtual {p0}, Landroid/graphics/Rect;->height()I

    move-result v5

    if-eq v3, v5, :cond_5

    goto :goto_2

    :cond_5
    invoke-virtual {v2}, Llyiahf/vczjk/ug0;->OooO0O0()I

    move-result v3

    invoke-virtual {p0}, Landroid/graphics/Rect;->width()I

    move-result v5

    if-ge v3, v5, :cond_6

    invoke-virtual {v2}, Llyiahf/vczjk/ug0;->OooO00o()I

    move-result v3

    invoke-virtual {p0}, Landroid/graphics/Rect;->height()I

    move-result v5

    if-ge v3, v5, :cond_6

    goto :goto_2

    :cond_6
    invoke-virtual {v2}, Llyiahf/vczjk/ug0;->OooO0O0()I

    move-result v3

    invoke-virtual {p0}, Landroid/graphics/Rect;->width()I

    move-result v5

    if-ne v3, v5, :cond_7

    invoke-virtual {v2}, Llyiahf/vczjk/ug0;->OooO00o()I

    move-result v2

    invoke-virtual {p0}, Landroid/graphics/Rect;->height()I

    move-result p0

    if-ne v2, p0, :cond_7

    :goto_2
    const/4 p0, 0x0

    return-object p0

    :cond_7
    new-instance p0, Llyiahf/vczjk/nm3;

    new-instance v2, Llyiahf/vczjk/ug0;

    invoke-virtual {p1}, Landroidx/window/extensions/layout/FoldingFeature;->getBounds()Landroid/graphics/Rect;

    move-result-object p1

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v2, p1}, Llyiahf/vczjk/ug0;-><init>(Landroid/graphics/Rect;)V

    invoke-direct {p0, v2, v0, v1}, Llyiahf/vczjk/nm3;-><init>(Llyiahf/vczjk/ug0;Llyiahf/vczjk/mm3;Llyiahf/vczjk/tqa;)V

    return-object p0
.end method

.method public static OooO0O0(Landroid/content/Context;Landroidx/window/extensions/layout/WindowLayoutInfo;)Llyiahf/vczjk/voa;
    .locals 12

    const-string v0, "context"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "info"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x22

    if-lt v0, v1, :cond_0

    sget-object v2, Llyiahf/vczjk/h62;->OooOOO0:Llyiahf/vczjk/h62;

    goto :goto_0

    :cond_0
    sget-object v2, Llyiahf/vczjk/xj0;->OooOOo0:Llyiahf/vczjk/xj0;

    :goto_0
    const/4 v3, 0x1

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    const/4 v3, 0x2

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    const/4 v3, 0x4

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    const/16 v3, 0x8

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    const/16 v3, 0x10

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    const/16 v3, 0x20

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    const/16 v3, 0x40

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    const/16 v3, 0x80

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    filled-new-array/range {v4 .. v11}, [Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/e21;->Oooo0o0([Ljava/lang/Object;)Ljava/util/ArrayList;

    sget-object v3, Llyiahf/vczjk/qp3;->OooOo0O:Llyiahf/vczjk/qp3;

    sget-object v4, Llyiahf/vczjk/zg0;->OooOOOo:Llyiahf/vczjk/zg0;

    sget-object v5, Llyiahf/vczjk/h62;->OooOOO:Llyiahf/vczjk/h62;

    const/16 v6, 0x1e

    if-lt v0, v6, :cond_3

    if-lt v0, v1, :cond_1

    move-object v3, v5

    goto :goto_1

    :cond_1
    if-lt v0, v6, :cond_2

    move-object v3, v4

    :cond_2
    :goto_1
    invoke-interface {v3, p0, v2}, Llyiahf/vczjk/apa;->OooOO0o(Landroid/content/Context;Llyiahf/vczjk/g62;)Llyiahf/vczjk/zoa;

    move-result-object p0

    invoke-static {p0, p1}, Llyiahf/vczjk/su2;->OooO0OO(Llyiahf/vczjk/zoa;Landroidx/window/extensions/layout/WindowLayoutInfo;)Llyiahf/vczjk/voa;

    move-result-object p0

    return-object p0

    :cond_3
    const/16 v7, 0x1d

    if-lt v0, v7, :cond_6

    instance-of v7, p0, Landroid/app/Activity;

    if-eqz v7, :cond_6

    check-cast p0, Landroid/app/Activity;

    if-lt v0, v1, :cond_4

    move-object v3, v5

    goto :goto_2

    :cond_4
    if-lt v0, v6, :cond_5

    move-object v3, v4

    :cond_5
    :goto_2
    invoke-interface {v3, p0, v2}, Llyiahf/vczjk/apa;->OooOOOO(Landroid/app/Activity;Llyiahf/vczjk/g62;)Llyiahf/vczjk/zoa;

    move-result-object p0

    invoke-static {p0, p1}, Llyiahf/vczjk/su2;->OooO0OO(Llyiahf/vczjk/zoa;Landroidx/window/extensions/layout/WindowLayoutInfo;)Llyiahf/vczjk/voa;

    move-result-object p0

    return-object p0

    :cond_6
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    const-string p1, "Display Features are only supported after Q. Display features for non-Activity contexts are not expected to be reported on devices running Q."

    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static OooO0OO(Llyiahf/vczjk/zoa;Landroidx/window/extensions/layout/WindowLayoutInfo;)Llyiahf/vczjk/voa;
    .locals 3

    const-string v0, "windowMetrics"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "info"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Landroidx/window/extensions/layout/WindowLayoutInfo;->getDisplayFeatures()Ljava/util/List;

    move-result-object p1

    const-string v0, "getDisplayFeatures(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/window/extensions/layout/DisplayFeature;

    instance-of v2, v1, Landroidx/window/extensions/layout/FoldingFeature;

    if-eqz v2, :cond_1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v1, Landroidx/window/extensions/layout/FoldingFeature;

    invoke-static {p0, v1}, Llyiahf/vczjk/su2;->OooO00o(Llyiahf/vczjk/zoa;Landroidx/window/extensions/layout/FoldingFeature;)Llyiahf/vczjk/nm3;

    move-result-object v1

    goto :goto_1

    :cond_1
    const/4 v1, 0x0

    :goto_1
    if-eqz v1, :cond_0

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    new-instance p0, Llyiahf/vczjk/voa;

    invoke-direct {p0, v0}, Llyiahf/vczjk/voa;-><init>(Ljava/util/List;)V

    return-object p0
.end method
