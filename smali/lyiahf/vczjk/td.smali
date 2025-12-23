.class public final Llyiahf/vczjk/td;
.super Llyiahf/vczjk/fx4;
.source "SourceFile"


# instance fields
.field public OooO0O0:Llyiahf/vczjk/r09;

.field public OooO0OO:Llyiahf/vczjk/nx4;

.field public OooO0Oo:Llyiahf/vczjk/jl8;


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/gl9;Llyiahf/vczjk/gl9;)V
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/td;->OooO0OO:Llyiahf/vczjk/nx4;

    if-eqz v0, :cond_e

    iget-object v1, v0, Llyiahf/vczjk/nx4;->OooO0oo:Llyiahf/vczjk/gl9;

    iget-wide v1, v1, Llyiahf/vczjk/gl9;->OooO0O0:J

    iget-wide v3, p2, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v1, v2, v3, v4}, Llyiahf/vczjk/gn9;->OooO00o(JJ)Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/nx4;->OooO0oo:Llyiahf/vczjk/gl9;

    iget-object v1, v1, Llyiahf/vczjk/gl9;->OooO0OO:Llyiahf/vczjk/gn9;

    iget-object v3, p2, Llyiahf/vczjk/gl9;->OooO0OO:Llyiahf/vczjk/gn9;

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    move v1, v2

    goto :goto_1

    :cond_1
    :goto_0
    const/4 v1, 0x1

    :goto_1
    iput-object p2, v0, Llyiahf/vczjk/nx4;->OooO0oo:Llyiahf/vczjk/gl9;

    iget-object v3, v0, Llyiahf/vczjk/nx4;->OooOO0:Ljava/util/ArrayList;

    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v3

    move v4, v2

    :goto_2
    if-ge v4, v3, :cond_3

    iget-object v5, v0, Llyiahf/vczjk/nx4;->OooOO0:Ljava/util/ArrayList;

    invoke-virtual {v5, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/ref/WeakReference;

    invoke-virtual {v5}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/rj7;

    if-nez v5, :cond_2

    goto :goto_3

    :cond_2
    iput-object p2, v5, Llyiahf/vczjk/rj7;->OooO0oO:Llyiahf/vczjk/gl9;

    :goto_3
    add-int/lit8 v4, v4, 0x1

    goto :goto_2

    :cond_3
    iget-object v3, v0, Llyiahf/vczjk/nx4;->OooOOO0:Llyiahf/vczjk/dx4;

    iget-object v4, v3, Llyiahf/vczjk/dx4;->OooO0OO:Ljava/lang/Object;

    monitor-enter v4

    const/4 v5, 0x0

    :try_start_0
    iput-object v5, v3, Llyiahf/vczjk/dx4;->OooOO0:Llyiahf/vczjk/gl9;

    iput-object v5, v3, Llyiahf/vczjk/dx4;->OooOO0o:Llyiahf/vczjk/s86;

    iput-object v5, v3, Llyiahf/vczjk/dx4;->OooOO0O:Llyiahf/vczjk/mm9;

    iput-object v5, v3, Llyiahf/vczjk/dx4;->OooOOO0:Llyiahf/vczjk/wj7;

    iput-object v5, v3, Llyiahf/vczjk/dx4;->OooOOO:Llyiahf/vczjk/wj7;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v4

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    const/4 v4, -0x1

    if-eqz v3, :cond_6

    if-eqz v1, :cond_e

    iget-object p1, v0, Llyiahf/vczjk/nx4;->OooO0O0:Llyiahf/vczjk/p04;

    iget-wide v1, p2, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v1, v2}, Llyiahf/vczjk/gn9;->OooO0o0(J)I

    move-result v7

    iget-wide v1, p2, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v1, v2}, Llyiahf/vczjk/gn9;->OooO0Oo(J)I

    move-result v8

    iget-object p2, v0, Llyiahf/vczjk/nx4;->OooO0oo:Llyiahf/vczjk/gl9;

    iget-object p2, p2, Llyiahf/vczjk/gl9;->OooO0OO:Llyiahf/vczjk/gn9;

    if-eqz p2, :cond_4

    iget-wide v1, p2, Llyiahf/vczjk/gn9;->OooO00o:J

    invoke-static {v1, v2}, Llyiahf/vczjk/gn9;->OooO0o0(J)I

    move-result p2

    move v9, p2

    goto :goto_4

    :cond_4
    move v9, v4

    :goto_4
    iget-object p2, v0, Llyiahf/vczjk/nx4;->OooO0oo:Llyiahf/vczjk/gl9;

    iget-object p2, p2, Llyiahf/vczjk/gl9;->OooO0OO:Llyiahf/vczjk/gn9;

    if-eqz p2, :cond_5

    iget-wide v0, p2, Llyiahf/vczjk/gn9;->OooO00o:J

    invoke-static {v0, v1}, Llyiahf/vczjk/gn9;->OooO0Oo(J)I

    move-result v4

    :cond_5
    move v10, v4

    invoke-virtual {p1}, Llyiahf/vczjk/p04;->OooO00o()Landroid/view/inputmethod/InputMethodManager;

    move-result-object v5

    iget-object v6, p1, Llyiahf/vczjk/p04;->OooO00o:Landroid/view/View;

    invoke-virtual/range {v5 .. v10}, Landroid/view/inputmethod/InputMethodManager;->updateSelection(Landroid/view/View;IIII)V

    return-void

    :cond_6
    if-eqz p1, :cond_8

    iget-object v1, p1, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v1, v1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    iget-object v3, p2, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v3, v3, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_7

    iget-wide v5, p1, Llyiahf/vczjk/gl9;->OooO0O0:J

    iget-wide v7, p2, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v5, v6, v7, v8}, Llyiahf/vczjk/gn9;->OooO00o(JJ)Z

    move-result v1

    if-eqz v1, :cond_8

    iget-object p1, p1, Llyiahf/vczjk/gl9;->OooO0OO:Llyiahf/vczjk/gn9;

    iget-object p2, p2, Llyiahf/vczjk/gl9;->OooO0OO:Llyiahf/vczjk/gn9;

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_8

    :cond_7
    iget-object p1, v0, Llyiahf/vczjk/nx4;->OooO0O0:Llyiahf/vczjk/p04;

    invoke-virtual {p1}, Llyiahf/vczjk/p04;->OooO00o()Landroid/view/inputmethod/InputMethodManager;

    move-result-object p2

    iget-object p1, p1, Llyiahf/vczjk/p04;->OooO00o:Landroid/view/View;

    invoke-virtual {p2, p1}, Landroid/view/inputmethod/InputMethodManager;->restartInput(Landroid/view/View;)V

    return-void

    :cond_8
    iget-object p1, v0, Llyiahf/vczjk/nx4;->OooOO0:Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result p1

    :goto_5
    if-ge v2, p1, :cond_e

    iget-object p2, v0, Llyiahf/vczjk/nx4;->OooOO0:Ljava/util/ArrayList;

    invoke-virtual {p2, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/ref/WeakReference;

    invoke-virtual {p2}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/rj7;

    if-eqz p2, :cond_d

    iget-object v1, v0, Llyiahf/vczjk/nx4;->OooO0oo:Llyiahf/vczjk/gl9;

    iget-object v3, v0, Llyiahf/vczjk/nx4;->OooO0O0:Llyiahf/vczjk/p04;

    iget-boolean v5, p2, Llyiahf/vczjk/rj7;->OooOO0O:Z

    if-nez v5, :cond_9

    goto :goto_8

    :cond_9
    iput-object v1, p2, Llyiahf/vczjk/rj7;->OooO0oO:Llyiahf/vczjk/gl9;

    iget-boolean v5, p2, Llyiahf/vczjk/rj7;->OooO:Z

    if-eqz v5, :cond_a

    iget p2, p2, Llyiahf/vczjk/rj7;->OooO0oo:I

    invoke-static {v1}, Llyiahf/vczjk/cl6;->OooO0o0(Llyiahf/vczjk/gl9;)Landroid/view/inputmethod/ExtractedText;

    move-result-object v5

    invoke-virtual {v3}, Llyiahf/vczjk/p04;->OooO00o()Landroid/view/inputmethod/InputMethodManager;

    move-result-object v6

    iget-object v7, v3, Llyiahf/vczjk/p04;->OooO00o:Landroid/view/View;

    invoke-virtual {v6, v7, p2, v5}, Landroid/view/inputmethod/InputMethodManager;->updateExtractedText(Landroid/view/View;ILandroid/view/inputmethod/ExtractedText;)V

    :cond_a
    iget-object p2, v1, Llyiahf/vczjk/gl9;->OooO0OO:Llyiahf/vczjk/gn9;

    if-eqz p2, :cond_b

    iget-wide v5, p2, Llyiahf/vczjk/gn9;->OooO00o:J

    invoke-static {v5, v6}, Llyiahf/vczjk/gn9;->OooO0o0(J)I

    move-result p2

    move v9, p2

    goto :goto_6

    :cond_b
    move v9, v4

    :goto_6
    iget-object p2, v1, Llyiahf/vczjk/gl9;->OooO0OO:Llyiahf/vczjk/gn9;

    if-eqz p2, :cond_c

    iget-wide v5, p2, Llyiahf/vczjk/gn9;->OooO00o:J

    invoke-static {v5, v6}, Llyiahf/vczjk/gn9;->OooO0Oo(J)I

    move-result p2

    move v10, p2

    goto :goto_7

    :cond_c
    move v10, v4

    :goto_7
    iget-wide v5, v1, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v5, v6}, Llyiahf/vczjk/gn9;->OooO0o0(J)I

    move-result v7

    invoke-static {v5, v6}, Llyiahf/vczjk/gn9;->OooO0Oo(J)I

    move-result v8

    invoke-virtual {v3}, Llyiahf/vczjk/p04;->OooO00o()Landroid/view/inputmethod/InputMethodManager;

    move-result-object v5

    iget-object v6, v3, Llyiahf/vczjk/p04;->OooO00o:Landroid/view/View;

    invoke-virtual/range {v5 .. v10}, Landroid/view/inputmethod/InputMethodManager;->updateSelection(Landroid/view/View;IIII)V

    :cond_d
    :goto_8
    add-int/lit8 v2, v2, 0x1

    goto :goto_5

    :catchall_0
    move-exception v0

    move-object p1, v0

    monitor-exit v4

    throw p1

    :cond_e
    return-void
.end method

.method public final OooO0O0()V
    .locals 1

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/td;->OooOO0O(Llyiahf/vczjk/nd;)V

    return-void
.end method

.method public final OooO0OO(Llyiahf/vczjk/gl9;Llyiahf/vczjk/s86;Llyiahf/vczjk/mm9;Llyiahf/vczjk/ni9;Llyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;)V
    .locals 1

    iget-object p4, p0, Llyiahf/vczjk/td;->OooO0OO:Llyiahf/vczjk/nx4;

    if-eqz p4, :cond_2

    iget-object p4, p4, Llyiahf/vczjk/nx4;->OooOOO0:Llyiahf/vczjk/dx4;

    iget-object v0, p4, Llyiahf/vczjk/dx4;->OooO0OO:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iput-object p1, p4, Llyiahf/vczjk/dx4;->OooOO0:Llyiahf/vczjk/gl9;

    iput-object p2, p4, Llyiahf/vczjk/dx4;->OooOO0o:Llyiahf/vczjk/s86;

    iput-object p3, p4, Llyiahf/vczjk/dx4;->OooOO0O:Llyiahf/vczjk/mm9;

    iput-object p5, p4, Llyiahf/vczjk/dx4;->OooOOO0:Llyiahf/vczjk/wj7;

    iput-object p6, p4, Llyiahf/vczjk/dx4;->OooOOO:Llyiahf/vczjk/wj7;

    iget-boolean p1, p4, Llyiahf/vczjk/dx4;->OooO0o0:Z

    if-nez p1, :cond_0

    iget-boolean p1, p4, Llyiahf/vczjk/dx4;->OooO0Oo:Z

    if-eqz p1, :cond_1

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    :goto_0
    invoke-virtual {p4}, Llyiahf/vczjk/dx4;->OooO00o()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_1
    monitor-exit v0

    return-void

    :goto_1
    monitor-exit v0

    throw p1

    :cond_2
    return-void
.end method

.method public final OooO0o()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/td;->OooO0O0:Llyiahf/vczjk/r09;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/k84;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    :cond_0
    iput-object v1, p0, Llyiahf/vczjk/td;->OooO0O0:Llyiahf/vczjk/r09;

    invoke-virtual {p0}, Llyiahf/vczjk/td;->OooOO0()Llyiahf/vczjk/os5;

    move-result-object v0

    if-eqz v0, :cond_1

    check-cast v0, Llyiahf/vczjk/jl8;

    invoke-virtual {v0}, Llyiahf/vczjk/jl8;->OooO0oO()V

    :cond_1
    return-void
.end method

.method public final OooO0o0(Llyiahf/vczjk/wj7;)V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/td;->OooO0OO:Llyiahf/vczjk/nx4;

    if-eqz v0, :cond_0

    new-instance v1, Landroid/graphics/Rect;

    iget v2, p1, Llyiahf/vczjk/wj7;->OooO00o:F

    invoke-static {v2}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v2

    iget v3, p1, Llyiahf/vczjk/wj7;->OooO0O0:F

    invoke-static {v3}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v3

    iget v4, p1, Llyiahf/vczjk/wj7;->OooO0OO:F

    invoke-static {v4}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v4

    iget p1, p1, Llyiahf/vczjk/wj7;->OooO0Oo:F

    invoke-static {p1}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result p1

    invoke-direct {v1, v2, v3, v4, p1}, Landroid/graphics/Rect;-><init>(IIII)V

    iput-object v1, v0, Llyiahf/vczjk/nx4;->OooOO0o:Landroid/graphics/Rect;

    iget-object p1, v0, Llyiahf/vczjk/nx4;->OooOO0:Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result p1

    if-eqz p1, :cond_0

    iget-object p1, v0, Llyiahf/vczjk/nx4;->OooOO0o:Landroid/graphics/Rect;

    if-eqz p1, :cond_0

    new-instance v1, Landroid/graphics/Rect;

    invoke-direct {v1, p1}, Landroid/graphics/Rect;-><init>(Landroid/graphics/Rect;)V

    iget-object p1, v0, Llyiahf/vczjk/nx4;->OooO00o:Landroid/view/View;

    invoke-virtual {p1, v1}, Landroid/view/View;->requestRectangleOnScreen(Landroid/graphics/Rect;)Z

    :cond_0
    return-void
.end method

.method public final OooO0oo(Llyiahf/vczjk/gl9;Llyiahf/vczjk/wv3;Llyiahf/vczjk/mi9;Llyiahf/vczjk/jx4;)V
    .locals 6

    new-instance v0, Llyiahf/vczjk/nd;

    move-object v2, p0

    move-object v1, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/nd;-><init>(Llyiahf/vczjk/gl9;Llyiahf/vczjk/td;Llyiahf/vczjk/wv3;Llyiahf/vczjk/mi9;Llyiahf/vczjk/jx4;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/td;->OooOO0O(Llyiahf/vczjk/nd;)V

    return-void
.end method

.method public final OooOO0()Llyiahf/vczjk/os5;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/td;->OooO0Oo:Llyiahf/vczjk/jl8;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    sget-boolean v0, Llyiahf/vczjk/o79;->OooO00o:Z

    if-nez v0, :cond_1

    const/4 v0, 0x0

    return-object v0

    :cond_1
    sget-object v0, Llyiahf/vczjk/aj0;->OooOOOO:Llyiahf/vczjk/aj0;

    const/4 v1, 0x2

    invoke-static {v1, v0}, Llyiahf/vczjk/zsa;->OooOO0o(ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jl8;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/td;->OooO0Oo:Llyiahf/vczjk/jl8;

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/nd;)V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/fx4;->OooO00o:Llyiahf/vczjk/cx4;

    if-nez v0, :cond_0

    return-void

    :cond_0
    new-instance v1, Llyiahf/vczjk/sd;

    const/4 v2, 0x0

    invoke-direct {v1, p1, p0, v0, v2}, Llyiahf/vczjk/sd;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/td;Llyiahf/vczjk/ex4;Llyiahf/vczjk/yo1;)V

    iget-boolean p1, v0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez p1, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object p1

    sget-object v3, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v4, Llyiahf/vczjk/bx4;

    invoke-direct {v4, v0, v1, v2}, Llyiahf/vczjk/bx4;-><init>(Llyiahf/vczjk/cx4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    const/4 v0, 0x1

    invoke-static {p1, v2, v3, v4, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v2

    :goto_0
    iput-object v2, p0, Llyiahf/vczjk/td;->OooO0O0:Llyiahf/vczjk/r09;

    return-void
.end method
