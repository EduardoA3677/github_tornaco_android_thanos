.class public final Llyiahf/vczjk/f50;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/go4;
.implements Llyiahf/vczjk/fg2;
.implements Llyiahf/vczjk/ne8;
.implements Llyiahf/vczjk/ny6;
.implements Llyiahf/vczjk/ql5;
.implements Llyiahf/vczjk/sl5;
.implements Llyiahf/vczjk/cp6;
.implements Llyiahf/vczjk/vn4;
.implements Llyiahf/vczjk/gi3;
.implements Llyiahf/vczjk/c83;
.implements Llyiahf/vczjk/u83;
.implements Llyiahf/vczjk/x83;
.implements Llyiahf/vczjk/ug6;
.implements Llyiahf/vczjk/qj0;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/il5;

.field public OooOoo:Ljava/util/HashSet;

.field public OooOoo0:Llyiahf/vczjk/c50;


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string v1, "null cannot be cast to non-null type androidx.compose.ui.layout.LayoutModifier"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/eo4;

    invoke-interface {v0, p1, p2, p3, p4}, Llyiahf/vczjk/eo4;->OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0O0()Llyiahf/vczjk/f62;
    .locals 1

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    return-object v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/ie7;)Ljava/lang/Object;
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoo:Ljava/util/HashSet;

    invoke-virtual {v0, p1}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v0, v0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    const-string v0, "visitAncestors called on an unattached node"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v1

    :goto_0
    if-eqz v1, :cond_b

    iget-object v2, v1, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v2, v2, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jl5;

    iget v2, v2, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/lit8 v2, v2, 0x20

    const/4 v3, 0x0

    if-eqz v2, :cond_9

    :goto_1
    if-eqz v0, :cond_9

    iget v2, v0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v2, v2, 0x20

    if-eqz v2, :cond_8

    move-object v2, v0

    move-object v4, v3

    :goto_2
    if-eqz v2, :cond_8

    instance-of v5, v2, Llyiahf/vczjk/ql5;

    if-eqz v5, :cond_1

    check-cast v2, Llyiahf/vczjk/ql5;

    invoke-interface {v2}, Llyiahf/vczjk/ql5;->OoooO0O()Llyiahf/vczjk/e16;

    move-result-object v5

    invoke-virtual {v5, p1}, Llyiahf/vczjk/e16;->OooOOo0(Llyiahf/vczjk/ie7;)Z

    move-result v5

    if-eqz v5, :cond_7

    invoke-interface {v2}, Llyiahf/vczjk/ql5;->OoooO0O()Llyiahf/vczjk/e16;

    move-result-object v0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/e16;->OooOo00(Llyiahf/vczjk/ie7;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_1
    iget v5, v2, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v5, v5, 0x20

    if-eqz v5, :cond_7

    instance-of v5, v2, Llyiahf/vczjk/m52;

    if-eqz v5, :cond_7

    move-object v5, v2

    check-cast v5, Llyiahf/vczjk/m52;

    iget-object v5, v5, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    const/4 v6, 0x0

    :goto_3
    const/4 v7, 0x1

    if-eqz v5, :cond_6

    iget v8, v5, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v8, v8, 0x20

    if-eqz v8, :cond_5

    add-int/lit8 v6, v6, 0x1

    if-ne v6, v7, :cond_2

    move-object v2, v5

    goto :goto_4

    :cond_2
    if-nez v4, :cond_3

    new-instance v4, Llyiahf/vczjk/ws5;

    const/16 v7, 0x10

    new-array v7, v7, [Llyiahf/vczjk/jl5;

    invoke-direct {v4, v7}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_3
    if-eqz v2, :cond_4

    invoke-virtual {v4, v2}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v2, v3

    :cond_4
    invoke-virtual {v4, v5}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_5
    :goto_4
    iget-object v5, v5, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_3

    :cond_6
    if-ne v6, v7, :cond_7

    goto :goto_2

    :cond_7
    invoke-static {v4}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v2

    goto :goto_2

    :cond_8
    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto :goto_1

    :cond_9
    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v1

    if-eqz v1, :cond_a

    iget-object v0, v1, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    if-eqz v0, :cond_a

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cf9;

    goto/16 :goto_0

    :cond_a
    move-object v0, v3

    goto/16 :goto_0

    :cond_b
    iget-object p1, p1, Llyiahf/vczjk/ie7;->OooO00o:Llyiahf/vczjk/rm4;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    instance-of v0, v0, Llyiahf/vczjk/uy6;

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/f50;->OooOoo0()V

    :cond_0
    return-void
.end method

.method public final OooO0o(Llyiahf/vczjk/s83;)V
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string v0, "applyFocusProperties called on wrong node"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1
.end method

.method public final OooO0o0()J
    .locals 2

    const/16 v0, 0x80

    invoke-static {p0, v0}, Llyiahf/vczjk/yi4;->o00ooo(Llyiahf/vczjk/l52;I)Llyiahf/vczjk/v16;

    move-result-object v0

    iget-wide v0, v0, Llyiahf/vczjk/ow6;->OooOOOO:J

    invoke-static {v0, v1}, Llyiahf/vczjk/e16;->Oooo0oO(J)J

    move-result-wide v0

    return-wide v0
.end method

.method public final OooOOO0(J)V
    .locals 0

    return-void
.end method

.method public final OooOOOo()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    return v0
.end method

.method public final OooOo0(Llyiahf/vczjk/xn4;)V
    .locals 0

    return-void
.end method

.method public final OooOo00(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string v1, "null cannot be cast to non-null type androidx.compose.ui.layout.LayoutModifier"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/eo4;

    new-instance v1, Llyiahf/vczjk/l22;

    sget-object v2, Llyiahf/vczjk/rf5;->OooOOO0:Llyiahf/vczjk/rf5;

    sget-object v3, Llyiahf/vczjk/sf5;->OooOOO:Llyiahf/vczjk/sf5;

    const/4 v4, 0x1

    invoke-direct {v1, p2, v2, v3, v4}, Llyiahf/vczjk/l22;-><init>(Llyiahf/vczjk/ef5;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    const/16 p2, 0xd

    const/4 v2, 0x0

    invoke-static {p3, v2, p2}, Llyiahf/vczjk/uk1;->OooO0O0(III)J

    move-result-wide p2

    new-instance v2, Llyiahf/vczjk/b44;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v3

    invoke-direct {v2, p1, v3}, Llyiahf/vczjk/b44;-><init>(Llyiahf/vczjk/o34;Llyiahf/vczjk/yn4;)V

    invoke-interface {v0, v2, v1, p2, p3}, Llyiahf/vczjk/eo4;->OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/mf5;->getHeight()I

    move-result p1

    return p1
.end method

.method public final OooOo0o(Llyiahf/vczjk/to4;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string v1, "null cannot be cast to non-null type androidx.compose.ui.draw.DrawModifier"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/nx3;

    invoke-virtual {p1}, Llyiahf/vczjk/to4;->OooO00o()V

    return-void
.end method

.method public final OooOoO0(Llyiahf/vczjk/v16;)V
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.layout.OnGloballyPositionedModifier"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/g20;

    iget-boolean v0, p1, Llyiahf/vczjk/g20;->OooOOO0:Z

    if-nez v0, :cond_1

    const/4 v0, 0x1

    iput-boolean v0, p1, Llyiahf/vczjk/g20;->OooOOO0:Z

    iget-object v0, p1, Llyiahf/vczjk/g20;->OooOOO:Llyiahf/vczjk/yp0;

    if-eqz v0, :cond_0

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    :cond_0
    const/4 v0, 0x0

    iput-object v0, p1, Llyiahf/vczjk/g20;->OooOOO:Llyiahf/vczjk/yp0;

    :cond_1
    return-void
.end method

.method public final OooOoo0()V
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string v1, "null cannot be cast to non-null type androidx.compose.ui.input.pointer.PointerInputModifier"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/uy6;

    iget-object v0, v0, Llyiahf/vczjk/uy6;->OooOOOo:Llyiahf/vczjk/ty6;

    iget-object v1, v0, Llyiahf/vczjk/ty6;->OooO0O0:Llyiahf/vczjk/py6;

    sget-object v2, Llyiahf/vczjk/py6;->OooOOO:Llyiahf/vczjk/py6;

    if-ne v1, v2, :cond_0

    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    move-result-wide v3

    new-instance v1, Llyiahf/vczjk/sy6;

    iget-object v2, v0, Llyiahf/vczjk/ty6;->OooO0OO:Llyiahf/vczjk/uy6;

    invoke-direct {v1, v2}, Llyiahf/vczjk/sy6;-><init>(Llyiahf/vczjk/uy6;)V

    const/4 v7, 0x3

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    move-wide v5, v3

    invoke-static/range {v3 .. v10}, Landroid/view/MotionEvent;->obtain(JJIFFI)Landroid/view/MotionEvent;

    move-result-object v3

    const/4 v4, 0x0

    invoke-virtual {v3, v4}, Landroid/view/MotionEvent;->setSource(I)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/sy6;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v3}, Landroid/view/MotionEvent;->recycle()V

    sget-object v1, Llyiahf/vczjk/py6;->OooOOO0:Llyiahf/vczjk/py6;

    iput-object v1, v0, Llyiahf/vczjk/ty6;->OooO0O0:Llyiahf/vczjk/py6;

    iput-boolean v4, v2, Llyiahf/vczjk/uy6;->OooOOOO:Z

    :cond_0
    return-void
.end method

.method public final OooOooO(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string v1, "null cannot be cast to non-null type androidx.compose.ui.layout.LayoutModifier"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/eo4;

    new-instance v1, Llyiahf/vczjk/l22;

    sget-object v2, Llyiahf/vczjk/rf5;->OooOOO:Llyiahf/vczjk/rf5;

    sget-object v3, Llyiahf/vczjk/sf5;->OooOOO:Llyiahf/vczjk/sf5;

    const/4 v4, 0x1

    invoke-direct {v1, p2, v2, v3, v4}, Llyiahf/vczjk/l22;-><init>(Llyiahf/vczjk/ef5;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    const/16 p2, 0xd

    const/4 v2, 0x0

    invoke-static {p3, v2, p2}, Llyiahf/vczjk/uk1;->OooO0O0(III)J

    move-result-wide p2

    new-instance v2, Llyiahf/vczjk/b44;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v3

    invoke-direct {v2, p1, v3}, Llyiahf/vczjk/b44;-><init>(Llyiahf/vczjk/o34;Llyiahf/vczjk/yn4;)V

    invoke-interface {v0, v2, v1, p2, p3}, Llyiahf/vczjk/eo4;->OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/mf5;->getHeight()I

    move-result p1

    return p1
.end method

.method public final Oooo00o()V
    .locals 0

    invoke-static {p0}, Llyiahf/vczjk/ye5;->OooOoO0(Llyiahf/vczjk/fg2;)V

    return-void
.end method

.method public final Oooo0O0()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string v1, "null cannot be cast to non-null type androidx.compose.ui.input.pointer.PointerInputModifier"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/uy6;

    iget-object v0, v0, Llyiahf/vczjk/uy6;->OooOOOo:Llyiahf/vczjk/ty6;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-void
.end method

.method public final OoooO0O()Llyiahf/vczjk/e16;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoo0:Llyiahf/vczjk/c50;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    sget-object v0, Llyiahf/vczjk/cn2;->OooOO0o:Llyiahf/vczjk/cn2;

    return-object v0
.end method

.method public final OoooOOo(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string v1, "null cannot be cast to non-null type androidx.compose.ui.layout.LayoutModifier"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/eo4;

    new-instance v1, Llyiahf/vczjk/l22;

    sget-object v2, Llyiahf/vczjk/rf5;->OooOOO0:Llyiahf/vczjk/rf5;

    sget-object v3, Llyiahf/vczjk/sf5;->OooOOO0:Llyiahf/vczjk/sf5;

    const/4 v4, 0x1

    invoke-direct {v1, p2, v2, v3, v4}, Llyiahf/vczjk/l22;-><init>(Llyiahf/vczjk/ef5;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    const/4 p2, 0x7

    const/4 v2, 0x0

    invoke-static {v2, p3, p2}, Llyiahf/vczjk/uk1;->OooO0O0(III)J

    move-result-wide p2

    new-instance v2, Llyiahf/vczjk/b44;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v3

    invoke-direct {v2, p1, v3}, Llyiahf/vczjk/b44;-><init>(Llyiahf/vczjk/o34;Llyiahf/vczjk/yn4;)V

    invoke-interface {v0, v2, v1, p2, p3}, Llyiahf/vczjk/eo4;->OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/mf5;->getWidth()I

    move-result p1

    return p1
.end method

.method public final OooooO0(Llyiahf/vczjk/af8;)V
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    iget-object v2, v0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string v3, "null cannot be cast to non-null type androidx.compose.ui.semantics.SemanticsModifier"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Llyiahf/vczjk/le8;

    invoke-interface {v2}, Llyiahf/vczjk/le8;->OooO()Llyiahf/vczjk/je8;

    move-result-object v2

    const-string v3, "null cannot be cast to non-null type androidx.compose.ui.semantics.SemanticsConfiguration"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, Llyiahf/vczjk/je8;

    iget-boolean v3, v2, Llyiahf/vczjk/je8;->OooOOOO:Z

    const/4 v4, 0x1

    if-eqz v3, :cond_0

    iput-boolean v4, v1, Llyiahf/vczjk/je8;->OooOOOO:Z

    :cond_0
    iget-boolean v3, v2, Llyiahf/vczjk/je8;->OooOOOo:Z

    if-eqz v3, :cond_1

    iput-boolean v4, v1, Llyiahf/vczjk/je8;->OooOOOo:Z

    :cond_1
    iget-object v2, v2, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    iget-object v3, v2, Llyiahf/vczjk/js5;->OooO0O0:[Ljava/lang/Object;

    iget-object v4, v2, Llyiahf/vczjk/js5;->OooO0OO:[Ljava/lang/Object;

    iget-object v2, v2, Llyiahf/vczjk/js5;->OooO00o:[J

    array-length v5, v2

    add-int/lit8 v5, v5, -0x2

    if-ltz v5, :cond_8

    const/4 v7, 0x0

    :goto_0
    aget-wide v8, v2, v7

    not-long v10, v8

    const/4 v12, 0x7

    shl-long/2addr v10, v12

    and-long/2addr v10, v8

    const-wide v12, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    and-long/2addr v10, v12

    cmp-long v10, v10, v12

    if-eqz v10, :cond_7

    sub-int v10, v7, v5

    not-int v10, v10

    ushr-int/lit8 v10, v10, 0x1f

    const/16 v11, 0x8

    rsub-int/lit8 v10, v10, 0x8

    const/4 v12, 0x0

    :goto_1
    if-ge v12, v10, :cond_6

    const-wide/16 v13, 0xff

    and-long/2addr v13, v8

    const-wide/16 v15, 0x80

    cmp-long v13, v13, v15

    if-gez v13, :cond_5

    shl-int/lit8 v13, v7, 0x3

    add-int/2addr v13, v12

    aget-object v14, v3, v13

    aget-object v13, v4, v13

    check-cast v14, Llyiahf/vczjk/ze8;

    iget-object v15, v1, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v15, v14}, Llyiahf/vczjk/js5;->OooO0O0(Ljava/lang/Object;)Z

    move-result v16

    if-nez v16, :cond_2

    invoke-virtual {v15, v14, v13}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_2

    :cond_2
    instance-of v6, v13, Llyiahf/vczjk/o0O00O;

    if-eqz v6, :cond_5

    invoke-virtual {v15, v14}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    move/from16 v16, v11

    const-string v11, "null cannot be cast to non-null type androidx.compose.ui.semantics.AccessibilityAction<*>"

    invoke-static {v6, v11}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v6, Llyiahf/vczjk/o0O00O;

    new-instance v11, Llyiahf/vczjk/o0O00O;

    iget-object v0, v6, Llyiahf/vczjk/o0O00O;->OooO00o:Ljava/lang/String;

    if-nez v0, :cond_3

    move-object v0, v13

    check-cast v0, Llyiahf/vczjk/o0O00O;

    iget-object v0, v0, Llyiahf/vczjk/o0O00O;->OooO00o:Ljava/lang/String;

    :cond_3
    iget-object v6, v6, Llyiahf/vczjk/o0O00O;->OooO0O0:Llyiahf/vczjk/cf3;

    if-nez v6, :cond_4

    check-cast v13, Llyiahf/vczjk/o0O00O;

    iget-object v6, v13, Llyiahf/vczjk/o0O00O;->OooO0O0:Llyiahf/vczjk/cf3;

    :cond_4
    invoke-direct {v11, v0, v6}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v15, v14, v11}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_3

    :cond_5
    :goto_2
    move/from16 v16, v11

    :goto_3
    shr-long v8, v8, v16

    add-int/lit8 v12, v12, 0x1

    move-object/from16 v0, p0

    move/from16 v11, v16

    goto :goto_1

    :cond_6
    move v0, v11

    if-ne v10, v0, :cond_8

    :cond_7
    if-eq v7, v5, :cond_8

    add-int/lit8 v7, v7, 0x1

    move-object/from16 v0, p0

    goto :goto_0

    :cond_8
    return-void
.end method

.method public final OooooOo(Llyiahf/vczjk/f62;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string p2, "null cannot be cast to non-null type androidx.compose.ui.layout.ParentDataModifier"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/bp6;

    invoke-interface {p1}, Llyiahf/vczjk/bp6;->OooO0oo()Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final getLayoutDirection()Llyiahf/vczjk/yn4;
    .locals 1

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ro4;->Oooo0o0:Llyiahf/vczjk/yn4;

    return-object v0
.end method

.method public final o00000OO(Z)V
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    const-string v0, "initializeModifier called on unattached node"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    iget v1, p0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v1, v1, 0x20

    if-eqz v1, :cond_4

    instance-of v1, v0, Llyiahf/vczjk/nl5;

    if-eqz v1, :cond_2

    new-instance v1, Llyiahf/vczjk/d50;

    invoke-direct {v1, p0}, Llyiahf/vczjk/d50;-><init>(Llyiahf/vczjk/f50;)V

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/xa;

    iget-object v2, v2, Llyiahf/vczjk/xa;->o000000:Llyiahf/vczjk/as5;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/c76;->OooO0OO(Ljava/lang/Object;)I

    move-result v3

    if-ltz v3, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {v2, v1}, Llyiahf/vczjk/as5;->OooO0oO(Ljava/lang/Object;)V

    :cond_2
    :goto_0
    instance-of v1, v0, Llyiahf/vczjk/rl5;

    if-eqz v1, :cond_4

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/rl5;

    iget-object v2, p0, Llyiahf/vczjk/f50;->OooOoo0:Llyiahf/vczjk/c50;

    if-eqz v2, :cond_3

    invoke-interface {v1}, Llyiahf/vczjk/rl5;->getKey()Llyiahf/vczjk/ie7;

    move-result-object v3

    invoke-virtual {v2, v3}, Llyiahf/vczjk/c50;->OooOOo0(Llyiahf/vczjk/ie7;)Z

    move-result v3

    if-eqz v3, :cond_3

    iput-object v1, v2, Llyiahf/vczjk/c50;->OooOO0o:Llyiahf/vczjk/rl5;

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/xa;

    invoke-virtual {v2}, Llyiahf/vczjk/xa;->getModifierLocalManager()Llyiahf/vczjk/pl5;

    move-result-object v2

    invoke-interface {v1}, Llyiahf/vczjk/rl5;->getKey()Llyiahf/vczjk/ie7;

    move-result-object v1

    iget-object v3, v2, Llyiahf/vczjk/pl5;->OooO0O0:Llyiahf/vczjk/ws5;

    invoke-virtual {v3, p0}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    iget-object v3, v2, Llyiahf/vczjk/pl5;->OooO0OO:Llyiahf/vczjk/ws5;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    invoke-virtual {v2}, Llyiahf/vczjk/pl5;->OooO00o()V

    goto :goto_1

    :cond_3
    new-instance v2, Llyiahf/vczjk/c50;

    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    iput-object v1, v2, Llyiahf/vczjk/c50;->OooOO0o:Llyiahf/vczjk/rl5;

    iput-object v2, p0, Llyiahf/vczjk/f50;->OooOoo0:Llyiahf/vczjk/c50;

    invoke-static {p0}, Llyiahf/vczjk/jp8;->OooO(Llyiahf/vczjk/f50;)Z

    move-result v2

    if-eqz v2, :cond_4

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/xa;

    invoke-virtual {v2}, Llyiahf/vczjk/xa;->getModifierLocalManager()Llyiahf/vczjk/pl5;

    move-result-object v2

    invoke-interface {v1}, Llyiahf/vczjk/rl5;->getKey()Llyiahf/vczjk/ie7;

    move-result-object v1

    iget-object v3, v2, Llyiahf/vczjk/pl5;->OooO0O0:Llyiahf/vczjk/ws5;

    invoke-virtual {v3, p0}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    iget-object v3, v2, Llyiahf/vczjk/pl5;->OooO0OO:Llyiahf/vczjk/ws5;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    invoke-virtual {v2}, Llyiahf/vczjk/pl5;->OooO00o()V

    :cond_4
    :goto_1
    iget v1, p0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v1, v1, 0x4

    const/4 v2, 0x2

    if-eqz v1, :cond_5

    if-nez p1, :cond_5

    invoke-static {p0, v2}, Llyiahf/vczjk/yi4;->o00ooo(Llyiahf/vczjk/l52;I)Llyiahf/vczjk/v16;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/v16;->o0000Oo()V

    :cond_5
    iget v1, p0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v1, v2

    if-eqz v1, :cond_7

    invoke-static {p0}, Llyiahf/vczjk/jp8;->OooO(Llyiahf/vczjk/f50;)Z

    move-result v1

    if-eqz v1, :cond_6

    iget-object v1, p0, Llyiahf/vczjk/jl5;->OooOo00:Llyiahf/vczjk/v16;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/io4;

    invoke-virtual {v3, p0}, Llyiahf/vczjk/io4;->o000O00O(Llyiahf/vczjk/go4;)V

    iget-object v1, v1, Llyiahf/vczjk/v16;->OoooO0O:Llyiahf/vczjk/sg6;

    if-eqz v1, :cond_6

    invoke-interface {v1}, Llyiahf/vczjk/sg6;->invalidate()V

    :cond_6
    if-nez p1, :cond_7

    invoke-static {p0, v2}, Llyiahf/vczjk/yi4;->o00ooo(Llyiahf/vczjk/l52;I)Llyiahf/vczjk/v16;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/v16;->o0000Oo()V

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/ro4;->OooOooo()V

    :cond_7
    instance-of p1, v0, Llyiahf/vczjk/ar4;

    if-eqz p1, :cond_8

    move-object p1, v0

    check-cast p1, Llyiahf/vczjk/ar4;

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v1

    iget v2, p1, Llyiahf/vczjk/ar4;->OooOOO0:I

    packed-switch v2, :pswitch_data_0

    iget-object p1, p1, Llyiahf/vczjk/ar4;->OooOOO:Llyiahf/vczjk/sa8;

    check-cast p1, Llyiahf/vczjk/lm6;

    iget-object p1, p1, Llyiahf/vczjk/lm6;->OooOo:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    goto :goto_2

    :pswitch_0
    iget-object p1, p1, Llyiahf/vczjk/ar4;->OooOOO:Llyiahf/vczjk/sa8;

    check-cast p1, Llyiahf/vczjk/dw4;

    iput-object v1, p1, Llyiahf/vczjk/dw4;->OooOO0:Llyiahf/vczjk/ro4;

    goto :goto_2

    :pswitch_1
    iget-object p1, p1, Llyiahf/vczjk/ar4;->OooOOO:Llyiahf/vczjk/sa8;

    check-cast p1, Llyiahf/vczjk/er4;

    iput-object v1, p1, Llyiahf/vczjk/er4;->OooOO0:Llyiahf/vczjk/ro4;

    :cond_8
    :goto_2
    iget p1, p0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 p1, p1, 0x100

    if-eqz p1, :cond_9

    instance-of p1, v0, Llyiahf/vczjk/g20;

    if-eqz p1, :cond_9

    invoke-static {p0}, Llyiahf/vczjk/jp8;->OooO(Llyiahf/vczjk/f50;)Z

    move-result p1

    if-eqz p1, :cond_9

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/ro4;->OooOooo()V

    :cond_9
    iget p1, p0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v1, p1, 0x10

    if-eqz v1, :cond_a

    instance-of v1, v0, Llyiahf/vczjk/uy6;

    if-eqz v1, :cond_a

    check-cast v0, Llyiahf/vczjk/uy6;

    iget-object v0, v0, Llyiahf/vczjk/uy6;->OooOOOo:Llyiahf/vczjk/ty6;

    iget-object v1, p0, Llyiahf/vczjk/jl5;->OooOo00:Llyiahf/vczjk/v16;

    iput-object v1, v0, Llyiahf/vczjk/ty6;->OooO00o:Llyiahf/vczjk/xn4;

    :cond_a
    and-int/lit8 p1, p1, 0x8

    if-eqz p1, :cond_b

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/xa;

    invoke-virtual {p1}, Llyiahf/vczjk/xa;->OooOooO()V

    :cond_b
    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final o00000Oo()V
    .locals 5

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    const-string v0, "unInitializeModifier called on unattached node"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    iget v1, p0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v1, v1, 0x20

    if-eqz v1, :cond_2

    instance-of v1, v0, Llyiahf/vczjk/rl5;

    if-eqz v1, :cond_1

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/xa;

    invoke-virtual {v1}, Llyiahf/vczjk/xa;->getModifierLocalManager()Llyiahf/vczjk/pl5;

    move-result-object v1

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/rl5;

    invoke-interface {v2}, Llyiahf/vczjk/rl5;->getKey()Llyiahf/vczjk/ie7;

    move-result-object v2

    iget-object v3, v1, Llyiahf/vczjk/pl5;->OooO0Oo:Llyiahf/vczjk/ws5;

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v4

    invoke-virtual {v3, v4}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    iget-object v3, v1, Llyiahf/vczjk/pl5;->OooO0o0:Llyiahf/vczjk/ws5;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    invoke-virtual {v1}, Llyiahf/vczjk/pl5;->OooO00o()V

    :cond_1
    instance-of v1, v0, Llyiahf/vczjk/nl5;

    if-eqz v1, :cond_2

    check-cast v0, Llyiahf/vczjk/nl5;

    sget-object v1, Llyiahf/vczjk/jp8;->OooOOO0:Llyiahf/vczjk/qp3;

    invoke-interface {v0, v1}, Llyiahf/vczjk/nl5;->OooO0o(Llyiahf/vczjk/sl5;)V

    :cond_2
    iget v0, p0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v0, v0, 0x8

    if-eqz v0, :cond_3

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->OooOooO()V

    :cond_3
    return-void
.end method

.method public final o00000o0()V
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoo:Ljava/util/HashSet;

    invoke-virtual {v0}, Ljava/util/HashSet;->clear()V

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getSnapshotObserver()Llyiahf/vczjk/vg6;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/o6;->Oooo0oo:Llyiahf/vczjk/o6;

    new-instance v2, Llyiahf/vczjk/e50;

    invoke-direct {v2, p0}, Llyiahf/vczjk/e50;-><init>(Llyiahf/vczjk/f50;)V

    invoke-virtual {v0, p0, v1, v2}, Llyiahf/vczjk/vg6;->OooO00o(Llyiahf/vczjk/ug6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;)V

    :cond_0
    return-void
.end method

.method public final o000OOo()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/f50;->o00000Oo()V

    return-void
.end method

.method public final o00O0O(Llyiahf/vczjk/a93;)V
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string v0, "onFocusEvent called on wrong node"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1
.end method

.method public final o0O0O00()V
    .locals 1

    const/4 v0, 0x1

    invoke-virtual {p0, v0}, Llyiahf/vczjk/f50;->o00000OO(Z)V

    return-void
.end method

.method public final o0OoOo0(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string v1, "null cannot be cast to non-null type androidx.compose.ui.layout.LayoutModifier"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/eo4;

    new-instance v1, Llyiahf/vczjk/l22;

    sget-object v2, Llyiahf/vczjk/rf5;->OooOOO:Llyiahf/vczjk/rf5;

    sget-object v3, Llyiahf/vczjk/sf5;->OooOOO0:Llyiahf/vczjk/sf5;

    const/4 v4, 0x1

    invoke-direct {v1, p2, v2, v3, v4}, Llyiahf/vczjk/l22;-><init>(Llyiahf/vczjk/ef5;Ljava/lang/Enum;Ljava/lang/Enum;I)V

    const/4 p2, 0x7

    const/4 v2, 0x0

    invoke-static {v2, p3, p2}, Llyiahf/vczjk/uk1;->OooO0O0(III)J

    move-result-wide p2

    new-instance v2, Llyiahf/vczjk/b44;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v3

    invoke-direct {v2, p1, v3}, Llyiahf/vczjk/b44;-><init>(Llyiahf/vczjk/o34;Llyiahf/vczjk/yn4;)V

    invoke-interface {v0, v2, v1, p2, p3}, Llyiahf/vczjk/eo4;->OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/mf5;->getWidth()I

    move-result p1

    return p1
.end method

.method public final oo000o()Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string v1, "null cannot be cast to non-null type androidx.compose.ui.input.pointer.PointerInputModifier"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/uy6;

    iget-object v0, v0, Llyiahf/vczjk/uy6;->OooOOOo:Llyiahf/vczjk/ty6;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v0, 0x1

    return v0
.end method

.method public final ooOO(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;J)V
    .locals 6

    iget-object p3, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    const-string p4, "null cannot be cast to non-null type androidx.compose.ui.input.pointer.PointerInputModifier"

    invoke-static {p3, p4}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p3, Llyiahf/vczjk/uy6;

    iget-object p3, p3, Llyiahf/vczjk/uy6;->OooOOOo:Llyiahf/vczjk/ty6;

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p4, p1, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    iget-object v0, p3, Llyiahf/vczjk/ty6;->OooO0OO:Llyiahf/vczjk/uy6;

    iget-boolean v1, v0, Llyiahf/vczjk/uy6;->OooOOOO:Z

    const/4 v2, 0x0

    if-nez v1, :cond_2

    invoke-interface {p4}, Ljava/util/Collection;->size()I

    move-result v1

    move v3, v2

    :goto_0
    if-ge v3, v1, :cond_1

    invoke-interface {p4, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ky6;

    invoke-static {v4}, Llyiahf/vczjk/vl6;->OooO0oo(Llyiahf/vczjk/ky6;)Z

    move-result v5

    if-nez v5, :cond_2

    invoke-static {v4}, Llyiahf/vczjk/vl6;->OooOO0(Llyiahf/vczjk/ky6;)Z

    move-result v4

    if-eqz v4, :cond_0

    goto :goto_1

    :cond_0
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    move v1, v2

    goto :goto_2

    :cond_2
    :goto_1
    const/4 v1, 0x1

    :goto_2
    iget-object v3, p3, Llyiahf/vczjk/ty6;->OooO0O0:Llyiahf/vczjk/py6;

    sget-object v4, Llyiahf/vczjk/py6;->OooOOOO:Llyiahf/vczjk/py6;

    if-eq v3, v4, :cond_4

    sget-object v3, Llyiahf/vczjk/fy6;->OooOOO0:Llyiahf/vczjk/fy6;

    if-ne p2, v3, :cond_3

    if-eqz v1, :cond_3

    invoke-virtual {p3, p1}, Llyiahf/vczjk/ty6;->OooO00o(Llyiahf/vczjk/ey6;)V

    :cond_3
    sget-object v3, Llyiahf/vczjk/fy6;->OooOOOO:Llyiahf/vczjk/fy6;

    if-ne p2, v3, :cond_4

    if-nez v1, :cond_4

    invoke-virtual {p3, p1}, Llyiahf/vczjk/ty6;->OooO00o(Llyiahf/vczjk/ey6;)V

    :cond_4
    sget-object p1, Llyiahf/vczjk/fy6;->OooOOOO:Llyiahf/vczjk/fy6;

    if-ne p2, p1, :cond_7

    invoke-interface {p4}, Ljava/util/Collection;->size()I

    move-result p1

    move p2, v2

    :goto_3
    if-ge p2, p1, :cond_6

    invoke-interface {p4, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ky6;

    invoke-static {v1}, Llyiahf/vczjk/vl6;->OooOO0(Llyiahf/vczjk/ky6;)Z

    move-result v1

    if-nez v1, :cond_5

    goto :goto_4

    :cond_5
    add-int/lit8 p2, p2, 0x1

    goto :goto_3

    :cond_6
    sget-object p1, Llyiahf/vczjk/py6;->OooOOO0:Llyiahf/vczjk/py6;

    iput-object p1, p3, Llyiahf/vczjk/ty6;->OooO0O0:Llyiahf/vczjk/py6;

    iput-boolean v2, v0, Llyiahf/vczjk/uy6;->OooOOOO:Z

    :cond_7
    :goto_4
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f50;->OooOoOO:Llyiahf/vczjk/il5;

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
