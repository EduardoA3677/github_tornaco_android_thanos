.class public final Llyiahf/vczjk/a04;
.super Llyiahf/vczjk/q65;
.source "SourceFile"


# virtual methods
.method public final OooO0OO(I)I
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0()Llyiahf/vczjk/era;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/era;->Oooo0OO()Llyiahf/vczjk/lf5;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ro4;

    iget-object v2, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v2, v2, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/v16;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOO0()Ljava/util/List;

    move-result-object v0

    invoke-interface {v1, v2, v0, p1}, Llyiahf/vczjk/lf5;->OooO(Llyiahf/vczjk/o34;Ljava/util/List;I)I

    move-result p1

    return p1
.end method

.method public final OooOo0(I)I
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0()Llyiahf/vczjk/era;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/era;->Oooo0OO()Llyiahf/vczjk/lf5;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ro4;

    iget-object v2, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v2, v2, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/v16;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOO0()Ljava/util/List;

    move-result-object v0

    invoke-interface {v1, v2, v0, p1}, Llyiahf/vczjk/lf5;->OooO0Oo(Llyiahf/vczjk/o34;Ljava/util/List;I)I

    move-result p1

    return p1
.end method

.method public final OooOo0o(I)I
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0()Llyiahf/vczjk/era;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/era;->Oooo0OO()Llyiahf/vczjk/lf5;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ro4;

    iget-object v2, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v2, v2, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/v16;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOO0()Ljava/util/List;

    move-result-object v0

    invoke-interface {v1, v2, v0, p1}, Llyiahf/vczjk/lf5;->OooO0o(Llyiahf/vczjk/o34;Ljava/util/List;I)I

    move-result p1

    return p1
.end method

.method public final OooOoOO(J)Llyiahf/vczjk/ow6;
    .locals 6

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ow6;->oo000o(J)V

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    iget-object v1, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v1

    iget-object v2, v1, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v1, v1, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v1, :cond_0

    aget-object v4, v2, v3

    check-cast v4, Llyiahf/vczjk/ro4;

    iget-object v4, v4, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v4, v4, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object v5, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    iput-object v5, v4, Llyiahf/vczjk/w65;->OooOo0O:Llyiahf/vczjk/no4;

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    iget-object v1, v0, Llyiahf/vczjk/ro4;->Oooo0:Llyiahf/vczjk/lf5;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOO0()Ljava/util/List;

    move-result-object v0

    invoke-interface {v1, p0, v0, p1, p2}, Llyiahf/vczjk/lf5;->OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-static {p0, p1}, Llyiahf/vczjk/q65;->o00000OO(Llyiahf/vczjk/q65;Llyiahf/vczjk/mf5;)V

    return-object p0
.end method

.method public final OooooO0(I)I
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0()Llyiahf/vczjk/era;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/era;->Oooo0OO()Llyiahf/vczjk/lf5;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ro4;

    iget-object v2, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v2, v2, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/v16;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOOO0()Ljava/util/List;

    move-result-object v0

    invoke-interface {v1, v2, v0, p1}, Llyiahf/vczjk/lf5;->OooOO0(Llyiahf/vczjk/o34;Ljava/util/List;I)I

    move-result p1

    return p1
.end method

.method public final o00000Oo()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v0}, Llyiahf/vczjk/w65;->o0OO00O()V

    return-void
.end method

.method public final o0ooOoO(Llyiahf/vczjk/p4;)I
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-boolean v1, v0, Llyiahf/vczjk/w65;->OooOo0o:Z

    const/4 v2, 0x1

    iget-object v3, v0, Llyiahf/vczjk/w65;->OooOooo:Llyiahf/vczjk/so4;

    if-nez v1, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/w65;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object v4, v1, Llyiahf/vczjk/vo4;->OooO0Oo:Llyiahf/vczjk/lo4;

    sget-object v5, Llyiahf/vczjk/lo4;->OooOOO:Llyiahf/vczjk/lo4;

    if-ne v4, v5, :cond_0

    iput-boolean v2, v3, Llyiahf/vczjk/v4;->OooO0o:Z

    iget-boolean v4, v3, Llyiahf/vczjk/v4;->OooO0O0:Z

    if-eqz v4, :cond_1

    iput-boolean v2, v1, Llyiahf/vczjk/vo4;->OooO0o:Z

    iput-boolean v2, v1, Llyiahf/vczjk/vo4;->OooO0oO:Z

    goto :goto_0

    :cond_0
    iput-boolean v2, v3, Llyiahf/vczjk/v4;->OooO0oO:Z

    :cond_1
    :goto_0
    invoke-virtual {v0}, Llyiahf/vczjk/w65;->OooO0oO()Llyiahf/vczjk/b04;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/b04;->OoooOoo:Llyiahf/vczjk/a04;

    if-nez v1, :cond_2

    goto :goto_1

    :cond_2
    iput-boolean v2, v1, Llyiahf/vczjk/o65;->OooOo00:Z

    :goto_1
    invoke-virtual {v0}, Llyiahf/vczjk/w65;->Oooo0O0()V

    invoke-virtual {v0}, Llyiahf/vczjk/w65;->OooO0oO()Llyiahf/vczjk/b04;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/b04;->OoooOoo:Llyiahf/vczjk/a04;

    if-nez v0, :cond_3

    goto :goto_2

    :cond_3
    const/4 v1, 0x0

    iput-boolean v1, v0, Llyiahf/vczjk/o65;->OooOo00:Z

    :goto_2
    iget-object v0, v3, Llyiahf/vczjk/v4;->OooO:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Integer;

    if-eqz v0, :cond_4

    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    move-result v0

    goto :goto_3

    :cond_4
    const/high16 v0, -0x80000000

    :goto_3
    iget-object v1, p0, Llyiahf/vczjk/q65;->OooOooO:Llyiahf/vczjk/zr5;

    invoke-virtual {v1, v0, p1}, Llyiahf/vczjk/zr5;->OooO0oO(ILjava/lang/Object;)V

    return v0
.end method
