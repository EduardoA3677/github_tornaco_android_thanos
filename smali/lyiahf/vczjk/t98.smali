.class public final Llyiahf/vczjk/t98;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/go4;
.implements Llyiahf/vczjk/ne8;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/z98;

.field public OooOoo0:Z


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 9

    iget-boolean v0, p0, Llyiahf/vczjk/t98;->OooOoo0:Z

    if-eqz v0, :cond_0

    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    :goto_0
    invoke-static {p3, p4, v0}, Llyiahf/vczjk/vc6;->OooOOO(JLlyiahf/vczjk/nf6;)V

    iget-boolean v0, p0, Llyiahf/vczjk/t98;->OooOoo0:Z

    const v1, 0x7fffffff

    if-eqz v0, :cond_1

    move v7, v1

    goto :goto_1

    :cond_1
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v0

    move v7, v0

    :goto_1
    iget-boolean v0, p0, Llyiahf/vczjk/t98;->OooOoo0:Z

    if-eqz v0, :cond_2

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v1

    :cond_2
    move v5, v1

    const/4 v4, 0x0

    const/4 v6, 0x0

    const/4 v8, 0x5

    move-wide v2, p3

    invoke-static/range {v2 .. v8}, Llyiahf/vczjk/rk1;->OooO00o(JIIIII)J

    move-result-wide p3

    invoke-interface {p2, p3, p4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    invoke-static {v2, v3}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result p4

    if-le p3, p4, :cond_3

    move p3, p4

    :cond_3
    iget p4, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    invoke-static {v2, v3}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v0

    if-le p4, v0, :cond_4

    move p4, v0

    :cond_4
    iget v0, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    sub-int/2addr v0, p4

    iget v1, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    sub-int/2addr v1, p3

    iget-boolean v2, p0, Llyiahf/vczjk/t98;->OooOoo0:Z

    if-eqz v2, :cond_5

    goto :goto_2

    :cond_5
    move v0, v1

    :goto_2
    iget-object v1, p0, Llyiahf/vczjk/t98;->OooOoOO:Llyiahf/vczjk/z98;

    iget-object v2, v1, Llyiahf/vczjk/z98;->OooO0Oo:Llyiahf/vczjk/qr5;

    check-cast v2, Llyiahf/vczjk/bw8;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    invoke-static {}, Llyiahf/vczjk/wr6;->OooOOO0()Llyiahf/vczjk/nv8;

    move-result-object v2

    if-eqz v2, :cond_6

    invoke-virtual {v2}, Llyiahf/vczjk/nv8;->OooO0o0()Llyiahf/vczjk/oe3;

    move-result-object v3

    goto :goto_3

    :cond_6
    const/4 v3, 0x0

    :goto_3
    invoke-static {v2}, Llyiahf/vczjk/wr6;->OooOOOo(Llyiahf/vczjk/nv8;)Llyiahf/vczjk/nv8;

    move-result-object v4

    :try_start_0
    invoke-virtual {v1}, Llyiahf/vczjk/z98;->OooO0o()I

    move-result v5

    if-le v5, v0, :cond_7

    iget-object v1, v1, Llyiahf/vczjk/z98;->OooO00o:Llyiahf/vczjk/qr5;

    check-cast v1, Llyiahf/vczjk/bw8;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/bw8;->OooOo00(I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_7
    invoke-static {v2, v4, v3}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    iget-object v1, p0, Llyiahf/vczjk/t98;->OooOoOO:Llyiahf/vczjk/z98;

    iget-boolean v2, p0, Llyiahf/vczjk/t98;->OooOoo0:Z

    if-eqz v2, :cond_8

    move v2, p4

    goto :goto_4

    :cond_8
    move v2, p3

    :goto_4
    iget-object v1, v1, Llyiahf/vczjk/z98;->OooO0O0:Llyiahf/vczjk/qr5;

    check-cast v1, Llyiahf/vczjk/bw8;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    new-instance v1, Llyiahf/vczjk/s98;

    invoke-direct {v1, p0, v0, p2}, Llyiahf/vczjk/s98;-><init>(Llyiahf/vczjk/t98;ILlyiahf/vczjk/ow6;)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, p3, p4, p2, v1}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1

    :catchall_0
    move-exception v0

    move-object p1, v0

    invoke-static {v2, v4, v3}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    throw p1
.end method

.method public final OooOo00(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 0

    iget-boolean p1, p0, Llyiahf/vczjk/t98;->OooOoo0:Z

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    const p3, 0x7fffffff

    :goto_0
    invoke-interface {p2, p3}, Llyiahf/vczjk/ef5;->OooooO0(I)I

    move-result p1

    return p1
.end method

.method public final OooOooO(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 0

    iget-boolean p1, p0, Llyiahf/vczjk/t98;->OooOoo0:Z

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    const p3, 0x7fffffff

    :goto_0
    invoke-interface {p2, p3}, Llyiahf/vczjk/ef5;->OooO0OO(I)I

    move-result p1

    return p1
.end method

.method public final OoooOOo(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 0

    iget-boolean p1, p0, Llyiahf/vczjk/t98;->OooOoo0:Z

    if-eqz p1, :cond_0

    const p3, 0x7fffffff

    :cond_0
    invoke-interface {p2, p3}, Llyiahf/vczjk/ef5;->OooOo0(I)I

    move-result p1

    return p1
.end method

.method public final OooooO0(Llyiahf/vczjk/af8;)V
    .locals 4

    invoke-static {p1}, Llyiahf/vczjk/ye8;->OooO0oO(Llyiahf/vczjk/af8;)V

    new-instance v0, Llyiahf/vczjk/b98;

    new-instance v1, Llyiahf/vczjk/p98;

    invoke-direct {v1, p0}, Llyiahf/vczjk/p98;-><init>(Llyiahf/vczjk/t98;)V

    new-instance v2, Llyiahf/vczjk/q98;

    invoke-direct {v2, p0}, Llyiahf/vczjk/q98;-><init>(Llyiahf/vczjk/t98;)V

    const/4 v3, 0x0

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/b98;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Z)V

    iget-boolean v1, p0, Llyiahf/vczjk/t98;->OooOoo0:Z

    if-eqz v1, :cond_0

    sget-object v1, Llyiahf/vczjk/ve8;->OooOo00:Llyiahf/vczjk/ze8;

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/16 v3, 0xb

    aget-object v2, v2, v3

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    return-void

    :cond_0
    sget-object v1, Llyiahf/vczjk/ve8;->OooOOoo:Llyiahf/vczjk/ze8;

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/16 v3, 0xa

    aget-object v2, v2, v3

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    return-void
.end method

.method public final o0OoOo0(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 0

    iget-boolean p1, p0, Llyiahf/vczjk/t98;->OooOoo0:Z

    if-eqz p1, :cond_0

    const p3, 0x7fffffff

    :cond_0
    invoke-interface {p2, p3}, Llyiahf/vczjk/ef5;->OooOo0o(I)I

    move-result p1

    return p1
.end method
