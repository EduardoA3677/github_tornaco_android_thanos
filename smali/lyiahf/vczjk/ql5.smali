.class public interface abstract Llyiahf/vczjk/ql5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sl5;
.implements Llyiahf/vczjk/l52;


# virtual methods
.method public OooO0OO(Llyiahf/vczjk/ie7;)Ljava/lang/Object;
    .locals 9

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/jl5;

    iget-object v1, v0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v1, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v1, :cond_0

    const-string v1, "ModifierLocal accessed from an unattached node"

    invoke-static {v1}, Llyiahf/vczjk/pz3;->OooO00o(Ljava/lang/String;)V

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v1, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v1, :cond_1

    const-string v1, "visitAncestors called on an unattached node"

    invoke-static {v1}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_1
    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v1

    :goto_0
    if-eqz v1, :cond_c

    iget-object v2, v1, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v2, v2, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jl5;

    iget v2, v2, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/lit8 v2, v2, 0x20

    const/4 v3, 0x0

    if-eqz v2, :cond_a

    :goto_1
    if-eqz v0, :cond_a

    iget v2, v0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v2, v2, 0x20

    if-eqz v2, :cond_9

    move-object v2, v0

    move-object v4, v3

    :goto_2
    if-eqz v2, :cond_9

    instance-of v5, v2, Llyiahf/vczjk/ql5;

    if-eqz v5, :cond_2

    check-cast v2, Llyiahf/vczjk/ql5;

    invoke-interface {v2}, Llyiahf/vczjk/ql5;->OoooO0O()Llyiahf/vczjk/e16;

    move-result-object v5

    invoke-virtual {v5, p1}, Llyiahf/vczjk/e16;->OooOOo0(Llyiahf/vczjk/ie7;)Z

    move-result v5

    if-eqz v5, :cond_8

    invoke-interface {v2}, Llyiahf/vczjk/ql5;->OoooO0O()Llyiahf/vczjk/e16;

    move-result-object v0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/e16;->OooOo00(Llyiahf/vczjk/ie7;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_2
    iget v5, v2, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v5, v5, 0x20

    if-eqz v5, :cond_8

    instance-of v5, v2, Llyiahf/vczjk/m52;

    if-eqz v5, :cond_8

    move-object v5, v2

    check-cast v5, Llyiahf/vczjk/m52;

    iget-object v5, v5, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    const/4 v6, 0x0

    :goto_3
    const/4 v7, 0x1

    if-eqz v5, :cond_7

    iget v8, v5, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit8 v8, v8, 0x20

    if-eqz v8, :cond_6

    add-int/lit8 v6, v6, 0x1

    if-ne v6, v7, :cond_3

    move-object v2, v5

    goto :goto_4

    :cond_3
    if-nez v4, :cond_4

    new-instance v4, Llyiahf/vczjk/ws5;

    const/16 v7, 0x10

    new-array v7, v7, [Llyiahf/vczjk/jl5;

    invoke-direct {v4, v7}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_4
    if-eqz v2, :cond_5

    invoke-virtual {v4, v2}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v2, v3

    :cond_5
    invoke-virtual {v4, v5}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_6
    :goto_4
    iget-object v5, v5, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_3

    :cond_7
    if-ne v6, v7, :cond_8

    goto :goto_2

    :cond_8
    invoke-static {v4}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v2

    goto :goto_2

    :cond_9
    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto :goto_1

    :cond_a
    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v1

    if-eqz v1, :cond_b

    iget-object v0, v1, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    if-eqz v0, :cond_b

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cf9;

    goto/16 :goto_0

    :cond_b
    move-object v0, v3

    goto/16 :goto_0

    :cond_c
    iget-object p1, p1, Llyiahf/vczjk/ie7;->OooO00o:Llyiahf/vczjk/rm4;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public OoooO0O()Llyiahf/vczjk/e16;
    .locals 1

    sget-object v0, Llyiahf/vczjk/cn2;->OooOO0o:Llyiahf/vczjk/cn2;

    return-object v0
.end method
