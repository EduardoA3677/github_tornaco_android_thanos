.class public abstract Llyiahf/vczjk/z16;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/zr5;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/a76;->OooO00o:Llyiahf/vczjk/zr5;

    new-instance v0, Llyiahf/vczjk/zr5;

    invoke-direct {v0}, Llyiahf/vczjk/zr5;-><init>()V

    sput-object v0, Llyiahf/vczjk/z16;->OooO00o:Llyiahf/vczjk/zr5;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/jl5;II)V
    .locals 2

    instance-of v0, p0, Llyiahf/vczjk/m52;

    if-eqz v0, :cond_1

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/m52;

    iget v1, v0, Llyiahf/vczjk/m52;->OooOoOO:I

    and-int/2addr v1, p1

    invoke-static {p0, v1, p2}, Llyiahf/vczjk/z16;->OooO0O0(Llyiahf/vczjk/jl5;II)V

    iget p0, v0, Llyiahf/vczjk/m52;->OooOoOO:I

    not-int p0, p0

    and-int/2addr p0, p1

    iget-object p1, v0, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    :goto_0
    if-eqz p1, :cond_0

    invoke-static {p1, p0, p2}, Llyiahf/vczjk/z16;->OooO00o(Llyiahf/vczjk/jl5;II)V

    iget-object p1, p1, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_0

    :cond_0
    return-void

    :cond_1
    iget v0, p0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr p1, v0

    invoke-static {p0, p1, p2}, Llyiahf/vczjk/z16;->OooO0O0(Llyiahf/vczjk/jl5;II)V

    return-void
.end method

.method public static final OooO0O0(Llyiahf/vczjk/jl5;II)V
    .locals 18

    move-object/from16 v0, p0

    move/from16 v1, p1

    move/from16 v2, p2

    if-nez v2, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/jl5;->o0Oo0oo()Z

    move-result v3

    if-nez v3, :cond_0

    goto/16 :goto_7

    :cond_0
    and-int/lit8 v3, v1, 0x2

    const/4 v4, 0x0

    const/4 v5, 0x2

    const/4 v6, 0x0

    const/4 v7, 0x1

    if-eqz v3, :cond_2

    instance-of v3, v0, Llyiahf/vczjk/go4;

    if-eqz v3, :cond_2

    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/go4;

    invoke-static {v3}, Llyiahf/vczjk/t51;->Oooo00o(Llyiahf/vczjk/go4;)V

    if-ne v2, v5, :cond_2

    invoke-static {v0, v5}, Llyiahf/vczjk/yi4;->o00ooo(Llyiahf/vczjk/l52;I)Llyiahf/vczjk/v16;

    move-result-object v3

    iput-boolean v7, v3, Llyiahf/vczjk/v16;->OooOoo0:Z

    iget-object v8, v3, Llyiahf/vczjk/v16;->OoooO00:Llyiahf/vczjk/r16;

    invoke-virtual {v8}, Llyiahf/vczjk/r16;->OooO00o()Ljava/lang/Object;

    iget-object v8, v3, Llyiahf/vczjk/v16;->OoooO0O:Llyiahf/vczjk/sg6;

    if-eqz v8, :cond_2

    iget-object v8, v3, Llyiahf/vczjk/v16;->OoooO:Llyiahf/vczjk/kj3;

    if-eqz v8, :cond_1

    iput-object v6, v3, Llyiahf/vczjk/v16;->OoooO:Llyiahf/vczjk/kj3;

    :cond_1
    invoke-virtual {v3, v6, v4}, Llyiahf/vczjk/v16;->o000Ooo(Llyiahf/vczjk/oe3;Z)V

    iget-object v3, v3, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/ro4;->o000oOoO(Z)V

    :cond_2
    and-int/lit16 v3, v1, 0x80

    if-eqz v3, :cond_3

    instance-of v3, v0, Llyiahf/vczjk/vn4;

    if-eqz v3, :cond_3

    if-eq v2, v5, :cond_3

    invoke-static {v0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/ro4;->OooOooo()V

    :cond_3
    and-int/lit16 v3, v1, 0x100

    if-eqz v3, :cond_5

    instance-of v3, v0, Llyiahf/vczjk/gi3;

    if-eqz v3, :cond_5

    if-eq v2, v5, :cond_5

    invoke-static {v0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/ro4;->OooOOo()Z

    move-result v3

    if-nez v3, :cond_5

    invoke-virtual {v2}, Llyiahf/vczjk/ro4;->OooOOoo()Z

    move-result v3

    if-nez v3, :cond_5

    iget-boolean v3, v2, Llyiahf/vczjk/ro4;->OoooOoo:Z

    if-eqz v3, :cond_4

    goto :goto_0

    :cond_4
    invoke-static {v2}, Llyiahf/vczjk/uo4;->OooO00o(Llyiahf/vczjk/ro4;)Llyiahf/vczjk/tg6;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/xa;

    iget-object v5, v3, Llyiahf/vczjk/xa;->OoooOo0:Llyiahf/vczjk/gf5;

    iget-object v5, v5, Llyiahf/vczjk/gf5;->OooO0o0:Llyiahf/vczjk/a27;

    iget-object v5, v5, Llyiahf/vczjk/a27;->OooOOO:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/ws5;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    iput-boolean v7, v2, Llyiahf/vczjk/ro4;->OoooOoo:Z

    invoke-virtual {v3, v6}, Llyiahf/vczjk/xa;->Oooo00o(Llyiahf/vczjk/ro4;)V

    :cond_5
    :goto_0
    and-int/lit8 v2, v1, 0x4

    if-eqz v2, :cond_6

    instance-of v2, v0, Llyiahf/vczjk/fg2;

    if-eqz v2, :cond_6

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/fg2;

    invoke-static {v2}, Llyiahf/vczjk/ye5;->OooOoO0(Llyiahf/vczjk/fg2;)V

    :cond_6
    and-int/lit8 v2, v1, 0x8

    if-eqz v2, :cond_7

    instance-of v2, v0, Llyiahf/vczjk/ne8;

    if-eqz v2, :cond_7

    invoke-static {v0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v2

    iput-boolean v7, v2, Llyiahf/vczjk/ro4;->OooOooO:Z

    :cond_7
    and-int/lit8 v2, v1, 0x40

    if-eqz v2, :cond_8

    instance-of v2, v0, Llyiahf/vczjk/cp6;

    if-eqz v2, :cond_8

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/cp6;

    invoke-static {v2}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v2

    iget-object v2, v2, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v3, v2, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iput-boolean v7, v3, Llyiahf/vczjk/kf5;->OooOooO:Z

    iget-object v2, v2, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    if-eqz v2, :cond_8

    iput-boolean v7, v2, Llyiahf/vczjk/w65;->Oooo0:Z

    :cond_8
    and-int/lit16 v2, v1, 0x800

    if-eqz v2, :cond_15

    instance-of v2, v0, Llyiahf/vczjk/u83;

    if-eqz v2, :cond_15

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/u83;

    sput-object v6, Llyiahf/vczjk/lp0;->OooO0O0:Ljava/lang/Boolean;

    sget-object v3, Llyiahf/vczjk/lp0;->OooO00o:Llyiahf/vczjk/lp0;

    invoke-interface {v2, v3}, Llyiahf/vczjk/u83;->OooO0o(Llyiahf/vczjk/s83;)V

    sget-object v3, Llyiahf/vczjk/lp0;->OooO0O0:Ljava/lang/Boolean;

    if-eqz v3, :cond_15

    check-cast v2, Llyiahf/vczjk/jl5;

    iget-object v3, v2, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v3, v3, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v3, :cond_9

    const-string v3, "visitChildren called on an unattached node"

    invoke-static {v3}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_9
    new-instance v3, Llyiahf/vczjk/ws5;

    const/16 v5, 0x10

    new-array v8, v5, [Llyiahf/vczjk/jl5;

    invoke-direct {v3, v8}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iget-object v2, v2, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-object v8, v2, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    if-nez v8, :cond_a

    invoke-static {v3, v2}, Llyiahf/vczjk/yi4;->OooOOoo(Llyiahf/vczjk/ws5;Llyiahf/vczjk/jl5;)V

    goto :goto_1

    :cond_a
    invoke-virtual {v3, v8}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_b
    :goto_1
    iget v2, v3, Llyiahf/vczjk/ws5;->OooOOOO:I

    if-eqz v2, :cond_15

    add-int/lit8 v2, v2, -0x1

    invoke-virtual {v3, v2}, Llyiahf/vczjk/ws5;->OooOO0O(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/jl5;

    iget v8, v2, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/lit16 v8, v8, 0x400

    if-nez v8, :cond_c

    invoke-static {v3, v2}, Llyiahf/vczjk/yi4;->OooOOoo(Llyiahf/vczjk/ws5;Llyiahf/vczjk/jl5;)V

    goto :goto_1

    :cond_c
    :goto_2
    if-eqz v2, :cond_b

    iget v8, v2, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v8, v8, 0x400

    if-eqz v8, :cond_14

    move-object v8, v6

    :goto_3
    if-eqz v2, :cond_b

    instance-of v9, v2, Llyiahf/vczjk/d93;

    if-eqz v9, :cond_d

    check-cast v2, Llyiahf/vczjk/d93;

    invoke-static {v2}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/xa;

    invoke-virtual {v9}, Llyiahf/vczjk/xa;->getFocusOwner()Llyiahf/vczjk/m83;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/r83;

    iget-object v12, v9, Llyiahf/vczjk/r83;->OooO0oO:Llyiahf/vczjk/k83;

    iget-object v9, v12, Llyiahf/vczjk/k83;->OooO0Oo:Llyiahf/vczjk/ks5;

    invoke-virtual {v9, v2}, Llyiahf/vczjk/ks5;->OooO0Oo(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_13

    iget-boolean v2, v12, Llyiahf/vczjk/k83;->OooO0o:Z

    if-nez v2, :cond_13

    new-instance v10, Llyiahf/vczjk/da;

    const-class v13, Llyiahf/vczjk/k83;

    const-string v14, "invalidateNodes"

    const/4 v11, 0x0

    const-string v15, "invalidateNodes()V"

    const/16 v16, 0x0

    const/16 v17, 0x5

    invoke-direct/range {v10 .. v17}, Llyiahf/vczjk/da;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    iget-object v2, v12, Llyiahf/vczjk/k83;->OooO00o:Llyiahf/vczjk/o00000;

    invoke-virtual {v2, v10}, Llyiahf/vczjk/o00000;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    iput-boolean v7, v12, Llyiahf/vczjk/k83;->OooO0o:Z

    goto :goto_6

    :cond_d
    iget v9, v2, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v9, v9, 0x400

    if-eqz v9, :cond_13

    instance-of v9, v2, Llyiahf/vczjk/m52;

    if-eqz v9, :cond_13

    move-object v9, v2

    check-cast v9, Llyiahf/vczjk/m52;

    iget-object v9, v9, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    move v10, v4

    :goto_4
    if-eqz v9, :cond_12

    iget v11, v9, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v11, v11, 0x400

    if-eqz v11, :cond_11

    add-int/lit8 v10, v10, 0x1

    if-ne v10, v7, :cond_e

    move-object v2, v9

    goto :goto_5

    :cond_e
    if-nez v8, :cond_f

    new-instance v8, Llyiahf/vczjk/ws5;

    new-array v11, v5, [Llyiahf/vczjk/jl5;

    invoke-direct {v8, v11}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_f
    if-eqz v2, :cond_10

    invoke-virtual {v8, v2}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v2, v6

    :cond_10
    invoke-virtual {v8, v9}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_11
    :goto_5
    iget-object v9, v9, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_4

    :cond_12
    if-ne v10, v7, :cond_13

    goto :goto_3

    :cond_13
    :goto_6
    invoke-static {v8}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v2

    goto :goto_3

    :cond_14
    iget-object v2, v2, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto/16 :goto_2

    :cond_15
    and-int/lit16 v1, v1, 0x1000

    if-eqz v1, :cond_16

    instance-of v1, v0, Llyiahf/vczjk/c83;

    if-eqz v1, :cond_16

    check-cast v0, Llyiahf/vczjk/c83;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/xa;

    invoke-virtual {v1}, Llyiahf/vczjk/xa;->getFocusOwner()Llyiahf/vczjk/m83;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/r83;

    iget-object v10, v1, Llyiahf/vczjk/r83;->OooO0oO:Llyiahf/vczjk/k83;

    iget-object v1, v10, Llyiahf/vczjk/k83;->OooO0o0:Llyiahf/vczjk/ks5;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ks5;->OooO0Oo(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_16

    iget-boolean v0, v10, Llyiahf/vczjk/k83;->OooO0o:Z

    if-nez v0, :cond_16

    new-instance v8, Llyiahf/vczjk/da;

    const-class v11, Llyiahf/vczjk/k83;

    const-string v12, "invalidateNodes"

    const/4 v9, 0x0

    const-string v13, "invalidateNodes()V"

    const/4 v14, 0x0

    const/4 v15, 0x5

    invoke-direct/range {v8 .. v15}, Llyiahf/vczjk/da;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    iget-object v0, v10, Llyiahf/vczjk/k83;->OooO00o:Llyiahf/vczjk/o00000;

    invoke-virtual {v0, v8}, Llyiahf/vczjk/o00000;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    iput-boolean v7, v10, Llyiahf/vczjk/k83;->OooO0o:Z

    :cond_16
    :goto_7
    return-void
.end method

.method public static final OooO0OO(Llyiahf/vczjk/jl5;)V
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    const-string v0, "autoInvalidateUpdatedNode called on unattached node"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    const/4 v0, -0x1

    const/4 v1, 0x0

    invoke-static {p0, v0, v1}, Llyiahf/vczjk/z16;->OooO00o(Llyiahf/vczjk/jl5;II)V

    return-void
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/il5;)I
    .locals 2

    instance-of v0, p0, Llyiahf/vczjk/eo4;

    if-eqz v0, :cond_0

    const/4 v0, 0x3

    goto :goto_0

    :cond_0
    const/4 v0, 0x1

    :goto_0
    instance-of v1, p0, Llyiahf/vczjk/nx3;

    if-eqz v1, :cond_1

    or-int/lit8 v0, v0, 0x4

    :cond_1
    instance-of v1, p0, Llyiahf/vczjk/le8;

    if-eqz v1, :cond_2

    or-int/lit8 v0, v0, 0x8

    :cond_2
    instance-of v1, p0, Llyiahf/vczjk/uy6;

    if-eqz v1, :cond_3

    or-int/lit8 v0, v0, 0x10

    :cond_3
    instance-of v1, p0, Llyiahf/vczjk/nl5;

    if-nez v1, :cond_4

    instance-of v1, p0, Llyiahf/vczjk/rl5;

    if-eqz v1, :cond_5

    :cond_4
    or-int/lit8 v0, v0, 0x20

    :cond_5
    instance-of v1, p0, Llyiahf/vczjk/g20;

    if-eqz v1, :cond_6

    or-int/lit16 v0, v0, 0x100

    :cond_6
    instance-of v1, p0, Llyiahf/vczjk/bp6;

    if-eqz v1, :cond_7

    or-int/lit8 v0, v0, 0x40

    :cond_7
    instance-of p0, p0, Llyiahf/vczjk/oh0;

    if-eqz p0, :cond_8

    const/high16 p0, 0x80000

    or-int/2addr p0, v0

    return p0

    :cond_8
    return v0
.end method

.method public static final OooO0o(Llyiahf/vczjk/jl5;)I
    .locals 2

    instance-of v0, p0, Llyiahf/vczjk/m52;

    if-eqz v0, :cond_1

    check-cast p0, Llyiahf/vczjk/m52;

    iget v0, p0, Llyiahf/vczjk/m52;->OooOoOO:I

    iget-object p0, p0, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    :goto_0
    if-eqz p0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/z16;->OooO0o(Llyiahf/vczjk/jl5;)I

    move-result v1

    or-int/2addr v0, v1

    iget-object p0, p0, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_0

    :cond_0
    return v0

    :cond_1
    invoke-static {p0}, Llyiahf/vczjk/z16;->OooO0o0(Llyiahf/vczjk/jl5;)I

    move-result p0

    return p0
.end method

.method public static final OooO0o0(Llyiahf/vczjk/jl5;)I
    .locals 4

    iget v0, p0, Llyiahf/vczjk/jl5;->OooOOOO:I

    if-eqz v0, :cond_0

    return v0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/z16;->OooO00o:Llyiahf/vczjk/zr5;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zr5;->OooO0Oo(Ljava/lang/Object;)I

    move-result v2

    if-ltz v2, :cond_1

    iget-object p0, v1, Llyiahf/vczjk/zr5;->OooO0OO:[I

    aget p0, p0, v2

    return p0

    :cond_1
    instance-of v2, p0, Llyiahf/vczjk/go4;

    if-eqz v2, :cond_2

    const/4 v2, 0x3

    goto :goto_0

    :cond_2
    const/4 v2, 0x1

    :goto_0
    instance-of v3, p0, Llyiahf/vczjk/fg2;

    if-eqz v3, :cond_3

    or-int/lit8 v2, v2, 0x4

    :cond_3
    instance-of v3, p0, Llyiahf/vczjk/ne8;

    if-eqz v3, :cond_4

    or-int/lit8 v2, v2, 0x8

    :cond_4
    instance-of v3, p0, Llyiahf/vczjk/ny6;

    if-eqz v3, :cond_5

    or-int/lit8 v2, v2, 0x10

    :cond_5
    instance-of v3, p0, Llyiahf/vczjk/ql5;

    if-eqz v3, :cond_6

    or-int/lit8 v2, v2, 0x20

    :cond_6
    instance-of v3, p0, Llyiahf/vczjk/cp6;

    if-eqz v3, :cond_7

    or-int/lit8 v2, v2, 0x40

    :cond_7
    instance-of v3, p0, Llyiahf/vczjk/vn4;

    if-eqz v3, :cond_8

    or-int/lit16 v2, v2, 0x80

    :cond_8
    instance-of v3, p0, Llyiahf/vczjk/gi3;

    if-eqz v3, :cond_9

    or-int/lit16 v2, v2, 0x100

    :cond_9
    instance-of v3, p0, Llyiahf/vczjk/d93;

    if-eqz v3, :cond_a

    or-int/lit16 v2, v2, 0x400

    :cond_a
    instance-of v3, p0, Llyiahf/vczjk/u83;

    if-eqz v3, :cond_b

    or-int/lit16 v2, v2, 0x800

    :cond_b
    instance-of v3, p0, Llyiahf/vczjk/c83;

    if-eqz v3, :cond_c

    or-int/lit16 v2, v2, 0x1000

    :cond_c
    instance-of v3, p0, Llyiahf/vczjk/bj4;

    if-eqz v3, :cond_d

    or-int/lit16 v2, v2, 0x2000

    :cond_d
    instance-of v3, p0, Llyiahf/vczjk/lv7;

    if-eqz v3, :cond_e

    or-int/lit16 v2, v2, 0x4000

    :cond_e
    instance-of v3, p0, Llyiahf/vczjk/ug1;

    if-eqz v3, :cond_f

    const v3, 0x8000

    or-int/2addr v2, v3

    :cond_f
    instance-of v3, p0, Llyiahf/vczjk/c0a;

    if-eqz v3, :cond_10

    const/high16 v3, 0x40000

    or-int/2addr v2, v3

    :cond_10
    instance-of p0, p0, Llyiahf/vczjk/oh0;

    if-eqz p0, :cond_11

    const/high16 p0, 0x80000

    or-int/2addr v2, p0

    :cond_11
    invoke-virtual {v1, v2, v0}, Llyiahf/vczjk/zr5;->OooO0oO(ILjava/lang/Object;)V

    return v2
.end method

.method public static final OooO0oO(I)Z
    .locals 0

    and-int/lit16 p0, p0, 0x80

    if-eqz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method
