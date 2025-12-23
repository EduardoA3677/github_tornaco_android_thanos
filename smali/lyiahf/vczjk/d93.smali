.class public final Llyiahf/vczjk/d93;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ug1;
.implements Llyiahf/vczjk/l86;
.implements Llyiahf/vczjk/ql5;
.implements Llyiahf/vczjk/l52;


# instance fields
.field public final OooOoOO:Llyiahf/vczjk/ze3;

.field public OooOoo:Z

.field public OooOoo0:Z

.field public final OooOooO:I


# direct methods
.method public constructor <init>(ILlyiahf/vczjk/fa;I)V
    .locals 1

    and-int/lit8 v0, p3, 0x1

    if-eqz v0, :cond_0

    const/4 p1, 0x1

    :cond_0
    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_1

    const/4 p2, 0x0

    :cond_1
    invoke-direct {p0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/d93;->OooOoOO:Llyiahf/vczjk/ze3;

    iput p1, p0, Llyiahf/vczjk/d93;->OooOooO:I

    return-void
.end method

.method public static synthetic o00000oo(Llyiahf/vczjk/d93;)Z
    .locals 1

    const/4 v0, 0x7

    invoke-virtual {p0, v0}, Llyiahf/vczjk/d93;->o00000oO(I)Z

    move-result p0

    return p0
.end method


# virtual methods
.method public final Oooooo()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/d93;->o0000Ooo()V

    return-void
.end method

.method public final o00000OO(Llyiahf/vczjk/a93;Llyiahf/vczjk/a93;)V
    .locals 11

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getFocusOwner()Llyiahf/vczjk/m83;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/r83;

    iget-object v1, v0, Llyiahf/vczjk/r83;->OooOO0o:Llyiahf/vczjk/d93;

    invoke-virtual {p1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_0

    iget-object v2, p0, Llyiahf/vczjk/d93;->OooOoOO:Llyiahf/vczjk/ze3;

    if-eqz v2, :cond_0

    invoke-interface {v2, p1, p2}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v2, p1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v2, :cond_1

    const-string v2, "visitAncestors called on an unattached node"

    invoke-static {v2}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v3

    :goto_0
    if-eqz v3, :cond_e

    iget-object v4, v3, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v4, v4, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/jl5;

    iget v4, v4, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/lit16 v4, v4, 0x1400

    const/4 v5, 0x0

    if-eqz v4, :cond_c

    :goto_1
    if-eqz v2, :cond_c

    iget v4, v2, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v6, v4, 0x1400

    if-eqz v6, :cond_b

    if-eq v2, p1, :cond_2

    and-int/lit16 v6, v4, 0x400

    if-eqz v6, :cond_2

    goto/16 :goto_6

    :cond_2
    and-int/lit16 v4, v4, 0x1000

    if-eqz v4, :cond_b

    move-object v4, v2

    move-object v6, v5

    :goto_2
    if-eqz v4, :cond_b

    instance-of v7, v4, Llyiahf/vczjk/c83;

    if-eqz v7, :cond_4

    check-cast v4, Llyiahf/vczjk/c83;

    iget-object v7, v0, Llyiahf/vczjk/r83;->OooOO0o:Llyiahf/vczjk/d93;

    if-eq v1, v7, :cond_3

    goto :goto_5

    :cond_3
    invoke-interface {v4, p2}, Llyiahf/vczjk/c83;->o00O0O(Llyiahf/vczjk/a93;)V

    goto :goto_5

    :cond_4
    iget v7, v4, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v7, v7, 0x1000

    if-eqz v7, :cond_a

    instance-of v7, v4, Llyiahf/vczjk/m52;

    if-eqz v7, :cond_a

    move-object v7, v4

    check-cast v7, Llyiahf/vczjk/m52;

    iget-object v7, v7, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    const/4 v8, 0x0

    :goto_3
    const/4 v9, 0x1

    if-eqz v7, :cond_9

    iget v10, v7, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v10, v10, 0x1000

    if-eqz v10, :cond_8

    add-int/lit8 v8, v8, 0x1

    if-ne v8, v9, :cond_5

    move-object v4, v7

    goto :goto_4

    :cond_5
    if-nez v6, :cond_6

    new-instance v6, Llyiahf/vczjk/ws5;

    const/16 v9, 0x10

    new-array v9, v9, [Llyiahf/vczjk/jl5;

    invoke-direct {v6, v9}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_6
    if-eqz v4, :cond_7

    invoke-virtual {v6, v4}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v4, v5

    :cond_7
    invoke-virtual {v6, v7}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_8
    :goto_4
    iget-object v7, v7, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_3

    :cond_9
    if-ne v8, v9, :cond_a

    goto :goto_2

    :cond_a
    :goto_5
    invoke-static {v6}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v4

    goto :goto_2

    :cond_b
    iget-object v2, v2, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto :goto_1

    :cond_c
    invoke-virtual {v3}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v3

    if-eqz v3, :cond_d

    iget-object v2, v3, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    if-eqz v2, :cond_d

    iget-object v2, v2, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/cf9;

    goto/16 :goto_0

    :cond_d
    move-object v2, v5

    goto/16 :goto_0

    :cond_e
    :goto_6
    return-void
.end method

.method public final o00000Oo()Llyiahf/vczjk/t83;
    .locals 12

    new-instance v0, Llyiahf/vczjk/t83;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    const/4 v1, 0x1

    iput-boolean v1, v0, Llyiahf/vczjk/t83;->OooO00o:Z

    sget-object v2, Llyiahf/vczjk/w83;->OooO0O0:Llyiahf/vczjk/w83;

    iput-object v2, v0, Llyiahf/vczjk/t83;->OooO0O0:Llyiahf/vczjk/w83;

    iput-object v2, v0, Llyiahf/vczjk/t83;->OooO0OO:Llyiahf/vczjk/w83;

    iput-object v2, v0, Llyiahf/vczjk/t83;->OooO0Oo:Llyiahf/vczjk/w83;

    iput-object v2, v0, Llyiahf/vczjk/t83;->OooO0o0:Llyiahf/vczjk/w83;

    iput-object v2, v0, Llyiahf/vczjk/t83;->OooO0o:Llyiahf/vczjk/w83;

    iput-object v2, v0, Llyiahf/vczjk/t83;->OooO0oO:Llyiahf/vczjk/w83;

    iput-object v2, v0, Llyiahf/vczjk/t83;->OooO0oo:Llyiahf/vczjk/w83;

    iput-object v2, v0, Llyiahf/vczjk/t83;->OooO:Llyiahf/vczjk/w83;

    sget-object v2, Llyiahf/vczjk/mo2;->OooOo0:Llyiahf/vczjk/mo2;

    iput-object v2, v0, Llyiahf/vczjk/t83;->OooOO0:Llyiahf/vczjk/rm4;

    sget-object v2, Llyiahf/vczjk/mo2;->OooOo0O:Llyiahf/vczjk/mo2;

    iput-object v2, v0, Llyiahf/vczjk/t83;->OooOO0O:Llyiahf/vczjk/rm4;

    iget v2, p0, Llyiahf/vczjk/d93;->OooOooO:I

    const/4 v3, 0x0

    if-ne v2, v1, :cond_0

    move v2, v1

    goto :goto_1

    :cond_0
    if-nez v2, :cond_2

    sget-object v2, Llyiahf/vczjk/ch1;->OooOOO0:Llyiahf/vczjk/l39;

    invoke-static {p0, v2}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/t04;

    check-cast v2, Llyiahf/vczjk/u04;

    iget-object v2, v2, Llyiahf/vczjk/u04;->OooO00o:Llyiahf/vczjk/qs5;

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/s04;

    iget v2, v2, Llyiahf/vczjk/s04;->OooO00o:I

    if-ne v2, v1, :cond_1

    move v2, v1

    goto :goto_0

    :cond_1
    move v2, v3

    :goto_0
    xor-int/2addr v2, v1

    goto :goto_1

    :cond_2
    const/4 v4, 0x2

    if-ne v2, v4, :cond_10

    move v2, v3

    :goto_1
    iput-boolean v2, v0, Llyiahf/vczjk/t83;->OooO00o:Z

    iget-object v2, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v4, v2, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v4, :cond_3

    const-string v4, "visitAncestors called on an unattached node"

    invoke-static {v4}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_3
    iget-object v4, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v5

    :goto_2
    if-eqz v5, :cond_f

    iget-object v6, v5, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v6, v6, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/jl5;

    iget v6, v6, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/lit16 v6, v6, 0xc00

    const/4 v7, 0x0

    if-eqz v6, :cond_d

    :goto_3
    if-eqz v4, :cond_d

    iget v6, v4, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v8, v6, 0xc00

    if-eqz v8, :cond_c

    if-eq v4, v2, :cond_4

    and-int/lit16 v8, v6, 0x400

    if-eqz v8, :cond_4

    goto/16 :goto_8

    :cond_4
    and-int/lit16 v6, v6, 0x800

    if-eqz v6, :cond_c

    move-object v6, v4

    move-object v8, v7

    :goto_4
    if-eqz v6, :cond_c

    instance-of v9, v6, Llyiahf/vczjk/u83;

    if-eqz v9, :cond_5

    check-cast v6, Llyiahf/vczjk/u83;

    invoke-interface {v6, v0}, Llyiahf/vczjk/u83;->OooO0o(Llyiahf/vczjk/s83;)V

    goto :goto_7

    :cond_5
    iget v9, v6, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v9, v9, 0x800

    if-eqz v9, :cond_b

    instance-of v9, v6, Llyiahf/vczjk/m52;

    if-eqz v9, :cond_b

    move-object v9, v6

    check-cast v9, Llyiahf/vczjk/m52;

    iget-object v9, v9, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    move v10, v3

    :goto_5
    if-eqz v9, :cond_a

    iget v11, v9, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v11, v11, 0x800

    if-eqz v11, :cond_9

    add-int/lit8 v10, v10, 0x1

    if-ne v10, v1, :cond_6

    move-object v6, v9

    goto :goto_6

    :cond_6
    if-nez v8, :cond_7

    new-instance v8, Llyiahf/vczjk/ws5;

    const/16 v11, 0x10

    new-array v11, v11, [Llyiahf/vczjk/jl5;

    invoke-direct {v8, v11}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_7
    if-eqz v6, :cond_8

    invoke-virtual {v8, v6}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v6, v7

    :cond_8
    invoke-virtual {v8, v9}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_9
    :goto_6
    iget-object v9, v9, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_5

    :cond_a
    if-ne v10, v1, :cond_b

    goto :goto_4

    :cond_b
    :goto_7
    invoke-static {v8}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v6

    goto :goto_4

    :cond_c
    iget-object v4, v4, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto :goto_3

    :cond_d
    invoke-virtual {v5}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v5

    if-eqz v5, :cond_e

    iget-object v4, v5, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    if-eqz v4, :cond_e

    iget-object v4, v4, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/cf9;

    goto :goto_2

    :cond_e
    move-object v4, v7

    goto/16 :goto_2

    :cond_f
    :goto_8
    return-object v0

    :cond_10
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Unknown Focusability"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final o00000o0()Llyiahf/vczjk/a93;
    .locals 9

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/a93;->OooOOOo:Llyiahf/vczjk/a93;

    return-object v0

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getFocusOwner()Llyiahf/vczjk/m83;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/r83;

    iget-object v1, v0, Llyiahf/vczjk/r83;->OooOO0o:Llyiahf/vczjk/d93;

    if-nez v1, :cond_1

    sget-object v0, Llyiahf/vczjk/a93;->OooOOOo:Llyiahf/vczjk/a93;

    return-object v0

    :cond_1
    if-ne p0, v1, :cond_2

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/a93;->OooOOO0:Llyiahf/vczjk/a93;

    return-object v0

    :cond_2
    iget-boolean v0, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v0, :cond_e

    iget-object v0, v1, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v0, v0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_3

    const-string v0, "visitAncestors called on an unattached node"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_3
    iget-object v0, v1, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    invoke-static {v1}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v1

    :goto_0
    if-eqz v1, :cond_e

    iget-object v2, v1, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v2, v2, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jl5;

    iget v2, v2, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/lit16 v2, v2, 0x400

    const/4 v3, 0x0

    if-eqz v2, :cond_c

    :goto_1
    if-eqz v0, :cond_c

    iget v2, v0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v2, v2, 0x400

    if-eqz v2, :cond_b

    move-object v2, v0

    move-object v4, v3

    :goto_2
    if-eqz v2, :cond_b

    instance-of v5, v2, Llyiahf/vczjk/d93;

    if-eqz v5, :cond_4

    check-cast v2, Llyiahf/vczjk/d93;

    if-ne p0, v2, :cond_a

    sget-object v0, Llyiahf/vczjk/a93;->OooOOO:Llyiahf/vczjk/a93;

    return-object v0

    :cond_4
    iget v5, v2, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v5, v5, 0x400

    if-eqz v5, :cond_a

    instance-of v5, v2, Llyiahf/vczjk/m52;

    if-eqz v5, :cond_a

    move-object v5, v2

    check-cast v5, Llyiahf/vczjk/m52;

    iget-object v5, v5, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    const/4 v6, 0x0

    :goto_3
    const/4 v7, 0x1

    if-eqz v5, :cond_9

    iget v8, v5, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v8, v8, 0x400

    if-eqz v8, :cond_8

    add-int/lit8 v6, v6, 0x1

    if-ne v6, v7, :cond_5

    move-object v2, v5

    goto :goto_4

    :cond_5
    if-nez v4, :cond_6

    new-instance v4, Llyiahf/vczjk/ws5;

    const/16 v7, 0x10

    new-array v7, v7, [Llyiahf/vczjk/jl5;

    invoke-direct {v4, v7}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_6
    if-eqz v2, :cond_7

    invoke-virtual {v4, v2}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v2, v3

    :cond_7
    invoke-virtual {v4, v5}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_8
    :goto_4
    iget-object v5, v5, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_3

    :cond_9
    if-ne v6, v7, :cond_a

    goto :goto_2

    :cond_a
    invoke-static {v4}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v2

    goto :goto_2

    :cond_b
    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto :goto_1

    :cond_c
    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v1

    if-eqz v1, :cond_d

    iget-object v0, v1, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    if-eqz v0, :cond_d

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cf9;

    goto :goto_0

    :cond_d
    move-object v0, v3

    goto :goto_0

    :cond_e
    sget-object v0, Llyiahf/vczjk/a93;->OooOOOo:Llyiahf/vczjk/a93;

    return-object v0
.end method

.method public final o00000oO(I)Z
    .locals 3

    const-string v0, "FocusTransactions:requestFocus"

    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    :try_start_0
    invoke-virtual {p0}, Llyiahf/vczjk/d93;->o00000Oo()Llyiahf/vczjk/t83;

    move-result-object v0

    iget-boolean v0, v0, Llyiahf/vczjk/t83;->OooO00o:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    invoke-static {}, Landroid/os/Trace;->endSection()V

    return v1

    :cond_0
    :try_start_1
    invoke-static {p0, p1}, Llyiahf/vczjk/bua;->Oooo0OO(Llyiahf/vczjk/d93;I)Llyiahf/vczjk/tu1;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    if-eqz p1, :cond_3

    const/4 v0, 0x1

    if-eq p1, v0, :cond_4

    const/4 v2, 0x2

    if-eq p1, v2, :cond_2

    const/4 v0, 0x3

    if-ne p1, v0, :cond_1

    goto :goto_0

    :cond_1
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_2
    move v1, v0

    goto :goto_0

    :cond_3
    invoke-static {p0}, Llyiahf/vczjk/bua;->Oooo0o0(Llyiahf/vczjk/d93;)Z

    move-result v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :cond_4
    :goto_0
    invoke-static {}, Landroid/os/Trace;->endSection()V

    return v1

    :goto_1
    invoke-static {}, Landroid/os/Trace;->endSection()V

    throw p1
.end method

.method public final o0000Ooo()V
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/d93;->o00000o0()Llyiahf/vczjk/a93;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    if-eqz v0, :cond_0

    const/4 v1, 0x2

    if-eq v0, v1, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/hl7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    new-instance v1, Llyiahf/vczjk/c93;

    invoke-direct {v1, v0, p0}, Llyiahf/vczjk/c93;-><init>(Llyiahf/vczjk/hl7;Llyiahf/vczjk/d93;)V

    invoke-static {p0, v1}, Llyiahf/vczjk/bua;->Oooo000(Llyiahf/vczjk/jl5;Llyiahf/vczjk/le3;)V

    iget-object v0, v0, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    if-eqz v0, :cond_2

    check-cast v0, Llyiahf/vczjk/s83;

    invoke-interface {v0}, Llyiahf/vczjk/s83;->OooO00o()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getFocusOwner()Llyiahf/vczjk/m83;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/r83;

    const/4 v1, 0x1

    const/16 v2, 0x8

    invoke-virtual {v0, v2, v1, v1}, Llyiahf/vczjk/r83;->OooO0O0(IZZ)Z

    :cond_1
    :goto_0
    return-void

    :cond_2
    const-string v0, "focusProperties"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final o000OOo()V
    .locals 12

    invoke-virtual {p0}, Llyiahf/vczjk/d93;->o00000o0()Llyiahf/vczjk/a93;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    if-eq v0, v1, :cond_1

    const/4 v2, 0x2

    if-eq v0, v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getFocusOwner()Llyiahf/vczjk/m83;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/r83;

    const/4 v2, 0x0

    const/16 v3, 0x8

    invoke-virtual {v0, v3, v1, v2}, Llyiahf/vczjk/r83;->OooO0O0(IZZ)Z

    iget-object v6, v0, Llyiahf/vczjk/r83;->OooO0oO:Llyiahf/vczjk/k83;

    iget-boolean v0, v6, Llyiahf/vczjk/k83;->OooO0o:Z

    if-nez v0, :cond_1

    new-instance v4, Llyiahf/vczjk/da;

    const-string v9, "invalidateNodes()V"

    const/4 v10, 0x0

    const/4 v5, 0x0

    const-class v7, Llyiahf/vczjk/k83;

    const-string v8, "invalidateNodes"

    const/4 v11, 0x5

    invoke-direct/range {v4 .. v11}, Llyiahf/vczjk/da;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    iget-object v0, v6, Llyiahf/vczjk/k83;->OooO00o:Llyiahf/vczjk/o00000;

    invoke-virtual {v0, v4}, Llyiahf/vczjk/o00000;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    iput-boolean v1, v6, Llyiahf/vczjk/k83;->OooO0o:Z

    :cond_1
    :goto_0
    return-void
.end method

.method public final o0O0O00()V
    .locals 0

    return-void
.end method

.method public final o0Oo0oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method
