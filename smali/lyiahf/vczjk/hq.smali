.class public final Llyiahf/vczjk/hq;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/a91;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/hq;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/hq;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/hq;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/hq;->OooOOo0:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/hq;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/hq;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/hq;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/hq;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/hq;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/hq;->OooOOo0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 130

    move-object/from16 v0, p0

    const/16 v4, 0x36

    sget-object v7, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/4 v9, 0x1

    sget-object v10, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v11, v0, Llyiahf/vczjk/hq;->OooOOo0:Ljava/lang/Object;

    iget-object v12, v0, Llyiahf/vczjk/hq;->OooOOOO:Ljava/lang/Object;

    iget-object v13, v0, Llyiahf/vczjk/hq;->OooOOO:Ljava/lang/Object;

    iget-object v14, v0, Llyiahf/vczjk/hq;->OooOOOo:Ljava/lang/Object;

    const/4 v15, 0x0

    const/4 v1, 0x2

    const/4 v2, 0x3

    const/16 v18, 0x6

    iget v5, v0, Llyiahf/vczjk/hq;->OooOOO0:I

    packed-switch v5, :pswitch_data_0

    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v4, p2

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    move-result v4

    and-int/2addr v2, v4

    if-eq v2, v1, :cond_0

    move v1, v9

    goto :goto_0

    :cond_0
    move v1, v15

    :goto_0
    and-int/lit8 v2, v4, 0x1

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v2, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_4

    const-string v1, "Container"

    invoke-static {v7, v1}, Landroidx/compose/ui/layout/OooO00o;->OooO0OO(Llyiahf/vczjk/kl5;Ljava/lang/Object;)Llyiahf/vczjk/kl5;

    move-result-object v1

    new-instance v16, Llyiahf/vczjk/ga;

    const-string v22, "getValue()Ljava/lang/Object;"

    const/16 v17, 0x0

    move-object/from16 v20, v12

    check-cast v20, Llyiahf/vczjk/qs5;

    const-class v19, Llyiahf/vczjk/qs5;

    const-string v21, "value"

    const/16 v18, 0x3

    invoke-direct/range {v16 .. v22}, Llyiahf/vczjk/ga;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    move-object/from16 v2, v16

    check-cast v14, Llyiahf/vczjk/fj9;

    invoke-static {v14}, Llyiahf/vczjk/wi9;->OooO0Oo(Llyiahf/vczjk/fj9;)Llyiahf/vczjk/m4;

    move-result-object v4

    sget v5, Llyiahf/vczjk/dg6;->OooO00o:F

    new-instance v5, Llyiahf/vczjk/oo0ooO;

    check-cast v11, Llyiahf/vczjk/di6;

    const/16 v6, 0xe

    invoke-direct {v5, v2, v11, v6, v4}, Llyiahf/vczjk/oo0ooO;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-static {v1, v5}, Landroidx/compose/ui/draw/OooO00o;->OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v2, v9}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v2

    iget v4, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v3, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v6, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_1

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_1
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v3, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v3, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_2

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_3

    :cond_2
    invoke-static {v4, v3, v4, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_3
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, v3, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    check-cast v13, Llyiahf/vczjk/a91;

    invoke-virtual {v13, v3, v1}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_2

    :cond_4
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_2
    return-object v10

    :pswitch_0
    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v5, p2

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    move-result v5

    and-int/2addr v2, v5

    if-eq v2, v1, :cond_5

    move v1, v9

    goto :goto_3

    :cond_5
    move v1, v15

    :goto_3
    and-int/lit8 v2, v5, 0x1

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v2, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_b

    sget v1, Llyiahf/vczjk/fz8;->OooOooO:F

    sget v2, Llyiahf/vczjk/fz8;->OooOoO:F

    invoke-static {v7, v1, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO00o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v1

    check-cast v12, Llyiahf/vczjk/qj8;

    instance-of v2, v12, Llyiahf/vczjk/xj;

    check-cast v11, Llyiahf/vczjk/yn4;

    check-cast v14, Llyiahf/vczjk/di6;

    if-eqz v2, :cond_6

    check-cast v12, Llyiahf/vczjk/xj;

    invoke-static {v14, v11}, Landroidx/compose/foundation/layout/OooO00o;->OooO0o(Llyiahf/vczjk/bi6;Llyiahf/vczjk/yn4;)F

    move-result v2

    invoke-static {v14, v11}, Landroidx/compose/foundation/layout/OooO00o;->OooO0o0(Llyiahf/vczjk/bi6;Llyiahf/vczjk/yn4;)F

    move-result v5

    new-instance v6, Llyiahf/vczjk/jo3;

    invoke-direct {v6, v2, v5, v12, v9}, Llyiahf/vczjk/jo3;-><init>(FFLlyiahf/vczjk/qj8;I)V

    invoke-static {v7, v6}, Landroidx/compose/ui/layout/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object v7

    goto :goto_4

    :cond_6
    instance-of v2, v12, Llyiahf/vczjk/ir1;

    if-eqz v2, :cond_7

    check-cast v12, Llyiahf/vczjk/ir1;

    invoke-static {v14, v11}, Landroidx/compose/foundation/layout/OooO00o;->OooO0o(Llyiahf/vczjk/bi6;Llyiahf/vczjk/yn4;)F

    move-result v2

    invoke-static {v14, v11}, Landroidx/compose/foundation/layout/OooO00o;->OooO0o0(Llyiahf/vczjk/bi6;Llyiahf/vczjk/yn4;)F

    move-result v5

    new-instance v6, Llyiahf/vczjk/jo3;

    invoke-direct {v6, v2, v5, v12, v15}, Llyiahf/vczjk/jo3;-><init>(FFLlyiahf/vczjk/qj8;I)V

    invoke-static {v7, v6}, Landroidx/compose/ui/layout/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object v7

    :cond_7
    :goto_4
    invoke-interface {v1, v7}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v1, v14}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v5, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    invoke-static {v2, v5, v3, v4}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    iget v4, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v3, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v6, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_8

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_5

    :cond_8
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_5
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v3, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v3, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_9

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_a

    :cond_9
    invoke-static {v4, v3, v4, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_a
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, v3, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/jw7;->OooO00o:Llyiahf/vczjk/jw7;

    invoke-static/range {v18 .. v18}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    check-cast v13, Llyiahf/vczjk/a91;

    invoke-virtual {v13, v1, v3, v2}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_6

    :cond_b
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_6
    return-object v10

    :pswitch_1
    move-object/from16 v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    move-object/from16 v5, p2

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    move-result v5

    and-int/2addr v5, v2

    if-ne v5, v1, :cond_d

    move-object v1, v4

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_c

    goto :goto_7

    :cond_c
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v25, v10

    goto/16 :goto_d

    :cond_d
    :goto_7
    sget-object v1, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    check-cast v13, Llyiahf/vczjk/bi6;

    invoke-static {v1, v13}, Llyiahf/vczjk/uoa;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v13, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v13, v15}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v13

    const/16 v31, 0x0

    move-object v3, v4

    check-cast v3, Llyiahf/vczjk/zf1;

    iget v6, v3, Llyiahf/vczjk/zf1;->Oooo:I

    move/from16 v33, v9

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v9

    invoke-static {v4, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v16, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v15, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v2, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v2, :cond_e

    invoke-virtual {v3, v15}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_8

    :cond_e
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_8
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v13, v4, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v9, v4, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v0, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_f

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    move-object/from16 v17, v1

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_10

    goto :goto_9

    :cond_f
    move-object/from16 v17, v1

    :goto_9
    invoke-static {v6, v3, v6, v9}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_10
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v5, v4, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o:Landroidx/compose/foundation/layout/OooO0O0;

    sget-object v5, Llyiahf/vczjk/mb6;->OooO00o:Ljava/util/List;

    invoke-interface {v5}, Ljava/util/List;->size()I

    move-result v16

    new-instance v6, Llyiahf/vczjk/mt;

    check-cast v12, Llyiahf/vczjk/km6;

    move-object/from16 p1, v5

    const/4 v5, 0x3

    invoke-direct {v6, v12, v5}, Llyiahf/vczjk/mt;-><init>(Ljava/lang/Object;I)V

    const v5, -0x47349d9d

    invoke-static {v5, v6, v4}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v26

    const/16 v29, 0x6

    const/16 v30, 0x1f8

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const v28, 0x30000030

    move-object/from16 v27, v4

    move-object/from16 v18, v12

    invoke-static/range {v16 .. v30}, Llyiahf/vczjk/ok6;->OooO0o0(ILlyiahf/vczjk/kl5;Llyiahf/vczjk/km6;ZFLlyiahf/vczjk/bi6;Llyiahf/vczjk/n4;Llyiahf/vczjk/o23;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/df3;Llyiahf/vczjk/rf1;III)V

    sget-object v5, Llyiahf/vczjk/op3;->OooOo0:Llyiahf/vczjk/ub0;

    invoke-virtual {v1, v7, v5}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v16

    const/16 v6, 0x78

    int-to-float v6, v6

    const/16 v17, 0x0

    const/16 v21, 0x7

    const/16 v18, 0x0

    const/16 v19, 0x0

    move/from16 v20, v6

    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v6

    move-object/from16 v25, v10

    sget-object v10, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    move-object/from16 v20, v11

    sget-object v11, Llyiahf/vczjk/op3;->OooOo0o:Llyiahf/vczjk/tb0;

    move-object/from16 v21, v14

    const/4 v14, 0x0

    invoke-static {v10, v11, v4, v14}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v10

    iget v11, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v4, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v22, v7

    iget-boolean v7, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_11

    invoke-virtual {v3, v15}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_a

    :cond_11
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_a
    invoke-static {v10, v4, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v14, v4, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_12

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v2, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_13

    :cond_12
    invoke-static {v11, v3, v11, v9}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_13
    invoke-static {v6, v4, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v0, -0x43b43e9c

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-interface/range {p1 .. p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    const/4 v2, 0x0

    :goto_b
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_16

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    add-int/lit8 v7, v2, 0x1

    if-ltz v2, :cond_15

    check-cast v6, Llyiahf/vczjk/ib6;

    invoke-virtual {v12}, Llyiahf/vczjk/km6;->OooO0oo()I

    move-result v6

    if-ne v2, v6, :cond_14

    move/from16 v2, v33

    goto :goto_c

    :cond_14
    const/4 v2, 0x0

    :goto_c
    sget-object v6, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    move-object v9, v4

    check-cast v9, Llyiahf/vczjk/zf1;

    invoke-virtual {v9, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/x21;

    iget-wide v9, v6, Llyiahf/vczjk/x21;->OooO0o:J

    const/4 v14, 0x0

    invoke-static {v2, v9, v10, v4, v14}, Llyiahf/vczjk/u34;->OooO0OO(ZJLlyiahf/vczjk/rf1;I)V

    move v2, v7

    goto :goto_b

    :cond_15
    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    throw v31

    :cond_16
    const/4 v14, 0x0

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move/from16 v0, v33

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static/range {v22 .. v22}, Landroidx/compose/animation/OooO0OO;->OooO00o(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-virtual {v1, v0, v5}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v13

    const/16 v0, 0x20

    int-to-float v0, v0

    const/4 v14, 0x0

    const/16 v18, 0x7

    const/4 v15, 0x0

    const/16 v16, 0x0

    move/from16 v17, v0

    invoke-static/range {v13 .. v18}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v15

    const v0, -0x6815fd56

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v12}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    move-object/from16 v14, v21

    check-cast v14, Llyiahf/vczjk/xr1;

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    or-int/2addr v0, v1

    move-object/from16 v11, v20

    check-cast v11, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    or-int/2addr v0, v1

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez v0, :cond_17

    if-ne v1, v8, :cond_18

    :cond_17
    new-instance v1, Llyiahf/vczjk/x5;

    const/16 v0, 0xc

    invoke-direct {v1, v12, v14, v0, v11}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_18
    move-object v14, v1

    check-cast v14, Llyiahf/vczjk/le3;

    const/4 v0, 0x0

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v0, Llyiahf/vczjk/u20;

    const/16 v1, 0xf

    invoke-direct {v0, v12, v1}, Llyiahf/vczjk/u20;-><init>(Ljava/lang/Object;I)V

    const v1, 0x5b362230

    invoke-static {v1, v0, v4}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v21

    const/high16 v23, 0x30000000

    const/16 v24, 0x1fc

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    move-object/from16 v22, v4

    invoke-static/range {v14 .. v24}, Llyiahf/vczjk/bua;->OooO0Oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    const/4 v0, 0x1

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_d
    return-object v25

    :pswitch_2
    move-object/from16 v25, v10

    move-object/from16 v20, v11

    move-object/from16 v21, v14

    const/16 v31, 0x0

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v19, 0x3

    and-int/lit8 v3, v2, 0x3

    if-eq v3, v1, :cond_19

    const/4 v15, 0x1

    :goto_e
    const/16 v33, 0x1

    goto :goto_f

    :cond_19
    const/4 v15, 0x0

    goto :goto_e

    :goto_f
    and-int/lit8 v1, v2, 0x1

    move-object v7, v0

    check-cast v7, Llyiahf/vczjk/zf1;

    invoke-virtual {v7, v1, v15}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v0

    if-eqz v0, :cond_1d

    check-cast v12, Llyiahf/vczjk/x21;

    if-nez v12, :cond_1a

    sget-object v0, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    sget-wide v38, Llyiahf/vczjk/zn6;->Oooo00O:J

    sget-wide v48, Llyiahf/vczjk/zn6;->Oooo0oO:J

    sget-wide v56, Llyiahf/vczjk/zn6;->OoooOO0:J

    sget-wide v82, Llyiahf/vczjk/zn6;->OooO0Oo:J

    const-wide/16 v126, 0x0

    const v128, -0x2001109

    const-wide/16 v32, 0x0

    const-wide/16 v34, 0x0

    const-wide/16 v36, 0x0

    const-wide/16 v40, 0x0

    const-wide/16 v42, 0x0

    const-wide/16 v44, 0x0

    const-wide/16 v46, 0x0

    const-wide/16 v50, 0x0

    const-wide/16 v52, 0x0

    const-wide/16 v54, 0x0

    const-wide/16 v58, 0x0

    const-wide/16 v60, 0x0

    const-wide/16 v62, 0x0

    const-wide/16 v64, 0x0

    const-wide/16 v66, 0x0

    const-wide/16 v68, 0x0

    const-wide/16 v70, 0x0

    const-wide/16 v72, 0x0

    const-wide/16 v74, 0x0

    const-wide/16 v76, 0x0

    const-wide/16 v78, 0x0

    const-wide/16 v80, 0x0

    const-wide/16 v84, 0x0

    const-wide/16 v86, 0x0

    const-wide/16 v88, 0x0

    const-wide/16 v90, 0x0

    const-wide/16 v92, 0x0

    const-wide/16 v94, 0x0

    const-wide/16 v96, 0x0

    const-wide/16 v98, 0x0

    const-wide/16 v100, 0x0

    const-wide/16 v102, 0x0

    const-wide/16 v104, 0x0

    const-wide/16 v106, 0x0

    const-wide/16 v108, 0x0

    const-wide/16 v110, 0x0

    const-wide/16 v112, 0x0

    const-wide/16 v114, 0x0

    const-wide/16 v116, 0x0

    const-wide/16 v118, 0x0

    const-wide/16 v120, 0x0

    const-wide/16 v122, 0x0

    const-wide/16 v124, 0x0

    const v129, 0xffff

    invoke-static/range {v32 .. v129}, Llyiahf/vczjk/z21;->OooO0o(JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJII)Llyiahf/vczjk/x21;

    move-result-object v12

    :cond_1a
    move-object v2, v12

    sget-object v3, Llyiahf/vczjk/wo5;->OooO00o:Llyiahf/vczjk/wo5;

    move-object/from16 v14, v21

    check-cast v14, Llyiahf/vczjk/al8;

    if-nez v14, :cond_1b

    new-instance v14, Llyiahf/vczjk/al8;

    invoke-direct {v14}, Llyiahf/vczjk/al8;-><init>()V

    :cond_1b
    move-object v4, v14

    move-object/from16 v11, v20

    check-cast v11, Llyiahf/vczjk/n6a;

    if-nez v11, :cond_1c

    new-instance v11, Llyiahf/vczjk/n6a;

    const/16 v0, 0x7fff

    move-object/from16 v1, v31

    invoke-direct {v11, v1, v0}, Llyiahf/vczjk/n6a;-><init>(Llyiahf/vczjk/rn9;I)V

    :cond_1c
    move-object v5, v11

    move-object v6, v13

    check-cast v6, Llyiahf/vczjk/a91;

    const/4 v8, 0x0

    invoke-static/range {v2 .. v8}, Llyiahf/vczjk/we5;->OooO0O0(Llyiahf/vczjk/x21;Llyiahf/vczjk/yo5;Llyiahf/vczjk/al8;Llyiahf/vczjk/n6a;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    goto :goto_10

    :cond_1d
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_10
    return-object v25

    :pswitch_3
    move-object/from16 v25, v10

    move-object/from16 v20, v11

    move-object/from16 v21, v14

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v19, 0x3

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v1, :cond_1f

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_1e

    goto :goto_11

    :cond_1e
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_12

    :cond_1f
    :goto_11
    new-instance v1, Llyiahf/vczjk/b6;

    check-cast v12, Landroid/content/Context;

    move-object/from16 v14, v21

    check-cast v14, Llyiahf/vczjk/qs5;

    const/16 v2, 0x15

    invoke-direct {v1, v2, v12, v14}, Llyiahf/vczjk/b6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v2, 0x17cae140

    invoke-static {v2, v1, v0}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    new-instance v1, Llyiahf/vczjk/o5;

    move-object/from16 v11, v20

    check-cast v11, Llyiahf/vczjk/ki2;

    const/4 v2, 0x1

    invoke-direct {v1, v11, v2}, Llyiahf/vczjk/o5;-><init>(Llyiahf/vczjk/ki2;I)V

    const v2, -0x38b2be3e

    invoke-static {v2, v1, v0}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v10

    sget-object v11, Llyiahf/vczjk/va1;->OooO00o:Llyiahf/vczjk/a91;

    move-object/from16 v16, v13

    check-cast v16, Llyiahf/vczjk/zu6;

    const/4 v14, 0x0

    const/16 v18, 0xd86

    const/4 v9, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v15, 0x0

    move-object/from16 v17, v0

    invoke-static/range {v8 .. v18}, Llyiahf/vczjk/up;->OooO0OO(Llyiahf/vczjk/a91;Llyiahf/vczjk/hl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;FFLlyiahf/vczjk/zy4;Llyiahf/vczjk/fx9;Llyiahf/vczjk/zu6;Llyiahf/vczjk/rf1;I)V

    :goto_12
    return-object v25

    :pswitch_4
    move-object/from16 v25, v10

    move-object/from16 v20, v11

    move-object/from16 v21, v14

    move-object/from16 v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    move-object/from16 v0, p2

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    move-result v0

    const/16 v19, 0x3

    and-int/lit8 v0, v0, 0x3

    if-ne v0, v1, :cond_21

    move-object v0, v5

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_20

    goto :goto_13

    :cond_20
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_17

    :cond_21
    :goto_13
    sget-object v6, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v0, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    sget-object v1, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v2, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    invoke-static {v1, v2, v5, v4}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v1

    move-object v14, v5

    check-cast v14, Llyiahf/vczjk/zf1;

    iget v2, v14, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {v5, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, v14, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_22

    invoke-virtual {v14, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_14

    :cond_22
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_14
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v1, v5, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, v5, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v3, v14, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_23

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_24

    :cond_23
    invoke-static {v2, v14, v2, v1}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_24
    sget-object v1, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v0, v5, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v0, 0x50

    int-to-float v0, v0

    invoke-static {v6, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    check-cast v13, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move/from16 v1, v18

    invoke-static {v0, v13, v5, v1}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    const/4 v0, 0x0

    invoke-static {v0, v5}, Llyiahf/vczjk/ru6;->OooO0O0(ILlyiahf/vczjk/rf1;)V

    check-cast v12, Ljava/lang/String;

    invoke-static {v12, v5, v0}, Llyiahf/vczjk/br6;->OooO0o0(Ljava/lang/String;Llyiahf/vczjk/rf1;I)V

    const v0, 0xb2644c5

    invoke-virtual {v14, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object/from16 v35, v21

    check-cast v35, Ljava/lang/String;

    if-nez v35, :cond_25

    :goto_15
    const/4 v0, 0x0

    goto :goto_16

    :cond_25
    const/16 v0, 0x8

    int-to-float v1, v0

    invoke-static {v6, v1}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0o0(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-static {v5, v0}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object v0, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    move-object v1, v5

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/n6a;

    iget-object v0, v0, Llyiahf/vczjk/n6a;->OooOO0O:Llyiahf/vczjk/rn9;

    sget-object v2, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/x21;

    iget-wide v1, v1, Llyiahf/vczjk/x21;->OooOOoo:J

    new-instance v3, Llyiahf/vczjk/ch9;

    const/4 v4, 0x3

    invoke-direct {v3, v4}, Llyiahf/vczjk/ch9;-><init>(I)V

    const/16 v56, 0x0

    const v57, 0x1fbfa

    const/16 v36, 0x0

    const-wide/16 v39, 0x0

    const/16 v41, 0x0

    const/16 v42, 0x0

    const-wide/16 v43, 0x0

    const-wide/16 v46, 0x0

    const/16 v48, 0x0

    const/16 v49, 0x0

    const/16 v50, 0x0

    const/16 v51, 0x0

    const/16 v52, 0x0

    const/16 v55, 0x0

    move-object/from16 v53, v0

    move-wide/from16 v37, v1

    move-object/from16 v45, v3

    move-object/from16 v54, v5

    invoke-static/range {v35 .. v57}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    goto :goto_15

    :goto_16
    invoke-virtual {v14, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v0, 0x40

    int-to-float v8, v0

    const/4 v7, 0x0

    const/16 v11, 0xd

    const/4 v9, 0x0

    const/4 v10, 0x0

    invoke-static/range {v6 .. v11}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v1

    new-instance v0, Llyiahf/vczjk/u20;

    move-object/from16 v11, v20

    check-cast v11, Llyiahf/vczjk/oe3;

    const/16 v2, 0x8

    invoke-direct {v0, v11, v2}, Llyiahf/vczjk/u20;-><init>(Ljava/lang/Object;I)V

    const v2, 0x44a98418

    invoke-static {v2, v0, v5}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v4

    const/16 v6, 0xc06

    const/4 v7, 0x6

    const/4 v2, 0x0

    const/4 v3, 0x0

    invoke-static/range {v1 .. v7}, Llyiahf/vczjk/dn8;->OooOOOo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;ZLlyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    const/4 v0, 0x1

    invoke-virtual {v14, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_17
    return-object v25

    :pswitch_5
    move-object/from16 v22, v7

    move-object/from16 v25, v10

    move-object/from16 v20, v11

    move-object/from16 v21, v14

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v19, 0x3

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v1, :cond_27

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_26

    goto :goto_18

    :cond_26
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_19

    :cond_27
    :goto_18
    sget-object v1, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/x21;

    iget-wide v1, v1, Llyiahf/vczjk/x21;->OooOOOo:J

    sget-object v3, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    move-object/from16 v4, v22

    invoke-static {v4, v1, v2, v3}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v37

    move-object v5, v13

    check-cast v5, Llyiahf/vczjk/qs5;

    invoke-interface {v5}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v35

    const v1, 0x4c5de2

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v8, :cond_28

    new-instance v1, Llyiahf/vczjk/l5;

    const/16 v2, 0x14

    invoke-direct {v1, v5, v2}, Llyiahf/vczjk/l5;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_28
    move-object/from16 v36, v1

    check-cast v36, Llyiahf/vczjk/le3;

    const/4 v14, 0x0

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v1, Llyiahf/vczjk/a6;

    move-object v2, v12

    check-cast v2, Ljava/util/List;

    move-object/from16 v3, v21

    check-cast v3, Llyiahf/vczjk/oe3;

    move-object/from16 v4, v20

    check-cast v4, Landroid/content/Context;

    const/4 v6, 0x4

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/a6;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    const v2, -0x3a89f7a7

    invoke-static {v2, v1, v0}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v47

    const/16 v46, 0x0

    const/16 v50, 0x7f8

    const-wide/16 v38, 0x0

    const/16 v40, 0x0

    const/16 v41, 0x0

    const/16 v42, 0x0

    const-wide/16 v43, 0x0

    const/16 v45, 0x0

    const/16 v49, 0x30

    move-object/from16 v48, v0

    invoke-static/range {v35 .. v50}, Llyiahf/vczjk/fe;->OooO00o(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/z98;Llyiahf/vczjk/d07;Llyiahf/vczjk/qj8;JFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_19
    return-object v25

    :pswitch_6
    move-object/from16 v25, v10

    move-object/from16 v20, v11

    move-object/from16 v21, v14

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v19, 0x3

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v1, :cond_2a

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_29

    goto :goto_1a

    :cond_29
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1b

    :cond_2a
    :goto_1a
    check-cast v0, Llyiahf/vczjk/zf1;

    const v1, -0x6815fd56

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v13, Llyiahf/vczjk/oe3;

    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v0, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    move-object/from16 v14, v21

    check-cast v14, Llyiahf/vczjk/zh1;

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_2b

    if-ne v2, v8, :cond_2c

    :cond_2b
    new-instance v2, Llyiahf/vczjk/x5;

    const/4 v1, 0x5

    invoke-direct {v2, v13, v12, v1, v14}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2c
    move-object/from16 v35, v2

    check-cast v35, Llyiahf/vczjk/le3;

    const/4 v14, 0x0

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v1, Llyiahf/vczjk/v5;

    move-object/from16 v11, v20

    check-cast v11, Ljava/lang/String;

    const/4 v4, 0x3

    invoke-direct {v1, v11, v4}, Llyiahf/vczjk/v5;-><init>(Ljava/lang/String;I)V

    const v2, 0x6a655d88

    invoke-static {v2, v1, v0}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v41

    const/high16 v43, 0x30000000

    const/16 v44, 0x1fe

    const/16 v36, 0x0

    const/16 v37, 0x0

    const/16 v38, 0x0

    const/16 v39, 0x0

    const/16 v40, 0x0

    move-object/from16 v42, v0

    invoke-static/range {v35 .. v44}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_1b
    return-object v25

    :pswitch_7
    move-object/from16 v25, v10

    move-object/from16 v20, v11

    move-object/from16 v21, v14

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v19, 0x3

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v1, :cond_2e

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_2d

    goto :goto_1c

    :cond_2d
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1d

    :cond_2e
    :goto_1c
    sget-object v28, Llyiahf/vczjk/fa1;->OooO0OO:Llyiahf/vczjk/a91;

    sget-object v29, Llyiahf/vczjk/fa1;->OooO0Oo:Llyiahf/vczjk/a91;

    check-cast v0, Llyiahf/vczjk/zf1;

    const v1, -0x48fade91

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object v3, v13

    check-cast v3, Llyiahf/vczjk/ov5;

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    move-object v4, v12

    check-cast v4, Llyiahf/vczjk/n3;

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    move-object/from16 v5, v21

    check-cast v5, Llyiahf/vczjk/wa5;

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    move-object/from16 v6, v20

    check-cast v6, Landroid/content/Context;

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_2f

    if-ne v2, v8, :cond_30

    :cond_2f
    new-instance v2, Llyiahf/vczjk/c02;

    const/4 v7, 0x0

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/c02;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_30
    move-object/from16 v30, v2

    check-cast v30, Llyiahf/vczjk/le3;

    const/4 v14, 0x0

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v27, 0x0

    const/16 v32, 0xdb0

    const/16 v26, 0x0

    move-object/from16 v31, v0

    invoke-static/range {v26 .. v32}, Llyiahf/vczjk/wt2;->OooO00o(Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    :goto_1d
    return-object v25

    :pswitch_8
    move-object/from16 v25, v10

    move-object/from16 v20, v11

    move-object/from16 v21, v14

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v19, 0x3

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v1, :cond_32

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_31

    goto :goto_1e

    :cond_31
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_20

    :cond_32
    :goto_1e
    move-object/from16 v11, v20

    check-cast v11, Llyiahf/vczjk/qs5;

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/r7a;

    invoke-static {v1}, Ljava/util/Objects;->toString(Ljava/lang/Object;)Ljava/lang/String;

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/r7a;

    instance-of v1, v1, Llyiahf/vczjk/p7a;

    if-eqz v1, :cond_35

    check-cast v0, Llyiahf/vczjk/zf1;

    const v1, 0x7b98b64a

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/r7a;

    const-string v2, "null cannot be cast to non-null type github.tornaco.android.thanos.module.compose.common.infra.UiState.Loaded<tornaco.apps.thanox.bc.BCApps>"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, Llyiahf/vczjk/p7a;

    iget-object v1, v1, Llyiahf/vczjk/p7a;->OooO00o:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/m20;

    iget-object v1, v1, Llyiahf/vczjk/m20;->OooO00o:Ljava/util/List;

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/r7a;

    invoke-static {v3, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v3, Llyiahf/vczjk/p7a;

    iget-object v2, v3, Llyiahf/vczjk/p7a;->OooO00o:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/m20;

    iget-object v2, v2, Llyiahf/vczjk/m20;->OooO0O0:Ljava/util/List;

    const/16 v3, 0x60

    int-to-float v3, v3

    const/4 v4, 0x7

    const/4 v5, 0x0

    invoke-static {v5, v5, v5, v3, v4}, Landroidx/compose/foundation/layout/OooO00o;->OooO0OO(FFFFI)Llyiahf/vczjk/di6;

    move-result-object v37

    const v3, -0x48fade91

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object v3, v13

    check-cast v3, Llyiahf/vczjk/qs5;

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    check-cast v12, Llyiahf/vczjk/i40;

    invoke-virtual {v0, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v3, v4

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v3, v4

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v3, v4

    move-object/from16 v14, v21

    check-cast v14, Llyiahf/vczjk/qs5;

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v3, v4

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_33

    if-ne v4, v8, :cond_34

    :cond_33
    new-instance v26, Llyiahf/vczjk/v20;

    move-object/from16 v31, v21

    check-cast v31, Llyiahf/vczjk/qs5;

    move-object/from16 v29, v13

    check-cast v29, Llyiahf/vczjk/qs5;

    move-object/from16 v27, v1

    move-object/from16 v30, v2

    move-object/from16 v28, v12

    invoke-direct/range {v26 .. v31}, Llyiahf/vczjk/v20;-><init>(Ljava/util/List;Llyiahf/vczjk/i40;Llyiahf/vczjk/qs5;Ljava/util/List;Llyiahf/vczjk/qs5;)V

    move-object/from16 v4, v26

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_34
    move-object/from16 v44, v4

    check-cast v44, Llyiahf/vczjk/oe3;

    const/4 v14, 0x0

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v46, 0x180

    const/16 v47, 0x1fb

    const/16 v35, 0x0

    const/16 v36, 0x0

    const/16 v38, 0x0

    const/16 v39, 0x0

    const/16 v40, 0x0

    const/16 v41, 0x0

    const/16 v42, 0x0

    const/16 v43, 0x0

    move-object/from16 v45, v0

    invoke-static/range {v35 .. v47}, Llyiahf/vczjk/mc4;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    const/4 v14, 0x0

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_20

    :cond_35
    const/4 v14, 0x0

    move-object v8, v0

    check-cast v8, Llyiahf/vczjk/zf1;

    const v0, 0x7bbe56d0

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v0, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    sget-object v1, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    invoke-static {v1, v14}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v1

    iget v2, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {v8, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_36

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1f

    :cond_36
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1f
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v1, v8, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, v8, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v3, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_37

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_38

    :cond_37
    invoke-static {v2, v8, v2, v1}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_38
    sget-object v1, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v0, v8, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/4 v9, 0x0

    const/16 v10, 0x1f

    const/4 v1, 0x0

    const-wide/16 v2, 0x0

    const-wide/16 v4, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    invoke-static/range {v1 .. v10}, Llyiahf/vczjk/so8;->OooO0OO(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/qj8;Ljava/util/List;Llyiahf/vczjk/rf1;II)V

    const/4 v0, 0x1

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v14, 0x0

    invoke-virtual {v8, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_20
    return-object v25

    :pswitch_9
    move-object/from16 v25, v10

    move-object/from16 v20, v11

    move-object/from16 v21, v14

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v19, 0x3

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v1, :cond_3a

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_39

    goto :goto_21

    :cond_39
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_22

    :cond_3a
    :goto_21
    sget-object v1, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    check-cast v13, Llyiahf/vczjk/bi6;

    invoke-static {v1, v13}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v35

    check-cast v0, Llyiahf/vczjk/zf1;

    const v1, -0x6815fd56

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v12, Llyiahf/vczjk/qs5;

    invoke-virtual {v0, v12}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    move-object/from16 v14, v21

    check-cast v14, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    move-object/from16 v11, v20

    check-cast v11, Llyiahf/vczjk/aw;

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_3b

    if-ne v2, v8, :cond_3c

    :cond_3b
    new-instance v2, Llyiahf/vczjk/oo0ooO;

    const/4 v4, 0x3

    invoke-direct {v2, v12, v14, v4, v11}, Llyiahf/vczjk/oo0ooO;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3c
    move-object/from16 v44, v2

    check-cast v44, Llyiahf/vczjk/oe3;

    const/4 v14, 0x0

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v46, 0x0

    const/16 v47, 0x1fe

    const/16 v36, 0x0

    const/16 v37, 0x0

    const/16 v38, 0x0

    const/16 v39, 0x0

    const/16 v40, 0x0

    const/16 v41, 0x0

    const/16 v42, 0x0

    const/16 v43, 0x0

    move-object/from16 v45, v0

    invoke-static/range {v35 .. v47}, Llyiahf/vczjk/mc4;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    :goto_22
    return-object v25

    :pswitch_a
    move-object/from16 v25, v10

    move-object/from16 v20, v11

    move-object/from16 v21, v14

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v19, 0x3

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v1, :cond_3e

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_3d

    goto :goto_23

    :cond_3d
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_24

    :cond_3e
    :goto_23
    sget-object v2, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    check-cast v13, Llyiahf/vczjk/bi6;

    invoke-static {v2, v13}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v35

    check-cast v0, Llyiahf/vczjk/zf1;

    const v2, -0x6815fd56

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v12, Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;

    invoke-virtual {v0, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    move-object/from16 v14, v21

    check-cast v14, Llyiahf/vczjk/qs5;

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    move-object/from16 v11, v20

    check-cast v11, Llyiahf/vczjk/dv;

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_3f

    if-ne v3, v8, :cond_40

    :cond_3f
    new-instance v3, Llyiahf/vczjk/oo0ooO;

    invoke-direct {v3, v12, v11, v1, v14}, Llyiahf/vczjk/oo0ooO;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_40
    move-object/from16 v44, v3

    check-cast v44, Llyiahf/vczjk/oe3;

    const/4 v14, 0x0

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v46, 0x0

    const/16 v47, 0x1fe

    const/16 v36, 0x0

    const/16 v37, 0x0

    const/16 v38, 0x0

    const/16 v39, 0x0

    const/16 v40, 0x0

    const/16 v41, 0x0

    const/16 v42, 0x0

    const/16 v43, 0x0

    move-object/from16 v45, v0

    invoke-static/range {v35 .. v47}, Llyiahf/vczjk/mc4;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    :goto_24
    return-object v25

    :pswitch_b
    move-object v4, v7

    move-object/from16 v25, v10

    move-object/from16 v20, v11

    move-object/from16 v21, v14

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v19, 0x3

    and-int/lit8 v3, v2, 0x3

    if-eq v3, v1, :cond_41

    const/4 v1, 0x1

    :goto_25
    const/16 v33, 0x1

    goto :goto_26

    :cond_41
    const/4 v1, 0x0

    goto :goto_25

    :goto_26
    and-int/lit8 v2, v2, 0x1

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_46

    sget-object v1, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    const/4 v14, 0x0

    invoke-static {v1, v14}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v1

    iget v2, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {v0, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_42

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_27

    :cond_42
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_27
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v1, v0, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, v0, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v3, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_43

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_44

    :cond_43
    invoke-static {v2, v0, v2, v1}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_44
    sget-object v1, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v4, v0, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v18, 0x6

    invoke-static/range {v18 .. v18}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    check-cast v13, Llyiahf/vczjk/a91;

    check-cast v12, Llyiahf/vczjk/dq;

    invoke-virtual {v13, v12, v0, v1}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v1, v12, Llyiahf/vczjk/dq;->OooO00o:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v35

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v8, :cond_45

    new-instance v1, Llyiahf/vczjk/gq;

    const/4 v14, 0x0

    invoke-direct {v1, v12, v14}, Llyiahf/vczjk/gq;-><init>(Llyiahf/vczjk/dq;I)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_45
    move-object/from16 v36, v1

    check-cast v36, Llyiahf/vczjk/le3;

    new-instance v1, Llyiahf/vczjk/n6;

    move-object/from16 v14, v21

    check-cast v14, Llyiahf/vczjk/eq;

    move-object/from16 v11, v20

    check-cast v11, Llyiahf/vczjk/p29;

    const/4 v2, 0x1

    invoke-direct {v1, v14, v11, v2, v12}, Llyiahf/vczjk/n6;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    const v2, 0x6a7619b1

    invoke-static {v2, v1, v0}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v47

    const/16 v46, 0x0

    const/16 v50, 0x7fc

    const/16 v37, 0x0

    const-wide/16 v38, 0x0

    const/16 v40, 0x0

    const/16 v41, 0x0

    const/16 v42, 0x0

    const-wide/16 v43, 0x0

    const/16 v45, 0x0

    const/16 v49, 0x30

    move-object/from16 v48, v0

    invoke-static/range {v35 .. v50}, Llyiahf/vczjk/fe;->OooO00o(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/z98;Llyiahf/vczjk/d07;Llyiahf/vczjk/qj8;JFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    const/4 v2, 0x1

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_28

    :cond_46
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_28
    return-object v25

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
