.class public final Llyiahf/vczjk/jg0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Llyiahf/vczjk/cf3;

.field public final synthetic OooOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;Z)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/jg0;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p4, p0, Llyiahf/vczjk/jg0;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/jg0;->OooOOOo:Llyiahf/vczjk/cf3;

    iput-boolean p5, p0, Llyiahf/vczjk/jg0;->OooOOO:Z

    iput-object p1, p0, Llyiahf/vczjk/jg0;->OooOOo0:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/jg0;->OooOOo:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/a91;Llyiahf/vczjk/xr1;ZLlyiahf/vczjk/a91;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/jg0;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/jg0;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/jg0;->OooOOOo:Llyiahf/vczjk/cf3;

    iput-object p3, p0, Llyiahf/vczjk/jg0;->OooOOo:Ljava/lang/Object;

    iput-boolean p4, p0, Llyiahf/vczjk/jg0;->OooOOO:Z

    iput-object p5, p0, Llyiahf/vczjk/jg0;->OooOOo0:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/jg0;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    const/4 v3, 0x2

    if-ne v2, v3, :cond_1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v3, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/x21;

    iget-wide v3, v3, Llyiahf/vczjk/x21;->OooOOOo:J

    sget-object v5, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v2, v3, v4, v5}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v6

    iget-object v2, v0, Llyiahf/vczjk/jg0;->OooOOOO:Ljava/lang/Object;

    move-object v11, v2

    check-cast v11, Llyiahf/vczjk/qs5;

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    const v2, 0x4c5de2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, v3, :cond_2

    new-instance v2, Llyiahf/vczjk/a67;

    const/16 v3, 0xb

    invoke-direct {v2, v11, v3}, Llyiahf/vczjk/a67;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2
    move-object v5, v2

    check-cast v5, Llyiahf/vczjk/le3;

    const/4 v2, 0x0

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v7, Llyiahf/vczjk/nx8;

    iget-object v2, v0, Llyiahf/vczjk/jg0;->OooOOo:Ljava/lang/Object;

    move-object v10, v2

    check-cast v10, Llyiahf/vczjk/oe3;

    iget-object v2, v0, Llyiahf/vczjk/jg0;->OooOOOo:Llyiahf/vczjk/cf3;

    move-object v9, v2

    check-cast v9, Llyiahf/vczjk/oe3;

    iget-boolean v12, v0, Llyiahf/vczjk/jg0;->OooOOO:Z

    iget-object v2, v0, Llyiahf/vczjk/jg0;->OooOOo0:Ljava/lang/Object;

    move-object v8, v2

    check-cast v8, Ljava/util/List;

    invoke-direct/range {v7 .. v12}, Llyiahf/vczjk/nx8;-><init>(Ljava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;Z)V

    const v2, -0x86e61e2

    invoke-static {v2, v7, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v16

    const/4 v15, 0x0

    const/16 v19, 0x7f8

    const-wide/16 v7, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const-wide/16 v12, 0x0

    const/4 v14, 0x0

    const/16 v18, 0x30

    move-object/from16 v17, v1

    invoke-static/range {v4 .. v19}, Llyiahf/vczjk/fe;->OooO00o(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/z98;Llyiahf/vczjk/d07;Llyiahf/vczjk/qj8;JFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_1
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v3, v2, 0x3

    const/4 v4, 0x0

    const/4 v5, 0x2

    const/4 v6, 0x1

    if-eq v3, v5, :cond_3

    move v3, v6

    goto :goto_2

    :cond_3
    move v3, v4

    :goto_2
    and-int/2addr v2, v6

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_f

    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v3, 0x3f800000    # 1.0f

    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    new-instance v5, Llyiahf/vczjk/vf0;

    iget-object v7, v0, Llyiahf/vczjk/jg0;->OooOOOO:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/zl8;

    const/4 v8, 0x1

    invoke-direct {v5, v7, v8}, Llyiahf/vczjk/vf0;-><init>(Llyiahf/vczjk/zl8;I)V

    invoke-static {v3, v5}, Landroidx/compose/ui/graphics/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v5, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v7, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v5, v7, v1, v4}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v5

    iget v7, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v1, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v9, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v10, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v10, :cond_4

    invoke-virtual {v1, v9}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_4
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v10, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v1, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v8, v1, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v11, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v11, :cond_5

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    invoke-static {v11, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v11

    if-nez v11, :cond_6

    :cond_5
    invoke-static {v7, v1, v7, v8}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_6
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v1, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/r31;->OooO00o:Llyiahf/vczjk/r31;

    iget-object v11, v0, Llyiahf/vczjk/jg0;->OooOOOo:Llyiahf/vczjk/cf3;

    check-cast v11, Llyiahf/vczjk/a91;

    if-eqz v11, :cond_e

    const v12, -0x3e3b6b13

    invoke-virtual {v1, v12}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget v12, Landroidx/compose/material3/R$string;->m3c_bottom_sheet_collapse_description:I

    invoke-static {v12, v1}, Llyiahf/vczjk/ru6;->OooOo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v12

    sget v13, Landroidx/compose/material3/R$string;->m3c_bottom_sheet_dismiss_description:I

    invoke-static {v13, v1}, Llyiahf/vczjk/ru6;->OooOo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v13

    sget v14, Landroidx/compose/material3/R$string;->m3c_bottom_sheet_expand_description:I

    invoke-static {v14, v1}, Llyiahf/vczjk/ru6;->OooOo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v14

    sget-object v15, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    invoke-virtual {v3, v2, v15}, Llyiahf/vczjk/r31;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/sb0;)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-object v15, v0, Llyiahf/vczjk/jg0;->OooOOOO:Ljava/lang/Object;

    check-cast v15, Llyiahf/vczjk/zl8;

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v16

    iget-object v6, v0, Llyiahf/vczjk/jg0;->OooOOo:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/xr1;

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v17

    or-int v16, v16, v17

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    move-object/from16 v20, v3

    sget-object v3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v16, :cond_8

    if-ne v4, v3, :cond_7

    goto :goto_4

    :cond_7
    move-object/from16 v21, v11

    goto :goto_5

    :cond_8
    :goto_4
    new-instance v4, Llyiahf/vczjk/bg0;

    move-object/from16 v21, v11

    const/4 v11, 0x3

    invoke-direct {v4, v15, v6, v11}, Llyiahf/vczjk/bg0;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/xr1;I)V

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_5
    check-cast v4, Llyiahf/vczjk/le3;

    const/4 v11, 0x0

    move-object/from16 v22, v7

    const/4 v7, 0x7

    move-object/from16 v23, v8

    const/4 v8, 0x0

    invoke-static {v2, v8, v11, v4, v7}, Landroidx/compose/foundation/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;ZLjava/lang/String;Llyiahf/vczjk/le3;I)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    move-object v7, v15

    iget-boolean v15, v0, Llyiahf/vczjk/jg0;->OooOOO:Z

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v8

    or-int/2addr v4, v8

    invoke-virtual {v1, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v4, v8

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v4, v8

    invoke-virtual {v1, v12}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v4, v8

    invoke-virtual {v1, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v4, v8

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v4, :cond_9

    if-ne v8, v3, :cond_a

    :cond_9
    move-object/from16 v18, v13

    new-instance v13, Llyiahf/vczjk/cg0;

    move-object/from16 v19, v6

    move-object/from16 v17, v12

    move-object/from16 v16, v14

    move-object v14, v7

    invoke-direct/range {v13 .. v19}, Llyiahf/vczjk/cg0;-><init>(Llyiahf/vczjk/zl8;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/xr1;)V

    invoke-virtual {v1, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v8, v13

    :cond_a
    check-cast v8, Llyiahf/vczjk/oe3;

    const/4 v3, 0x1

    invoke-static {v2, v3, v8}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    const/4 v8, 0x0

    invoke-static {v3, v8}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v3

    iget v4, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v1, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_b

    invoke-virtual {v1, v9}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_b
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    invoke-static {v3, v1, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v6, v1, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v3, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_c

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_d

    :cond_c
    move-object/from16 v3, v23

    goto :goto_8

    :cond_d
    :goto_7
    move-object/from16 v3, v22

    goto :goto_9

    :goto_8
    invoke-static {v4, v1, v4, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    goto :goto_7

    :goto_9
    invoke-static {v2, v1, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/4 v8, 0x0

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    move-object/from16 v11, v21

    invoke-virtual {v11, v1, v2}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v3, 0x1

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_a

    :cond_e
    move-object/from16 v20, v3

    move v8, v4

    const v2, -0x3e0798c5

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_a
    const/4 v2, 0x6

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    iget-object v3, v0, Llyiahf/vczjk/jg0;->OooOOo0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/a91;

    move-object/from16 v4, v20

    invoke-virtual {v3, v4, v1, v2}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v3, 0x1

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_b

    :cond_f
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_b
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
