.class public final Llyiahf/vczjk/ou;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/qs5;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ou;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ou;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 43

    move-object/from16 v0, p0

    const/4 v1, 0x1

    const v2, 0x4c5de2

    sget-object v3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    sget-object v4, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/4 v5, 0x0

    sget-object v6, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v7, v0, Llyiahf/vczjk/ou;->OooOOO:Llyiahf/vczjk/qs5;

    const/4 v8, 0x2

    const/4 v9, 0x3

    iget v10, v0, Llyiahf/vczjk/ou;->OooOOO0:I

    packed-switch v10, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/2addr v2, v9

    if-ne v2, v8, :cond_1

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
    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/j28;

    iget-boolean v11, v2, Llyiahf/vczjk/j28;->OooO0OO:Z

    new-instance v2, Llyiahf/vczjk/p5;

    const/4 v3, 0x6

    invoke-direct {v2, v7, v3}, Llyiahf/vczjk/p5;-><init>(Llyiahf/vczjk/qs5;I)V

    const v3, -0x3ea7ab5b

    invoke-static {v3, v2, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v16

    const/high16 v18, 0x30000

    const/16 v19, 0x1e

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    move-object/from16 v17, v1

    invoke-static/range {v11 .. v19}, Landroidx/compose/animation/OooO0O0;->OooO0Oo(ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_1
    return-object v6

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/2addr v2, v9

    if-ne v2, v8, :cond_3

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3

    :cond_3
    :goto_2
    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/i28;

    iget-boolean v2, v2, Llyiahf/vczjk/i28;->OooO00o:Z

    if-eqz v2, :cond_4

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->apps_count:I

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/i28;

    iget-object v3, v3, Llyiahf/vczjk/i28;->OooO0O0:Ljava/util/Set;

    invoke-interface {v3}, Ljava/util/Set;->size()I

    move-result v3

    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v3

    filled-new-array {v3}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2, v3, v1}, Llyiahf/vczjk/vt6;->Oooo0O0(I[Ljava/lang/Object;Llyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v20

    const/16 v41, 0x0

    const v42, 0x3fffe

    const/16 v21, 0x0

    const-wide/16 v22, 0x0

    const-wide/16 v24, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const-wide/16 v28, 0x0

    const/16 v30, 0x0

    const-wide/16 v31, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    const/16 v35, 0x0

    const/16 v36, 0x0

    const/16 v37, 0x0

    const/16 v38, 0x0

    const/16 v40, 0x0

    move-object/from16 v39, v1

    invoke-static/range {v20 .. v42}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :cond_4
    :goto_3
    return-object v6

    :pswitch_1
    move-object/from16 v13, p1

    check-cast v13, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    and-int/2addr v1, v9

    if-ne v1, v8, :cond_6

    move-object v1, v13

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v8

    if-nez v8, :cond_5

    goto :goto_4

    :cond_5
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_7

    :cond_6
    :goto_4
    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/kt2;

    sget-object v7, Llyiahf/vczjk/kt2;->OooOOO0:Llyiahf/vczjk/kt2;

    if-ne v1, v7, :cond_7

    const/high16 v1, 0x43340000    # 180.0f

    :goto_5
    move v10, v1

    goto :goto_6

    :cond_7
    const/4 v1, 0x0

    goto :goto_5

    :goto_6
    const/16 v14, 0xc00

    const/16 v15, 0x16

    const/4 v11, 0x0

    const-string v12, "Trailing Icon Rotation"

    invoke-static/range {v10 .. v15}, Llyiahf/vczjk/ti;->OooO0O0(FLlyiahf/vczjk/p13;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/p29;

    move-result-object v1

    invoke-static {}, Llyiahf/vczjk/e16;->OooOo0o()Llyiahf/vczjk/qv3;

    move-result-object v14

    const/16 v7, 0x18

    int-to-float v7, v7

    invoke-static {v4, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    check-cast v13, Llyiahf/vczjk/zf1;

    invoke-virtual {v13, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v2, :cond_8

    if-ne v7, v3, :cond_9

    :cond_8
    new-instance v7, Llyiahf/vczjk/fl0;

    invoke-direct {v7, v1, v9}, Llyiahf/vczjk/fl0;-><init>(Llyiahf/vczjk/p29;I)V

    invoke-virtual {v13, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    check-cast v7, Llyiahf/vczjk/oe3;

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v4, v7}, Landroidx/compose/ui/graphics/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v16

    const/16 v20, 0x30

    const/16 v21, 0x8

    const-string v15, ""

    const-wide/16 v17, 0x0

    move-object/from16 v19, v13

    invoke-static/range {v14 .. v21}, Llyiahf/vczjk/yt3;->OooO00o(Llyiahf/vczjk/qv3;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    :goto_7
    return-object v6

    :pswitch_2
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v10, p2

    check-cast v10, Ljava/lang/Number;

    invoke-virtual {v10}, Ljava/lang/Number;->intValue()I

    move-result v10

    and-int/2addr v9, v10

    if-eq v9, v8, :cond_a

    move v8, v1

    goto :goto_8

    :cond_a
    move v8, v5

    :goto_8
    and-int/lit8 v9, v10, 0x1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v9, v8}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v8

    if-eqz v8, :cond_f

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-ne v8, v3, :cond_b

    new-instance v8, Llyiahf/vczjk/rt3;

    const/4 v3, 0x7

    invoke-direct {v8, v3}, Llyiahf/vczjk/rt3;-><init>(I)V

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    check-cast v8, Llyiahf/vczjk/oe3;

    invoke-static {v4, v5, v8}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v4, v5}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v4

    iget v8, v2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v9

    invoke-static {v2, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v10, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v11, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v11, :cond_c

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_9

    :cond_c
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_9
    sget-object v10, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v4, v2, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v9, v2, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v9, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v9, :cond_d

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-nez v9, :cond_e

    :cond_d
    invoke-static {v8, v2, v8, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_e
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v2, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ze3;

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-interface {v3, v2, v4}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_a

    :cond_f
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_a
    return-object v6

    :pswitch_3
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/2addr v2, v9

    if-ne v2, v8, :cond_11

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_10

    goto :goto_b

    :cond_10
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_c

    :cond_11
    :goto_b
    new-instance v2, Llyiahf/vczjk/p5;

    invoke-direct {v2, v7, v9}, Llyiahf/vczjk/p5;-><init>(Llyiahf/vczjk/qs5;I)V

    const v3, 0x15c84aba

    invoke-static {v3, v2, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/va1;->OooO0OO:Llyiahf/vczjk/a91;

    const/4 v4, 0x0

    const/16 v5, 0x186

    invoke-static {v2, v4, v3, v1, v5}, Llyiahf/vczjk/l50;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    :goto_c
    return-object v6

    :pswitch_4
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/2addr v2, v9

    if-ne v2, v8, :cond_13

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_12

    goto :goto_d

    :cond_12
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_e

    :cond_13
    :goto_d
    invoke-static {v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooOo0(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOoo(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/cl8;->OooO00o:Llyiahf/vczjk/l39;

    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/al8;

    iget-object v3, v3, Llyiahf/vczjk/al8;->OooO0Oo:Llyiahf/vczjk/ir1;

    sget v13, Llyiahf/vczjk/y3;->OooO00o:F

    new-instance v4, Llyiahf/vczjk/ou;

    invoke-direct {v4, v7, v8}, Llyiahf/vczjk/ou;-><init>(Llyiahf/vczjk/qs5;I)V

    const v5, -0x18cb1fd5

    invoke-static {v5, v4, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v15

    const v17, 0xc00006

    const/16 v18, 0x6c

    const-wide/16 v9, 0x0

    const-wide/16 v11, 0x0

    const/4 v14, 0x0

    move-object/from16 v16, v1

    move-object v7, v2

    move-object v8, v3

    invoke-static/range {v7 .. v18}, Llyiahf/vczjk/ua9;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_e
    return-object v6

    :pswitch_5
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/2addr v3, v9

    if-ne v3, v8, :cond_15

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v8

    if-nez v8, :cond_14

    goto :goto_f

    :cond_14
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_11

    :cond_15
    :goto_f
    const/16 v3, 0x10

    int-to-float v3, v3

    invoke-static {v4, v3}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v8, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v4, v8, v2, v5}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v4

    move-object v5, v2

    check-cast v5, Llyiahf/vczjk/zf1;

    iget v8, v5, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v9

    invoke-static {v2, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v10, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v11, v5, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v11, :cond_16

    invoke-virtual {v5, v10}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_10

    :cond_16
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_10
    sget-object v10, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v4, v2, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v9, v2, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v9, v5, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v9, :cond_17

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-nez v9, :cond_18

    :cond_17
    invoke-static {v8, v5, v8, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_18
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v2, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v3, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OoooO0O:I

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ka0;

    iget-object v3, v3, Llyiahf/vczjk/ka0;->OooO0O0:Ljava/lang/String;

    const/16 v40, 0x0

    const v41, 0x3fffe

    const/16 v20, 0x0

    const-wide/16 v21, 0x0

    const-wide/16 v23, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const-wide/16 v27, 0x0

    const/16 v29, 0x0

    const-wide/16 v30, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    const/16 v35, 0x0

    const/16 v36, 0x0

    const/16 v37, 0x0

    const/16 v39, 0x0

    move-object/from16 v38, v2

    move-object/from16 v19, v3

    invoke-static/range {v19 .. v41}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    const-wide/16 v22, 0x0

    const/16 v27, 0x0

    const/16 v19, 0x0

    const-wide/16 v20, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    move-object/from16 v26, v38

    invoke-static/range {v19 .. v27}, Llyiahf/vczjk/ea7;->OooO0OO(Llyiahf/vczjk/kl5;JJIFLlyiahf/vczjk/rf1;I)V

    invoke-virtual {v5, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_11
    return-object v6

    :pswitch_6
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v4, p2

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    move-result v4

    and-int/2addr v4, v9

    if-ne v4, v8, :cond_1a

    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v8

    if-nez v8, :cond_19

    goto :goto_12

    :cond_19
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_13

    :cond_1a
    :goto_12
    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v3, :cond_1b

    new-instance v2, Llyiahf/vczjk/l5;

    const/16 v3, 0xa

    invoke-direct {v2, v7, v3}, Llyiahf/vczjk/l5;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1b
    move-object v9, v2

    check-cast v9, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v15, Llyiahf/vczjk/r91;->OooO0O0:Llyiahf/vczjk/a91;

    const v17, 0x30000006

    const/16 v18, 0x1fe

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    move-object/from16 v16, v1

    invoke-static/range {v9 .. v18}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_13
    return-object v6

    :pswitch_7
    move-object/from16 v38, p1

    check-cast v38, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    and-int/2addr v1, v9

    if-ne v1, v8, :cond_1d

    move-object/from16 v1, v38

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_1c

    goto :goto_14

    :cond_1c
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_15

    :cond_1d
    :goto_14
    sget v1, Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;->OoooO0O:I

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/xu;

    iget-object v1, v1, Llyiahf/vczjk/xu;->OooO0Oo:Ljava/lang/String;

    move-object/from16 v2, v38

    check-cast v2, Llyiahf/vczjk/zf1;

    const v3, -0x4021aeb5

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v3, Llyiahf/vczjk/gm9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    move-object/from16 v37, v3

    check-cast v37, Llyiahf/vczjk/rn9;

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v40, 0x0

    const v41, 0x1fffe

    const/16 v20, 0x0

    const-wide/16 v21, 0x0

    const-wide/16 v23, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const-wide/16 v27, 0x0

    const/16 v29, 0x0

    const-wide/16 v30, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    const/16 v35, 0x0

    const/16 v36, 0x0

    const/16 v39, 0x0

    move-object/from16 v19, v1

    invoke-static/range {v19 .. v41}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_15
    return-object v6

    :pswitch_data_0
    .packed-switch 0x0
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
