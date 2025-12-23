.class public abstract Llyiahf/vczjk/fe;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/d07;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/d07;

    const/16 v1, 0xe

    invoke-direct {v0, v1}, Llyiahf/vczjk/d07;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/fe;->OooO00o:Llyiahf/vczjk/d07;

    return-void
.end method

.method public static final OooO00o(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/z98;Llyiahf/vczjk/d07;Llyiahf/vczjk/qj8;JFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V
    .locals 28

    move/from16 v14, p14

    const/4 v0, 0x0

    const/4 v1, 0x4

    const/4 v2, 0x1

    move-object/from16 v3, p13

    check-cast v3, Llyiahf/vczjk/zf1;

    const v4, 0x66dab59f

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    move/from16 v4, p0

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v5

    if-eqz v5, :cond_0

    move v5, v1

    goto :goto_0

    :cond_0
    const/4 v5, 0x2

    :goto_0
    or-int/2addr v5, v14

    and-int/lit8 v6, v14, 0x30

    const/16 v7, 0x20

    if-nez v6, :cond_2

    move-object/from16 v6, p1

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_1

    move v8, v7

    goto :goto_1

    :cond_1
    const/16 v8, 0x10

    :goto_1
    or-int/2addr v5, v8

    goto :goto_2

    :cond_2
    move-object/from16 v6, p1

    :goto_2
    and-int/lit8 v1, p15, 0x4

    if-eqz v1, :cond_4

    or-int/lit16 v5, v5, 0x180

    :cond_3
    move-object/from16 v8, p2

    goto :goto_4

    :cond_4
    and-int/lit16 v8, v14, 0x180

    if-nez v8, :cond_3

    move-object/from16 v8, p2

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_5

    const/16 v9, 0x100

    goto :goto_3

    :cond_5
    const/16 v9, 0x80

    :goto_3
    or-int/2addr v5, v9

    :goto_4
    const v9, 0x364b2c00

    or-int/2addr v5, v9

    const v9, 0x12492493

    and-int/2addr v9, v5

    const v10, 0x12492492

    if-ne v9, v10, :cond_6

    move v9, v0

    goto :goto_5

    :cond_6
    move v9, v2

    :goto_5
    and-int/lit8 v10, v5, 0x1

    invoke-virtual {v3, v10, v9}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v9

    if-eqz v9, :cond_10

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/2addr v2, v14

    const v9, -0x1f8e001

    if-eqz v2, :cond_8

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v2

    if-eqz v2, :cond_7

    goto :goto_6

    :cond_7
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int v1, v5, v9

    move-object/from16 v20, p5

    move-object/from16 v15, p6

    move-object/from16 v21, p7

    move-wide/from16 v22, p8

    move/from16 v24, p10

    move/from16 v25, p11

    move-object/from16 v17, v8

    move-wide/from16 v7, p3

    goto :goto_8

    :cond_8
    :goto_6
    if-eqz v1, :cond_9

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_7

    :cond_9
    move-object v1, v8

    :goto_7
    int-to-float v2, v0

    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v8

    int-to-long v10, v8

    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v12, v2

    shl-long v7, v10, v7

    const-wide v10, 0xffffffffL

    and-long/2addr v10, v12

    or-long/2addr v7, v10

    invoke-static {v3}, Llyiahf/vczjk/mt6;->OooOOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/z98;

    move-result-object v2

    sget v10, Llyiahf/vczjk/tg5;->OooO00o:F

    sget-object v10, Llyiahf/vczjk/ei5;->OooO0OO:Llyiahf/vczjk/dk8;

    invoke-static {v10, v3}, Llyiahf/vczjk/cl8;->OooO0O0(Llyiahf/vczjk/dk8;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qj8;

    move-result-object v10

    sget-object v11, Llyiahf/vczjk/ei5;->OooO00o:Llyiahf/vczjk/y21;

    invoke-static {v11, v3}, Llyiahf/vczjk/z21;->OooO0o0(Llyiahf/vczjk/y21;Llyiahf/vczjk/rf1;)J

    move-result-wide v11

    and-int/2addr v5, v9

    sget v9, Llyiahf/vczjk/tg5;->OooO00o:F

    sget v13, Llyiahf/vczjk/tg5;->OooO0O0:F

    sget-object v15, Llyiahf/vczjk/fe;->OooO00o:Llyiahf/vczjk/d07;

    move-object/from16 v17, v1

    move-object/from16 v20, v2

    move v1, v5

    move/from16 v24, v9

    move-object/from16 v21, v10

    move-wide/from16 v22, v11

    move/from16 v25, v13

    :goto_8
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOo0()V

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, v5, :cond_a

    new-instance v2, Llyiahf/vczjk/ss5;

    sget-object v9, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-direct {v2, v9}, Llyiahf/vczjk/ss5;-><init>(Ljava/lang/Object;)V

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    check-cast v2, Llyiahf/vczjk/ss5;

    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v9

    iget-object v10, v2, Llyiahf/vczjk/ss5;->OooO0OO:Llyiahf/vczjk/qs5;

    check-cast v10, Llyiahf/vczjk/fw8;

    invoke-virtual {v10, v9}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v9, v2, Llyiahf/vczjk/ss5;->OooO0O0:Llyiahf/vczjk/qs5;

    check-cast v9, Llyiahf/vczjk/fw8;

    invoke-virtual {v9}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Boolean;

    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v9

    if-nez v9, :cond_c

    iget-object v9, v2, Llyiahf/vczjk/ss5;->OooO0OO:Llyiahf/vczjk/qs5;

    check-cast v9, Llyiahf/vczjk/fw8;

    invoke-virtual {v9}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Boolean;

    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v9

    if-eqz v9, :cond_b

    goto :goto_9

    :cond_b
    const v1, 0x458e7383

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v1, v3

    goto/16 :goto_a

    :cond_c
    :goto_9
    const v9, 0x457e4ab5

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-ne v9, v5, :cond_d

    sget-wide v9, Llyiahf/vczjk/ey9;->OooO0O0:J

    new-instance v11, Llyiahf/vczjk/ey9;

    invoke-direct {v11, v9, v10}, Llyiahf/vczjk/ey9;-><init>(J)V

    invoke-static {v11}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v9

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    check-cast v9, Llyiahf/vczjk/qs5;

    sget-object v10, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/f62;

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    if-nez v11, :cond_e

    if-ne v12, v5, :cond_f

    :cond_e
    new-instance v12, Llyiahf/vczjk/mj2;

    new-instance v5, Llyiahf/vczjk/xd;

    invoke-direct {v5, v9, v0}, Llyiahf/vczjk/xd;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-direct {v12, v7, v8, v10, v5}, Llyiahf/vczjk/mj2;-><init>(JLlyiahf/vczjk/f62;Llyiahf/vczjk/xd;)V

    invoke-virtual {v3, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_f
    check-cast v12, Llyiahf/vczjk/mj2;

    new-instance v16, Llyiahf/vczjk/ae;

    move-object/from16 v26, p12

    move-object/from16 v18, v2

    move-object/from16 v19, v9

    invoke-direct/range {v16 .. v26}, Llyiahf/vczjk/ae;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ss5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/z98;Llyiahf/vczjk/qj8;JFFLlyiahf/vczjk/a91;)V

    move-object/from16 v2, v16

    const v5, -0x36afd328    # -852685.5f

    invoke-static {v5, v2, v3}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    and-int/lit8 v1, v1, 0x70

    or-int/lit16 v1, v1, 0xd80

    const/4 v5, 0x0

    move/from16 p7, v1

    move-object/from16 p5, v2

    move-object/from16 p6, v3

    move/from16 p8, v5

    move-object/from16 p3, v6

    move-object/from16 p2, v12

    move-object/from16 p4, v15

    invoke-static/range {p2 .. p8}, Llyiahf/vczjk/of;->OooO00o(Llyiahf/vczjk/c07;Llyiahf/vczjk/le3;Llyiahf/vczjk/d07;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    move-object/from16 v1, p6

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_a
    move-wide v4, v7

    move-object v7, v15

    move-object/from16 v3, v17

    move-object/from16 v6, v20

    move-object/from16 v8, v21

    move-wide/from16 v9, v22

    move/from16 v11, v24

    move/from16 v12, v25

    goto :goto_b

    :cond_10
    move-object v1, v3

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-wide/from16 v4, p3

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    move-wide/from16 v9, p8

    move/from16 v11, p10

    move/from16 v12, p11

    move-object v3, v8

    move-object/from16 v8, p7

    :goto_b
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_11

    move-object v1, v0

    new-instance v0, Llyiahf/vczjk/yd;

    move-object/from16 v2, p1

    move-object/from16 v13, p12

    move/from16 v15, p15

    move-object/from16 v27, v1

    move/from16 v1, p0

    invoke-direct/range {v0 .. v15}, Llyiahf/vczjk/yd;-><init>(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/z98;Llyiahf/vczjk/d07;Llyiahf/vczjk/qj8;JFFLlyiahf/vczjk/a91;II)V

    move-object/from16 v1, v27

    iput-object v0, v1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_11
    return-void
.end method

.method public static final OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/bh5;Llyiahf/vczjk/di6;Llyiahf/vczjk/rf1;II)V
    .locals 28

    move/from16 v7, p7

    const/16 v0, 0x20

    const/4 v1, 0x1

    move-object/from16 v14, p6

    check-cast v14, Llyiahf/vczjk/zf1;

    const v2, -0x1fc44f8d

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    move-object/from16 v9, p1

    invoke-virtual {v14, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    move v2, v0

    goto :goto_0

    :cond_0
    const/16 v2, 0x10

    :goto_0
    or-int/2addr v2, v7

    and-int/lit8 v3, p8, 0x4

    if-eqz v3, :cond_2

    or-int/lit16 v2, v2, 0x180

    :cond_1
    move-object/from16 v4, p2

    goto :goto_2

    :cond_2
    and-int/lit16 v4, v7, 0x180

    if-nez v4, :cond_1

    move-object/from16 v4, p2

    invoke-virtual {v14, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_3

    const/16 v5, 0x100

    goto :goto_1

    :cond_3
    const/16 v5, 0x80

    :goto_1
    or-int/2addr v2, v5

    :goto_2
    or-int/lit16 v5, v2, 0x6c00

    and-int/lit8 v0, p8, 0x20

    if-eqz v0, :cond_4

    const v5, 0x36c00

    or-int/2addr v2, v5

    move v5, v2

    move/from16 v2, p3

    goto :goto_4

    :cond_4
    move/from16 v2, p3

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v6

    if-eqz v6, :cond_5

    const/high16 v6, 0x20000

    goto :goto_3

    :cond_5
    const/high16 v6, 0x10000

    :goto_3
    or-int/2addr v5, v6

    :goto_4
    const/high16 v6, 0x6c80000

    or-int/2addr v5, v6

    const v6, 0x2492493

    and-int/2addr v6, v5

    const v8, 0x2492492

    if-eq v6, v8, :cond_6

    move v6, v1

    goto :goto_5

    :cond_6
    const/4 v6, 0x0

    :goto_5
    and-int/lit8 v8, v5, 0x1

    invoke-virtual {v14, v8, v6}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v6

    if-eqz v6, :cond_c

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v6, v7, 0x1

    const v8, -0x380001

    if-eqz v6, :cond_8

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v6

    if-eqz v6, :cond_7

    goto :goto_6

    :cond_7
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int v0, v5, v8

    move-object/from16 v12, p4

    move-object/from16 v13, p5

    move v11, v2

    move-object v10, v4

    goto :goto_a

    :cond_8
    :goto_6
    if-eqz v3, :cond_9

    sget-object v3, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_7

    :cond_9
    move-object v3, v4

    :goto_7
    if-eqz v0, :cond_a

    goto :goto_8

    :cond_a
    move v1, v2

    :goto_8
    sget v0, Llyiahf/vczjk/tg5;->OooO00o:F

    sget-object v0, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v14, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/x21;

    iget-object v2, v0, Llyiahf/vczjk/x21;->Oooooo:Llyiahf/vczjk/bh5;

    if-nez v2, :cond_b

    new-instance v15, Llyiahf/vczjk/bh5;

    sget-object v2, Llyiahf/vczjk/p15;->OooO0oO:Llyiahf/vczjk/y21;

    invoke-static {v0, v2}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v16

    sget-object v2, Llyiahf/vczjk/p15;->OooO0oo:Llyiahf/vczjk/y21;

    invoke-static {v0, v2}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v18

    sget-object v2, Llyiahf/vczjk/p15;->OooO:Llyiahf/vczjk/y21;

    invoke-static {v0, v2}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v20

    sget-object v2, Llyiahf/vczjk/p15;->OooO00o:Llyiahf/vczjk/y21;

    invoke-static {v0, v2}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v10

    sget v2, Llyiahf/vczjk/p15;->OooO0O0:F

    invoke-static {v2, v10, v11}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v22

    sget-object v2, Llyiahf/vczjk/p15;->OooO0OO:Llyiahf/vczjk/y21;

    invoke-static {v0, v2}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v10

    sget v2, Llyiahf/vczjk/p15;->OooO0Oo:F

    invoke-static {v2, v10, v11}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v24

    sget-object v2, Llyiahf/vczjk/p15;->OooO0o0:Llyiahf/vczjk/y21;

    invoke-static {v0, v2}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v10

    sget v2, Llyiahf/vczjk/p15;->OooO0o:F

    invoke-static {v2, v10, v11}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v26

    invoke-direct/range {v15 .. v27}, Llyiahf/vczjk/bh5;-><init>(JJJJJJ)V

    iput-object v15, v0, Llyiahf/vczjk/x21;->Oooooo:Llyiahf/vczjk/bh5;

    goto :goto_9

    :cond_b
    move-object v15, v2

    :goto_9
    and-int v0, v5, v8

    sget-object v2, Llyiahf/vczjk/tg5;->OooO0OO:Llyiahf/vczjk/di6;

    move v11, v1

    move-object v13, v2

    move-object v10, v3

    move-object v12, v15

    :goto_a
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OooOOo0()V

    const v1, 0xffffffe

    and-int v15, v0, v1

    move-object/from16 v8, p0

    invoke-static/range {v8 .. v15}, Llyiahf/vczjk/sh5;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/bh5;Llyiahf/vczjk/di6;Llyiahf/vczjk/rf1;I)V

    move-object v3, v10

    move v4, v11

    move-object v5, v12

    move-object v6, v13

    goto :goto_b

    :cond_c
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move-object v3, v4

    move v4, v2

    :goto_b
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v9

    if-eqz v9, :cond_d

    new-instance v0, Llyiahf/vczjk/zd;

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move/from16 v8, p8

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/zd;-><init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/bh5;Llyiahf/vczjk/di6;II)V

    iput-object v0, v9, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_d
    return-void
.end method
