.class public abstract Llyiahf/vczjk/tp6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/hia;


# direct methods
.method public static final OooO(Llyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;I)Z
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move/from16 v3, p3

    invoke-static {v3, v2, v0}, Llyiahf/vczjk/tp6;->OooOO0(ILlyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;)Z

    move-result v4

    if-nez v4, :cond_12

    invoke-static {v3, v1, v0}, Llyiahf/vczjk/tp6;->OooOO0(ILlyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;)Z

    move-result v4

    if-nez v4, :cond_0

    goto/16 :goto_4

    :cond_0
    const-string v4, "This function should only be used for 2-D focus search"

    const/4 v5, 0x6

    const/4 v6, 0x5

    const/4 v7, 0x4

    const/4 v8, 0x3

    iget v9, v2, Llyiahf/vczjk/wj7;->OooO0O0:F

    iget v10, v2, Llyiahf/vczjk/wj7;->OooO0Oo:F

    iget v11, v2, Llyiahf/vczjk/wj7;->OooO00o:F

    iget v2, v2, Llyiahf/vczjk/wj7;->OooO0OO:F

    iget v12, v0, Llyiahf/vczjk/wj7;->OooO0Oo:F

    iget v13, v0, Llyiahf/vczjk/wj7;->OooO0O0:F

    iget v14, v0, Llyiahf/vczjk/wj7;->OooO0OO:F

    iget v0, v0, Llyiahf/vczjk/wj7;->OooO00o:F

    if-ne v3, v8, :cond_1

    cmpl-float v15, v0, v2

    if-ltz v15, :cond_10

    goto :goto_0

    :cond_1
    if-ne v3, v7, :cond_2

    cmpg-float v15, v14, v11

    if-gtz v15, :cond_10

    goto :goto_0

    :cond_2
    if-ne v3, v6, :cond_3

    cmpl-float v15, v13, v10

    if-ltz v15, :cond_10

    goto :goto_0

    :cond_3
    if-ne v3, v5, :cond_11

    cmpg-float v15, v12, v9

    if-gtz v15, :cond_10

    :goto_0
    if-ne v3, v8, :cond_4

    goto :goto_3

    :cond_4
    if-ne v3, v7, :cond_5

    goto :goto_3

    :cond_5
    if-ne v3, v8, :cond_6

    iget v1, v1, Llyiahf/vczjk/wj7;->OooO0OO:F

    sub-float v1, v0, v1

    goto :goto_1

    :cond_6
    if-ne v3, v7, :cond_7

    iget v1, v1, Llyiahf/vczjk/wj7;->OooO00o:F

    sub-float/2addr v1, v14

    goto :goto_1

    :cond_7
    if-ne v3, v6, :cond_8

    iget v1, v1, Llyiahf/vczjk/wj7;->OooO0Oo:F

    sub-float v1, v13, v1

    goto :goto_1

    :cond_8
    if-ne v3, v5, :cond_f

    iget v1, v1, Llyiahf/vczjk/wj7;->OooO0O0:F

    sub-float/2addr v1, v12

    :goto_1
    const/4 v15, 0x0

    cmpg-float v16, v1, v15

    if-gez v16, :cond_9

    move v1, v15

    :cond_9
    if-ne v3, v8, :cond_a

    sub-float/2addr v0, v11

    goto :goto_2

    :cond_a
    if-ne v3, v7, :cond_b

    sub-float v0, v2, v14

    goto :goto_2

    :cond_b
    if-ne v3, v6, :cond_c

    sub-float v0, v13, v9

    goto :goto_2

    :cond_c
    if-ne v3, v5, :cond_e

    sub-float v0, v10, v12

    :goto_2
    const/high16 v2, 0x3f800000    # 1.0f

    cmpg-float v3, v0, v2

    if-gez v3, :cond_d

    move v0, v2

    :cond_d
    cmpg-float v0, v1, v0

    if-gez v0, :cond_12

    goto :goto_3

    :cond_e
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_10
    :goto_3
    const/4 v0, 0x1

    return v0

    :cond_11
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_12
    :goto_4
    const/4 v0, 0x0

    return v0
.end method

.method public static final OooO0Oo(JLlyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V
    .locals 7

    check-cast p4, Llyiahf/vczjk/zf1;

    const v0, -0x28d355e8

    invoke-virtual {p4, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p5, 0x6

    if-nez v0, :cond_1

    invoke-virtual {p4, p0, p1}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p5

    goto :goto_1

    :cond_1
    move v0, p5

    :goto_1
    and-int/lit8 v1, p5, 0x30

    if-nez v1, :cond_3

    invoke-virtual {p4, p2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    const/16 v1, 0x20

    goto :goto_2

    :cond_2
    const/16 v1, 0x10

    :goto_2
    or-int/2addr v0, v1

    :cond_3
    and-int/lit16 v1, p5, 0x180

    if-nez v1, :cond_5

    invoke-virtual {p4, p3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_4

    const/16 v1, 0x100

    goto :goto_3

    :cond_4
    const/16 v1, 0x80

    :goto_3
    or-int/2addr v0, v1

    :cond_5
    and-int/lit16 v1, v0, 0x93

    const/16 v2, 0x92

    if-eq v1, v2, :cond_6

    const/4 v1, 0x1

    goto :goto_4

    :cond_6
    const/4 v1, 0x0

    :goto_4
    and-int/lit8 v2, v0, 0x1

    invoke-virtual {p4, v2, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_7

    sget-object v1, Llyiahf/vczjk/gm9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {p4, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/rn9;

    invoke-virtual {v2, p2}, Llyiahf/vczjk/rn9;->OooO0Oo(Llyiahf/vczjk/rn9;)Llyiahf/vczjk/rn9;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/km1;->OooO00o:Llyiahf/vczjk/jh1;

    new-instance v4, Llyiahf/vczjk/n21;

    invoke-direct {v4, p0, p1}, Llyiahf/vczjk/n21;-><init>(J)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v3

    invoke-virtual {v1, v2}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v1

    filled-new-array {v3, v1}, [Llyiahf/vczjk/ke7;

    move-result-object v1

    shr-int/lit8 v0, v0, 0x3

    and-int/lit8 v0, v0, 0x70

    const/16 v2, 0x8

    or-int/2addr v0, v2

    invoke-static {v1, p3, p4, v0}, Llyiahf/vczjk/r02;->OooO0O0([Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_5

    :cond_7
    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_5
    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p4

    if-eqz p4, :cond_8

    new-instance v0, Llyiahf/vczjk/je7;

    const/4 v6, 0x0

    move-wide v1, p0

    move-object v3, p2

    move-object v4, p3

    move v5, p5

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/je7;-><init>(JLlyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;II)V

    iput-object v0, p4, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_8
    return-void
.end method

.method public static final OooO0o(Llyiahf/vczjk/r39;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 11

    const-string v0, "chartState"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onItemSelected"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onCenterSelected"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v7, p3

    check-cast v7, Llyiahf/vczjk/zf1;

    const p3, 0x4aa0554e    # 5253799.0f

    invoke-virtual {v7, p3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v7, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p3

    if-eqz p3, :cond_0

    const/4 p3, 0x4

    goto :goto_0

    :cond_0
    const/4 p3, 0x2

    :goto_0
    or-int/2addr p3, p4

    invoke-virtual {v7, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    const/16 v0, 0x20

    goto :goto_1

    :cond_1
    const/16 v0, 0x10

    :goto_1
    or-int/2addr p3, v0

    invoke-virtual {v7, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    const/16 v0, 0x100

    goto :goto_2

    :cond_2
    const/16 v0, 0x80

    :goto_2
    or-int/2addr p3, v0

    and-int/lit16 v0, p3, 0x93

    const/16 v1, 0x92

    if-ne v0, v1, :cond_4

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_4

    :cond_4
    :goto_3
    iget-boolean v0, p0, Llyiahf/vczjk/r39;->OooO00o:Z

    const/4 v10, 0x0

    if-eqz v0, :cond_5

    const p3, 0x5829f46d

    invoke-virtual {v7, p3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object p3, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v7, p3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/x21;

    iget-wide v2, p3, Llyiahf/vczjk/x21;->OooO00o:J

    sget-object p3, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v0, 0x3f800000    # 1.0f

    invoke-static {p3, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object p3

    const/4 v0, 0x6

    int-to-float v0, v0

    invoke-static {p3, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0o0(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    const-wide/16 v4, 0x0

    const/4 v6, 0x0

    const/4 v8, 0x6

    const/16 v9, 0xc

    invoke-static/range {v1 .. v9}, Llyiahf/vczjk/fa7;->OooO0O0(Llyiahf/vczjk/kl5;JJILlyiahf/vczjk/rf1;II)V

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_4

    :cond_5
    const v0, 0x582cff4d

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit16 p3, p3, 0x3fe

    invoke-static {p0, p1, p2, v7, p3}, Llyiahf/vczjk/tp6;->OooO0o0(Llyiahf/vczjk/r39;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_4
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p3

    if-eqz p3, :cond_6

    new-instance v0, Llyiahf/vczjk/s39;

    const/4 v5, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/s39;-><init>(Llyiahf/vczjk/r39;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;II)V

    iput-object v0, p3, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_6
    return-void
.end method

.method public static final OooO0o0(Llyiahf/vczjk/r39;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 18

    move-object/from16 v1, p0

    move-object/from16 v7, p3

    check-cast v7, Llyiahf/vczjk/zf1;

    const v0, 0x10f5645e

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int v0, p4, v0

    move-object/from16 v2, p1

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    const/16 v4, 0x10

    const/16 v10, 0x20

    if-eqz v3, :cond_1

    move v3, v10

    goto :goto_1

    :cond_1
    move v3, v4

    :goto_1
    or-int/2addr v0, v3

    move-object/from16 v3, p2

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2

    const/16 v5, 0x100

    goto :goto_2

    :cond_2
    const/16 v5, 0x80

    :goto_2
    or-int/2addr v0, v5

    and-int/lit16 v5, v0, 0x93

    const/16 v6, 0x92

    if-ne v5, v6, :cond_4

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_5

    :cond_4
    :goto_3
    sget-object v11, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v12, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    const/16 v5, 0x40

    int-to-float v14, v5

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/4 v13, 0x0

    const/16 v17, 0xd

    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v5

    int-to-float v4, v4

    invoke-static {v5, v4}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    sget-object v6, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    const/16 v8, 0x30

    invoke-static {v6, v5, v7, v8}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v5

    iget v6, v7, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v7, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v9, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_5

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_5
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v7, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v8, v7, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v8, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v8, :cond_6

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_7

    :cond_6
    invoke-static {v6, v7, v6, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_7
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v4, v7, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v4, 0x3f19999a    # 0.6f

    invoke-static {v11, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    const/4 v5, 0x0

    invoke-static {v4, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;Z)Llyiahf/vczjk/kl5;

    move-result-object v4

    const/16 v5, 0x26

    int-to-float v5, v5

    move-object v2, v4

    move v4, v5

    iget-object v5, v1, Llyiahf/vczjk/r39;->OooO0OO:Ljava/util/List;

    new-instance v3, Llyiahf/vczjk/wr0;

    iget-wide v8, v1, Llyiahf/vczjk/r39;->OooO0O0:J

    invoke-static {v8, v9}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    move-result-object v6

    sget-object v8, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v7, v8}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/x21;

    iget-wide v8, v8, Llyiahf/vczjk/x21;->OooOOo0:J

    const/16 v12, 0x18

    int-to-float v12, v12

    invoke-direct {v3, v8, v9, v6, v12}, Llyiahf/vczjk/wr0;-><init>(JLjava/lang/String;F)V

    shl-int/lit8 v0, v0, 0x9

    const v6, 0xe000

    and-int/2addr v6, v0

    const/16 v8, 0x186

    or-int/2addr v6, v8

    const/high16 v8, 0x70000

    and-int/2addr v0, v8

    or-int v9, v6, v0

    move-object/from16 v6, p1

    move-object v8, v7

    move-object/from16 v7, p2

    invoke-static/range {v2 .. v9}, Llyiahf/vczjk/vt6;->OooO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/wr0;FLjava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    move-object v7, v8

    int-to-float v0, v10

    invoke-static {v11, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v7, v2}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const v2, 0x3f4ccccd    # 0.8f

    invoke-static {v11, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/4 v5, 0x0

    iget-object v6, v1, Llyiahf/vczjk/r39;->OooO0OO:Ljava/util/List;

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/16 v8, 0x186

    invoke-static/range {v2 .. v8}, Llyiahf/vczjk/r02;->OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/di6;FLlyiahf/vczjk/tv7;Ljava/util/List;Llyiahf/vczjk/rf1;I)V

    const/4 v0, 0x1

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_5
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_8

    new-instance v0, Llyiahf/vczjk/s39;

    const/4 v5, 0x1

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move/from16 v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/s39;-><init>(Llyiahf/vczjk/r39;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_8
    return-void
.end method

.method public static final OooO0oO(Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 13

    move-object v12, p2

    const-string v0, "onBackPressed"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onItemSelected"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onCenterSelected"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v9, p3

    check-cast v9, Llyiahf/vczjk/zf1;

    const v0, -0x18cf8005

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v9, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int v0, p4, v0

    and-int/lit16 v2, v0, 0x93

    const/16 v3, 0x92

    if-ne v2, v3, :cond_2

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_3

    :cond_2
    :goto_1
    const v2, 0x70b323c8

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-static {v9}, Llyiahf/vczjk/c45;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lha;

    move-result-object v2

    if-eqz v2, :cond_7

    invoke-static {v2, v9}, Llyiahf/vczjk/mc4;->OooOo0O(Llyiahf/vczjk/lha;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/sn3;

    move-result-object v3

    const v4, 0x671a9c9b

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    instance-of v4, v2, Llyiahf/vczjk/om3;

    if-eqz v4, :cond_3

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/om3;

    invoke-interface {v4}, Llyiahf/vczjk/om3;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v4

    goto :goto_2

    :cond_3
    sget-object v4, Llyiahf/vczjk/ms1;->OooO0O0:Llyiahf/vczjk/ms1;

    :goto_2
    const-class v5, Llyiahf/vczjk/w39;

    invoke-static {v5, v2, v3, v4, v9}, Llyiahf/vczjk/eo6;->OooOooO(Ljava/lang/Class;Llyiahf/vczjk/lha;Llyiahf/vczjk/sn3;Llyiahf/vczjk/os1;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/dha;

    move-result-object v2

    const/4 v3, 0x0

    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    check-cast v2, Llyiahf/vczjk/w39;

    iget-object v4, v2, Llyiahf/vczjk/w39;->OooO0Oo:Llyiahf/vczjk/gh7;

    invoke-static {v4, v9}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v4

    const v5, 0x4c5de2

    invoke-virtual {v9, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_4

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v6, v5, :cond_5

    :cond_4
    new-instance v6, Llyiahf/vczjk/t39;

    const/4 v5, 0x0

    invoke-direct {v6, v2, v5}, Llyiahf/vczjk/t39;-><init>(Llyiahf/vczjk/w39;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v9, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v6, Llyiahf/vczjk/ze3;

    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v2, v9, v6}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/cd1;->OooO00o:Llyiahf/vczjk/a91;

    new-instance v2, Llyiahf/vczjk/n6;

    const/16 v3, 0x15

    invoke-direct {v2, v4, p1, p2, v3}, Llyiahf/vczjk/n6;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/cf3;Llyiahf/vczjk/cf3;I)V

    const v3, -0x4db6f6a6

    invoke-static {v3, v2, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    shl-int/lit8 v0, v0, 0xc

    const v2, 0xe000

    and-int/2addr v0, v2

    const v2, 0x6000030

    or-int v10, v0, v2

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v0, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    const/16 v11, 0xed

    move-object v4, p0

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/xr6;->OooO0Oo(Llyiahf/vczjk/hl5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/hb8;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_3
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_6

    new-instance v0, Llyiahf/vczjk/h19;

    const/4 v5, 0x1

    move-object v1, p0

    move-object v2, p1

    move/from16 v4, p4

    move-object v3, v12

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/h19;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_6
    return-void

    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static OooO0oo(IILjava/lang/String;)Ljava/lang/String;
    .locals 0

    if-gez p0, :cond_0

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    filled-new-array {p2, p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string p1, "%s (%s) must not be negative"

    invoke-static {p1, p0}, Llyiahf/vczjk/fu6;->OooOo00(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_0
    if-ltz p1, :cond_1

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    filled-new-array {p2, p0, p1}, [Ljava/lang/Object;

    move-result-object p0

    const-string p1, "%s (%s) must not be greater than size (%s)"

    invoke-static {p1, p0}, Llyiahf/vczjk/fu6;->OooOo00(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p2, "negative size: "

    invoke-static {p1, p2}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooOO0(ILlyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;)Z
    .locals 1

    const/4 v0, 0x3

    if-ne p0, v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x4

    if-ne p0, v0, :cond_1

    :goto_0
    iget p0, p2, Llyiahf/vczjk/wj7;->OooO0O0:F

    iget v0, p1, Llyiahf/vczjk/wj7;->OooO0Oo:F

    cmpl-float p0, v0, p0

    if-lez p0, :cond_3

    iget p0, p1, Llyiahf/vczjk/wj7;->OooO0O0:F

    iget p1, p2, Llyiahf/vczjk/wj7;->OooO0Oo:F

    cmpg-float p0, p0, p1

    if-gez p0, :cond_3

    goto :goto_2

    :cond_1
    const/4 v0, 0x5

    if-ne p0, v0, :cond_2

    goto :goto_1

    :cond_2
    const/4 v0, 0x6

    if-ne p0, v0, :cond_4

    :goto_1
    iget p0, p2, Llyiahf/vczjk/wj7;->OooO00o:F

    iget v0, p1, Llyiahf/vczjk/wj7;->OooO0OO:F

    cmpl-float p0, v0, p0

    if-lez p0, :cond_3

    iget p0, p1, Llyiahf/vczjk/wj7;->OooO00o:F

    iget p1, p2, Llyiahf/vczjk/wj7;->OooO0OO:F

    cmpg-float p0, p0, p1

    if-gez p0, :cond_3

    :goto_2
    const/4 p0, 0x1

    return p0

    :cond_3
    const/4 p0, 0x0

    return p0

    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "This function should only be used for 2-D focus search"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static OooOO0O(ZIIJJIZJJJJ)J
    .locals 3

    const-string v0, "backoffPolicy"

    invoke-static {p2, v0}, Llyiahf/vczjk/u81;->OooOOo(ILjava/lang/String;)V

    const-wide v0, 0x7fffffffffffffffL

    cmp-long v2, p15, v0

    if-eqz v2, :cond_2

    if-eqz p8, :cond_2

    if-nez p7, :cond_0

    goto :goto_0

    :cond_0
    const-wide/32 p0, 0xdbba0

    add-long/2addr p5, p0

    cmp-long p0, p15, p5

    if-gez p0, :cond_1

    return-wide p5

    :cond_1
    :goto_0
    return-wide p15

    :cond_2
    if-eqz p0, :cond_5

    const/4 p0, 0x2

    if-ne p2, p0, :cond_3

    int-to-long p0, p1

    mul-long/2addr p3, p0

    goto :goto_1

    :cond_3
    long-to-float p0, p3

    add-int/lit8 p1, p1, -0x1

    invoke-static {p0, p1}, Ljava/lang/Math;->scalb(FI)F

    move-result p0

    float-to-long p3, p0

    :goto_1
    const-wide/32 p0, 0x112a880

    cmp-long p2, p3, p0

    if-lez p2, :cond_4

    move-wide p3, p0

    :cond_4
    add-long/2addr p5, p3

    return-wide p5

    :cond_5
    if-eqz p8, :cond_8

    if-nez p7, :cond_6

    add-long/2addr p5, p9

    goto :goto_2

    :cond_6
    add-long p5, p5, p13

    :goto_2
    cmp-long p0, p11, p13

    if-eqz p0, :cond_7

    if-nez p7, :cond_7

    sub-long p0, p13, p11

    add-long/2addr p0, p5

    return-wide p0

    :cond_7
    return-wide p5

    :cond_8
    const-wide/16 p0, -0x1

    cmp-long p0, p5, p0

    if-nez p0, :cond_9

    return-wide v0

    :cond_9
    add-long/2addr p5, p9

    return-wide p5
.end method

.method public static OooOO0o(ZLjava/lang/String;Ljava/io/Serializable;)V
    .locals 0

    if-eqz p0, :cond_0

    return-void

    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    filled-new-array {p2}, [Ljava/lang/Object;

    move-result-object p2

    invoke-static {p1, p2}, Llyiahf/vczjk/fu6;->OooOo00(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static OooOOO(II)V
    .locals 2

    if-ltz p0, :cond_0

    if-gt p0, p1, :cond_0

    return-void

    :cond_0
    new-instance v0, Ljava/lang/IndexOutOfBoundsException;

    const-string v1, "index"

    invoke-static {p0, p1, v1}, Llyiahf/vczjk/tp6;->OooO0oo(IILjava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static OooOOO0(II)V
    .locals 2

    if-ltz p0, :cond_1

    if-lt p0, p1, :cond_0

    goto :goto_0

    :cond_0
    return-void

    :cond_1
    :goto_0
    new-instance v0, Ljava/lang/IndexOutOfBoundsException;

    const-string v1, "index"

    if-ltz p0, :cond_3

    if-ltz p1, :cond_2

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    filled-new-array {v1, p0, p1}, [Ljava/lang/Object;

    move-result-object p0

    const-string p1, "%s (%s) must be less than size (%s)"

    invoke-static {p1, p0}, Llyiahf/vczjk/fu6;->OooOo00(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    goto :goto_1

    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string v0, "negative size: "

    invoke-static {p1, v0}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_3
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    filled-new-array {v1, p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string p1, "%s (%s) must not be negative"

    invoke-static {p1, p0}, Llyiahf/vczjk/fu6;->OooOo00(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    :goto_1
    invoke-direct {v0, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static OooOOOO(III)V
    .locals 1

    if-ltz p0, :cond_1

    if-lt p1, p0, :cond_1

    if-le p1, p2, :cond_0

    goto :goto_0

    :cond_0
    return-void

    :cond_1
    :goto_0
    new-instance v0, Ljava/lang/IndexOutOfBoundsException;

    if-ltz p0, :cond_4

    if-gt p0, p2, :cond_4

    if-ltz p1, :cond_3

    if-le p1, p2, :cond_2

    goto :goto_1

    :cond_2
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    filled-new-array {p1, p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string p1, "end index (%s) must not be less than start index (%s)"

    invoke-static {p1, p0}, Llyiahf/vczjk/fu6;->OooOo00(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    goto :goto_2

    :cond_3
    :goto_1
    const-string p0, "end index"

    invoke-static {p1, p2, p0}, Llyiahf/vczjk/tp6;->OooO0oo(IILjava/lang/String;)Ljava/lang/String;

    move-result-object p0

    goto :goto_2

    :cond_4
    const-string p1, "start index"

    invoke-static {p0, p2, p1}, Llyiahf/vczjk/tp6;->OooO0oo(IILjava/lang/String;)Ljava/lang/String;

    move-result-object p0

    :goto_2
    invoke-direct {v0, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static final OooOOOo(Llyiahf/vczjk/d93;Llyiahf/vczjk/ws5;)V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v0, v0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    const-string v0, "visitChildren called on an unattached node"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    new-instance v0, Llyiahf/vczjk/ws5;

    const/16 v1, 0x10

    new-array v2, v1, [Llyiahf/vczjk/jl5;

    invoke-direct {v0, v2}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iget-object p0, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-object v2, p0, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    if-nez v2, :cond_1

    invoke-static {v0, p0}, Llyiahf/vczjk/yi4;->OooOOoo(Llyiahf/vczjk/ws5;Llyiahf/vczjk/jl5;)V

    goto :goto_0

    :cond_1
    invoke-virtual {v0, v2}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_2
    :goto_0
    iget p0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    if-eqz p0, :cond_e

    add-int/lit8 p0, p0, -0x1

    invoke-virtual {v0, p0}, Llyiahf/vczjk/ws5;->OooOO0O(I)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/jl5;

    iget v2, p0, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/lit16 v2, v2, 0x400

    if-nez v2, :cond_3

    invoke-static {v0, p0}, Llyiahf/vczjk/yi4;->OooOOoo(Llyiahf/vczjk/ws5;Llyiahf/vczjk/jl5;)V

    goto :goto_0

    :cond_3
    :goto_1
    if-eqz p0, :cond_2

    iget v2, p0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v2, v2, 0x400

    if-eqz v2, :cond_d

    const/4 v2, 0x0

    move-object v3, v2

    :goto_2
    if-eqz p0, :cond_2

    instance-of v4, p0, Llyiahf/vczjk/d93;

    if-eqz v4, :cond_6

    check-cast p0, Llyiahf/vczjk/d93;

    iget-boolean v4, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v4, :cond_c

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v4

    iget-boolean v4, v4, Llyiahf/vczjk/ro4;->Ooooo00:Z

    if-eqz v4, :cond_4

    goto :goto_5

    :cond_4
    invoke-virtual {p0}, Llyiahf/vczjk/d93;->o00000Oo()Llyiahf/vczjk/t83;

    move-result-object v4

    iget-boolean v4, v4, Llyiahf/vczjk/t83;->OooO00o:Z

    if-eqz v4, :cond_5

    invoke-virtual {p1, p0}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    goto :goto_5

    :cond_5
    invoke-static {p0, p1}, Llyiahf/vczjk/tp6;->OooOOOo(Llyiahf/vczjk/d93;Llyiahf/vczjk/ws5;)V

    goto :goto_5

    :cond_6
    iget v4, p0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v4, v4, 0x400

    if-eqz v4, :cond_c

    instance-of v4, p0, Llyiahf/vczjk/m52;

    if-eqz v4, :cond_c

    move-object v4, p0

    check-cast v4, Llyiahf/vczjk/m52;

    iget-object v4, v4, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    const/4 v5, 0x0

    :goto_3
    const/4 v6, 0x1

    if-eqz v4, :cond_b

    iget v7, v4, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v7, v7, 0x400

    if-eqz v7, :cond_a

    add-int/lit8 v5, v5, 0x1

    if-ne v5, v6, :cond_7

    move-object p0, v4

    goto :goto_4

    :cond_7
    if-nez v3, :cond_8

    new-instance v3, Llyiahf/vczjk/ws5;

    new-array v6, v1, [Llyiahf/vczjk/jl5;

    invoke-direct {v3, v6}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_8
    if-eqz p0, :cond_9

    invoke-virtual {v3, p0}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object p0, v2

    :cond_9
    invoke-virtual {v3, v4}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_a
    :goto_4
    iget-object v4, v4, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_3

    :cond_b
    if-ne v5, v6, :cond_c

    goto :goto_2

    :cond_c
    :goto_5
    invoke-static {v3}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object p0

    goto :goto_2

    :cond_d
    iget-object p0, p0, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_1

    :cond_e
    return-void
.end method

.method public static OooOOo0(Landroid/content/ComponentName;)[Ljava/lang/String;
    .locals 2

    if-nez p0, :cond_0

    const/4 p0, 0x0

    new-array p0, p0, [Ljava/lang/String;

    return-object p0

    :cond_0
    invoke-virtual {p0}, Landroid/content/ComponentName;->flattenToShortString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "KEEP "

    invoke-static {v1, v0}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0}, Landroid/content/ComponentName;->flattenToString()Ljava/lang/String;

    move-result-object p0

    invoke-static {v1, p0}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    filled-new-array {v0, p0}, [Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOo(Llyiahf/vczjk/sd9;)Llyiahf/vczjk/xr1;
    .locals 6

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-boolean v0, p0, Llyiahf/vczjk/sd9;->OooO0oo:Z

    if-eqz v0, :cond_2

    const-string v0, "systemServiceScope"

    iget-object v1, p0, Llyiahf/vczjk/sd9;->OooO0o0:Ljava/util/LinkedHashMap;

    monitor-enter v1

    :try_start_0
    iget-object v2, p0, Llyiahf/vczjk/sd9;->OooO0o0:Ljava/util/LinkedHashMap;

    invoke-virtual {v2, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    monitor-exit v1

    check-cast v2, Llyiahf/vczjk/xr1;

    if-eqz v2, :cond_0

    return-object v2

    :cond_0
    invoke-static {}, Llyiahf/vczjk/vl6;->OooO0O0()Llyiahf/vczjk/u99;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/sd9;->OooO0o:Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/os/Handler;

    const-string v3, "<get-handler>(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "HD#Scope"

    sget v4, Llyiahf/vczjk/yl3;->OooO00o:I

    new-instance v4, Llyiahf/vczjk/xl3;

    const/4 v5, 0x0

    invoke-direct {v4, v2, v3, v5}, Llyiahf/vczjk/xl3;-><init>(Landroid/os/Handler;Ljava/lang/String;Z)V

    invoke-static {v1, v4}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooO0oO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/to1;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/sd9;->OooO0o0:Ljava/util/LinkedHashMap;

    monitor-enter v2

    :try_start_1
    iget-object v3, p0, Llyiahf/vczjk/sd9;->OooO0o0:Ljava/util/LinkedHashMap;

    invoke-interface {v3, v0}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_1

    iget-object p0, p0, Llyiahf/vczjk/sd9;->OooO0o0:Ljava/util/LinkedHashMap;

    invoke-interface {p0, v0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :cond_1
    :goto_0
    monitor-exit v2

    return-object v1

    :goto_1
    monitor-exit v2

    throw p0

    :catchall_1
    move-exception p0

    monitor-exit v1

    throw p0

    :cond_2
    const-string p0, "Trying to access systemServiceScope[- Service] before System started!"

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static final OooOo0(Llyiahf/vczjk/d93;ILlyiahf/vczjk/oe3;)Z
    .locals 4

    new-instance v0, Llyiahf/vczjk/ws5;

    const/16 v1, 0x10

    new-array v1, v1, [Llyiahf/vczjk/d93;

    invoke-direct {v0, v1}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    invoke-static {p0, v0}, Llyiahf/vczjk/tp6;->OooOOOo(Llyiahf/vczjk/d93;Llyiahf/vczjk/ws5;)V

    iget v1, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-gt v1, v2, :cond_1

    if-nez v1, :cond_0

    const/4 p0, 0x0

    goto :goto_0

    :cond_0
    iget-object p0, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object p0, p0, v3

    :goto_0
    check-cast p0, Llyiahf/vczjk/d93;

    if-eqz p0, :cond_6

    invoke-interface {p2, p0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Boolean;

    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p0

    return p0

    :cond_1
    const/4 v1, 0x7

    const/4 v2, 0x4

    if-ne p1, v1, :cond_2

    move p1, v2

    :cond_2
    if-ne p1, v2, :cond_3

    goto :goto_1

    :cond_3
    const/4 v1, 0x6

    if-ne p1, v1, :cond_4

    :goto_1
    invoke-static {p0}, Llyiahf/vczjk/sb;->OooOoOO(Llyiahf/vczjk/d93;)Llyiahf/vczjk/wj7;

    move-result-object p0

    new-instance v1, Llyiahf/vczjk/wj7;

    iget v2, p0, Llyiahf/vczjk/wj7;->OooO0O0:F

    iget p0, p0, Llyiahf/vczjk/wj7;->OooO00o:F

    invoke-direct {v1, p0, v2, p0, v2}, Llyiahf/vczjk/wj7;-><init>(FFFF)V

    goto :goto_3

    :cond_4
    const/4 v1, 0x3

    if-ne p1, v1, :cond_5

    goto :goto_2

    :cond_5
    const/4 v1, 0x5

    if-ne p1, v1, :cond_7

    :goto_2
    invoke-static {p0}, Llyiahf/vczjk/sb;->OooOoOO(Llyiahf/vczjk/d93;)Llyiahf/vczjk/wj7;

    move-result-object p0

    new-instance v1, Llyiahf/vczjk/wj7;

    iget v2, p0, Llyiahf/vczjk/wj7;->OooO0Oo:F

    iget p0, p0, Llyiahf/vczjk/wj7;->OooO0OO:F

    invoke-direct {v1, p0, v2, p0, v2}, Llyiahf/vczjk/wj7;-><init>(FFFF)V

    :goto_3
    invoke-static {v0, v1, p1}, Llyiahf/vczjk/tp6;->OooOo00(Llyiahf/vczjk/ws5;Llyiahf/vczjk/wj7;I)Llyiahf/vczjk/d93;

    move-result-object p0

    if-eqz p0, :cond_6

    invoke-interface {p2, p0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Boolean;

    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p0

    return p0

    :cond_6
    return v3

    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "This function should only be used for 2-D focus search"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooOo00(Llyiahf/vczjk/ws5;Llyiahf/vczjk/wj7;I)Llyiahf/vczjk/d93;
    .locals 7

    const/4 v0, 0x3

    const/4 v1, 0x1

    const/4 v2, 0x0

    if-ne p2, v0, :cond_0

    iget v0, p1, Llyiahf/vczjk/wj7;->OooO0OO:F

    iget v3, p1, Llyiahf/vczjk/wj7;->OooO00o:F

    sub-float/2addr v0, v3

    int-to-float v1, v1

    add-float/2addr v0, v1

    invoke-virtual {p1, v0, v2}, Llyiahf/vczjk/wj7;->OooO0oo(FF)Llyiahf/vczjk/wj7;

    move-result-object v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x4

    if-ne p2, v0, :cond_1

    iget v0, p1, Llyiahf/vczjk/wj7;->OooO0OO:F

    iget v3, p1, Llyiahf/vczjk/wj7;->OooO00o:F

    sub-float/2addr v0, v3

    int-to-float v1, v1

    add-float/2addr v0, v1

    neg-float v0, v0

    invoke-virtual {p1, v0, v2}, Llyiahf/vczjk/wj7;->OooO0oo(FF)Llyiahf/vczjk/wj7;

    move-result-object v0

    goto :goto_0

    :cond_1
    const/4 v0, 0x5

    if-ne p2, v0, :cond_2

    iget v0, p1, Llyiahf/vczjk/wj7;->OooO0Oo:F

    iget v3, p1, Llyiahf/vczjk/wj7;->OooO0O0:F

    sub-float/2addr v0, v3

    int-to-float v1, v1

    add-float/2addr v0, v1

    invoke-virtual {p1, v2, v0}, Llyiahf/vczjk/wj7;->OooO0oo(FF)Llyiahf/vczjk/wj7;

    move-result-object v0

    goto :goto_0

    :cond_2
    const/4 v0, 0x6

    if-ne p2, v0, :cond_5

    iget v0, p1, Llyiahf/vczjk/wj7;->OooO0Oo:F

    iget v3, p1, Llyiahf/vczjk/wj7;->OooO0O0:F

    sub-float/2addr v0, v3

    int-to-float v1, v1

    add-float/2addr v0, v1

    neg-float v0, v0

    invoke-virtual {p1, v2, v0}, Llyiahf/vczjk/wj7;->OooO0oo(FF)Llyiahf/vczjk/wj7;

    move-result-object v0

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget p0, p0, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v2, 0x0

    const/4 v3, 0x0

    :goto_1
    if-ge v3, p0, :cond_4

    aget-object v4, v1, v3

    check-cast v4, Llyiahf/vczjk/d93;

    invoke-static {v4}, Llyiahf/vczjk/sb;->Oooo0(Llyiahf/vczjk/d93;)Z

    move-result v5

    if-eqz v5, :cond_3

    invoke-static {v4}, Llyiahf/vczjk/sb;->OooOoOO(Llyiahf/vczjk/d93;)Llyiahf/vczjk/wj7;

    move-result-object v5

    invoke-static {v5, v0, p1, p2}, Llyiahf/vczjk/tp6;->OooOoO(Llyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;I)Z

    move-result v6

    if-eqz v6, :cond_3

    move-object v2, v4

    move-object v0, v5

    :cond_3
    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_4
    return-object v2

    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "This function should only be used for 2-D focus search"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooOo0O(Llyiahf/vczjk/d93;Llyiahf/vczjk/wj7;ILlyiahf/vczjk/oe3;)Z
    .locals 8

    invoke-static {p0, p1, p2, p3}, Llyiahf/vczjk/tp6;->Oooo00O(Llyiahf/vczjk/d93;Llyiahf/vczjk/wj7;ILlyiahf/vczjk/oe3;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getFocusOwner()Llyiahf/vczjk/m83;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/r83;

    iget-object v2, v0, Llyiahf/vczjk/r83;->OooO0oo:Llyiahf/vczjk/f93;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getFocusOwner()Llyiahf/vczjk/m83;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/r83;

    iget-object v3, v0, Llyiahf/vczjk/r83;->OooOO0o:Llyiahf/vczjk/d93;

    new-instance v1, Llyiahf/vczjk/k1a;

    move-object v4, p0

    move-object v5, p1

    move v6, p2

    move-object v7, p3

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/k1a;-><init>(Llyiahf/vczjk/f93;Llyiahf/vczjk/d93;Llyiahf/vczjk/d93;Llyiahf/vczjk/wj7;ILlyiahf/vczjk/oe3;)V

    invoke-static {v4, v6, v1}, Llyiahf/vczjk/tg0;->Oooo0O0(Llyiahf/vczjk/d93;ILlyiahf/vczjk/oe3;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Boolean;

    if-eqz p0, :cond_1

    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p0

    return p0

    :cond_1
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOo0o(Ljava/util/List;)V
    .locals 1

    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-nez v0, :cond_0

    return-void

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/q99;->OooO0o0(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    move-result-object p0

    throw p0
.end method

.method public static final OooOoO(Llyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;I)Z
    .locals 2

    invoke-static {p3, p0, p2}, Llyiahf/vczjk/tp6;->OooOoOO(ILlyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;)Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    invoke-static {p3, p1, p2}, Llyiahf/vczjk/tp6;->OooOoOO(ILlyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;)Z

    move-result v0

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    invoke-static {p2, p0, p1, p3}, Llyiahf/vczjk/tp6;->OooO(Llyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;I)Z

    move-result v0

    if-eqz v0, :cond_2

    goto :goto_0

    :cond_2
    invoke-static {p2, p1, p0, p3}, Llyiahf/vczjk/tp6;->OooO(Llyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;I)Z

    move-result v0

    if-eqz v0, :cond_3

    goto :goto_1

    :cond_3
    invoke-static {p3, p2, p0}, Llyiahf/vczjk/tp6;->OooOoo0(ILlyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;)J

    move-result-wide v0

    invoke-static {p3, p2, p1}, Llyiahf/vczjk/tp6;->OooOoo0(ILlyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;)J

    move-result-wide p0

    cmp-long p0, v0, p0

    if-gez p0, :cond_4

    :goto_0
    const/4 p0, 0x1

    return p0

    :cond_4
    :goto_1
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOoO0(Landroidx/appcompat/widget/AppCompatTextView;)Llyiahf/vczjk/t07;
    .locals 8

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1c

    if-lt v0, v1, :cond_0

    new-instance v0, Llyiahf/vczjk/t07;

    invoke-static {p0}, Llyiahf/vczjk/wo;->OooOo0(Landroidx/appcompat/widget/AppCompatTextView;)Landroid/text/PrecomputedText$Params;

    move-result-object p0

    invoke-direct {v0, p0}, Llyiahf/vczjk/t07;-><init>(Landroid/text/PrecomputedText$Params;)V

    return-object v0

    :cond_0
    new-instance v2, Landroid/text/TextPaint;

    invoke-virtual {p0}, Landroid/widget/TextView;->getPaint()Landroid/text/TextPaint;

    move-result-object v3

    invoke-direct {v2, v3}, Landroid/text/TextPaint;-><init>(Landroid/graphics/Paint;)V

    sget-object v3, Landroid/text/TextDirectionHeuristics;->FIRSTSTRONG_LTR:Landroid/text/TextDirectionHeuristic;

    invoke-virtual {p0}, Landroid/widget/TextView;->getBreakStrategy()I

    move-result v4

    invoke-virtual {p0}, Landroid/widget/TextView;->getHyphenationFrequency()I

    move-result v5

    invoke-virtual {p0}, Landroid/widget/TextView;->getTransformationMethod()Landroid/text/method/TransformationMethod;

    move-result-object v6

    instance-of v6, v6, Landroid/text/method/PasswordTransformationMethod;

    if-eqz v6, :cond_1

    sget-object v3, Landroid/text/TextDirectionHeuristics;->LTR:Landroid/text/TextDirectionHeuristic;

    goto :goto_2

    :cond_1
    const/4 v6, 0x1

    const/4 v7, 0x0

    if-lt v0, v1, :cond_4

    invoke-virtual {p0}, Landroid/widget/TextView;->getInputType()I

    move-result v0

    and-int/lit8 v0, v0, 0xf

    const/4 v1, 0x3

    if-ne v0, v1, :cond_4

    invoke-virtual {p0}, Landroid/widget/TextView;->getTextLocale()Ljava/util/Locale;

    move-result-object p0

    invoke-static {p0}, Landroid/icu/text/DecimalFormatSymbols;->getInstance(Ljava/util/Locale;)Landroid/icu/text/DecimalFormatSymbols;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/wo;->OooO0oo(Landroid/icu/text/DecimalFormatSymbols;)[Ljava/lang/String;

    move-result-object p0

    aget-object p0, p0, v7

    invoke-virtual {p0, v7}, Ljava/lang/String;->codePointAt(I)I

    move-result p0

    invoke-static {p0}, Ljava/lang/Character;->getDirectionality(I)B

    move-result p0

    if-eq p0, v6, :cond_3

    const/4 v0, 0x2

    if-ne p0, v0, :cond_2

    goto :goto_0

    :cond_2
    sget-object v3, Landroid/text/TextDirectionHeuristics;->LTR:Landroid/text/TextDirectionHeuristic;

    goto :goto_2

    :cond_3
    :goto_0
    sget-object v3, Landroid/text/TextDirectionHeuristics;->RTL:Landroid/text/TextDirectionHeuristic;

    goto :goto_2

    :cond_4
    invoke-virtual {p0}, Landroid/view/View;->getLayoutDirection()I

    move-result v0

    if-ne v0, v6, :cond_5

    goto :goto_1

    :cond_5
    move v6, v7

    :goto_1
    invoke-virtual {p0}, Landroid/view/View;->getTextDirection()I

    move-result p0

    packed-switch p0, :pswitch_data_0

    if-eqz v6, :cond_6

    sget-object v3, Landroid/text/TextDirectionHeuristics;->FIRSTSTRONG_RTL:Landroid/text/TextDirectionHeuristic;

    goto :goto_2

    :pswitch_0
    sget-object v3, Landroid/text/TextDirectionHeuristics;->FIRSTSTRONG_RTL:Landroid/text/TextDirectionHeuristic;

    goto :goto_2

    :pswitch_1
    sget-object v3, Landroid/text/TextDirectionHeuristics;->LOCALE:Landroid/text/TextDirectionHeuristic;

    goto :goto_2

    :pswitch_2
    sget-object v3, Landroid/text/TextDirectionHeuristics;->RTL:Landroid/text/TextDirectionHeuristic;

    goto :goto_2

    :pswitch_3
    sget-object v3, Landroid/text/TextDirectionHeuristics;->LTR:Landroid/text/TextDirectionHeuristic;

    goto :goto_2

    :pswitch_4
    sget-object v3, Landroid/text/TextDirectionHeuristics;->ANYRTL_LTR:Landroid/text/TextDirectionHeuristic;

    :cond_6
    :goto_2
    :pswitch_5
    new-instance p0, Llyiahf/vczjk/t07;

    invoke-direct {p0, v2, v3, v4, v5}, Llyiahf/vczjk/t07;-><init>(Landroid/text/TextPaint;Landroid/text/TextDirectionHeuristic;II)V

    return-object p0

    nop

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_5
        :pswitch_0
    .end packed-switch
.end method

.method public static final OooOoOO(ILlyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;)Z
    .locals 3

    const/4 v0, 0x3

    iget v1, p1, Llyiahf/vczjk/wj7;->OooO00o:F

    iget v2, p1, Llyiahf/vczjk/wj7;->OooO0OO:F

    if-ne p0, v0, :cond_1

    iget p0, p2, Llyiahf/vczjk/wj7;->OooO0OO:F

    cmpl-float p0, p0, v2

    iget p1, p2, Llyiahf/vczjk/wj7;->OooO00o:F

    if-gtz p0, :cond_0

    cmpl-float p0, p1, v2

    if-ltz p0, :cond_7

    :cond_0
    cmpl-float p0, p1, v1

    if-lez p0, :cond_7

    goto :goto_0

    :cond_1
    const/4 v0, 0x4

    if-ne p0, v0, :cond_3

    iget p0, p2, Llyiahf/vczjk/wj7;->OooO00o:F

    cmpg-float p0, p0, v1

    iget p1, p2, Llyiahf/vczjk/wj7;->OooO0OO:F

    if-ltz p0, :cond_2

    cmpg-float p0, p1, v1

    if-gtz p0, :cond_7

    :cond_2
    cmpg-float p0, p1, v2

    if-gez p0, :cond_7

    goto :goto_0

    :cond_3
    const/4 v0, 0x5

    iget v1, p1, Llyiahf/vczjk/wj7;->OooO0O0:F

    iget p1, p1, Llyiahf/vczjk/wj7;->OooO0Oo:F

    if-ne p0, v0, :cond_5

    iget p0, p2, Llyiahf/vczjk/wj7;->OooO0Oo:F

    cmpl-float p0, p0, p1

    iget p2, p2, Llyiahf/vczjk/wj7;->OooO0O0:F

    if-gtz p0, :cond_4

    cmpl-float p0, p2, p1

    if-ltz p0, :cond_7

    :cond_4
    cmpl-float p0, p2, v1

    if-lez p0, :cond_7

    goto :goto_0

    :cond_5
    const/4 v0, 0x6

    if-ne p0, v0, :cond_8

    iget p0, p2, Llyiahf/vczjk/wj7;->OooO0O0:F

    cmpg-float p0, p0, v1

    iget p2, p2, Llyiahf/vczjk/wj7;->OooO0Oo:F

    if-ltz p0, :cond_6

    cmpg-float p0, p2, v1

    if-gtz p0, :cond_7

    :cond_6
    cmpg-float p0, p2, p1

    if-gez p0, :cond_7

    :goto_0
    const/4 p0, 0x1

    return p0

    :cond_7
    const/4 p0, 0x0

    return p0

    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "This function should only be used for 2-D focus search"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static OooOoo(ILjava/lang/CharSequence;)Z
    .locals 1

    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    move-result v0

    if-ge p0, v0, :cond_0

    invoke-interface {p1, p0}, Ljava/lang/CharSequence;->charAt(I)C

    move-result p0

    packed-switch p0, :pswitch_data_0

    packed-switch p0, :pswitch_data_1

    packed-switch p0, :pswitch_data_2

    packed-switch p0, :pswitch_data_3

    goto :goto_0

    :pswitch_0
    const/4 p0, 0x1

    return p0

    :cond_0
    :goto_0
    const/4 p0, 0x0

    return p0

    nop

    :pswitch_data_0
    .packed-switch 0x21
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch

    :pswitch_data_1
    .packed-switch 0x3a
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch

    :pswitch_data_2
    .packed-switch 0x5b
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch

    :pswitch_data_3
    .packed-switch 0x7b
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public static final OooOoo0(ILlyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;)J
    .locals 11

    iget v0, p2, Llyiahf/vczjk/wj7;->OooO0O0:F

    iget v1, p2, Llyiahf/vczjk/wj7;->OooO0Oo:F

    iget v2, p2, Llyiahf/vczjk/wj7;->OooO00o:F

    iget p2, p2, Llyiahf/vczjk/wj7;->OooO0OO:F

    const-string v3, "This function should only be used for 2-D focus search"

    const/4 v4, 0x6

    const/4 v5, 0x5

    const/4 v6, 0x4

    const/4 v7, 0x3

    if-ne p0, v7, :cond_0

    iget v8, p1, Llyiahf/vczjk/wj7;->OooO00o:F

    sub-float/2addr v8, p2

    goto :goto_0

    :cond_0
    if-ne p0, v6, :cond_1

    iget v8, p1, Llyiahf/vczjk/wj7;->OooO0OO:F

    sub-float v8, v2, v8

    goto :goto_0

    :cond_1
    if-ne p0, v5, :cond_2

    iget v8, p1, Llyiahf/vczjk/wj7;->OooO0O0:F

    sub-float/2addr v8, v1

    goto :goto_0

    :cond_2
    if-ne p0, v4, :cond_8

    iget v8, p1, Llyiahf/vczjk/wj7;->OooO0Oo:F

    sub-float v8, v0, v8

    :goto_0
    const/4 v9, 0x0

    cmpg-float v10, v8, v9

    if-gez v10, :cond_3

    move v8, v9

    :cond_3
    float-to-long v8, v8

    const/4 v10, 0x2

    if-ne p0, v7, :cond_4

    goto :goto_1

    :cond_4
    if-ne p0, v6, :cond_5

    :goto_1
    iget p0, p1, Llyiahf/vczjk/wj7;->OooO0Oo:F

    iget p1, p1, Llyiahf/vczjk/wj7;->OooO0O0:F

    sub-float/2addr p0, p1

    int-to-float p2, v10

    div-float/2addr p0, p2

    add-float/2addr p0, p1

    sub-float/2addr v1, v0

    div-float/2addr v1, p2

    add-float/2addr v1, v0

    sub-float/2addr p0, v1

    goto :goto_3

    :cond_5
    if-ne p0, v5, :cond_6

    goto :goto_2

    :cond_6
    if-ne p0, v4, :cond_7

    :goto_2
    iget p0, p1, Llyiahf/vczjk/wj7;->OooO0OO:F

    iget p1, p1, Llyiahf/vczjk/wj7;->OooO00o:F

    sub-float/2addr p0, p1

    int-to-float v0, v10

    div-float/2addr p0, v0

    add-float/2addr p0, p1

    sub-float/2addr p2, v2

    div-float/2addr p2, v0

    add-float/2addr p2, v2

    sub-float/2addr p0, p2

    :goto_3
    float-to-long p0, p0

    const/16 p2, 0xd

    int-to-long v0, p2

    mul-long/2addr v0, v8

    mul-long/2addr v0, v8

    mul-long/2addr p0, p0

    add-long/2addr p0, v0

    return-wide p0

    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooOooO(Ljava/lang/String;)V
    .locals 3

    const-string v0, "key"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "No valid saved state was found for the key \'"

    const-string v2, "\'. It may be missing, null, or not of the expected type. This can occur if the value was saved with a different type or if the saved state was modified unexpectedly."

    invoke-static {v1, p0, v2}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static OooOooo(Llyiahf/vczjk/xr1;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;
    .locals 4

    sget-object v0, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    sget-object v1, Llyiahf/vczjk/as1;->OooOOO0:Llyiahf/vczjk/as1;

    const-string v2, "<this>"

    invoke-static {p0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/vd9;

    const/4 v3, 0x0

    invoke-direct {v2, p1, v3}, Llyiahf/vczjk/vd9;-><init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    invoke-static {p0, v0, v1, v2}, Llyiahf/vczjk/os9;->Oooo0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    move-result-object p0

    return-object p0
.end method

.method public static Oooo(Landroid/view/ActionMode$Callback;)Landroid/view/ActionMode$Callback;
    .locals 2

    instance-of v0, p0, Llyiahf/vczjk/wn9;

    if-eqz v0, :cond_0

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1a

    if-lt v0, v1, :cond_0

    check-cast p0, Llyiahf/vczjk/wn9;

    iget-object p0, p0, Llyiahf/vczjk/wn9;->OooO00o:Landroid/view/ActionMode$Callback;

    :cond_0
    return-object p0
.end method

.method public static Oooo0(Landroid/widget/TextView;I)V
    .locals 3

    invoke-static {p1}, Llyiahf/vczjk/br6;->OooOOO0(I)V

    invoke-virtual {p0}, Landroid/widget/TextView;->getPaint()Landroid/text/TextPaint;

    move-result-object v0

    invoke-virtual {v0}, Landroid/graphics/Paint;->getFontMetricsInt()Landroid/graphics/Paint$FontMetricsInt;

    move-result-object v0

    invoke-virtual {p0}, Landroid/widget/TextView;->getIncludeFontPadding()Z

    move-result v1

    if-eqz v1, :cond_0

    iget v0, v0, Landroid/graphics/Paint$FontMetricsInt;->bottom:I

    goto :goto_0

    :cond_0
    iget v0, v0, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    :goto_0
    invoke-static {v0}, Ljava/lang/Math;->abs(I)I

    move-result v1

    if-le p1, v1, :cond_1

    sub-int/2addr p1, v0

    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    move-result v0

    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    move-result v1

    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    move-result v2

    invoke-virtual {p0, v0, v1, v2, p1}, Landroid/widget/TextView;->setPadding(IIII)V

    :cond_1
    return-void
.end method

.method public static final Oooo000(Llyiahf/vczjk/le3;)Ljava/lang/Object;
    .locals 5

    invoke-static {}, Landroid/os/Binder;->clearCallingIdentity()J

    move-result-wide v0

    :try_start_0
    invoke-interface {p0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    invoke-static {p0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p0

    :goto_0
    invoke-static {p0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v2

    if-nez v2, :cond_0

    invoke-static {v0, v1}, Landroid/os/Binder;->restoreCallingIdentity(J)V

    goto :goto_1

    :cond_0
    new-instance p0, Lgithub/tornaco/android/thanos/core/Logger;

    const/4 v3, 0x0

    const/4 v4, 0x1

    invoke-direct {p0, v3, v4, v3}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;ILlyiahf/vczjk/n12;)V

    const-string v4, "runClearCallingIdentity"

    invoke-virtual {p0, v2, v4}, Lgithub/tornaco/android/thanos/core/Logger;->e(Ljava/lang/Throwable;Ljava/lang/Object;)V

    invoke-static {v0, v1}, Landroid/os/Binder;->restoreCallingIdentity(J)V

    move-object p0, v3

    :goto_1
    return-object p0
.end method

.method public static final Oooo00O(Llyiahf/vczjk/d93;Llyiahf/vczjk/wj7;ILlyiahf/vczjk/oe3;)Z
    .locals 10

    new-instance v0, Llyiahf/vczjk/ws5;

    const/16 v1, 0x10

    new-array v2, v1, [Llyiahf/vczjk/d93;

    invoke-direct {v0, v2}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iget-object v2, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v2, v2, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v2, :cond_0

    const-string v2, "visitChildren called on an unattached node"

    invoke-static {v2}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    new-instance v2, Llyiahf/vczjk/ws5;

    new-array v3, v1, [Llyiahf/vczjk/jl5;

    invoke-direct {v2, v3}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iget-object p0, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-object v3, p0, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    if-nez v3, :cond_1

    invoke-static {v2, p0}, Llyiahf/vczjk/yi4;->OooOOoo(Llyiahf/vczjk/ws5;Llyiahf/vczjk/jl5;)V

    goto :goto_0

    :cond_1
    invoke-virtual {v2, v3}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_2
    :goto_0
    iget p0, v2, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v3, 0x1

    const/4 v4, 0x0

    if-eqz p0, :cond_c

    add-int/lit8 p0, p0, -0x1

    invoke-virtual {v2, p0}, Llyiahf/vczjk/ws5;->OooOO0O(I)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/jl5;

    iget v5, p0, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/lit16 v5, v5, 0x400

    if-nez v5, :cond_3

    invoke-static {v2, p0}, Llyiahf/vczjk/yi4;->OooOOoo(Llyiahf/vczjk/ws5;Llyiahf/vczjk/jl5;)V

    goto :goto_0

    :cond_3
    :goto_1
    if-eqz p0, :cond_2

    iget v5, p0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v5, v5, 0x400

    if-eqz v5, :cond_b

    const/4 v5, 0x0

    move-object v6, v5

    :goto_2
    if-eqz p0, :cond_2

    instance-of v7, p0, Llyiahf/vczjk/d93;

    if-eqz v7, :cond_4

    check-cast p0, Llyiahf/vczjk/d93;

    iget-boolean v7, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v7, :cond_a

    invoke-virtual {v0, p0}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    goto :goto_5

    :cond_4
    iget v7, p0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v7, v7, 0x400

    if-eqz v7, :cond_a

    instance-of v7, p0, Llyiahf/vczjk/m52;

    if-eqz v7, :cond_a

    move-object v7, p0

    check-cast v7, Llyiahf/vczjk/m52;

    iget-object v7, v7, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    move v8, v4

    :goto_3
    if-eqz v7, :cond_9

    iget v9, v7, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v9, v9, 0x400

    if-eqz v9, :cond_8

    add-int/lit8 v8, v8, 0x1

    if-ne v8, v3, :cond_5

    move-object p0, v7

    goto :goto_4

    :cond_5
    if-nez v6, :cond_6

    new-instance v6, Llyiahf/vczjk/ws5;

    new-array v9, v1, [Llyiahf/vczjk/jl5;

    invoke-direct {v6, v9}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_6
    if-eqz p0, :cond_7

    invoke-virtual {v6, p0}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object p0, v5

    :cond_7
    invoke-virtual {v6, v7}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_8
    :goto_4
    iget-object v7, v7, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_3

    :cond_9
    if-ne v8, v3, :cond_a

    goto :goto_2

    :cond_a
    :goto_5
    invoke-static {v6}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object p0

    goto :goto_2

    :cond_b
    iget-object p0, p0, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_1

    :cond_c
    :goto_6
    iget p0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    if-eqz p0, :cond_10

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/tp6;->OooOo00(Llyiahf/vczjk/ws5;Llyiahf/vczjk/wj7;I)Llyiahf/vczjk/d93;

    move-result-object p0

    if-nez p0, :cond_d

    goto :goto_7

    :cond_d
    invoke-virtual {p0}, Llyiahf/vczjk/d93;->o00000Oo()Llyiahf/vczjk/t83;

    move-result-object v1

    iget-boolean v1, v1, Llyiahf/vczjk/t83;->OooO00o:Z

    if-eqz v1, :cond_e

    invoke-interface {p3, p0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Boolean;

    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p0

    return p0

    :cond_e
    invoke-static {p0, p1, p2, p3}, Llyiahf/vczjk/tp6;->OooOo0O(Llyiahf/vczjk/d93;Llyiahf/vczjk/wj7;ILlyiahf/vczjk/oe3;)Z

    move-result v1

    if-eqz v1, :cond_f

    return v3

    :cond_f
    invoke-virtual {v0, p0}, Llyiahf/vczjk/ws5;->OooOO0(Ljava/lang/Object;)Z

    goto :goto_6

    :cond_10
    :goto_7
    return v4
.end method

.method public static Oooo00o(Landroid/widget/TextView;I)V
    .locals 3

    invoke-static {p1}, Llyiahf/vczjk/br6;->OooOOO0(I)V

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1c

    if-lt v0, v1, :cond_0

    invoke-static {p0, p1}, Llyiahf/vczjk/wo;->OooOo0o(Landroid/widget/TextView;I)V

    return-void

    :cond_0
    invoke-virtual {p0}, Landroid/widget/TextView;->getPaint()Landroid/text/TextPaint;

    move-result-object v0

    invoke-virtual {v0}, Landroid/graphics/Paint;->getFontMetricsInt()Landroid/graphics/Paint$FontMetricsInt;

    move-result-object v0

    invoke-virtual {p0}, Landroid/widget/TextView;->getIncludeFontPadding()Z

    move-result v1

    if-eqz v1, :cond_1

    iget v0, v0, Landroid/graphics/Paint$FontMetricsInt;->top:I

    goto :goto_0

    :cond_1
    iget v0, v0, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    :goto_0
    invoke-static {v0}, Ljava/lang/Math;->abs(I)I

    move-result v1

    if-le p1, v1, :cond_2

    add-int/2addr p1, v0

    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    move-result v0

    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    move-result v1

    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    move-result v2

    invoke-virtual {p0, v0, p1, v1, v2}, Landroid/widget/TextView;->setPadding(IIII)V

    :cond_2
    return-void
.end method

.method public static Oooo0O0(Landroid/widget/TextView;I)V
    .locals 2

    invoke-static {p1}, Llyiahf/vczjk/br6;->OooOOO0(I)V

    invoke-virtual {p0}, Landroid/widget/TextView;->getPaint()Landroid/text/TextPaint;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->getFontMetricsInt(Landroid/graphics/Paint$FontMetricsInt;)I

    move-result v0

    if-eq p1, v0, :cond_0

    sub-int/2addr p1, v0

    int-to-float p1, p1

    const/high16 v0, 0x3f800000    # 1.0f

    invoke-virtual {p0, p1, v0}, Landroid/widget/TextView;->setLineSpacing(FF)V

    :cond_0
    return-void
.end method

.method public static Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;
    .locals 1

    invoke-static {p0}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object p0

    const-string v0, "singleton(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public static Oooo0o(Ljava/lang/CharSequence;II)I
    .locals 2

    :goto_0
    if-ge p1, p2, :cond_1

    invoke-interface {p0, p1}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v0

    const/16 v1, 0x9

    if-eq v0, v1, :cond_0

    const/16 v1, 0x20

    if-eq v0, v1, :cond_0

    return p1

    :cond_0
    add-int/lit8 p1, p1, 0x1

    goto :goto_0

    :cond_1
    return p2
.end method

.method public static Oooo0o0(CIILjava/lang/CharSequence;)I
    .locals 1

    :goto_0
    if-ge p1, p2, :cond_1

    invoke-interface {p3, p1}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v0

    if-eq v0, p0, :cond_0

    return p1

    :cond_0
    add-int/lit8 p1, p1, 0x1

    goto :goto_0

    :cond_1
    return p2
.end method

.method public static final Oooo0oO(Llyiahf/vczjk/nw7;Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/profile/RuleInfo;
    .locals 13

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    invoke-interface {p0}, Llyiahf/vczjk/nw7;->getName()Ljava/lang/String;

    move-result-object v3

    const-string v0, "getName(...)"

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Llyiahf/vczjk/nw7;->getDescription()Ljava/lang/String;

    move-result-object v4

    const-string v0, "getDescription(...)"

    invoke-static {v4, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v7

    invoke-interface {p0}, Llyiahf/vczjk/nw7;->getPriority()I

    move-result v12

    const-string v6, ""

    const/4 v9, 0x0

    const/4 v2, -0x1

    const/4 v11, 0x1

    move-object v5, p1

    move v10, p2

    invoke-direct/range {v1 .. v12}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JZIII)V

    return-object v1
.end method

.method public static final Oooo0oo(Llyiahf/vczjk/d93;ILlyiahf/vczjk/wj7;Llyiahf/vczjk/o83;)Ljava/lang/Boolean;
    .locals 6

    invoke-virtual {p0}, Llyiahf/vczjk/d93;->o00000o0()Llyiahf/vczjk/a93;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    if-eqz v0, :cond_d

    const/4 v1, 0x3

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eq v0, v3, :cond_3

    if-eq v0, v2, :cond_d

    if-ne v0, v1, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/d93;->o00000Oo()Llyiahf/vczjk/t83;

    move-result-object v0

    iget-boolean v0, v0, Llyiahf/vczjk/t83;->OooO00o:Z

    if-eqz v0, :cond_0

    invoke-virtual {p3, p0}, Llyiahf/vczjk/o83;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Boolean;

    return-object p0

    :cond_0
    if-nez p2, :cond_1

    invoke-static {p0, p1, p3}, Llyiahf/vczjk/tp6;->OooOo0(Llyiahf/vczjk/d93;ILlyiahf/vczjk/oe3;)Z

    move-result p0

    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p0

    return-object p0

    :cond_1
    invoke-static {p0, p2, p1, p3}, Llyiahf/vczjk/tp6;->Oooo00O(Llyiahf/vczjk/d93;Llyiahf/vczjk/wj7;ILlyiahf/vczjk/oe3;)Z

    move-result p0

    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p0

    return-object p0

    :cond_2
    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_3
    invoke-static {p0}, Llyiahf/vczjk/sb;->OooOooO(Llyiahf/vczjk/d93;)Llyiahf/vczjk/d93;

    move-result-object v0

    const-string v4, "ActiveParent must have a focusedChild"

    if-eqz v0, :cond_c

    invoke-virtual {v0}, Llyiahf/vczjk/d93;->o00000o0()Llyiahf/vczjk/a93;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    move-result v5

    if-eqz v5, :cond_a

    if-eq v5, v3, :cond_5

    if-eq v5, v2, :cond_a

    if-eq v5, v1, :cond_4

    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_5
    invoke-static {v0, p1, p2, p3}, Llyiahf/vczjk/tp6;->Oooo0oo(Llyiahf/vczjk/d93;ILlyiahf/vczjk/wj7;Llyiahf/vczjk/o83;)Ljava/lang/Boolean;

    move-result-object v1

    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_6

    return-object v1

    :cond_6
    if-nez p2, :cond_9

    invoke-virtual {v0}, Llyiahf/vczjk/d93;->o00000o0()Llyiahf/vczjk/a93;

    move-result-object p2

    sget-object v1, Llyiahf/vczjk/a93;->OooOOO:Llyiahf/vczjk/a93;

    if-ne p2, v1, :cond_8

    invoke-static {v0}, Llyiahf/vczjk/sb;->OooOoO0(Llyiahf/vczjk/d93;)Llyiahf/vczjk/d93;

    move-result-object p2

    if-eqz p2, :cond_7

    invoke-static {p2}, Llyiahf/vczjk/sb;->OooOoOO(Llyiahf/vczjk/d93;)Llyiahf/vczjk/wj7;

    move-result-object p2

    goto :goto_0

    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "Searching for active node in inactive hierarchy"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_9
    :goto_0
    invoke-static {p0, p2, p1, p3}, Llyiahf/vczjk/tp6;->OooOo0O(Llyiahf/vczjk/d93;Llyiahf/vczjk/wj7;ILlyiahf/vczjk/oe3;)Z

    move-result p0

    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p0

    return-object p0

    :cond_a
    if-nez p2, :cond_b

    invoke-static {v0}, Llyiahf/vczjk/sb;->OooOoOO(Llyiahf/vczjk/d93;)Llyiahf/vczjk/wj7;

    move-result-object p2

    :cond_b
    invoke-static {p0, p2, p1, p3}, Llyiahf/vczjk/tp6;->OooOo0O(Llyiahf/vczjk/d93;Llyiahf/vczjk/wj7;ILlyiahf/vczjk/oe3;)Z

    move-result p0

    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p0

    return-object p0

    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_d
    invoke-static {p0, p1, p3}, Llyiahf/vczjk/tp6;->OooOo0(Llyiahf/vczjk/d93;ILlyiahf/vczjk/oe3;)Z

    move-result p0

    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p0

    return-object p0
.end method

.method public static OoooO00(Landroid/view/ActionMode$Callback;Landroid/widget/TextView;)Landroid/view/ActionMode$Callback;
    .locals 2

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1a

    if-lt v0, v1, :cond_1

    const/16 v1, 0x1b

    if-gt v0, v1, :cond_1

    instance-of v0, p0, Llyiahf/vczjk/wn9;

    if-nez v0, :cond_1

    if-nez p0, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/wn9;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/wn9;-><init>(Landroid/view/ActionMode$Callback;Landroid/widget/TextView;)V

    return-object v0

    :cond_1
    :goto_0
    return-object p0
.end method


# virtual methods
.method public OooO00o()V
    .locals 0

    return-void
.end method

.method public OooO0OO(Landroid/view/View;)V
    .locals 0

    return-void
.end method

.method public abstract OooOOo([BII)Ljava/lang/String;
.end method

.method public abstract OooOOoo(Ljava/lang/String;[BII)I
.end method
