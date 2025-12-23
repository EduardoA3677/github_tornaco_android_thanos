.class public abstract Llyiahf/vczjk/uk5;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:F

.field public static final OooO0O0:F

.field public static final OooO0OO:J


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const/16 v0, 0x30

    int-to-float v0, v0

    sput v0, Llyiahf/vczjk/uk5;->OooO00o:F

    const/16 v0, 0x18

    int-to-float v0, v0

    sput v0, Llyiahf/vczjk/uk5;->OooO0O0:F

    const/high16 v0, 0x3f000000    # 0.5f

    const/4 v1, 0x0

    invoke-static {v0, v1}, Llyiahf/vczjk/vl6;->OooO0OO(FF)J

    move-result-wide v0

    sput-wide v0, Llyiahf/vczjk/uk5;->OooO0OO:J

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/le3;Llyiahf/vczjk/hl5;Llyiahf/vczjk/zl8;FZLlyiahf/vczjk/qj8;JJFJLlyiahf/vczjk/a91;Llyiahf/vczjk/md1;Llyiahf/vczjk/vk5;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 32

    move-object/from16 v1, p0

    move-object/from16 v3, p2

    const/16 v20, 0x1

    move-object/from16 v0, p17

    check-cast v0, Llyiahf/vczjk/zf1;

    const v2, 0x7188eb30

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    const/4 v2, 0x4

    goto :goto_0

    :cond_0
    const/4 v2, 0x2

    :goto_0
    or-int v2, p18, v2

    or-int/lit8 v2, v2, 0x30

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1

    const/16 v5, 0x100

    goto :goto_1

    :cond_1
    const/16 v5, 0x80

    :goto_1
    or-int/2addr v2, v5

    const v5, 0x16496c00

    or-int/2addr v2, v5

    const v5, 0x12492493

    and-int/2addr v5, v2

    const v7, 0x12492492

    const/4 v8, 0x0

    if-ne v5, v7, :cond_2

    move v5, v8

    goto :goto_2

    :cond_2
    move/from16 v5, v20

    :goto_2
    and-int/lit8 v7, v2, 0x1

    invoke-virtual {v0, v7, v5}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v5

    if-eqz v5, :cond_24

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v5, p18, 0x1

    const v7, -0x71ff0001

    if-eqz v5, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v5

    if-eqz v5, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int/2addr v2, v7

    move/from16 v9, p3

    move/from16 v10, p4

    move-object/from16 v11, p5

    move-wide/from16 v12, p6

    move-wide/from16 v14, p8

    move/from16 v16, p10

    move-wide/from16 v17, p11

    move-object/from16 v5, p14

    move-object/from16 v21, p15

    move v7, v2

    move/from16 v19, v8

    move-object/from16 v8, p1

    move-object/from16 v2, p13

    goto :goto_4

    :cond_4
    :goto_3
    sget-object v5, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget v9, Llyiahf/vczjk/nf0;->OooO0OO:F

    sget-object v10, Llyiahf/vczjk/nf0;->OooO00o:Llyiahf/vczjk/nf0;

    sget-object v10, Llyiahf/vczjk/sl8;->OooO0O0:Llyiahf/vczjk/dk8;

    invoke-static {v10, v0}, Llyiahf/vczjk/cl8;->OooO0O0(Llyiahf/vczjk/dk8;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qj8;

    move-result-object v10

    sget-object v11, Llyiahf/vczjk/sl8;->OooO00o:Llyiahf/vczjk/y21;

    invoke-static {v11, v0}, Llyiahf/vczjk/z21;->OooO0o0(Llyiahf/vczjk/y21;Llyiahf/vczjk/rf1;)J

    move-result-wide v11

    invoke-static {v11, v12, v0}, Llyiahf/vczjk/z21;->OooO0O0(JLlyiahf/vczjk/rf1;)J

    move-result-wide v13

    int-to-float v15, v8

    move/from16 p17, v7

    sget-object v7, Llyiahf/vczjk/a98;->OooO00o:Llyiahf/vczjk/y21;

    move/from16 p1, v9

    invoke-static {v7, v0}, Llyiahf/vczjk/z21;->OooO0o0(Llyiahf/vczjk/y21;Llyiahf/vczjk/rf1;)J

    move-result-wide v8

    const v7, 0x3ea3d70a    # 0.32f

    invoke-static {v7, v8, v9}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v7

    and-int v2, v2, p17

    sget-object v9, Llyiahf/vczjk/wa1;->OooO00o:Llyiahf/vczjk/a91;

    sget-object v17, Llyiahf/vczjk/md1;->OooOo00:Llyiahf/vczjk/md1;

    new-instance v18, Llyiahf/vczjk/vk5;

    invoke-direct/range {v18 .. v18}, Llyiahf/vczjk/vk5;-><init>()V

    move/from16 v16, v15

    move-object/from16 v21, v18

    const/16 v19, 0x0

    move-wide v14, v13

    move-wide v12, v11

    move-object v11, v10

    move/from16 v10, v20

    move-object/from16 v29, v9

    move/from16 v9, p1

    move-wide/from16 v30, v7

    move v7, v2

    move-object v8, v5

    move-object/from16 v2, v29

    move-object/from16 v5, v17

    move-wide/from16 v17, v30

    :goto_4
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo0()V

    sget-object v4, Llyiahf/vczjk/zo5;->OooOOO0:Llyiahf/vczjk/zo5;

    invoke-static {v4, v0}, Llyiahf/vczjk/so8;->OoooO0O(Llyiahf/vczjk/zo5;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p13;

    move-result-object v6

    invoke-static {v4, v0}, Llyiahf/vczjk/so8;->OoooO0O(Llyiahf/vczjk/zo5;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p13;

    move-result-object v4

    move-object/from16 p1, v2

    sget-object v2, Llyiahf/vczjk/zo5;->OooOOOo:Llyiahf/vczjk/zo5;

    invoke-static {v2, v0}, Llyiahf/vczjk/so8;->OoooO0O(Llyiahf/vczjk/zo5;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p13;

    move-result-object v2

    move-object/from16 p9, v5

    and-int/lit16 v5, v7, 0x380

    xor-int/lit16 v5, v5, 0x180

    move-object/from16 p10, v8

    const/16 v8, 0x100

    if-le v5, v8, :cond_5

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v22

    if-nez v22, :cond_6

    :cond_5
    and-int/lit16 v3, v7, 0x180

    if-ne v3, v8, :cond_7

    :cond_6
    move/from16 v3, v20

    goto :goto_5

    :cond_7
    move/from16 v3, v19

    :goto_5
    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v3, v8

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v3, v8

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v3, v8

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    move-object/from16 p6, v2

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v3, :cond_9

    if-ne v8, v2, :cond_8

    goto :goto_6

    :cond_8
    move-object/from16 v3, p2

    goto :goto_7

    :cond_9
    :goto_6
    new-instance v3, Llyiahf/vczjk/sf0;

    const/4 v8, 0x1

    move-object/from16 p4, p2

    move-object/from16 p3, v3

    move-object/from16 p5, v4

    move-object/from16 p7, v6

    move/from16 p8, v8

    invoke-direct/range {p3 .. p8}, Llyiahf/vczjk/sf0;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/p13;Llyiahf/vczjk/p13;Llyiahf/vczjk/p13;I)V

    move-object/from16 v8, p3

    move-object/from16 v3, p4

    invoke-virtual {v0, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_7
    check-cast v8, Llyiahf/vczjk/le3;

    invoke-static {v8, v0}, Llyiahf/vczjk/c6a;->OooOo00(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;)V

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v2, :cond_a

    invoke-static {v0}, Llyiahf/vczjk/c6a;->Oooo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/xr1;

    move-result-object v4

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    move-object v6, v4

    check-cast v6, Llyiahf/vczjk/xr1;

    const/16 v8, 0x100

    if-le v5, v8, :cond_b

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_c

    :cond_b
    and-int/lit16 v4, v7, 0x180

    if-ne v4, v8, :cond_d

    :cond_c
    move/from16 v4, v20

    goto :goto_8

    :cond_d
    move/from16 v4, v19

    :goto_8
    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v4, v8

    and-int/lit8 v8, v7, 0xe

    move/from16 p3, v4

    const/4 v4, 0x4

    if-ne v8, v4, :cond_e

    move/from16 v4, v20

    goto :goto_9

    :cond_e
    move/from16 v4, v19

    :goto_9
    or-int v4, p3, v4

    move/from16 p3, v4

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez p3, :cond_f

    if-ne v4, v2, :cond_10

    :cond_f
    new-instance v4, Llyiahf/vczjk/ck5;

    invoke-direct {v4, v3, v6, v1}, Llyiahf/vczjk/ck5;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/xr1;Llyiahf/vczjk/le3;)V

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_10
    check-cast v4, Llyiahf/vczjk/le3;

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v23

    move-object/from16 p11, v4

    const/16 v4, 0x100

    if-le v5, v4, :cond_11

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v22

    if-nez v22, :cond_12

    :cond_11
    move/from16 p12, v9

    goto :goto_a

    :cond_12
    move/from16 p12, v9

    goto :goto_b

    :goto_a
    and-int/lit16 v9, v7, 0x180

    if-ne v9, v4, :cond_13

    :goto_b
    move/from16 v4, v20

    goto :goto_c

    :cond_13
    move/from16 v4, v19

    :goto_c
    or-int v4, v23, v4

    const/4 v9, 0x4

    if-ne v8, v9, :cond_14

    move/from16 v9, v20

    goto :goto_d

    :cond_14
    move/from16 v9, v19

    :goto_d
    or-int/2addr v4, v9

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v4, :cond_15

    if-ne v9, v2, :cond_16

    :cond_15
    new-instance v9, Llyiahf/vczjk/oo0ooO;

    const/16 v4, 0xc

    invoke-direct {v9, v6, v3, v4, v1}, Llyiahf/vczjk/oo0ooO;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v0, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_16
    check-cast v9, Llyiahf/vczjk/oe3;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v2, :cond_17

    const/4 v4, 0x0

    invoke-static {v4}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object v4

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_17
    check-cast v4, Llyiahf/vczjk/gi;

    const/16 v1, 0x100

    if-le v5, v1, :cond_18

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v22

    if-nez v22, :cond_19

    :cond_18
    and-int/lit16 v3, v7, 0x180

    if-ne v3, v1, :cond_1a

    :cond_19
    move/from16 v3, v20

    goto :goto_e

    :cond_1a
    move/from16 v3, v19

    :goto_e
    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v22

    or-int v3, v3, v22

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v22

    or-int v3, v3, v22

    const/4 v1, 0x4

    if-ne v8, v1, :cond_1b

    move/from16 v1, v20

    goto :goto_f

    :cond_1b
    move/from16 v1, v19

    :goto_f
    or-int/2addr v1, v3

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v1, :cond_1c

    if-ne v3, v2, :cond_1d

    :cond_1c
    new-instance v1, Llyiahf/vczjk/c02;

    const/4 v3, 0x1

    move-object/from16 p7, p0

    move-object/from16 p4, p2

    move-object/from16 p3, v1

    move/from16 p8, v3

    move-object/from16 p6, v4

    move-object/from16 p5, v6

    invoke-direct/range {p3 .. p8}, Llyiahf/vczjk/c02;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    move-object/from16 v3, p3

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1d
    move-object/from16 v23, v3

    check-cast v23, Llyiahf/vczjk/le3;

    move-object v1, v0

    new-instance v0, Llyiahf/vczjk/ik5;

    move-object/from16 v8, p10

    move-object/from16 v3, p11

    move-object/from16 v19, p16

    move-object/from16 v24, v1

    move-object/from16 v27, v2

    move/from16 v26, v5

    move/from16 v25, v7

    move-object v7, v9

    move-wide/from16 v1, v17

    move-object/from16 v17, p1

    move-object/from16 v18, p9

    move/from16 v9, p12

    move-object v5, v4

    move-object/from16 v4, p2

    invoke-direct/range {v0 .. v19}, Llyiahf/vczjk/ik5;-><init>(JLlyiahf/vczjk/le3;Llyiahf/vczjk/zl8;Llyiahf/vczjk/gi;Llyiahf/vczjk/xr1;Llyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;FZLlyiahf/vczjk/qj8;JJFLlyiahf/vczjk/a91;Llyiahf/vczjk/md1;Llyiahf/vczjk/a91;)V

    move-object v3, v4

    move-object v4, v5

    const v5, 0x3c33c970

    move-object/from16 v6, v24

    invoke-static {v5, v0, v6}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v0

    const/16 v5, 0x7180

    move-object/from16 p8, v0

    move-object/from16 p7, v4

    move/from16 p10, v5

    move-object/from16 p9, v6

    move-wide/from16 p4, v14

    move-object/from16 p6, v21

    move-object/from16 p3, v23

    invoke-static/range {p3 .. p10}, Llyiahf/vczjk/mc4;->OooO(Llyiahf/vczjk/le3;JLlyiahf/vczjk/vk5;Llyiahf/vczjk/gi;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    move-object/from16 v0, p6

    iget-object v4, v3, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    invoke-virtual {v4}, Llyiahf/vczjk/c9;->OooO0Oo()Llyiahf/vczjk/kb5;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/am8;->OooOOO:Llyiahf/vczjk/am8;

    iget-object v4, v4, Llyiahf/vczjk/kb5;->OooO00o:Ljava/lang/Object;

    invoke-interface {v4, v5}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_23

    const v4, 0x2c9b7832

    invoke-virtual {v6, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move/from16 v5, v26

    const/16 v4, 0x100

    if-le v5, v4, :cond_1e

    invoke-virtual {v6, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_20

    :cond_1e
    move/from16 v5, v25

    and-int/lit16 v5, v5, 0x180

    if-ne v5, v4, :cond_1f

    goto :goto_10

    :cond_1f
    const/16 v20, 0x0

    :cond_20
    :goto_10
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v20, :cond_21

    move-object/from16 v5, v27

    if-ne v4, v5, :cond_22

    :cond_21
    new-instance v4, Llyiahf/vczjk/jk5;

    const/4 v5, 0x0

    invoke-direct {v4, v3, v5}, Llyiahf/vczjk/jk5;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v6, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_22
    check-cast v4, Llyiahf/vczjk/ze3;

    invoke-static {v3, v6, v4}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/4 v4, 0x0

    invoke-virtual {v6, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_11

    :cond_23
    const/4 v4, 0x0

    const v5, 0x2c9c6872

    invoke-virtual {v6, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v6, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_11
    move-wide v4, v1

    move-object v2, v8

    move-wide v7, v12

    move-wide v12, v4

    move-object v1, v6

    move v4, v9

    move v5, v10

    move-object v6, v11

    move-wide v9, v14

    move/from16 v11, v16

    move-object/from16 v14, v17

    move-object/from16 v15, v18

    move-object/from16 v16, v0

    goto :goto_12

    :cond_24
    move-object v6, v0

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v2, p1

    move/from16 v4, p3

    move/from16 v5, p4

    move-wide/from16 v7, p6

    move-wide/from16 v9, p8

    move/from16 v11, p10

    move-wide/from16 v12, p11

    move-object/from16 v14, p13

    move-object/from16 v15, p14

    move-object/from16 v16, p15

    move-object v1, v6

    move-object/from16 v6, p5

    :goto_12
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_25

    move-object v1, v0

    new-instance v0, Llyiahf/vczjk/dk5;

    move-object/from16 v17, p16

    move/from16 v18, p18

    move-object/from16 v28, v1

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v18}, Llyiahf/vczjk/dk5;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/hl5;Llyiahf/vczjk/zl8;FZLlyiahf/vczjk/qj8;JJFJLlyiahf/vczjk/a91;Llyiahf/vczjk/md1;Llyiahf/vczjk/vk5;Llyiahf/vczjk/a91;I)V

    move-object/from16 v1, v28

    iput-object v0, v1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_25
    return-void
.end method

.method public static final OooO0O0(Llyiahf/vczjk/gi;Llyiahf/vczjk/xr1;Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;Llyiahf/vczjk/zl8;FZLlyiahf/vczjk/qj8;JJFLlyiahf/vczjk/a91;Llyiahf/vczjk/ze3;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 36

    move-object/from16 v1, p0

    move-object/from16 v9, p3

    move-object/from16 v10, p4

    move-object/from16 v3, p5

    move/from16 v11, p6

    move/from16 v7, p7

    sget-object v5, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o:Landroidx/compose/foundation/layout/OooO0O0;

    move-object/from16 v12, p17

    check-cast v12, Llyiahf/vczjk/zf1;

    const v6, -0x23aaf70

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_0

    const/16 v6, 0x20

    goto :goto_0

    :cond_0
    const/16 v6, 0x10

    :goto_0
    or-int v6, p18, v6

    move-object/from16 v14, p1

    invoke-virtual {v12, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v15

    const/16 v16, 0x80

    const/16 v17, 0x100

    if-eqz v15, :cond_1

    move/from16 v15, v17

    goto :goto_1

    :cond_1
    move/from16 v15, v16

    :goto_1
    or-int/2addr v6, v15

    move-object/from16 v15, p2

    invoke-virtual {v12, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v18

    const/16 v19, 0x800

    const/16 v20, 0x400

    if-eqz v18, :cond_2

    move/from16 v18, v19

    goto :goto_2

    :cond_2
    move/from16 v18, v20

    :goto_2
    or-int v6, v6, v18

    invoke-virtual {v12, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v18

    const/16 v21, 0x2000

    if-eqz v18, :cond_3

    const/16 v18, 0x4000

    goto :goto_3

    :cond_3
    move/from16 v18, v21

    :goto_3
    or-int v6, v6, v18

    invoke-virtual {v12, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v18

    const/high16 v22, 0x10000

    const/high16 v23, 0x20000

    if-eqz v18, :cond_4

    move/from16 v18, v23

    goto :goto_4

    :cond_4
    move/from16 v18, v22

    :goto_4
    or-int v6, v6, v18

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v18

    if-eqz v18, :cond_5

    const/high16 v18, 0x100000

    goto :goto_5

    :cond_5
    const/high16 v18, 0x80000

    :goto_5
    or-int v6, v6, v18

    invoke-virtual {v12, v11}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v18

    if-eqz v18, :cond_6

    const/high16 v18, 0x800000

    goto :goto_6

    :cond_6
    const/high16 v18, 0x400000

    :goto_6
    or-int v6, v6, v18

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v18

    if-eqz v18, :cond_7

    const/high16 v18, 0x4000000

    goto :goto_7

    :cond_7
    const/high16 v18, 0x2000000

    :goto_7
    or-int v6, v6, v18

    move-object/from16 v2, p8

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v24

    if-eqz v24, :cond_8

    const/high16 v24, 0x20000000

    goto :goto_8

    :cond_8
    const/high16 v24, 0x10000000

    :goto_8
    or-int v24, v6, v24

    move-wide/from16 v0, p9

    invoke-virtual {v12, v0, v1}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v25

    if-eqz v25, :cond_9

    const/16 v25, 0x4

    :goto_9
    move-wide/from16 v8, p11

    goto :goto_a

    :cond_9
    const/16 v25, 0x2

    goto :goto_9

    :goto_a
    invoke-virtual {v12, v8, v9}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v26

    if-eqz v26, :cond_a

    const/16 v26, 0x20

    goto :goto_b

    :cond_a
    const/16 v26, 0x10

    :goto_b
    or-int v25, v25, v26

    move/from16 v13, p13

    invoke-virtual {v12, v13}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v26

    if-eqz v26, :cond_b

    move/from16 v16, v17

    :cond_b
    or-int v16, v25, v16

    move-object/from16 v6, p14

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v25

    if-eqz v25, :cond_c

    goto :goto_c

    :cond_c
    move/from16 v19, v20

    :goto_c
    or-int v16, v16, v19

    move-object/from16 v4, p15

    const/16 v19, 0x1

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v20

    if-eqz v20, :cond_d

    const/16 v21, 0x4000

    :cond_d
    or-int v16, v16, v21

    move-object/from16 v0, p16

    invoke-virtual {v12, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_e

    move/from16 v22, v23

    :cond_e
    or-int v16, v16, v22

    const v1, 0x12492493

    and-int v1, v24, v1

    const v0, 0x12492492

    if-ne v1, v0, :cond_10

    const v0, 0x12493

    and-int v0, v16, v0

    const v1, 0x12492

    if-eq v0, v1, :cond_f

    goto :goto_d

    :cond_f
    const/4 v0, 0x0

    goto :goto_e

    :cond_10
    :goto_d
    move/from16 v0, v19

    :goto_e
    and-int/lit8 v1, v24, 0x1

    invoke-virtual {v12, v1, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v0

    if-eqz v0, :cond_2d

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v0, p18, 0x1

    if-eqz v0, :cond_12

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v0

    if-eqz v0, :cond_11

    goto :goto_f

    :cond_11
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :cond_12
    :goto_f
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOOo0()V

    sget v0, Landroidx/compose/material3/R$string;->m3c_bottom_sheet_pane_title:I

    invoke-static {v0, v12}, Llyiahf/vczjk/ru6;->OooOo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/op3;->OooOOOO:Llyiahf/vczjk/ub0;

    invoke-virtual {v5, v10, v1}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v1

    const/4 v5, 0x0

    move/from16 v2, v19

    invoke-static {v1, v5, v11, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOo(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v1

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/high16 v20, 0x380000

    sget-object v5, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v21, 0x180000

    if-eqz v7, :cond_18

    const v4, -0x5e4bf1d8

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int v4, v24, v20

    xor-int v4, v4, v21

    const/high16 v6, 0x100000

    if-le v4, v6, :cond_13

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_14

    :cond_13
    and-int v4, v24, v21

    if-ne v4, v6, :cond_15

    :cond_14
    const/4 v6, 0x1

    goto :goto_10

    :cond_15
    const/4 v6, 0x0

    :goto_10
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v6, :cond_17

    if-ne v4, v2, :cond_16

    goto :goto_11

    :cond_16
    move-object/from16 v6, p3

    goto :goto_12

    :cond_17
    :goto_11
    sget-object v4, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    sget v4, Llyiahf/vczjk/wl8;->OooO00o:F

    new-instance v4, Llyiahf/vczjk/vl8;

    move-object/from16 v6, p3

    invoke-direct {v4, v3, v6}, Llyiahf/vczjk/vl8;-><init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/oe3;)V

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_12
    check-cast v4, Llyiahf/vczjk/bz5;

    const/4 v7, 0x0

    invoke-static {v5, v4, v7}, Landroidx/compose/ui/input/nestedscroll/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bz5;Llyiahf/vczjk/fz5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    const/4 v4, 0x0

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_13

    :cond_18
    move-object/from16 v6, p3

    const/4 v4, 0x0

    const v7, -0x5e4bb948

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_13
    invoke-interface {v1, v5}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    iget-object v4, v3, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    sget-object v28, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    and-int v5, v24, v20

    xor-int v5, v5, v21

    const/high16 v7, 0x100000

    if-le v5, v7, :cond_19

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v20

    if-nez v20, :cond_1a

    :cond_19
    and-int v8, v24, v21

    if-ne v8, v7, :cond_1b

    :cond_1a
    const/4 v7, 0x1

    goto :goto_14

    :cond_1b
    const/4 v7, 0x0

    :goto_14
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v7, :cond_1d

    if-ne v8, v2, :cond_1c

    goto :goto_15

    :cond_1c
    const/4 v7, 0x1

    goto :goto_16

    :cond_1d
    :goto_15
    new-instance v8, Llyiahf/vczjk/sj5;

    const/4 v7, 0x1

    invoke-direct {v8, v3, v7}, Llyiahf/vczjk/sj5;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v12, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_16
    check-cast v8, Llyiahf/vczjk/ze3;

    invoke-static {v1, v4, v8}, Landroidx/compose/material3/internal/OooO0O0;->OooO0Oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/c9;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/kl5;

    move-result-object v26

    iget-object v1, v3, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    iget-object v1, v1, Llyiahf/vczjk/c9;->OooO0o:Llyiahf/vczjk/x8;

    if-eqz p7, :cond_1e

    invoke-virtual {v3}, Llyiahf/vczjk/zl8;->OooO0o0()Z

    move-result v4

    if-eqz v4, :cond_1e

    move/from16 v29, v7

    goto :goto_17

    :cond_1e
    const/16 v29, 0x0

    :goto_17
    iget-object v4, v3, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    iget-object v4, v4, Llyiahf/vczjk/c9;->OooOO0o:Llyiahf/vczjk/qs5;

    check-cast v4, Llyiahf/vczjk/fw8;

    invoke-virtual {v4}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v4

    if-eqz v4, :cond_1f

    move/from16 v31, v7

    goto :goto_18

    :cond_1f
    const/16 v31, 0x0

    :goto_18
    const v9, 0xe000

    and-int v4, v24, v9

    const/16 v8, 0x4000

    if-ne v4, v8, :cond_20

    move v4, v7

    goto :goto_19

    :cond_20
    const/4 v4, 0x0

    :goto_19
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v4, :cond_21

    if-ne v8, v2, :cond_22

    :cond_21
    new-instance v8, Llyiahf/vczjk/mk5;

    const/4 v4, 0x0

    invoke-direct {v8, v4, v6}, Llyiahf/vczjk/mk5;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)V

    invoke-virtual {v12, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_22
    move-object/from16 v32, v8

    check-cast v32, Llyiahf/vczjk/bf3;

    const/16 v30, 0x0

    const/16 v33, 0x0

    const/16 v34, 0xa8

    move-object/from16 v27, v1

    invoke-static/range {v26 .. v34}, Llyiahf/vczjk/uf2;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ag2;Llyiahf/vczjk/nf6;ZLlyiahf/vczjk/rr5;ZLlyiahf/vczjk/bf3;ZI)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-virtual {v12, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v4, :cond_23

    if-ne v8, v2, :cond_24

    :cond_23
    new-instance v8, Llyiahf/vczjk/kf0;

    const/4 v4, 0x4

    invoke-direct {v8, v0, v4}, Llyiahf/vczjk/kf0;-><init>(Ljava/lang/String;I)V

    invoke-virtual {v12, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_24
    check-cast v8, Llyiahf/vczjk/oe3;

    const/4 v4, 0x0

    invoke-static {v1, v4, v8}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v0

    iget-object v1, v3, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    invoke-virtual {v1}, Llyiahf/vczjk/c9;->OooO0o0()F

    move-result v1

    float-to-int v1, v1

    if-gez v1, :cond_25

    const/4 v1, 0x0

    :cond_25
    new-instance v4, Llyiahf/vczjk/s13;

    invoke-direct {v4, v1}, Llyiahf/vczjk/s13;-><init>(I)V

    sget-object v1, Llyiahf/vczjk/uoa;->OooO00o:Llyiahf/vczjk/ie7;

    new-instance v1, Llyiahf/vczjk/qoa;

    invoke-direct {v1, v4}, Llyiahf/vczjk/qoa;-><init>(Llyiahf/vczjk/s13;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/ng0;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object v0

    const/high16 v1, 0x100000

    if-le v5, v1, :cond_26

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_27

    :cond_26
    and-int v4, v24, v21

    if-ne v4, v1, :cond_28

    :cond_27
    move v1, v7

    goto :goto_1a

    :cond_28
    const/4 v1, 0x0

    :goto_1a
    and-int/lit8 v4, v24, 0x70

    const/16 v5, 0x20

    if-eq v4, v5, :cond_2a

    move-object/from16 v4, p0

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_29

    goto :goto_1b

    :cond_29
    const/4 v7, 0x0

    goto :goto_1b

    :cond_2a
    move-object/from16 v4, p0

    :goto_1b
    or-int/2addr v1, v7

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v1, :cond_2b

    if-ne v5, v2, :cond_2c

    :cond_2b
    new-instance v5, Llyiahf/vczjk/o0OO000o;

    const/16 v1, 0x14

    invoke-direct {v5, v1, v3, v4}, Llyiahf/vczjk/o0OO000o;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2c
    check-cast v5, Llyiahf/vczjk/oe3;

    invoke-static {v0, v5}, Landroidx/compose/ui/graphics/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/vf0;

    const/4 v2, 0x0

    invoke-direct {v1, v3, v2}, Llyiahf/vczjk/vf0;-><init>(Llyiahf/vczjk/zl8;I)V

    invoke-static {v0, v1}, Landroidx/compose/ui/graphics/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v17

    new-instance v0, Llyiahf/vczjk/tk5;

    move/from16 v7, p7

    move-object/from16 v1, p15

    move-object/from16 v8, p16

    move-object v2, v4

    move-object v6, v14

    move-object v5, v15

    move-object/from16 v4, p14

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/tk5;-><init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/gi;Llyiahf/vczjk/zl8;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/xr1;ZLlyiahf/vczjk/a91;)V

    const v1, 0x2b6fbd6b

    invoke-static {v1, v0, v12}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v20

    shr-int/lit8 v0, v24, 0x18

    and-int/lit8 v0, v0, 0x70

    const/high16 v1, 0xc00000

    or-int/2addr v0, v1

    shl-int/lit8 v1, v16, 0x6

    and-int/lit16 v2, v1, 0x380

    or-int/2addr v0, v2

    and-int/lit16 v2, v1, 0x1c00

    or-int/2addr v0, v2

    and-int/2addr v1, v9

    or-int v22, v0, v1

    const/16 v23, 0x60

    const/16 v19, 0x0

    move-wide/from16 v14, p9

    move-object/from16 v21, v12

    move/from16 v18, v13

    move-object/from16 v12, v17

    move-object/from16 v13, p8

    move-wide/from16 v16, p11

    invoke-static/range {v12 .. v23}, Llyiahf/vczjk/ua9;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    goto :goto_1c

    :cond_2d
    move-object/from16 v21, v12

    invoke-virtual/range {v21 .. v21}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1c
    invoke-virtual/range {v21 .. v21}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_2e

    move-object v1, v0

    new-instance v0, Llyiahf/vczjk/bk5;

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    move-object/from16 v6, p5

    move/from16 v8, p7

    move-object/from16 v9, p8

    move-wide/from16 v12, p11

    move/from16 v14, p13

    move-object/from16 v15, p14

    move-object/from16 v16, p15

    move-object/from16 v17, p16

    move/from16 v18, p18

    move-object/from16 v35, v1

    move-object v5, v10

    move v7, v11

    move-object/from16 v1, p0

    move-wide/from16 v10, p9

    invoke-direct/range {v0 .. v18}, Llyiahf/vczjk/bk5;-><init>(Llyiahf/vczjk/gi;Llyiahf/vczjk/xr1;Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;Llyiahf/vczjk/zl8;FZLlyiahf/vczjk/qj8;JJFLlyiahf/vczjk/a91;Llyiahf/vczjk/ze3;Llyiahf/vczjk/a91;I)V

    move-object/from16 v1, v35

    iput-object v0, v1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_2e
    return-void
.end method

.method public static final OooO0OO(JLlyiahf/vczjk/le3;ZLlyiahf/vczjk/rf1;I)V
    .locals 16

    move-wide/from16 v1, p0

    move-object/from16 v3, p2

    move/from16 v4, p3

    move-object/from16 v8, p4

    check-cast v8, Llyiahf/vczjk/zf1;

    const v0, 0x38bc6405

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v8, v1, v2}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int v0, p5, v0

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    const/16 v12, 0x20

    if-eqz v5, :cond_1

    move v5, v12

    goto :goto_1

    :cond_1
    const/16 v5, 0x10

    :goto_1
    or-int/2addr v0, v5

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v5

    if-eqz v5, :cond_2

    const/16 v5, 0x100

    goto :goto_2

    :cond_2
    const/16 v5, 0x80

    :goto_2
    or-int/2addr v0, v5

    and-int/lit16 v5, v0, 0x93

    const/4 v13, 0x1

    const/16 v6, 0x92

    const/4 v14, 0x0

    if-eq v5, v6, :cond_3

    move v5, v13

    goto :goto_3

    :cond_3
    move v5, v14

    :goto_3
    and-int/lit8 v6, v0, 0x1

    invoke-virtual {v8, v6, v5}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v5

    if-eqz v5, :cond_10

    const-wide/16 v5, 0x10

    cmp-long v5, v1, v5

    if-eqz v5, :cond_f

    const v5, 0x6b3ebef6

    invoke-virtual {v8, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-eqz v4, :cond_4

    const/high16 v5, 0x3f800000    # 1.0f

    goto :goto_4

    :cond_4
    const/4 v5, 0x0

    :goto_4
    sget-object v6, Llyiahf/vczjk/zo5;->OooOOOO:Llyiahf/vczjk/zo5;

    invoke-static {v6, v8}, Llyiahf/vczjk/so8;->OoooO0O(Llyiahf/vczjk/zo5;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p13;

    move-result-object v6

    const/16 v10, 0x1c

    const/4 v7, 0x0

    const/4 v9, 0x0

    invoke-static/range {v5 .. v10}, Llyiahf/vczjk/ti;->OooO0O0(FLlyiahf/vczjk/p13;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/p29;

    move-result-object v5

    sget v6, Landroidx/compose/ui/R$string;->close_sheet:I

    invoke-static {v6, v8}, Llyiahf/vczjk/ru6;->OooOo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    sget-object v9, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    if-eqz v4, :cond_b

    const v10, 0x6b432fe9

    invoke-virtual {v8, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v10, v0, 0x70

    if-ne v10, v12, :cond_5

    move v15, v13

    goto :goto_5

    :cond_5
    move v15, v14

    :goto_5
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v15, :cond_6

    if-ne v11, v7, :cond_7

    :cond_6
    new-instance v11, Llyiahf/vczjk/o0000O0;

    const/4 v15, 0x4

    invoke-direct {v11, v3, v15}, Llyiahf/vczjk/o0000O0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v8, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v11, Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

    invoke-static {v9, v3, v11}, Llyiahf/vczjk/gb9;->OooO00o(Llyiahf/vczjk/kl5;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Llyiahf/vczjk/kl5;

    move-result-object v9

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    if-ne v10, v12, :cond_8

    move v10, v13

    goto :goto_6

    :cond_8
    move v10, v14

    :goto_6
    or-int/2addr v10, v11

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v10, :cond_9

    if-ne v11, v7, :cond_a

    :cond_9
    new-instance v11, Llyiahf/vczjk/o0OO000o;

    const/16 v10, 0x15

    invoke-direct {v11, v10, v6, v3}, Llyiahf/vczjk/o0OO000o;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v8, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    check-cast v11, Llyiahf/vczjk/oe3;

    invoke-static {v9, v13, v11}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v9

    invoke-virtual {v8, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_7

    :cond_b
    const v6, 0x6b49b0b5

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_7
    sget-object v6, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-interface {v6, v9}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    and-int/lit8 v0, v0, 0xe

    const/4 v9, 0x4

    if-ne v0, v9, :cond_c

    goto :goto_8

    :cond_c
    move v13, v14

    :goto_8
    invoke-virtual {v8, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    or-int/2addr v0, v13

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v0, :cond_d

    if-ne v9, v7, :cond_e

    :cond_d
    new-instance v9, Llyiahf/vczjk/zj5;

    invoke-direct {v9, v1, v2, v5}, Llyiahf/vczjk/zj5;-><init>(JLlyiahf/vczjk/p29;)V

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    check-cast v9, Llyiahf/vczjk/oe3;

    invoke-static {v6, v9, v8, v14}, Llyiahf/vczjk/vc6;->OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v8, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_9

    :cond_f
    const v0, 0x6b4c74dd

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_9

    :cond_10
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_9
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_11

    new-instance v0, Llyiahf/vczjk/ak5;

    move/from16 v5, p5

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/ak5;-><init>(JLlyiahf/vczjk/le3;ZI)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_11
    return-void
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/ft7;F)F
    .locals 4

    iget-wide v0, p0, Llyiahf/vczjk/ft7;->OooOoOO:J

    const/16 v2, 0x20

    shr-long/2addr v0, v2

    long-to-int v0, v0

    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    move-result v1

    const/high16 v2, 0x3f800000    # 1.0f

    if-nez v1, :cond_1

    const/4 v1, 0x0

    cmpg-float v3, v0, v1

    if-nez v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/ft7;->OooO0O0()F

    move-result p0

    sget v3, Llyiahf/vczjk/uk5;->OooO00o:F

    mul-float/2addr p0, v3

    invoke-static {p0, v0}, Ljava/lang/Math;->min(FF)F

    move-result p0

    invoke-static {v1, p0, p1}, Llyiahf/vczjk/so8;->Oooo00O(FFF)F

    move-result p0

    div-float/2addr p0, v0

    sub-float/2addr v2, p0

    :cond_1
    :goto_0
    return v2
.end method

.method public static final OooO0o(IILlyiahf/vczjk/rf1;)Llyiahf/vczjk/zl8;
    .locals 7

    const/4 v0, 0x1

    and-int/2addr p1, v0

    if-eqz p1, :cond_0

    const/4 v0, 0x0

    :cond_0
    move v1, v0

    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, v2, :cond_1

    new-instance v0, Llyiahf/vczjk/rt3;

    const/4 v2, 0x5

    invoke-direct {v0, v2}, Llyiahf/vczjk/rt3;-><init>(I)V

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/oe3;

    sget-object v3, Llyiahf/vczjk/am8;->OooOOO0:Llyiahf/vczjk/am8;

    and-int/lit8 p0, p0, 0xe

    or-int/lit16 v5, p0, 0x180

    const/16 v6, 0x38

    move-object v4, p2

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/wl8;->OooO00o(ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/am8;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/zl8;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0o0(Llyiahf/vczjk/ft7;F)F
    .locals 4

    iget-wide v0, p0, Llyiahf/vczjk/ft7;->OooOoOO:J

    const-wide v2, 0xffffffffL

    and-long/2addr v0, v2

    long-to-int v0, v0

    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    move-result v1

    const/high16 v2, 0x3f800000    # 1.0f

    if-nez v1, :cond_1

    const/4 v1, 0x0

    cmpg-float v3, v0, v1

    if-nez v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/ft7;->OooO0O0()F

    move-result p0

    sget v3, Llyiahf/vczjk/uk5;->OooO0O0:F

    mul-float/2addr p0, v3

    invoke-static {p0, v0}, Ljava/lang/Math;->min(FF)F

    move-result p0

    invoke-static {v1, p0, p1}, Llyiahf/vczjk/so8;->Oooo00O(FFF)F

    move-result p0

    div-float/2addr p0, v0

    sub-float/2addr v2, p0

    :cond_1
    :goto_0
    return v2
.end method
