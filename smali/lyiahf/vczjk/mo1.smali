.class public abstract Llyiahf/vczjk/mo1;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/d07;

.field public static final OooO0O0:Llyiahf/vczjk/tn1;


# direct methods
.method static constructor <clinit>()V
    .locals 13

    new-instance v0, Llyiahf/vczjk/d07;

    const/16 v1, 0xe

    invoke-direct {v0, v1}, Llyiahf/vczjk/d07;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/mo1;->OooO00o:Llyiahf/vczjk/d07;

    new-instance v2, Llyiahf/vczjk/tn1;

    sget-wide v3, Llyiahf/vczjk/n21;->OooO0o:J

    sget-wide v5, Llyiahf/vczjk/n21;->OooO0O0:J

    const v0, 0x3ec28f5c    # 0.38f

    invoke-static {v0, v5, v6}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v9

    invoke-static {v0, v5, v6}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v11

    move-wide v7, v5

    invoke-direct/range {v2 .. v12}, Llyiahf/vczjk/tn1;-><init>(JJJJJ)V

    sput-object v2, Llyiahf/vczjk/mo1;->OooO0O0:Llyiahf/vczjk/tn1;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/tn1;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V
    .locals 9

    const/4 v0, 0x2

    const/4 v1, 0x4

    check-cast p3, Llyiahf/vczjk/zf1;

    const v2, -0x36e94d1d

    invoke-virtual {p3, v2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    const/4 v2, 0x1

    and-int/lit8 v3, p5, 0x1

    if-eqz v3, :cond_0

    or-int/lit8 v3, p4, 0x6

    goto :goto_1

    :cond_0
    and-int/lit8 v3, p4, 0x6

    if-nez v3, :cond_2

    invoke-virtual {p3, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    move v3, v1

    goto :goto_0

    :cond_1
    move v3, v0

    :goto_0
    or-int/2addr v3, p4

    goto :goto_1

    :cond_2
    move v3, p4

    :goto_1
    and-int/2addr v0, p5

    if-eqz v0, :cond_3

    or-int/lit8 v3, v3, 0x30

    goto :goto_3

    :cond_3
    and-int/lit8 v4, p4, 0x30

    if-nez v4, :cond_5

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_4

    const/16 v4, 0x20

    goto :goto_2

    :cond_4
    const/16 v4, 0x10

    :goto_2
    or-int/2addr v3, v4

    :cond_5
    :goto_3
    and-int/2addr v1, p5

    if-eqz v1, :cond_6

    or-int/lit16 v3, v3, 0x180

    goto :goto_5

    :cond_6
    and-int/lit16 v1, p4, 0x180

    if-nez v1, :cond_8

    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_7

    const/16 v1, 0x100

    goto :goto_4

    :cond_7
    const/16 v1, 0x80

    :goto_4
    or-int/2addr v3, v1

    :cond_8
    :goto_5
    and-int/lit16 v1, v3, 0x93

    const/16 v4, 0x92

    const/4 v5, 0x0

    if-eq v1, v4, :cond_9

    move v1, v2

    goto :goto_6

    :cond_9
    move v1, v5

    :goto_6
    and-int/lit8 v4, v3, 0x1

    invoke-virtual {p3, v4, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_e

    if-eqz v0, :cond_a

    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    :cond_a
    sget v0, Llyiahf/vczjk/ao1;->OooO0Oo:F

    sget v1, Llyiahf/vczjk/ao1;->OooO0o0:F

    invoke-static {v1}, Llyiahf/vczjk/uv7;->OooO00o(F)Llyiahf/vczjk/tv7;

    move-result-object v1

    const/16 v4, 0x1c

    invoke-static {p1, v0, v1, v4}, Llyiahf/vczjk/vt6;->Oooo00O(Llyiahf/vczjk/kl5;FLlyiahf/vczjk/qj8;I)Llyiahf/vczjk/kl5;

    move-result-object v0

    iget-wide v6, p0, Llyiahf/vczjk/tn1;->OooO00o:J

    sget-object v1, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v0, v6, v7, v1}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/q34;->OooOOO0:Llyiahf/vczjk/q34;

    invoke-static {v0}, Landroidx/compose/foundation/layout/OooO00o;->OooOOOO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget v1, Llyiahf/vczjk/ao1;->OooO:F

    const/4 v4, 0x0

    invoke-static {v0, v4, v1, v2}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-static {p3}, Llyiahf/vczjk/mt6;->OooOOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/z98;

    move-result-object v1

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/mt6;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/z98;Z)Llyiahf/vczjk/kl5;

    move-result-object v0

    shl-int/lit8 v1, v3, 0x3

    and-int/lit16 v1, v1, 0x1c00

    sget-object v3, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v4, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v3, v4, p3, v5}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v3

    iget v4, p3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {p3, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v6, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, p3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_b

    invoke-virtual {p3, v6}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_b
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, p3, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, p3, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, p3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_c

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_d

    :cond_c
    invoke-static {v4, p3, v4, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_d
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v0, p3, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/r31;->OooO00o:Llyiahf/vczjk/r31;

    shr-int/lit8 v1, v1, 0x6

    and-int/lit8 v1, v1, 0x70

    or-int/lit8 v1, v1, 0x6

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-interface {p2, v0, p3, v1}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p3, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_8
    move-object v5, p1

    goto :goto_9

    :cond_e
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_8

    :goto_9
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_f

    new-instance v3, Llyiahf/vczjk/fo1;

    move-object v4, p0

    move-object v6, p2

    move v7, p4

    move v8, p5

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/fo1;-><init>(Llyiahf/vczjk/tn1;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;II)V

    iput-object v3, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_f
    return-void
.end method

.method public static final OooO0O0(Ljava/lang/String;ZLlyiahf/vczjk/tn1;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V
    .locals 31

    move-object/from16 v0, p0

    move/from16 v12, p1

    move-object/from16 v13, p2

    move-object/from16 v14, p5

    move/from16 v15, p7

    const/16 v1, 0x10

    const/16 v2, 0x20

    move-object/from16 v9, p6

    check-cast v9, Llyiahf/vczjk/zf1;

    const v3, 0x2f25fb7f

    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    const/4 v3, 0x1

    and-int/lit8 v4, p8, 0x1

    const/4 v5, 0x4

    const/4 v6, 0x2

    if-eqz v4, :cond_0

    or-int/lit8 v4, v15, 0x6

    goto :goto_1

    :cond_0
    and-int/lit8 v4, v15, 0x6

    if-nez v4, :cond_2

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1

    move v4, v5

    goto :goto_0

    :cond_1
    move v4, v6

    :goto_0
    or-int/2addr v4, v15

    goto :goto_1

    :cond_2
    move v4, v15

    :goto_1
    and-int/lit8 v7, p8, 0x2

    if-eqz v7, :cond_3

    or-int/lit8 v4, v4, 0x30

    goto :goto_3

    :cond_3
    and-int/lit8 v7, v15, 0x30

    if-nez v7, :cond_5

    invoke-virtual {v9, v12}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v7

    if-eqz v7, :cond_4

    move v7, v2

    goto :goto_2

    :cond_4
    move v7, v1

    :goto_2
    or-int/2addr v4, v7

    :cond_5
    :goto_3
    and-int/lit8 v7, p8, 0x4

    if-eqz v7, :cond_6

    or-int/lit16 v4, v4, 0x180

    goto :goto_5

    :cond_6
    and-int/lit16 v7, v15, 0x180

    if-nez v7, :cond_8

    invoke-virtual {v9, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_7

    const/16 v7, 0x100

    goto :goto_4

    :cond_7
    const/16 v7, 0x80

    :goto_4
    or-int/2addr v4, v7

    :cond_8
    :goto_5
    and-int/lit8 v7, p8, 0x8

    if-eqz v7, :cond_a

    or-int/lit16 v4, v4, 0xc00

    :cond_9
    move-object/from16 v8, p3

    goto :goto_7

    :cond_a
    and-int/lit16 v8, v15, 0xc00

    if-nez v8, :cond_9

    move-object/from16 v8, p3

    invoke-virtual {v9, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_b

    const/16 v10, 0x800

    goto :goto_6

    :cond_b
    const/16 v10, 0x400

    :goto_6
    or-int/2addr v4, v10

    :goto_7
    and-int/lit8 v1, p8, 0x10

    if-eqz v1, :cond_d

    or-int/lit16 v4, v4, 0x6000

    :cond_c
    move-object/from16 v10, p4

    goto :goto_9

    :cond_d
    and-int/lit16 v10, v15, 0x6000

    if-nez v10, :cond_c

    move-object/from16 v10, p4

    invoke-virtual {v9, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_e

    const/16 v11, 0x4000

    goto :goto_8

    :cond_e
    const/16 v11, 0x2000

    :goto_8
    or-int/2addr v4, v11

    :goto_9
    and-int/lit8 v11, p8, 0x20

    move/from16 p6, v3

    const/high16 v3, 0x20000

    const/high16 v16, 0x30000

    if-eqz v11, :cond_f

    or-int v4, v4, v16

    goto :goto_b

    :cond_f
    and-int v11, v15, v16

    if-nez v11, :cond_11

    invoke-virtual {v9, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_10

    move v11, v3

    goto :goto_a

    :cond_10
    const/high16 v11, 0x10000

    :goto_a
    or-int/2addr v4, v11

    :cond_11
    :goto_b
    const v11, 0x12493

    and-int/2addr v11, v4

    const v6, 0x12492

    if-eq v11, v6, :cond_12

    move/from16 v6, p6

    goto :goto_c

    :cond_12
    const/4 v6, 0x0

    :goto_c
    and-int/lit8 v11, v4, 0x1

    invoke-virtual {v9, v11, v6}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v6

    if-eqz v6, :cond_23

    sget-object v17, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    if-eqz v7, :cond_13

    move-object/from16 v6, v17

    goto :goto_d

    :cond_13
    move-object v6, v8

    :goto_d
    if-eqz v1, :cond_14

    const/4 v1, 0x0

    goto :goto_e

    :cond_14
    move-object v1, v10

    :goto_e
    sget-object v7, Llyiahf/vczjk/ao1;->OooO0o:Llyiahf/vczjk/tb0;

    sget-object v8, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    sget v8, Llyiahf/vczjk/ao1;->OooO0oo:F

    invoke-static {v8}, Llyiahf/vczjk/tx;->OooO0oO(F)Llyiahf/vczjk/ox;

    move-result-object v10

    and-int/lit8 v11, v4, 0x70

    if-ne v11, v2, :cond_15

    move/from16 v2, p6

    goto :goto_f

    :cond_15
    const/4 v2, 0x0

    :goto_f
    const/high16 v11, 0x70000

    and-int/2addr v11, v4

    if-ne v11, v3, :cond_16

    move/from16 v3, p6

    goto :goto_10

    :cond_16
    const/4 v3, 0x0

    :goto_10
    or-int/2addr v2, v3

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_17

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v3, v2, :cond_18

    :cond_17
    new-instance v3, Llyiahf/vczjk/go1;

    invoke-direct {v3, v14, v12}, Llyiahf/vczjk/go1;-><init>(Llyiahf/vczjk/le3;Z)V

    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_18
    check-cast v3, Llyiahf/vczjk/le3;

    const/4 v2, 0x4

    invoke-static {v6, v12, v0, v3, v2}, Landroidx/compose/foundation/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;ZLjava/lang/String;Llyiahf/vczjk/le3;I)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/high16 v3, 0x3f800000    # 1.0f

    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget v11, Llyiahf/vczjk/ao1;->OooO00o:F

    sget v3, Llyiahf/vczjk/ao1;->OooO0O0:F

    sget v5, Llyiahf/vczjk/ao1;->OooO0OO:F

    invoke-static {v2, v11, v5, v3, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOO(Llyiahf/vczjk/kl5;FFFF)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/4 v3, 0x0

    const/4 v5, 0x2

    invoke-static {v2, v8, v3, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/16 v3, 0x36

    invoke-static {v10, v7, v9, v3}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    iget v5, v9, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v9, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v10, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v10, :cond_19

    invoke-virtual {v9, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_11

    :cond_19
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_11
    sget-object v10, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v9, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, v9, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v11, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v11, :cond_1a

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-static {v11, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1b

    :cond_1a
    invoke-static {v5, v9, v5, v7}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1b
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v9, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    if-nez v1, :cond_1c

    const v0, 0x2111652d

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const/4 v0, 0x0

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move/from16 v16, v4

    move-object/from16 v17, v6

    goto/16 :goto_14

    :cond_1c
    const v2, 0x2111652e

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget v18, Llyiahf/vczjk/ao1;->OooOO0:F

    const/16 v22, 0x2

    const/16 v19, 0x0

    move/from16 v20, v18

    move/from16 v21, v18

    invoke-static/range {v17 .. v22}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0O(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v5, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    const/4 v11, 0x0

    invoke-static {v5, v11}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v5

    iget v11, v9, Llyiahf/vczjk/zf1;->Oooo:I

    move/from16 v16, v4

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v9, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v17, v6

    iget-boolean v6, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_1d

    invoke-virtual {v9, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_12

    :cond_1d
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_12
    invoke-static {v5, v9, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v4, v9, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v3, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_1e

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_1f

    :cond_1e
    invoke-static {v11, v9, v11, v7}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1f
    invoke-static {v2, v9, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    if-eqz v12, :cond_20

    iget-wide v2, v13, Llyiahf/vczjk/tn1;->OooO0OO:J

    goto :goto_13

    :cond_20
    iget-wide v2, v13, Llyiahf/vczjk/tn1;->OooO0o0:J

    :goto_13
    new-instance v0, Llyiahf/vczjk/n21;

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/n21;-><init>(J)V

    const/4 v11, 0x0

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-interface {v1, v0, v9, v2}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move/from16 v0, p6

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v9, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_14
    if-eqz v12, :cond_21

    iget-wide v2, v13, Llyiahf/vczjk/tn1;->OooO0O0:J

    :goto_15
    move-wide/from16 v19, v2

    goto :goto_16

    :cond_21
    iget-wide v2, v13, Llyiahf/vczjk/tn1;->OooO0Oo:J

    goto :goto_15

    :goto_16
    new-instance v2, Llyiahf/vczjk/rn9;

    sget-wide v21, Llyiahf/vczjk/ao1;->OooOO0O:J

    sget-object v23, Llyiahf/vczjk/ao1;->OooOO0o:Llyiahf/vczjk/ib3;

    sget-wide v25, Llyiahf/vczjk/ao1;->OooOOO:J

    sget v27, Llyiahf/vczjk/ao1;->OooO0oO:I

    sget-wide v28, Llyiahf/vczjk/ao1;->OooOOO0:J

    const/16 v24, 0x0

    const v30, 0xfd7f78

    move-object/from16 v18, v2

    invoke-direct/range {v18 .. v30}, Llyiahf/vczjk/rn9;-><init>(JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ba3;JIJI)V

    const/high16 v0, 0x3f800000    # 1.0f

    float-to-double v3, v0

    const-wide/16 v5, 0x0

    cmpl-double v3, v3, v5

    if-lez v3, :cond_22

    :goto_17
    move-object v10, v1

    goto :goto_18

    :cond_22
    const-string v3, "invalid weight; must be greater than zero"

    invoke-static {v3}, Llyiahf/vczjk/nz3;->OooO00o(Ljava/lang/String;)V

    goto :goto_17

    :goto_18
    new-instance v1, Landroidx/compose/foundation/layout/LayoutWeightElement;

    const/4 v3, 0x1

    invoke-direct {v1, v0, v3}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    and-int/lit8 v0, v16, 0xe

    const/high16 v4, 0x180000

    or-int/2addr v0, v4

    const/4 v7, 0x0

    const/4 v8, 0x0

    move v4, v3

    const/4 v3, 0x0

    move v5, v4

    const/4 v4, 0x0

    move v6, v5

    const/4 v5, 0x0

    move v11, v6

    const/4 v6, 0x1

    move/from16 v16, v11

    const/16 v11, 0x3b8

    move/from16 v12, v16

    move-object/from16 v16, v10

    move v10, v0

    move-object/from16 v0, p0

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/sb;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;Llyiahf/vczjk/rn9;Llyiahf/vczjk/oe3;IZIILlyiahf/vczjk/w21;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v9, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v5, v16

    move-object/from16 v4, v17

    goto :goto_19

    :cond_23
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v4, v8

    move-object v5, v10

    :goto_19
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v9

    if-eqz v9, :cond_24

    new-instance v0, Llyiahf/vczjk/ho1;

    move-object/from16 v1, p0

    move/from16 v2, p1

    move/from16 v8, p8

    move-object v3, v13

    move-object v6, v14

    move v7, v15

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/ho1;-><init>(Ljava/lang/String;ZLlyiahf/vczjk/tn1;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;Llyiahf/vczjk/le3;II)V

    iput-object v0, v9, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_24
    return-void
.end method

.method public static final OooO0OO(Llyiahf/vczjk/c07;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/tn1;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V
    .locals 14

    move-object/from16 v4, p3

    move-object/from16 v5, p4

    move/from16 v6, p6

    move-object/from16 v11, p5

    check-cast v11, Llyiahf/vczjk/zf1;

    const v0, 0x56425b5b

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p7, 0x1

    if-eqz v0, :cond_0

    or-int/lit8 v0, v6, 0x6

    goto :goto_1

    :cond_0
    and-int/lit8 v0, v6, 0x6

    if-nez v0, :cond_2

    invoke-virtual {v11, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    const/4 v0, 0x4

    goto :goto_0

    :cond_1
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, v6

    goto :goto_1

    :cond_2
    move v0, v6

    :goto_1
    and-int/lit8 v1, p7, 0x2

    if-eqz v1, :cond_3

    or-int/lit8 v0, v0, 0x30

    goto :goto_3

    :cond_3
    and-int/lit8 v1, v6, 0x30

    if-nez v1, :cond_5

    invoke-virtual {v11, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_4

    const/16 v1, 0x20

    goto :goto_2

    :cond_4
    const/16 v1, 0x10

    :goto_2
    or-int/2addr v0, v1

    :cond_5
    :goto_3
    and-int/lit8 v1, p7, 0x4

    if-eqz v1, :cond_7

    or-int/lit16 v0, v0, 0x180

    :cond_6
    move-object/from16 v2, p2

    goto :goto_5

    :cond_7
    and-int/lit16 v2, v6, 0x180

    if-nez v2, :cond_6

    move-object/from16 v2, p2

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_8

    const/16 v3, 0x100

    goto :goto_4

    :cond_8
    const/16 v3, 0x80

    :goto_4
    or-int/2addr v0, v3

    :goto_5
    and-int/lit8 v3, p7, 0x8

    if-eqz v3, :cond_9

    or-int/lit16 v0, v0, 0xc00

    goto :goto_7

    :cond_9
    and-int/lit16 v3, v6, 0xc00

    if-nez v3, :cond_b

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_a

    const/16 v3, 0x800

    goto :goto_6

    :cond_a
    const/16 v3, 0x400

    :goto_6
    or-int/2addr v0, v3

    :cond_b
    :goto_7
    and-int/lit8 v3, p7, 0x10

    if-eqz v3, :cond_c

    or-int/lit16 v0, v0, 0x6000

    goto :goto_9

    :cond_c
    and-int/lit16 v3, v6, 0x6000

    if-nez v3, :cond_e

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_d

    const/16 v3, 0x4000

    goto :goto_8

    :cond_d
    const/16 v3, 0x2000

    :goto_8
    or-int/2addr v0, v3

    :cond_e
    :goto_9
    and-int/lit16 v3, v0, 0x2493

    const/16 v7, 0x2492

    if-eq v3, v7, :cond_f

    const/4 v3, 0x1

    goto :goto_a

    :cond_f
    const/4 v3, 0x0

    :goto_a
    and-int/lit8 v7, v0, 0x1

    invoke-virtual {v11, v7, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v3

    if-eqz v3, :cond_11

    if-eqz v1, :cond_10

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_b

    :cond_10
    move-object v1, v2

    :goto_b
    new-instance v2, Llyiahf/vczjk/ko1;

    invoke-direct {v2, v4, v1, v5}, Llyiahf/vczjk/ko1;-><init>(Llyiahf/vczjk/tn1;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)V

    const v3, 0x2f709e7d

    invoke-static {v3, v2, v11}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v10

    and-int/lit8 v2, v0, 0xe

    or-int/lit16 v2, v2, 0xd80

    and-int/lit8 v0, v0, 0x70

    or-int v12, v2, v0

    const/4 v13, 0x0

    sget-object v9, Llyiahf/vczjk/mo1;->OooO00o:Llyiahf/vczjk/d07;

    move-object v7, p0

    move-object v8, p1

    invoke-static/range {v7 .. v13}, Llyiahf/vczjk/of;->OooO00o(Llyiahf/vczjk/c07;Llyiahf/vczjk/le3;Llyiahf/vczjk/d07;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    move-object v3, v1

    goto :goto_c

    :cond_11
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v3, v2

    :goto_c
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_12

    new-instance v0, Llyiahf/vczjk/lo1;

    move-object v1, p0

    move-object v2, p1

    move/from16 v7, p7

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/lo1;-><init>(Llyiahf/vczjk/c07;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/tn1;Llyiahf/vczjk/oe3;II)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_12
    return-void
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/c07;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V
    .locals 25

    move/from16 v5, p5

    move-object/from16 v11, p4

    check-cast v11, Llyiahf/vczjk/zf1;

    const v0, 0x2a7121cd

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p6, 0x1

    if-eqz v0, :cond_0

    or-int/lit8 v0, v5, 0x6

    move-object/from16 v1, p0

    goto :goto_1

    :cond_0
    and-int/lit8 v0, v5, 0x6

    move-object/from16 v1, p0

    if-nez v0, :cond_2

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    const/4 v0, 0x4

    goto :goto_0

    :cond_1
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, v5

    goto :goto_1

    :cond_2
    move v0, v5

    :goto_1
    and-int/lit8 v2, p6, 0x2

    if-eqz v2, :cond_4

    or-int/lit8 v0, v0, 0x30

    :cond_3
    move-object/from16 v2, p1

    goto :goto_3

    :cond_4
    and-int/lit8 v2, v5, 0x30

    if-nez v2, :cond_3

    move-object/from16 v2, p1

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    const/16 v3, 0x20

    goto :goto_2

    :cond_5
    const/16 v3, 0x10

    :goto_2
    or-int/2addr v0, v3

    :goto_3
    and-int/lit8 v3, p6, 0x4

    if-eqz v3, :cond_7

    or-int/lit16 v0, v0, 0x180

    :cond_6
    move-object/from16 v4, p2

    goto :goto_5

    :cond_7
    and-int/lit16 v4, v5, 0x180

    if-nez v4, :cond_6

    move-object/from16 v4, p2

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_8

    const/16 v6, 0x100

    goto :goto_4

    :cond_8
    const/16 v6, 0x80

    :goto_4
    or-int/2addr v0, v6

    :goto_5
    and-int/lit8 v6, p6, 0x8

    if-eqz v6, :cond_9

    or-int/lit16 v0, v0, 0xc00

    move-object/from16 v10, p3

    goto :goto_7

    :cond_9
    and-int/lit16 v6, v5, 0xc00

    move-object/from16 v10, p3

    if-nez v6, :cond_b

    invoke-virtual {v11, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_a

    const/16 v6, 0x800

    goto :goto_6

    :cond_a
    const/16 v6, 0x400

    :goto_6
    or-int/2addr v0, v6

    :cond_b
    :goto_7
    and-int/lit16 v6, v0, 0x493

    const/16 v7, 0x492

    const/4 v8, 0x0

    if-eq v6, v7, :cond_c

    const/4 v6, 0x1

    goto :goto_8

    :cond_c
    move v6, v8

    :goto_8
    and-int/lit8 v7, v0, 0x1

    invoke-virtual {v11, v7, v6}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v6

    if-eqz v6, :cond_17

    if-eqz v3, :cond_d

    sget-object v3, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_9

    :cond_d
    move-object v3, v4

    :goto_9
    sget-object v4, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Landroid/content/Context;

    sget-object v6, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v11, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Landroid/content/res/Configuration;

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v11, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v6, v7

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v6, :cond_e

    sget-object v6, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v7, v6, :cond_16

    :cond_e
    sget-object v6, Llyiahf/vczjk/mo1;->OooO0O0:Llyiahf/vczjk/tn1;

    iget-wide v12, v6, Llyiahf/vczjk/tn1;->OooO00o:J

    const v7, 0x1010031

    filled-new-array {v7}, [I

    move-result-object v7

    const v9, 0x1030086

    invoke-virtual {v4, v9, v7}, Landroid/content/Context;->obtainStyledAttributes(I[I)Landroid/content/res/TypedArray;

    move-result-object v7

    invoke-static {v12, v13}, Llyiahf/vczjk/v34;->ooOO(J)I

    move-result v9

    invoke-virtual {v7, v8, v9}, Landroid/content/res/TypedArray;->getColor(II)I

    move-result v14

    invoke-virtual {v7}, Landroid/content/res/TypedArray;->recycle()V

    if-ne v14, v9, :cond_f

    :goto_a
    move-wide v15, v12

    goto :goto_b

    :cond_f
    invoke-static {v14}, Llyiahf/vczjk/v34;->OooO0OO(I)J

    move-result-wide v12

    goto :goto_a

    :goto_b
    const v7, 0x1010036

    filled-new-array {v7}, [I

    move-result-object v7

    const v9, 0x1030080

    invoke-virtual {v4, v9, v7}, Landroid/content/Context;->obtainStyledAttributes(I[I)Landroid/content/res/TypedArray;

    move-result-object v4

    invoke-virtual {v4, v8}, Landroid/content/res/TypedArray;->getColorStateList(I)Landroid/content/res/ColorStateList;

    move-result-object v7

    invoke-virtual {v4}, Landroid/content/res/TypedArray;->recycle()V

    iget-wide v8, v6, Llyiahf/vczjk/tn1;->OooO0O0:J

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->ooOO(J)I

    move-result v4

    const/4 v12, 0x0

    if-eqz v7, :cond_10

    const v13, 0x101009e

    filled-new-array {v13}, [I

    move-result-object v13

    invoke-virtual {v7, v13, v4}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    move-result v13

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    goto :goto_c

    :cond_10
    move-object v13, v12

    :goto_c
    if-eqz v13, :cond_12

    invoke-virtual {v13}, Ljava/lang/Integer;->intValue()I

    move-result v14

    if-ne v14, v4, :cond_11

    goto :goto_d

    :cond_11
    invoke-virtual {v13}, Ljava/lang/Integer;->intValue()I

    move-result v4

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooO0OO(I)J

    move-result-wide v8

    :cond_12
    :goto_d
    move-wide/from16 v17, v8

    iget-wide v8, v6, Llyiahf/vczjk/tn1;->OooO0Oo:J

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->ooOO(J)I

    move-result v4

    if-eqz v7, :cond_13

    const v6, -0x101009e

    filled-new-array {v6}, [I

    move-result-object v6

    invoke-virtual {v7, v6, v4}, Landroid/content/res/ColorStateList;->getColorForState([II)I

    move-result v6

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    :cond_13
    if-eqz v12, :cond_15

    invoke-virtual {v12}, Ljava/lang/Integer;->intValue()I

    move-result v6

    if-ne v6, v4, :cond_14

    goto :goto_e

    :cond_14
    invoke-virtual {v12}, Ljava/lang/Integer;->intValue()I

    move-result v4

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooO0OO(I)J

    move-result-wide v8

    :cond_15
    :goto_e
    move-wide/from16 v21, v8

    new-instance v14, Llyiahf/vczjk/tn1;

    move-wide/from16 v19, v17

    move-wide/from16 v23, v21

    invoke-direct/range {v14 .. v24}, Llyiahf/vczjk/tn1;-><init>(JJJJJ)V

    invoke-virtual {v11, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v7, v14

    :cond_16
    move-object v9, v7

    check-cast v9, Llyiahf/vczjk/tn1;

    and-int/lit16 v4, v0, 0x3fe

    shl-int/lit8 v0, v0, 0x3

    const v6, 0xe000

    and-int/2addr v0, v6

    or-int v12, v4, v0

    const/4 v13, 0x0

    move-object v6, v1

    move-object v7, v2

    move-object v8, v3

    invoke-static/range {v6 .. v13}, Llyiahf/vczjk/mo1;->OooO0OO(Llyiahf/vczjk/c07;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/tn1;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    move-object v3, v8

    goto :goto_f

    :cond_17
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v3, v4

    :goto_f
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v7

    if-eqz v7, :cond_18

    new-instance v0, Llyiahf/vczjk/io1;

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v4, p3

    move/from16 v6, p6

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/io1;-><init>(Llyiahf/vczjk/c07;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;II)V

    iput-object v0, v7, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_18
    return-void
.end method
