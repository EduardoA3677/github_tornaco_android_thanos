.class public abstract Llyiahf/vczjk/kla;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/h1a;

.field public static final OooO0O0:Llyiahf/vczjk/h1a;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    sget-object v0, Llyiahf/vczjk/cp5;->OooO0Oo:Llyiahf/vczjk/cu1;

    const/16 v1, 0x1f4

    const/4 v2, 0x0

    const/4 v3, 0x2

    invoke-static {v1, v2, v0, v3}, Llyiahf/vczjk/ng0;->OooooO0(IILlyiahf/vczjk/ik2;I)Llyiahf/vczjk/h1a;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/kla;->OooO00o:Llyiahf/vczjk/h1a;

    sget-object v0, Llyiahf/vczjk/cp5;->OooO00o:Llyiahf/vczjk/cu1;

    invoke-static {v1, v2, v0, v3}, Llyiahf/vczjk/ng0;->OooooO0(IILlyiahf/vczjk/ik2;I)Llyiahf/vczjk/h1a;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/kla;->OooO0O0:Llyiahf/vczjk/h1a;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFFFLlyiahf/vczjk/rf1;I)V
    .locals 28

    const/4 v0, 0x1

    move-object/from16 v1, p11

    check-cast v1, Llyiahf/vczjk/zf1;

    const v2, 0x3926fbd5

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    const v2, 0x2592490

    or-int v2, p12, v2

    const v3, 0x2492493

    and-int/2addr v3, v2

    const v4, 0x2492492

    const/4 v5, 0x0

    if-eq v3, v4, :cond_0

    move v3, v0

    goto :goto_0

    :cond_0
    move v3, v5

    :goto_0
    and-int/2addr v2, v0

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_6

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v2, p12, 0x1

    if-eqz v2, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v2

    if-eqz v2, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-wide/from16 v2, p1

    move-wide/from16 v6, p3

    move-object/from16 v8, p5

    move-object/from16 v4, p6

    move/from16 v9, p7

    move/from16 v11, p8

    move/from16 v10, p9

    move/from16 v12, p10

    goto :goto_2

    :cond_2
    :goto_1
    sget v2, Llyiahf/vczjk/hla;->OooO00o:F

    sget-object v2, Llyiahf/vczjk/ga7;->OooO00o:Llyiahf/vczjk/y21;

    invoke-static {v2, v1}, Llyiahf/vczjk/z21;->OooO0o0(Llyiahf/vczjk/y21;Llyiahf/vczjk/rf1;)J

    move-result-wide v2

    sget-object v4, Llyiahf/vczjk/ga7;->OooO0O0:Llyiahf/vczjk/y21;

    invoke-static {v4, v1}, Llyiahf/vczjk/z21;->OooO0o0(Llyiahf/vczjk/y21;Llyiahf/vczjk/rf1;)J

    move-result-wide v6

    sget-object v4, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/f62;

    sget v9, Llyiahf/vczjk/ix0;->OooO00o:F

    invoke-interface {v8, v9}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v8

    new-instance v9, Llyiahf/vczjk/h79;

    const/4 v10, 0x1

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/16 v13, 0x1a

    move/from16 p2, v8

    move-object/from16 p1, v9

    move/from16 p4, v10

    move/from16 p5, v11

    move/from16 p3, v12

    move/from16 p6, v13

    invoke-direct/range {p1 .. p6}, Llyiahf/vczjk/h79;-><init>(FFIII)V

    move-object/from16 v8, p1

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/f62;

    sget v9, Llyiahf/vczjk/ix0;->OooO0o0:F

    invoke-interface {v4, v9}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v4

    new-instance v9, Llyiahf/vczjk/h79;

    const/4 v10, 0x1

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/16 v13, 0x1a

    move/from16 p2, v4

    move-object/from16 p1, v9

    move/from16 p4, v10

    move/from16 p5, v11

    move/from16 p3, v12

    move/from16 p6, v13

    invoke-direct/range {p1 .. p6}, Llyiahf/vczjk/h79;-><init>(FFIII)V

    move-object/from16 v4, p1

    sget v9, Llyiahf/vczjk/hla;->OooO0oO:F

    sget v10, Llyiahf/vczjk/hla;->OooO0o0:F

    const/high16 v11, 0x3f800000    # 1.0f

    move v12, v10

    :goto_2
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOo0()V

    sget v13, Llyiahf/vczjk/hla;->OooO0Oo:F

    move-object/from16 v15, p0

    invoke-static {v15, v13}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v13

    sget-object v14, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v14, v5}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v5

    iget v14, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v0

    invoke-static {v1, v13}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v13

    sget-object v17, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-wide/from16 p2, v2

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v3, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v3, :cond_3

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_3
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v2, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_4

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_5

    :cond_4
    invoke-static {v14, v1, v14, v0}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_5
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v13, v1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    move-object/from16 p1, v0

    move-object/from16 p7, v4

    move-wide/from16 p4, v6

    move-object/from16 p6, v8

    move/from16 p8, v9

    move/from16 p10, v10

    move/from16 p9, v11

    move/from16 p11, v12

    invoke-static/range {p1 .. p11}, Landroidx/compose/material3/internal/OooO0O0;->OooO0OO(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFFF)Llyiahf/vczjk/kl5;

    move-result-object v0

    move-object/from16 v12, p1

    move-wide/from16 v2, p2

    move-wide/from16 v6, p4

    move-object/from16 v8, p6

    move-object/from16 v4, p7

    move/from16 v9, p8

    move/from16 v11, p9

    move/from16 v10, p10

    move/from16 v5, p11

    invoke-static {v1, v0}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    invoke-static {v12}, Llyiahf/vczjk/rl6;->OooOo0o(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-static {v1, v0}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const/4 v0, 0x1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-wide/from16 v16, v2

    move-object/from16 v21, v4

    move/from16 v25, v5

    move-wide/from16 v18, v6

    move-object/from16 v20, v8

    move/from16 v22, v9

    move/from16 v24, v10

    move/from16 v23, v11

    goto :goto_4

    :cond_6
    move-object/from16 v15, p0

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-wide/from16 v16, p1

    move-wide/from16 v18, p3

    move-object/from16 v20, p5

    move-object/from16 v21, p6

    move/from16 v22, p7

    move/from16 v23, p8

    move/from16 v24, p9

    move/from16 v25, p10

    :goto_4
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_7

    new-instance v14, Llyiahf/vczjk/ila;

    const/16 v27, 0x0

    move/from16 v26, p12

    invoke-direct/range {v14 .. v27}, Llyiahf/vczjk/ila;-><init>(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFFFII)V

    iput-object v14, v0, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_7
    return-void
.end method

.method public static final OooO0O0(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFFFLlyiahf/vczjk/rf1;I)V
    .locals 25

    const/4 v0, 0x0

    const/4 v1, 0x1

    move-object/from16 v2, p11

    check-cast v2, Llyiahf/vczjk/zf1;

    const v3, -0x7b6a5971

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    move-wide/from16 v6, p1

    invoke-virtual {v2, v6, v7}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v3

    if-eqz v3, :cond_0

    const/16 v3, 0x20

    goto :goto_0

    :cond_0
    const/16 v3, 0x10

    :goto_0
    or-int v3, p12, v3

    const v4, 0x2592480

    or-int/2addr v3, v4

    const v4, 0x2492493

    and-int/2addr v4, v3

    const v5, 0x2492492

    if-eq v4, v5, :cond_1

    move v4, v1

    goto :goto_1

    :cond_1
    move v4, v0

    :goto_1
    and-int/2addr v3, v1

    invoke-virtual {v2, v3, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v3

    if-eqz v3, :cond_e

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v3, p12, 0x1

    if-eqz v3, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v3

    if-eqz v3, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-wide/from16 v11, p3

    move-object/from16 v13, p5

    move-object/from16 v14, p6

    move/from16 v15, p7

    move/from16 v3, p8

    move/from16 v17, p9

    move/from16 v18, p10

    goto :goto_3

    :cond_3
    :goto_2
    sget v3, Llyiahf/vczjk/hla;->OooO00o:F

    sget-object v3, Llyiahf/vczjk/ga7;->OooO0O0:Llyiahf/vczjk/y21;

    invoke-static {v3, v2}, Llyiahf/vczjk/z21;->OooO0o0(Llyiahf/vczjk/y21;Llyiahf/vczjk/rf1;)J

    move-result-wide v8

    sget-object v3, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/f62;

    sget v10, Llyiahf/vczjk/xz4;->OooO00o:F

    invoke-interface {v5, v10}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v5

    new-instance v10, Llyiahf/vczjk/h79;

    const/4 v11, 0x1

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/16 v14, 0x1a

    move/from16 p4, v5

    move-object/from16 p3, v10

    move/from16 p6, v11

    move/from16 p7, v12

    move/from16 p5, v13

    move/from16 p8, v14

    invoke-direct/range {p3 .. p8}, Llyiahf/vczjk/h79;-><init>(FFIII)V

    move-object/from16 v5, p3

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/f62;

    sget v10, Llyiahf/vczjk/xz4;->OooO0o0:F

    invoke-interface {v3, v10}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v3

    new-instance v10, Llyiahf/vczjk/h79;

    const/4 v11, 0x1

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/16 v14, 0x1a

    move/from16 p4, v3

    move-object/from16 p3, v10

    move/from16 p6, v11

    move/from16 p7, v12

    move/from16 p5, v13

    move/from16 p8, v14

    invoke-direct/range {p3 .. p8}, Llyiahf/vczjk/h79;-><init>(FFIII)V

    move-object/from16 v3, p3

    sget v10, Llyiahf/vczjk/hla;->OooO0o:F

    sget v11, Llyiahf/vczjk/hla;->OooO00o:F

    move-object v14, v3

    move-object v13, v5

    move v15, v10

    move/from16 v17, v11

    move/from16 v18, v17

    const/high16 v3, 0x3f800000    # 1.0f

    move-wide v11, v8

    :goto_3
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOo0()V

    invoke-static {v0, v2}, Llyiahf/vczjk/rs;->OoooOO0(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/jy3;

    move-result-object v5

    sget v8, Llyiahf/vczjk/ea7;->OooO00o:F

    new-instance v8, Llyiahf/vczjk/vj4;

    new-instance v9, Llyiahf/vczjk/uj4;

    invoke-direct {v9}, Llyiahf/vczjk/uj4;-><init>()V

    const/16 v10, 0x6d6

    iput v10, v9, Llyiahf/vczjk/uj4;->OooO00o:I

    const/16 v16, 0x0

    const/high16 p11, 0x3f800000    # 1.0f

    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    invoke-virtual {v9, v0, v4}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    move-result-object v4

    sget-object v1, Llyiahf/vczjk/ea7;->OooO0Oo:Llyiahf/vczjk/cu1;

    iput-object v1, v4, Llyiahf/vczjk/tj4;->OooO0O0:Llyiahf/vczjk/ik2;

    invoke-static/range {p11 .. p11}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    const/16 v0, 0x3e8

    invoke-virtual {v9, v0, v4}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    invoke-direct {v8, v9}, Llyiahf/vczjk/vj4;-><init>(Llyiahf/vczjk/uj4;)V

    const/4 v0, 0x6

    invoke-static {v8, v0}, Llyiahf/vczjk/ng0;->Oooo00O(Llyiahf/vczjk/xj2;I)Llyiahf/vczjk/cy3;

    move-result-object v4

    const/4 v8, 0x0

    const/high16 v9, 0x3f800000    # 1.0f

    const-string v19, "LinearWavyProgressIndicatorFirstHead"

    const/16 v20, 0x71b8

    const/16 v21, 0x0

    move-object/from16 p8, v2

    move-object/from16 p6, v4

    move-object/from16 p3, v5

    move/from16 p4, v8

    move/from16 p5, v9

    move-object/from16 p7, v19

    move/from16 p9, v20

    move/from16 p10, v21

    invoke-static/range {p3 .. p10}, Llyiahf/vczjk/rs;->OooO0o0(Llyiahf/vczjk/jy3;FFLlyiahf/vczjk/cy3;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/dy3;

    move-result-object v2

    move-object/from16 v4, p8

    move/from16 v8, p9

    new-instance v9, Llyiahf/vczjk/vj4;

    new-instance v8, Llyiahf/vczjk/uj4;

    invoke-direct {v8}, Llyiahf/vczjk/uj4;-><init>()V

    iput v10, v8, Llyiahf/vczjk/uj4;->OooO00o:I

    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v10

    const/16 v0, 0xfa

    invoke-virtual {v8, v0, v10}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    move-result-object v0

    iput-object v1, v0, Llyiahf/vczjk/tj4;->OooO0O0:Llyiahf/vczjk/ik2;

    invoke-static/range {p11 .. p11}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    const/16 v10, 0x4e2

    invoke-virtual {v8, v10, v0}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    invoke-direct {v9, v8}, Llyiahf/vczjk/vj4;-><init>(Llyiahf/vczjk/uj4;)V

    const/4 v0, 0x6

    invoke-static {v9, v0}, Llyiahf/vczjk/ng0;->Oooo00O(Llyiahf/vczjk/xj2;I)Llyiahf/vczjk/cy3;

    move-result-object v8

    const/4 v0, 0x0

    const/high16 v9, 0x3f800000    # 1.0f

    const-string v10, "LinearWavyProgressIndicatorFirstTail"

    const/16 v21, 0x0

    move/from16 p4, v0

    move-object/from16 p8, v4

    move-object/from16 p3, v5

    move-object/from16 p6, v8

    move/from16 p5, v9

    move-object/from16 p7, v10

    move/from16 p10, v21

    const/16 p9, 0x71b8

    invoke-static/range {p3 .. p10}, Llyiahf/vczjk/rs;->OooO0o0(Llyiahf/vczjk/jy3;FFLlyiahf/vczjk/cy3;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/dy3;

    move-result-object v0

    move/from16 v8, p9

    new-instance v9, Llyiahf/vczjk/vj4;

    new-instance v10, Llyiahf/vczjk/uj4;

    invoke-direct {v10}, Llyiahf/vczjk/uj4;-><init>()V

    const/16 v8, 0x6d6

    iput v8, v10, Llyiahf/vczjk/uj4;->OooO00o:I

    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v8

    move/from16 v21, v3

    const/16 v3, 0x28a

    invoke-virtual {v10, v3, v8}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    move-result-object v3

    iput-object v1, v3, Llyiahf/vczjk/tj4;->OooO0O0:Llyiahf/vczjk/ik2;

    invoke-static/range {p11 .. p11}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v3

    const/16 v8, 0x5dc

    invoke-virtual {v10, v8, v3}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    invoke-direct {v9, v10}, Llyiahf/vczjk/vj4;-><init>(Llyiahf/vczjk/uj4;)V

    const/4 v3, 0x6

    invoke-static {v9, v3}, Llyiahf/vczjk/ng0;->Oooo00O(Llyiahf/vczjk/xj2;I)Llyiahf/vczjk/cy3;

    move-result-object v8

    const/4 v3, 0x0

    const/high16 v9, 0x3f800000    # 1.0f

    const-string v10, "LinearWavyProgressIndicatorSecondHead"

    const/16 v22, 0x0

    move/from16 p4, v3

    move-object/from16 p8, v4

    move-object/from16 p3, v5

    move-object/from16 p6, v8

    move/from16 p5, v9

    move-object/from16 p7, v10

    move/from16 p10, v22

    const/16 p9, 0x71b8

    invoke-static/range {p3 .. p10}, Llyiahf/vczjk/rs;->OooO0o0(Llyiahf/vczjk/jy3;FFLlyiahf/vczjk/cy3;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/dy3;

    move-result-object v3

    move/from16 v8, p9

    new-instance v9, Llyiahf/vczjk/vj4;

    new-instance v10, Llyiahf/vczjk/uj4;

    invoke-direct {v10}, Llyiahf/vczjk/uj4;-><init>()V

    const/16 v8, 0x6d6

    iput v8, v10, Llyiahf/vczjk/uj4;->OooO00o:I

    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v8

    move-object/from16 p8, v4

    const/16 v4, 0x384

    invoke-virtual {v10, v4, v8}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    move-result-object v4

    iput-object v1, v4, Llyiahf/vczjk/tj4;->OooO0O0:Llyiahf/vczjk/ik2;

    invoke-static/range {p11 .. p11}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    const/16 v8, 0x6d6

    invoke-virtual {v10, v8, v1}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    invoke-direct {v9, v10}, Llyiahf/vczjk/vj4;-><init>(Llyiahf/vczjk/uj4;)V

    const/4 v1, 0x6

    invoke-static {v9, v1}, Llyiahf/vczjk/ng0;->Oooo00O(Llyiahf/vczjk/xj2;I)Llyiahf/vczjk/cy3;

    move-result-object v1

    const/4 v4, 0x0

    const/high16 v8, 0x3f800000    # 1.0f

    const-string v9, "LinearWavyProgressIndicatorSecondTail"

    const/4 v10, 0x0

    move-object/from16 p6, v1

    move/from16 p4, v4

    move-object/from16 p3, v5

    move/from16 p5, v8

    move-object/from16 p7, v9

    move/from16 p10, v10

    const/16 p9, 0x71b8

    invoke-static/range {p3 .. p10}, Llyiahf/vczjk/rs;->OooO0o0(Llyiahf/vczjk/jy3;FFLlyiahf/vczjk/cy3;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/dy3;

    move-result-object v1

    move-object/from16 v4, p8

    sget-object v5, Llyiahf/vczjk/o0OO0o;->OooO0Oo:Llyiahf/vczjk/kl5;

    move-object/from16 v8, p0

    invoke-interface {v8, v5}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/rl6;->OooOo0o(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget v9, Llyiahf/vczjk/hla;->OooO0OO:F

    sget v10, Llyiahf/vczjk/hla;->OooO0O0:F

    invoke-static {v5, v9, v10}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOO0(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/zsa;->Oooo000(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v4, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    move-object/from16 p3, v5

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v9, :cond_4

    if-ne v10, v5, :cond_5

    :cond_4
    new-instance v10, Llyiahf/vczjk/jla;

    const/4 v9, 0x0

    invoke-direct {v10, v2, v9}, Llyiahf/vczjk/jla;-><init>(Llyiahf/vczjk/dy3;I)V

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v10, Llyiahf/vczjk/le3;

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v2, :cond_6

    if-ne v9, v5, :cond_7

    :cond_6
    new-instance v9, Llyiahf/vczjk/jla;

    const/4 v2, 0x1

    invoke-direct {v9, v0, v2}, Llyiahf/vczjk/jla;-><init>(Llyiahf/vczjk/dy3;I)V

    invoke-virtual {v4, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v9, Llyiahf/vczjk/le3;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v0, :cond_8

    if-ne v2, v5, :cond_9

    :cond_8
    new-instance v2, Llyiahf/vczjk/jla;

    const/4 v0, 0x2

    invoke-direct {v2, v3, v0}, Llyiahf/vczjk/jla;-><init>(Llyiahf/vczjk/dy3;I)V

    invoke-virtual {v4, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    check-cast v2, Llyiahf/vczjk/le3;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v0, :cond_a

    if-ne v3, v5, :cond_b

    :cond_a
    new-instance v3, Llyiahf/vczjk/jla;

    const/4 v0, 0x3

    invoke-direct {v3, v1, v0}, Llyiahf/vczjk/jla;-><init>(Llyiahf/vczjk/dy3;I)V

    invoke-virtual {v4, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    check-cast v3, Llyiahf/vczjk/le3;

    cmpg-float v0, v21, v16

    if-gez v0, :cond_c

    goto :goto_4

    :cond_c
    move/from16 v16, v21

    :goto_4
    cmpl-float v0, v16, p11

    if-lez v0, :cond_d

    move/from16 v16, p11

    :cond_d
    move-object v8, v3

    move-object v0, v4

    move-object v5, v10

    move-object/from16 v4, p3

    move-wide/from16 v23, v6

    move-object v7, v2

    move-object v6, v9

    move-wide/from16 v9, v23

    invoke-static/range {v4 .. v18}, Landroidx/compose/material3/internal/OooO0O0;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFFF)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    move-wide v8, v11

    move-object v10, v13

    move-object v11, v14

    move v12, v15

    move/from16 v14, v17

    move/from16 v15, v18

    move/from16 v13, v21

    goto :goto_5

    :cond_e
    move-object v0, v2

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-wide/from16 v8, p3

    move-object/from16 v10, p5

    move-object/from16 v11, p6

    move/from16 v12, p7

    move/from16 v13, p8

    move/from16 v14, p9

    move/from16 v15, p10

    :goto_5
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_f

    new-instance v4, Llyiahf/vczjk/ila;

    const/16 v17, 0x1

    move-object/from16 v5, p0

    move-wide/from16 v6, p1

    move/from16 v16, p12

    invoke-direct/range {v4 .. v17}, Llyiahf/vczjk/ila;-><init>(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFFFII)V

    iput-object v4, v0, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_f
    return-void
.end method
