.class public abstract Llyiahf/vczjk/qqa;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/uj3;

.field public static final OooO0O0:Llyiahf/vczjk/rp3;

.field public static final OooO0OO:Llyiahf/vczjk/i01;

.field public static OooO0Oo:Llyiahf/vczjk/i01;

.field public static final synthetic OooO0o:I

.field public static final OooO0o0:Llyiahf/vczjk/pp3;

.field public static OooO0oO:Llyiahf/vczjk/qv3;

.field public static OooO0oo:Llyiahf/vczjk/qv3;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/uj3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/qqa;->OooO00o:Llyiahf/vczjk/uj3;

    new-instance v0, Llyiahf/vczjk/rp3;

    const/16 v1, 0x10

    invoke-direct {v0, v1}, Llyiahf/vczjk/rp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/qqa;->OooO0O0:Llyiahf/vczjk/rp3;

    new-instance v0, Llyiahf/vczjk/i01;

    const/4 v1, 0x0

    invoke-direct {v0, v1, v1, v1}, Llyiahf/vczjk/i01;-><init>(Ljava/lang/reflect/Method;Ljava/lang/reflect/Method;Ljava/lang/reflect/Method;)V

    sput-object v0, Llyiahf/vczjk/qqa;->OooO0OO:Llyiahf/vczjk/i01;

    new-instance v0, Llyiahf/vczjk/pp3;

    const/16 v1, 0x19

    invoke-direct {v0, v1}, Llyiahf/vczjk/pp3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/qqa;->OooO0o0:Llyiahf/vczjk/pp3;

    return-void
.end method

.method public static final OooO(Llyiahf/vczjk/ma0;Llyiahf/vczjk/yu;Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 10

    move-object/from16 v6, p6

    check-cast v6, Llyiahf/vczjk/zf1;

    const v0, 0x2f50a1bb

    invoke-virtual {v6, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v6, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int v0, p7, v0

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    const/16 v2, 0x20

    goto :goto_1

    :cond_1
    const/16 v2, 0x10

    :goto_1
    or-int/2addr v0, v2

    invoke-virtual {v6, p2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_2

    const/16 v2, 0x100

    goto :goto_2

    :cond_2
    const/16 v2, 0x80

    :goto_2
    or-int/2addr v0, v2

    invoke-virtual {v6, p3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_3

    const/16 v3, 0x800

    goto :goto_3

    :cond_3
    const/16 v3, 0x400

    :goto_3
    or-int/2addr v0, v3

    invoke-virtual {v6, p4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_4

    const/16 v5, 0x4000

    goto :goto_4

    :cond_4
    const/16 v5, 0x2000

    :goto_4
    or-int/2addr v0, v5

    invoke-virtual {v6, p5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_5

    const/high16 v8, 0x20000

    goto :goto_5

    :cond_5
    const/high16 v8, 0x10000

    :goto_5
    or-int/2addr v8, v0

    const v0, 0x12493

    and-int/2addr v0, v8

    const v9, 0x12492

    if-ne v0, v9, :cond_7

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_6

    goto :goto_6

    :cond_6
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_7

    :cond_7
    :goto_6
    iget-boolean v9, p1, Llyiahf/vczjk/yu;->OooOO0O:Z

    new-instance v0, Llyiahf/vczjk/y60;

    move-object v4, p0

    move-object v1, p1

    move-object v2, p3

    move-object v3, p4

    move-object v5, p5

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/y60;-><init>(Llyiahf/vczjk/yu;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/ma0;Llyiahf/vczjk/le3;)V

    const v1, 0x54220493

    invoke-static {v1, v0, v6}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v5

    shr-int/lit8 v0, v8, 0x3

    and-int/lit8 v0, v0, 0x70

    const/high16 v1, 0x30000

    or-int/2addr v0, v1

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v2, 0x0

    const/16 v8, 0x1c

    move-object v1, p2

    move v7, v0

    move v0, v9

    invoke-static/range {v0 .. v8}, Landroidx/compose/animation/OooO0O0;->OooO0Oo(ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_7
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_8

    new-instance v0, Llyiahf/vczjk/f60;

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    move-object v6, p5

    move/from16 v7, p7

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/f60;-><init>(Llyiahf/vczjk/ma0;Llyiahf/vczjk/yu;Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;I)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_8
    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/yu;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;I)V
    .locals 9

    move-object v6, p3

    check-cast v6, Llyiahf/vczjk/zf1;

    const v0, 0x2a674d34

    invoke-virtual {v6, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v6, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p4

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    const/16 v3, 0x20

    goto :goto_1

    :cond_1
    const/16 v3, 0x10

    :goto_1
    or-int/2addr v0, v3

    invoke-virtual {v6, p2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v4

    if-eqz v4, :cond_2

    const/16 v4, 0x100

    goto :goto_2

    :cond_2
    const/16 v4, 0x80

    :goto_2
    or-int/2addr v0, v4

    and-int/lit16 v4, v0, 0x93

    const/16 v5, 0x92

    if-ne v4, v5, :cond_4

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_4

    :cond_4
    :goto_3
    iget-object v2, p0, Llyiahf/vczjk/yu;->OooO0Oo:Llyiahf/vczjk/nw;

    shl-int/lit8 v0, v0, 0x3

    and-int/lit16 v7, v0, 0x1f80

    const/4 v8, 0x0

    iget-object v3, p0, Llyiahf/vczjk/yu;->OooO0OO:Ljava/util/List;

    move-object v4, p1

    move v5, p2

    invoke-static/range {v2 .. v8}, Llyiahf/vczjk/tg0;->OooOO0O(Llyiahf/vczjk/w03;Ljava/util/List;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;II)V

    :goto_4
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_5

    new-instance v0, Llyiahf/vczjk/h60;

    const/4 v5, 0x0

    move-object v1, p0

    move-object v2, p1

    move v3, p2

    move v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/h60;-><init>(Llyiahf/vczjk/yu;Llyiahf/vczjk/oe3;ZII)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_5
    return-void
.end method

.method public static final OooO0O0(Lgithub/tornaco/android/thanos/core/pm/AppInfo;ZZZZLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Ljava/util/List;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;III)V
    .locals 31

    move-object/from16 v1, p0

    move/from16 v2, p1

    move/from16 v3, p2

    move/from16 v4, p3

    move/from16 v5, p4

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    move-object/from16 v9, p8

    move-object/from16 v10, p9

    move-object/from16 v0, p11

    check-cast v0, Llyiahf/vczjk/zf1;

    const v8, 0x12c50fd5

    invoke-virtual {v0, v8}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_0

    const/4 v8, 0x4

    goto :goto_0

    :cond_0
    const/4 v8, 0x2

    :goto_0
    or-int v8, p12, v8

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v13

    if-eqz v13, :cond_1

    const/16 v13, 0x20

    goto :goto_1

    :cond_1
    const/16 v13, 0x10

    :goto_1
    or-int/2addr v8, v13

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v13

    if-eqz v13, :cond_2

    const/16 v13, 0x100

    goto :goto_2

    :cond_2
    const/16 v13, 0x80

    :goto_2
    or-int/2addr v8, v13

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v13

    if-eqz v13, :cond_3

    const/16 v13, 0x800

    goto :goto_3

    :cond_3
    const/16 v13, 0x400

    :goto_3
    or-int/2addr v8, v13

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v13

    if-eqz v13, :cond_4

    const/16 v13, 0x4000

    goto :goto_4

    :cond_4
    const/16 v13, 0x2000

    :goto_4
    or-int/2addr v8, v13

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_5

    const/high16 v13, 0x20000

    goto :goto_5

    :cond_5
    const/high16 v13, 0x10000

    :goto_5
    or-int/2addr v8, v13

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_6

    const/high16 v13, 0x100000

    goto :goto_6

    :cond_6
    const/high16 v13, 0x80000

    :goto_6
    or-int/2addr v8, v13

    move-object/from16 v13, p7

    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_7

    const/high16 v15, 0x800000

    goto :goto_7

    :cond_7
    const/high16 v15, 0x400000

    :goto_7
    or-int/2addr v8, v15

    invoke-virtual {v0, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_8

    const/high16 v15, 0x4000000

    goto :goto_8

    :cond_8
    const/high16 v15, 0x2000000

    :goto_8
    or-int/2addr v8, v15

    const/high16 v15, 0x30000000

    and-int v15, p12, v15

    if-nez v15, :cond_a

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_9

    const/high16 v15, 0x20000000

    goto :goto_9

    :cond_9
    const/high16 v15, 0x10000000

    :goto_9
    or-int/2addr v8, v15

    :cond_a
    move/from16 v15, p14

    and-int/lit16 v11, v15, 0x400

    if-eqz v11, :cond_b

    move-object/from16 v14, p10

    const/16 v24, 0x6

    goto :goto_b

    :cond_b
    and-int/lit8 v16, p13, 0x6

    move-object/from16 v14, p10

    if-nez v16, :cond_d

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v17

    if-eqz v17, :cond_c

    const/16 v17, 0x4

    goto :goto_a

    :cond_c
    const/16 v17, 0x2

    :goto_a
    or-int v17, p13, v17

    move/from16 v24, v17

    goto :goto_b

    :cond_d
    move/from16 v24, p13

    :goto_b
    const v17, 0x12492493

    and-int v13, v8, v17

    const v12, 0x12492492

    if-ne v13, v12, :cond_f

    and-int/lit8 v12, v24, 0x3

    const/4 v13, 0x2

    if-ne v12, v13, :cond_f

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v12

    if-nez v12, :cond_e

    goto :goto_c

    :cond_e
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v4, v0

    move-object v11, v14

    goto/16 :goto_1d

    :cond_f
    :goto_c
    if-eqz v11, :cond_10

    const/4 v11, 0x0

    goto :goto_d

    :cond_10
    move-object v11, v14

    :goto_d
    sget-object v12, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v13, 0x3f800000    # 1.0f

    invoke-static {v12, v13}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v14

    const v13, 0x75c0a946

    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-eqz v2, :cond_11

    const/4 v13, 0x6

    int-to-float v2, v13

    const/4 v13, 0x0

    invoke-static {v2, v0, v13}, Llyiahf/vczjk/u34;->OooO0o(FLlyiahf/vczjk/rf1;I)J

    move-result-wide v19

    :goto_e
    move-wide/from16 v2, v19

    goto :goto_f

    :cond_11
    const/4 v13, 0x0

    sget-wide v19, Llyiahf/vczjk/n21;->OooOO0:J

    goto :goto_e

    :goto_f
    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v13, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v14, v2, v3, v13}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v2, v7, v6}, Landroidx/compose/foundation/OooO00o;->OooO0oO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/16 v3, 0x10

    int-to-float v3, v3

    const/4 v13, 0x4

    int-to-float v13, v13

    invoke-static {v2, v3, v13}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/16 v3, 0x48

    int-to-float v3, v3

    const/4 v13, 0x0

    const/4 v14, 0x2

    invoke-static {v2, v3, v13, v14}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    sget-object v14, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v13, 0x36

    invoke-static {v3, v14, v0, v13}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    iget v13, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v0, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v17, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_12

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_10

    :cond_12
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_10
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v0, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v4, v0, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v7, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_13

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    move/from16 v17, v8

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_14

    goto :goto_11

    :cond_13
    move/from16 v17, v8

    :goto_11
    invoke-static {v13, v0, v13, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_14
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v0, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object/from16 p10, v11

    const/high16 v2, 0x3f800000    # 1.0f

    float-to-double v10, v2

    const-wide/16 v20, 0x0

    cmpl-double v8, v10, v20

    if-lez v8, :cond_15

    goto :goto_12

    :cond_15
    const-string v8, "invalid weight; must be greater than zero"

    invoke-static {v8}, Llyiahf/vczjk/nz3;->OooO00o(Ljava/lang/String;)V

    :goto_12
    new-instance v8, Landroidx/compose/foundation/layout/LayoutWeightElement;

    const/4 v13, 0x0

    invoke-direct {v8, v2, v13}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    sget-object v2, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v10, 0x36

    invoke-static {v2, v14, v0, v10}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v11

    iget v10, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v13

    invoke-static {v0, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_16

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_13

    :cond_16
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_13
    invoke-static {v11, v0, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v13, v0, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v11, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v11, :cond_17

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    invoke-static {v11, v13}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v11

    if-nez v11, :cond_18

    :cond_17
    invoke-static {v10, v0, v10, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_18
    invoke-static {v8, v0, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v8, 0x26

    int-to-float v8, v8

    invoke-static {v12, v8}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v8

    shl-int/lit8 v10, v17, 0x3

    and-int/lit8 v10, v10, 0x70

    const/4 v13, 0x6

    or-int/2addr v10, v13

    invoke-static {v8, v1, v0, v10}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    const/16 v8, 0xc

    int-to-float v8, v8

    invoke-static {v12, v8}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v8

    invoke-static {v0, v8}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object v8, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v10, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v8, v10, v0, v13}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v8

    iget v10, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v11

    invoke-static {v0, v12}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v13

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_19

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_14

    :cond_19
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_14
    invoke-static {v8, v0, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v11, v0, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v8, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v8, :cond_1a

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v8, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_1b

    :cond_1a
    invoke-static {v10, v0, v10, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1b
    invoke-static {v13, v0, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v8, 0x30

    invoke-static {v2, v14, v0, v8}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    iget v10, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v11

    invoke-static {v0, v12}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v13

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_1c

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_15

    :cond_1c
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_15
    invoke-static {v2, v0, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v11, v0, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_1d

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v2, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_1e

    :cond_1d
    invoke-static {v10, v0, v10, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1e
    invoke-static {v13, v0, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v2, 0xf0

    int-to-float v2, v2

    const/16 v10, 0xb

    const/4 v11, 0x0

    invoke-static {v12, v11, v11, v2, v10}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOOO(Llyiahf/vczjk/kl5;FFFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v10

    const-string v11, "getAppLabel(...)"

    invoke-static {v10, v11}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v11, 0x0

    const/4 v13, 0x6

    invoke-static {v13, v11, v10, v0, v2}, Llyiahf/vczjk/os9;->OooO0O0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const/4 v2, 0x1

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v10, -0x4b7f5b41

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-nez v9, :cond_1f

    :goto_16
    const/4 v13, 0x0

    goto :goto_17

    :cond_1f
    shr-int/lit8 v10, v17, 0x18

    and-int/lit8 v10, v10, 0xe

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-virtual {v9, v0, v10}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_16

    :goto_17
    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v10, -0x4b7f5661

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-nez p9, :cond_20

    move-object/from16 v11, p9

    :goto_18
    const/4 v13, 0x0

    goto :goto_19

    :cond_20
    shr-int/lit8 v10, v17, 0x1b

    and-int/lit8 v10, v10, 0xe

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    move-object/from16 v11, p9

    invoke-virtual {v11, v0, v10}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_18

    :goto_19
    invoke-static {v0, v13, v2, v2}, Llyiahf/vczjk/ii5;->OooOo0O(Llyiahf/vczjk/zf1;ZZZ)V

    sget-object v10, Llyiahf/vczjk/tx;->OooO0O0:Llyiahf/vczjk/e86;

    const/16 v13, 0x36

    invoke-static {v10, v14, v0, v13}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v10

    iget v13, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v0, v12}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v15

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v2, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v2, :cond_21

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1a

    :cond_21
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1a
    invoke-static {v10, v0, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v14, v0, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_22

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_23

    :cond_22
    invoke-static {v13, v0, v13, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_23
    invoke-static {v15, v0, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v2, -0x47862ac4

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-interface/range {p7 .. p7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1b
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_24

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/String;

    const/4 v13, 0x6

    int-to-float v4, v13

    const/16 v28, 0x0

    const/16 v29, 0x0

    const/16 v27, 0x0

    const/16 v30, 0xe

    move/from16 v26, v4

    move-object/from16 v25, v12

    invoke-static/range {v25 .. v30}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v4

    const/4 v13, 0x0

    invoke-static {v8, v13, v3, v0, v4}, Llyiahf/vczjk/nqa;->OooO0o0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    goto :goto_1b

    :cond_24
    move-object/from16 v25, v12

    const/4 v13, 0x0

    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v2, -0x47861bcf

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const/16 v2, 0x12

    if-eqz p2, :cond_25

    const/4 v3, 0x6

    int-to-float v4, v3

    const/16 v28, 0x0

    const/16 v29, 0x0

    const/16 v27, 0x0

    const/16 v30, 0xe

    move/from16 v26, v4

    invoke-static/range {v25 .. v30}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v4

    int-to-float v5, v2

    invoke-static {v4, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    const/16 v20, 0x0

    const/16 v21, 0x0

    move/from16 v19, v13

    const-wide/16 v12, 0x0

    const-wide/16 v14, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    move/from16 v5, v19

    const/16 v19, 0x0

    const/16 v23, 0x6

    move-object/from16 v22, v0

    move-object v11, v4

    move-object/from16 v0, p10

    invoke-static/range {v11 .. v23}, Llyiahf/vczjk/kla;->OooO00o(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFFFLlyiahf/vczjk/rf1;I)V

    move-object/from16 v4, v22

    goto :goto_1c

    :cond_25
    move-object v4, v0

    move v5, v13

    const/4 v3, 0x6

    move-object/from16 v0, p10

    :goto_1c
    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v6, -0x4785fe1f

    invoke-virtual {v4, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-eqz p3, :cond_26

    sget v6, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_zzz_fill:I

    invoke-static {v6, v4}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v11

    sget-wide v14, Llyiahf/vczjk/n21;->OooO0Oo:J

    int-to-float v6, v3

    const/16 v28, 0x0

    const/16 v29, 0x0

    const/16 v27, 0x0

    const/16 v30, 0xe

    move/from16 v26, v6

    invoke-static/range {v25 .. v30}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v6

    int-to-float v7, v2

    invoke-static {v6, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v13

    const/16 v18, 0x0

    const/4 v12, 0x0

    const/16 v17, 0xdb0

    move-object/from16 v16, v4

    invoke-static/range {v11 .. v18}, Llyiahf/vczjk/yt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    :cond_26
    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v6, -0x4785cb08

    invoke-virtual {v4, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-eqz p4, :cond_27

    sget v6, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_netease_cloud_music_fill:I

    invoke-static {v6, v4}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v11

    sget-wide v14, Llyiahf/vczjk/n21;->OooO0oO:J

    int-to-float v3, v3

    const/16 v28, 0x0

    const/16 v29, 0x0

    const/16 v27, 0x0

    const/16 v30, 0xe

    move/from16 v26, v3

    invoke-static/range {v25 .. v30}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v3

    int-to-float v2, v2

    invoke-static {v3, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v13

    const/16 v18, 0x0

    const/4 v12, 0x0

    const/16 v17, 0xdb0

    move-object/from16 v16, v4

    invoke-static/range {v11 .. v18}, Llyiahf/vczjk/yt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    :cond_27
    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v2, -0x4785964b

    invoke-virtual {v4, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-eqz v0, :cond_28

    invoke-static {v5, v4}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    and-int/lit8 v2, v24, 0xe

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v0, v4, v2}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_28
    const/4 v2, 0x1

    invoke-static {v4, v5, v2, v2}, Llyiahf/vczjk/ii5;->OooOo0O(Llyiahf/vczjk/zf1;ZZZ)V

    move-object v11, v0

    :goto_1d
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v15

    if-eqz v15, :cond_29

    new-instance v0, Llyiahf/vczjk/g60;

    move/from16 v2, p1

    move/from16 v3, p2

    move/from16 v4, p3

    move/from16 v5, p4

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    move-object/from16 v8, p7

    move-object/from16 v10, p9

    move/from16 v12, p12

    move/from16 v13, p13

    move/from16 v14, p14

    invoke-direct/range {v0 .. v14}, Llyiahf/vczjk/g60;-><init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;ZZZZLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Ljava/util/List;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;III)V

    iput-object v0, v15, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_29
    return-void
.end method

.method public static final OooO0OO(Lgithub/tornaco/android/thanos/module/compose/common/infra/BaseAppListFilterActivity;Llyiahf/vczjk/e60;Llyiahf/vczjk/rf1;I)V
    .locals 21

    move-object/from16 v0, p0

    move-object/from16 v3, p1

    move/from16 v7, p3

    const-string v1, "<this>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "config"

    invoke-static {v3, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v8, p2

    check-cast v8, Llyiahf/vczjk/zf1;

    const v1, 0x4a58090c    # 3539523.0f

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v1, 0x4

    goto :goto_0

    :cond_0
    const/4 v1, 0x2

    :goto_0
    or-int/2addr v1, v7

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    const/16 v2, 0x20

    goto :goto_1

    :cond_1
    const/16 v2, 0x10

    :goto_1
    or-int/2addr v1, v2

    and-int/lit8 v1, v1, 0x13

    const/16 v2, 0x12

    if-ne v1, v2, :cond_3

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v17, v8

    goto/16 :goto_4

    :cond_3
    :goto_2
    const v1, 0x70b323c8

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-static {v8}, Llyiahf/vczjk/c45;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lha;

    move-result-object v1

    if-eqz v1, :cond_f

    invoke-static {v1, v8}, Llyiahf/vczjk/mc4;->OooOo0O(Llyiahf/vczjk/lha;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/sn3;

    move-result-object v2

    const v4, 0x671a9c9b

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    instance-of v4, v1, Llyiahf/vczjk/om3;

    if-eqz v4, :cond_4

    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/om3;

    invoke-interface {v4}, Llyiahf/vczjk/om3;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v4

    goto :goto_3

    :cond_4
    sget-object v4, Llyiahf/vczjk/ms1;->OooO0O0:Llyiahf/vczjk/ms1;

    :goto_3
    const-class v5, Llyiahf/vczjk/g70;

    invoke-static {v5, v1, v2, v4, v8}, Llyiahf/vczjk/eo6;->OooOooO(Ljava/lang/Class;Llyiahf/vczjk/lha;Llyiahf/vczjk/sn3;Llyiahf/vczjk/os1;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/dha;

    move-result-object v1

    const/4 v9, 0x0

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v10, v1

    check-cast v10, Llyiahf/vczjk/g70;

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const v2, -0x615d173a

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v4, v5

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    sget-object v11, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/4 v6, 0x0

    if-nez v4, :cond_5

    if-ne v5, v11, :cond_6

    :cond_5
    new-instance v5, Llyiahf/vczjk/i60;

    invoke-direct {v5, v10, v3, v6}, Llyiahf/vczjk/i60;-><init>(Llyiahf/vczjk/g70;Llyiahf/vczjk/e60;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v8, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v5, Llyiahf/vczjk/ze3;

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v1, v8, v5}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    move-object v5, v1

    check-cast v5, Landroid/content/Context;

    const v1, 0x6e3c21fe

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v11, :cond_7

    iget-object v1, v3, Llyiahf/vczjk/e60;->OooO0O0:Llyiahf/vczjk/fp;

    iget-object v1, v1, Llyiahf/vczjk/fp;->OooO00o:Llyiahf/vczjk/oe3;

    invoke-interface {v1, v5}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v1, Ljava/lang/String;

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v8}, Llyiahf/vczjk/xr6;->OooOOOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/hb8;

    move-result-object v14

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v8, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v2, v4

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v2, :cond_8

    if-ne v4, v11, :cond_9

    :cond_8
    new-instance v4, Llyiahf/vczjk/j60;

    invoke-direct {v4, v14, v10, v6}, Llyiahf/vczjk/j60;-><init>(Llyiahf/vczjk/hb8;Llyiahf/vczjk/g70;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    check-cast v4, Llyiahf/vczjk/ze3;

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v14, v8, v4}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v14}, Llyiahf/vczjk/hb8;->OooO0OO()Z

    move-result v2

    const v12, 0x4c5de2

    invoke-virtual {v8, v12}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v4, :cond_a

    if-ne v6, v11, :cond_b

    :cond_a
    new-instance v6, Llyiahf/vczjk/n20;

    const/4 v4, 0x2

    invoke-direct {v6, v14, v4}, Llyiahf/vczjk/n20;-><init>(Llyiahf/vczjk/hb8;I)V

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    check-cast v6, Llyiahf/vczjk/le3;

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v2, v6, v8, v9, v9}, Llyiahf/vczjk/c6a;->OooO0O0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    new-instance v2, Llyiahf/vczjk/b6;

    const/4 v4, 0x2

    invoke-direct {v2, v4, v1, v3}, Llyiahf/vczjk/b6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v1, -0x4ff65a5f

    invoke-static {v1, v2, v8}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v13

    new-instance v1, Llyiahf/vczjk/n6;

    const/4 v2, 0x4

    const/4 v6, 0x0

    move-object v4, v14

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/n6;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    const v2, 0x796fe1ca

    invoke-static {v2, v1, v8}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v15

    invoke-virtual {v8, v12}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_c

    if-ne v2, v11, :cond_d

    :cond_c
    new-instance v2, Llyiahf/vczjk/k1;

    const/16 v1, 0xc

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/k1;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    move-object v12, v2

    check-cast v12, Llyiahf/vczjk/le3;

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v1, Llyiahf/vczjk/b6;

    const/4 v2, 0x3

    invoke-direct {v1, v2, v3, v5}, Llyiahf/vczjk/b6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v2, 0xc92d7a5

    invoke-static {v2, v1, v8}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v9

    new-instance v1, Llyiahf/vczjk/n6;

    const/4 v2, 0x5

    const/4 v6, 0x0

    move-object v4, v3

    move-object v3, v10

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/n6;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    move-object v3, v4

    const v2, 0x3e3876b

    invoke-static {v2, v1, v8}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v16

    const/4 v11, 0x0

    move-object v10, v15

    const/4 v15, 0x0

    move-object/from16 v17, v8

    const/4 v8, 0x0

    const v18, 0x60301b0

    const/16 v19, 0x89

    move-object/from16 v20, v13

    move-object v13, v9

    move-object/from16 v9, v20

    invoke-static/range {v8 .. v19}, Llyiahf/vczjk/xr6;->OooO0Oo(Llyiahf/vczjk/hl5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/hb8;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_4
    invoke-virtual/range {v17 .. v17}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v1

    if-eqz v1, :cond_e

    new-instance v2, Llyiahf/vczjk/e2;

    const/4 v4, 0x1

    invoke-direct {v2, v0, v3, v7, v4}, Llyiahf/vczjk/e2;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v2, v1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_e
    return-void

    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/za2;Llyiahf/vczjk/rf1;I)V
    .locals 16

    move-object/from16 v2, p0

    move/from16 v7, p2

    move-object/from16 v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    const v0, 0x118f13d0

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x2

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    or-int/2addr v0, v7

    and-int/lit8 v0, v0, 0x3

    if-ne v0, v1, :cond_2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v6, v2

    move-object v3, v8

    goto/16 :goto_5

    :cond_2
    :goto_1
    invoke-static {v8}, Llyiahf/vczjk/eo6;->OooOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/r58;

    move-result-object v3

    invoke-virtual {v2}, Llyiahf/vczjk/sy5;->OooO0O0()Llyiahf/vczjk/pu5;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/pu5;->OooO0o0:Llyiahf/vczjk/gh7;

    invoke-static {v0, v8}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/List;

    sget-object v4, Llyiahf/vczjk/j14;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Boolean;

    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    sget-object v9, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v5, :cond_3

    if-ne v6, v9, :cond_7

    :cond_3
    new-instance v6, Llyiahf/vczjk/tw8;

    invoke-direct {v6}, Llyiahf/vczjk/tw8;-><init>()V

    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_4
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v10

    if-eqz v10, :cond_6

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v10

    move-object v11, v10

    check-cast v11, Llyiahf/vczjk/ku5;

    if-eqz v4, :cond_5

    goto :goto_3

    :cond_5
    iget-object v11, v11, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    iget-object v11, v11, Llyiahf/vczjk/mu5;->OooOO0:Llyiahf/vczjk/wy4;

    iget-object v11, v11, Llyiahf/vczjk/wy4;->OooO0Oo:Llyiahf/vczjk/jy4;

    sget-object v12, Llyiahf/vczjk/jy4;->OooOOOo:Llyiahf/vczjk/jy4;

    invoke-virtual {v11, v12}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    move-result v11

    if-ltz v11, :cond_4

    :goto_3
    invoke-virtual {v5, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_6
    invoke-virtual {v6, v5}, Llyiahf/vczjk/tw8;->addAll(Ljava/util/Collection;)Z

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v6, Llyiahf/vczjk/tw8;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/List;

    const/4 v10, 0x0

    invoke-static {v6, v0, v8, v10}, Llyiahf/vczjk/qqa;->OooO0oO(Llyiahf/vczjk/tw8;Ljava/util/List;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v2}, Llyiahf/vczjk/sy5;->OooO0O0()Llyiahf/vczjk/pu5;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/pu5;->OooO0o:Llyiahf/vczjk/gh7;

    invoke-static {v0, v8}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v11

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v9, :cond_8

    new-instance v0, Llyiahf/vczjk/tw8;

    invoke-direct {v0}, Llyiahf/vczjk/tw8;-><init>()V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    move-object v4, v0

    check-cast v4, Llyiahf/vczjk/tw8;

    const v0, -0x15e65d02

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v6}, Llyiahf/vczjk/tw8;->listIterator()Ljava/util/ListIterator;

    move-result-object v12

    :goto_4
    move-object v0, v12

    check-cast v0, Llyiahf/vczjk/co3;

    invoke-virtual {v0}, Llyiahf/vczjk/co3;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_b

    invoke-virtual {v0}, Llyiahf/vczjk/co3;->next()Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/ku5;

    iget-object v0, v1, Llyiahf/vczjk/ku5;->OooOOO:Llyiahf/vczjk/av5;

    const-string v5, "null cannot be cast to non-null type androidx.navigation.compose.DialogNavigator.Destination"

    invoke-static {v0, v5}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v5, v0

    check-cast v5, Llyiahf/vczjk/ya2;

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v0, v6

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v0, :cond_9

    if-ne v6, v9, :cond_a

    :cond_9
    new-instance v6, Llyiahf/vczjk/oo0oO0;

    const/16 v0, 0xb

    invoke-direct {v6, v0, v2, v1}, Llyiahf/vczjk/oo0oO0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    move-object v13, v6

    check-cast v13, Llyiahf/vczjk/le3;

    new-instance v0, Llyiahf/vczjk/ha2;

    const/4 v6, 0x0

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/ha2;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    move-object v6, v2

    move-object v14, v3

    move-object v15, v4

    const v1, 0x43541ebc

    invoke-static {v1, v0, v8}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    const/4 v0, 0x0

    iget-object v1, v5, Llyiahf/vczjk/ya2;->OooOOo:Llyiahf/vczjk/ab2;

    const/16 v4, 0x180

    move v5, v0

    move-object v3, v8

    move-object v0, v13

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/dn8;->OooOOo0(Llyiahf/vczjk/le3;Llyiahf/vczjk/ab2;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    move-object v2, v6

    move-object v3, v14

    move-object v4, v15

    goto :goto_4

    :cond_b
    move-object v6, v2

    move-object v15, v4

    move-object v3, v8

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Set;

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_c

    if-ne v2, v9, :cond_d

    :cond_c
    new-instance v2, Llyiahf/vczjk/ia2;

    const/4 v1, 0x0

    invoke-direct {v2, v11, v6, v15, v1}, Llyiahf/vczjk/ia2;-><init>(Llyiahf/vczjk/p29;Llyiahf/vczjk/za2;Llyiahf/vczjk/tw8;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    check-cast v2, Llyiahf/vczjk/ze3;

    invoke-static {v0, v15, v2, v3}, Llyiahf/vczjk/c6a;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;)V

    :goto_5
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_e

    new-instance v1, Llyiahf/vczjk/c4;

    const/16 v2, 0x14

    invoke-direct {v1, v7, v2, v6}, Llyiahf/vczjk/c4;-><init>(IILjava/lang/Object;)V

    iput-object v1, v0, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_e
    return-void
.end method

.method public static final OooO0o(Llyiahf/vczjk/yu;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;I)V
    .locals 9

    move-object v6, p3

    check-cast v6, Llyiahf/vczjk/zf1;

    const v0, -0x28048969

    invoke-virtual {v6, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v6, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p4

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    const/16 v3, 0x20

    goto :goto_1

    :cond_1
    const/16 v3, 0x10

    :goto_1
    or-int/2addr v0, v3

    invoke-virtual {v6, p2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v4

    if-eqz v4, :cond_2

    const/16 v4, 0x100

    goto :goto_2

    :cond_2
    const/16 v4, 0x80

    :goto_2
    or-int/2addr v0, v4

    and-int/lit16 v4, v0, 0x93

    const/16 v5, 0x92

    if-ne v4, v5, :cond_4

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_4

    :cond_4
    :goto_3
    iget-object v2, p0, Llyiahf/vczjk/yu;->OooO0o:Llyiahf/vczjk/nw;

    shl-int/lit8 v0, v0, 0x3

    and-int/lit16 v7, v0, 0x1f80

    const/4 v8, 0x0

    iget-object v3, p0, Llyiahf/vczjk/yu;->OooO0o0:Ljava/util/List;

    move-object v4, p1

    move v5, p2

    invoke-static/range {v2 .. v8}, Llyiahf/vczjk/tg0;->OooOO0O(Llyiahf/vczjk/w03;Ljava/util/List;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;II)V

    :goto_4
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_5

    new-instance v0, Llyiahf/vczjk/h60;

    const/4 v5, 0x1

    move-object v1, p0

    move-object v2, p1

    move v3, p2

    move v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/h60;-><init>(Llyiahf/vczjk/yu;Llyiahf/vczjk/oe3;ZII)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_5
    return-void
.end method

.method public static final OooO0o0(Ljava/lang/Object;ILlyiahf/vczjk/hu4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V
    .locals 17

    move-object/from16 v1, p0

    move/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    move/from16 v5, p5

    move-object/from16 v0, p4

    check-cast v0, Llyiahf/vczjk/zf1;

    const v6, -0x7beccd10

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v6, v5, 0x6

    if-nez v6, :cond_1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_0

    const/4 v6, 0x4

    goto :goto_0

    :cond_0
    const/4 v6, 0x2

    :goto_0
    or-int/2addr v6, v5

    goto :goto_1

    :cond_1
    move v6, v5

    :goto_1
    and-int/lit8 v7, v5, 0x30

    if-nez v7, :cond_3

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v7

    if-eqz v7, :cond_2

    const/16 v7, 0x20

    goto :goto_2

    :cond_2
    const/16 v7, 0x10

    :goto_2
    or-int/2addr v6, v7

    :cond_3
    and-int/lit16 v7, v5, 0x180

    if-nez v7, :cond_5

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_4

    const/16 v7, 0x100

    goto :goto_3

    :cond_4
    const/16 v7, 0x80

    :goto_3
    or-int/2addr v6, v7

    :cond_5
    and-int/lit16 v7, v5, 0xc00

    if-nez v7, :cond_7

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_6

    const/16 v7, 0x800

    goto :goto_4

    :cond_6
    const/16 v7, 0x400

    :goto_4
    or-int/2addr v6, v7

    :cond_7
    and-int/lit16 v7, v6, 0x493

    const/16 v8, 0x492

    if-eq v7, v8, :cond_8

    const/4 v7, 0x1

    goto :goto_5

    :cond_8
    const/4 v7, 0x0

    :goto_5
    and-int/lit8 v8, v6, 0x1

    invoke-virtual {v0, v8, v7}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v7

    if-eqz v7, :cond_11

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v7, v8

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v7, :cond_9

    if-ne v8, v9, :cond_a

    :cond_9
    new-instance v8, Llyiahf/vczjk/eu4;

    invoke-direct {v8, v1, v3}, Llyiahf/vczjk/eu4;-><init>(Ljava/lang/Object;Llyiahf/vczjk/hu4;)V

    invoke-virtual {v0, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    check-cast v8, Llyiahf/vczjk/eu4;

    iput v2, v8, Llyiahf/vczjk/eu4;->OooO0OO:I

    sget-object v7, Llyiahf/vczjk/xu6;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/eu4;

    invoke-static {}, Llyiahf/vczjk/wr6;->OooOOO0()Llyiahf/vczjk/nv8;

    move-result-object v11

    if-eqz v11, :cond_b

    invoke-virtual {v11}, Llyiahf/vczjk/nv8;->OooO0o0()Llyiahf/vczjk/oe3;

    move-result-object v13

    goto :goto_6

    :cond_b
    const/4 v13, 0x0

    :goto_6
    invoke-static {v11}, Llyiahf/vczjk/wr6;->OooOOOo(Llyiahf/vczjk/nv8;)Llyiahf/vczjk/nv8;

    move-result-object v14

    iget-object v15, v8, Llyiahf/vczjk/eu4;->OooO0oO:Llyiahf/vczjk/qs5;

    :try_start_0
    move-object/from16 v16, v15

    check-cast v16, Llyiahf/vczjk/fw8;

    invoke-virtual/range {v16 .. v16}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v16

    move-object/from16 v12, v16

    check-cast v12, Llyiahf/vczjk/eu4;

    if-eq v10, v12, :cond_e

    check-cast v15, Llyiahf/vczjk/fw8;

    invoke-virtual {v15, v10}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget v12, v8, Llyiahf/vczjk/eu4;->OooO0Oo:I

    if-lez v12, :cond_e

    iget-object v12, v8, Llyiahf/vczjk/eu4;->OooO0o0:Llyiahf/vczjk/eu4;

    if-eqz v12, :cond_c

    invoke-virtual {v12}, Llyiahf/vczjk/eu4;->OooO0O0()V

    goto :goto_7

    :catchall_0
    move-exception v0

    goto :goto_9

    :cond_c
    :goto_7
    if-eqz v10, :cond_d

    invoke-virtual {v10}, Llyiahf/vczjk/eu4;->OooO00o()Llyiahf/vczjk/eu4;

    goto :goto_8

    :cond_d
    const/4 v10, 0x0

    :goto_8
    iput-object v10, v8, Llyiahf/vczjk/eu4;->OooO0o0:Llyiahf/vczjk/eu4;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_e
    invoke-static {v11, v14, v13}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    invoke-virtual {v0, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v10

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v10, :cond_f

    if-ne v11, v9, :cond_10

    :cond_f
    new-instance v11, Llyiahf/vczjk/fu4;

    invoke-direct {v11, v8}, Llyiahf/vczjk/fu4;-><init>(Llyiahf/vczjk/eu4;)V

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_10
    check-cast v11, Llyiahf/vczjk/oe3;

    invoke-static {v8, v11, v0}, Llyiahf/vczjk/c6a;->OooOO0o(Ljava/lang/Object;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)V

    invoke-virtual {v7, v8}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v7

    shr-int/lit8 v6, v6, 0x6

    and-int/lit8 v6, v6, 0x70

    const/16 v8, 0x8

    or-int/2addr v6, v8

    invoke-static {v7, v4, v0, v6}, Llyiahf/vczjk/r02;->OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_a

    :goto_9
    invoke-static {v11, v14, v13}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    throw v0

    :cond_11
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_a
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_12

    new-instance v0, Llyiahf/vczjk/gu4;

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/gu4;-><init>(Ljava/lang/Object;ILlyiahf/vczjk/hu4;Llyiahf/vczjk/ze3;I)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_12
    return-void
.end method

.method public static final OooO0oO(Llyiahf/vczjk/tw8;Ljava/util/List;Llyiahf/vczjk/rf1;I)V
    .locals 6

    check-cast p2, Llyiahf/vczjk/zf1;

    const v0, 0x5baa69c3

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p2, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p3

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    const/16 v1, 0x20

    goto :goto_1

    :cond_1
    const/16 v1, 0x10

    :goto_1
    or-int/2addr v0, v1

    and-int/lit8 v0, v0, 0x13

    const/16 v1, 0x12

    if-ne v0, v1, :cond_3

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_4

    :cond_3
    :goto_2
    sget-object v0, Llyiahf/vczjk/j14;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_6

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ku5;

    iget-object v3, v2, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    iget-object v3, v3, Llyiahf/vczjk/mu5;->OooOO0:Llyiahf/vczjk/wy4;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v4

    invoke-virtual {p2, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v4, v5

    invoke-virtual {p2, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v4, v5

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v4, :cond_4

    sget-object v4, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v5, v4, :cond_5

    :cond_4
    new-instance v5, Llyiahf/vczjk/fa2;

    invoke-direct {v5, v2, p0, v0}, Llyiahf/vczjk/fa2;-><init>(Llyiahf/vczjk/ku5;Llyiahf/vczjk/tw8;Z)V

    invoke-virtual {p2, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v5, Llyiahf/vczjk/oe3;

    invoke-static {v3, v5, p2}, Llyiahf/vczjk/c6a;->OooOO0o(Ljava/lang/Object;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)V

    goto :goto_3

    :cond_6
    :goto_4
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_7

    new-instance v0, Llyiahf/vczjk/e2;

    const/16 v1, 0x10

    invoke-direct {v0, p0, p1, p3, v1}, Llyiahf/vczjk/e2;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_7
    return-void
.end method

.method public static final OooO0oo(ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V
    .locals 3

    check-cast p2, Llyiahf/vczjk/zf1;

    const v0, 0x6c6a2a1a

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p2, p0}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p3

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    const/16 v1, 0x20

    goto :goto_1

    :cond_1
    const/16 v1, 0x10

    :goto_1
    or-int/2addr v0, v1

    and-int/lit8 v1, v0, 0x13

    const/16 v2, 0x12

    if-ne v1, v2, :cond_3

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3

    :cond_3
    :goto_2
    and-int/lit8 v0, v0, 0x7e

    const/4 v1, 0x0

    invoke-static {p0, p1, p2, v0, v1}, Llyiahf/vczjk/dr6;->OooO0Oo(ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    :goto_3
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_4

    new-instance v0, Llyiahf/vczjk/ou5;

    invoke-direct {v0, p0, p1, p3}, Llyiahf/vczjk/ou5;-><init>(ZLlyiahf/vczjk/ze3;I)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_4
    return-void
.end method

.method public static OooOO0(FFI)F
    .locals 1

    add-int/lit8 p2, p2, -0x1

    const/4 v0, 0x0

    invoke-static {v0, p2}, Ljava/lang/Math;->max(II)I

    move-result p2

    int-to-float p2, p2

    mul-float/2addr p2, p1

    add-float/2addr p2, p0

    return p2
.end method

.method public static final OooOO0O(Ljava/util/List;Ljava/lang/Object;Llyiahf/vczjk/fy9;Llyiahf/vczjk/fy9;II)V
    .locals 3

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    if-eqz p2, :cond_0

    iget-object p2, p2, Llyiahf/vczjk/fy9;->OooO00o:[I

    goto :goto_0

    :cond_0
    move-object p2, v0

    :goto_0
    if-eqz p3, :cond_1

    iget-object v0, p3, Llyiahf/vczjk/fy9;->OooO00o:[I

    :cond_1
    if-eqz p2, :cond_3

    if-eqz v0, :cond_3

    array-length p3, p2

    array-length v1, v0

    add-int v2, p3, v1

    invoke-static {p2, v2}, Ljava/util/Arrays;->copyOf([II)[I

    move-result-object p2

    const/4 v2, 0x0

    invoke-static {v0, v2, p2, p3, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    invoke-static {p2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    new-instance p3, Ljava/util/LinkedHashSet;

    array-length v0, p2

    invoke-static {v0}, Llyiahf/vczjk/lc5;->o00oO0o(I)I

    move-result v0

    invoke-direct {p3, v0}, Ljava/util/LinkedHashSet;-><init>(I)V

    array-length v0, p2

    :goto_1
    if-ge v2, v0, :cond_2

    aget v1, p2, v2

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-interface {p3, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    :cond_2
    invoke-static {p3}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/d21;->o0000(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/d21;->o0000O0O(Ljava/util/List;)[I

    move-result-object p2

    goto :goto_2

    :cond_3
    if-nez p2, :cond_4

    if-eqz v0, :cond_4

    move-object p2, v0

    goto :goto_2

    :cond_4
    if-eqz p2, :cond_6

    if-nez v0, :cond_6

    :goto_2
    if-nez p1, :cond_5

    return-void

    :cond_5
    new-instance p3, Llyiahf/vczjk/fy9;

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    invoke-static {p5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p5

    invoke-static {p5}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p5

    invoke-direct {p3, p2, p1, p4, p5}, Llyiahf/vczjk/fy9;-><init>([ILjava/util/List;ILjava/util/List;)V

    invoke-interface {p0, p3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void

    :cond_6
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Separator page expected adjacentPageBefore or adjacentPageAfter, but both were null."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static OooOO0o(FFI)F
    .locals 0

    if-lez p2, :cond_0

    const/high16 p2, 0x40000000    # 2.0f

    div-float/2addr p1, p2

    add-float/2addr p1, p0

    return p1

    :cond_0
    return p0
.end method

.method public static OooOOO(ILandroid/graphics/Rect;Landroid/graphics/Rect;Landroid/graphics/Rect;)Z
    .locals 8

    invoke-static {p0, p1, p2}, Llyiahf/vczjk/qqa;->OooOOOO(ILandroid/graphics/Rect;Landroid/graphics/Rect;)Z

    move-result v0

    invoke-static {p0, p1, p3}, Llyiahf/vczjk/qqa;->OooOOOO(ILandroid/graphics/Rect;Landroid/graphics/Rect;)Z

    move-result v1

    if-nez v1, :cond_b

    if-nez v0, :cond_0

    goto/16 :goto_4

    :cond_0
    const-string v0, "direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}."

    const/16 v1, 0x82

    const/16 v2, 0x21

    const/16 v3, 0x42

    const/16 v4, 0x11

    const/4 v5, 0x1

    if-eq p0, v4, :cond_4

    if-eq p0, v2, :cond_3

    if-eq p0, v3, :cond_2

    if-ne p0, v1, :cond_1

    iget v6, p1, Landroid/graphics/Rect;->bottom:I

    iget v7, p3, Landroid/graphics/Rect;->top:I

    if-gt v6, v7, :cond_a

    goto :goto_0

    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    iget v6, p1, Landroid/graphics/Rect;->right:I

    iget v7, p3, Landroid/graphics/Rect;->left:I

    if-gt v6, v7, :cond_a

    goto :goto_0

    :cond_3
    iget v6, p1, Landroid/graphics/Rect;->top:I

    iget v7, p3, Landroid/graphics/Rect;->bottom:I

    if-lt v6, v7, :cond_a

    goto :goto_0

    :cond_4
    iget v6, p1, Landroid/graphics/Rect;->left:I

    iget v7, p3, Landroid/graphics/Rect;->right:I

    if-lt v6, v7, :cond_a

    :goto_0
    if-eq p0, v4, :cond_a

    if-ne p0, v3, :cond_5

    goto :goto_3

    :cond_5
    invoke-static {p0, p1, p2}, Llyiahf/vczjk/qqa;->Oooo0o0(ILandroid/graphics/Rect;Landroid/graphics/Rect;)I

    move-result p2

    if-eq p0, v4, :cond_9

    if-eq p0, v2, :cond_8

    if-eq p0, v3, :cond_7

    if-ne p0, v1, :cond_6

    iget p0, p3, Landroid/graphics/Rect;->bottom:I

    iget p1, p1, Landroid/graphics/Rect;->bottom:I

    :goto_1
    sub-int/2addr p0, p1

    goto :goto_2

    :cond_6
    new-instance p0, Ljava/lang/IllegalArgumentException;

    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_7
    iget p0, p3, Landroid/graphics/Rect;->right:I

    iget p1, p1, Landroid/graphics/Rect;->right:I

    goto :goto_1

    :cond_8
    iget p0, p1, Landroid/graphics/Rect;->top:I

    iget p1, p3, Landroid/graphics/Rect;->top:I

    goto :goto_1

    :cond_9
    iget p0, p1, Landroid/graphics/Rect;->left:I

    iget p1, p3, Landroid/graphics/Rect;->left:I

    goto :goto_1

    :goto_2
    invoke-static {v5, p0}, Ljava/lang/Math;->max(II)I

    move-result p0

    if-ge p2, p0, :cond_b

    :cond_a
    :goto_3
    return v5

    :cond_b
    :goto_4
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOOOO(ILandroid/graphics/Rect;Landroid/graphics/Rect;)Z
    .locals 1

    const/16 v0, 0x11

    if-eq p0, v0, :cond_2

    const/16 v0, 0x21

    if-eq p0, v0, :cond_1

    const/16 v0, 0x42

    if-eq p0, v0, :cond_2

    const/16 v0, 0x82

    if-ne p0, v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_1
    :goto_0
    iget p0, p2, Landroid/graphics/Rect;->right:I

    iget v0, p1, Landroid/graphics/Rect;->left:I

    if-lt p0, v0, :cond_3

    iget p0, p2, Landroid/graphics/Rect;->left:I

    iget p1, p1, Landroid/graphics/Rect;->right:I

    if-gt p0, p1, :cond_3

    goto :goto_1

    :cond_2
    iget p0, p2, Landroid/graphics/Rect;->bottom:I

    iget v0, p1, Landroid/graphics/Rect;->top:I

    if-lt p0, v0, :cond_3

    iget p0, p2, Landroid/graphics/Rect;->top:I

    iget p1, p1, Landroid/graphics/Rect;->bottom:I

    if-gt p0, p1, :cond_3

    :goto_1
    const/4 p0, 0x1

    return p0

    :cond_3
    const/4 p0, 0x0

    return p0
.end method

.method public static final varargs OooOOOo([Llyiahf/vczjk/xn6;)Landroid/os/Bundle;
    .locals 9

    new-instance v0, Landroid/os/Bundle;

    array-length v1, p0

    invoke-direct {v0, v1}, Landroid/os/Bundle;-><init>(I)V

    array-length v1, p0

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_1d

    aget-object v3, p0, v2

    invoke-virtual {v3}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    invoke-virtual {v3}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v3

    if-nez v3, :cond_0

    const/4 v3, 0x0

    invoke-virtual {v0, v4, v3}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    goto/16 :goto_1

    :cond_0
    instance-of v5, v3, Ljava/lang/Boolean;

    if-eqz v5, :cond_1

    check-cast v3, Ljava/lang/Boolean;

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    invoke-virtual {v0, v4, v3}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    goto/16 :goto_1

    :cond_1
    instance-of v5, v3, Ljava/lang/Byte;

    if-eqz v5, :cond_2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->byteValue()B

    move-result v3

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putByte(Ljava/lang/String;B)V

    goto/16 :goto_1

    :cond_2
    instance-of v5, v3, Ljava/lang/Character;

    if-eqz v5, :cond_3

    check-cast v3, Ljava/lang/Character;

    invoke-virtual {v3}, Ljava/lang/Character;->charValue()C

    move-result v3

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putChar(Ljava/lang/String;C)V

    goto/16 :goto_1

    :cond_3
    instance-of v5, v3, Ljava/lang/Double;

    if-eqz v5, :cond_4

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->doubleValue()D

    move-result-wide v5

    invoke-virtual {v0, v4, v5, v6}, Landroid/os/BaseBundle;->putDouble(Ljava/lang/String;D)V

    goto/16 :goto_1

    :cond_4
    instance-of v5, v3, Ljava/lang/Float;

    if-eqz v5, :cond_5

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    move-result v3

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putFloat(Ljava/lang/String;F)V

    goto/16 :goto_1

    :cond_5
    instance-of v5, v3, Ljava/lang/Integer;

    if-eqz v5, :cond_6

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    invoke-virtual {v0, v4, v3}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    goto/16 :goto_1

    :cond_6
    instance-of v5, v3, Ljava/lang/Long;

    if-eqz v5, :cond_7

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->longValue()J

    move-result-wide v5

    invoke-virtual {v0, v4, v5, v6}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    goto/16 :goto_1

    :cond_7
    instance-of v5, v3, Ljava/lang/Short;

    if-eqz v5, :cond_8

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->shortValue()S

    move-result v3

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putShort(Ljava/lang/String;S)V

    goto/16 :goto_1

    :cond_8
    instance-of v5, v3, Landroid/os/Bundle;

    if-eqz v5, :cond_9

    check-cast v3, Landroid/os/Bundle;

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    goto/16 :goto_1

    :cond_9
    instance-of v5, v3, Ljava/lang/CharSequence;

    if-eqz v5, :cond_a

    check-cast v3, Ljava/lang/CharSequence;

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    goto/16 :goto_1

    :cond_a
    instance-of v5, v3, Landroid/os/Parcelable;

    if-eqz v5, :cond_b

    check-cast v3, Landroid/os/Parcelable;

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    goto/16 :goto_1

    :cond_b
    instance-of v5, v3, [Z

    if-eqz v5, :cond_c

    check-cast v3, [Z

    invoke-virtual {v0, v4, v3}, Landroid/os/BaseBundle;->putBooleanArray(Ljava/lang/String;[Z)V

    goto/16 :goto_1

    :cond_c
    instance-of v5, v3, [B

    if-eqz v5, :cond_d

    check-cast v3, [B

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putByteArray(Ljava/lang/String;[B)V

    goto/16 :goto_1

    :cond_d
    instance-of v5, v3, [C

    if-eqz v5, :cond_e

    check-cast v3, [C

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putCharArray(Ljava/lang/String;[C)V

    goto/16 :goto_1

    :cond_e
    instance-of v5, v3, [D

    if-eqz v5, :cond_f

    check-cast v3, [D

    invoke-virtual {v0, v4, v3}, Landroid/os/BaseBundle;->putDoubleArray(Ljava/lang/String;[D)V

    goto/16 :goto_1

    :cond_f
    instance-of v5, v3, [F

    if-eqz v5, :cond_10

    check-cast v3, [F

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putFloatArray(Ljava/lang/String;[F)V

    goto/16 :goto_1

    :cond_10
    instance-of v5, v3, [I

    if-eqz v5, :cond_11

    check-cast v3, [I

    invoke-virtual {v0, v4, v3}, Landroid/os/BaseBundle;->putIntArray(Ljava/lang/String;[I)V

    goto/16 :goto_1

    :cond_11
    instance-of v5, v3, [J

    if-eqz v5, :cond_12

    check-cast v3, [J

    invoke-virtual {v0, v4, v3}, Landroid/os/BaseBundle;->putLongArray(Ljava/lang/String;[J)V

    goto/16 :goto_1

    :cond_12
    instance-of v5, v3, [S

    if-eqz v5, :cond_13

    check-cast v3, [S

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putShortArray(Ljava/lang/String;[S)V

    goto/16 :goto_1

    :cond_13
    instance-of v5, v3, [Ljava/lang/Object;

    const/16 v6, 0x22

    const-string v7, " for key \""

    if-eqz v5, :cond_18

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const-class v8, Landroid/os/Parcelable;

    invoke-virtual {v8, v5}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v8

    if-eqz v8, :cond_14

    check-cast v3, [Landroid/os/Parcelable;

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putParcelableArray(Ljava/lang/String;[Landroid/os/Parcelable;)V

    goto/16 :goto_1

    :cond_14
    const-class v8, Ljava/lang/String;

    invoke-virtual {v8, v5}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v8

    if-eqz v8, :cond_15

    check-cast v3, [Ljava/lang/String;

    invoke-virtual {v0, v4, v3}, Landroid/os/BaseBundle;->putStringArray(Ljava/lang/String;[Ljava/lang/String;)V

    goto :goto_1

    :cond_15
    const-class v8, Ljava/lang/CharSequence;

    invoke-virtual {v8, v5}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v8

    if-eqz v8, :cond_16

    check-cast v3, [Ljava/lang/CharSequence;

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putCharSequenceArray(Ljava/lang/String;[Ljava/lang/CharSequence;)V

    goto :goto_1

    :cond_16
    const-class v8, Ljava/io/Serializable;

    invoke-virtual {v8, v5}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v8

    if-eqz v8, :cond_17

    check-cast v3, Ljava/io/Serializable;

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putSerializable(Ljava/lang/String;Ljava/io/Serializable;)V

    goto :goto_1

    :cond_17
    invoke-virtual {v5}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    move-result-object p0

    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Illegal value array type "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_18
    instance-of v5, v3, Ljava/io/Serializable;

    if-eqz v5, :cond_19

    check-cast v3, Ljava/io/Serializable;

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putSerializable(Ljava/lang/String;Ljava/io/Serializable;)V

    goto :goto_1

    :cond_19
    instance-of v5, v3, Landroid/os/IBinder;

    if-eqz v5, :cond_1a

    check-cast v3, Landroid/os/IBinder;

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putBinder(Ljava/lang/String;Landroid/os/IBinder;)V

    goto :goto_1

    :cond_1a
    instance-of v5, v3, Landroid/util/Size;

    if-eqz v5, :cond_1b

    check-cast v3, Landroid/util/Size;

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putSize(Ljava/lang/String;Landroid/util/Size;)V

    goto :goto_1

    :cond_1b
    instance-of v5, v3, Landroid/util/SizeF;

    if-eqz v5, :cond_1c

    check-cast v3, Landroid/util/SizeF;

    invoke-virtual {v0, v4, v3}, Landroid/os/Bundle;->putSizeF(Ljava/lang/String;Landroid/util/SizeF;)V

    :goto_1
    add-int/lit8 v2, v2, 0x1

    goto/16 :goto_0

    :cond_1c
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    move-result-object p0

    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Illegal value type "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1d
    return-object v0
.end method

.method public static OooOOo(Landroid/os/Bundle;)Ljava/lang/String;
    .locals 2

    if-nez p0, :cond_0

    const-string p0, "null"

    return-object p0

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    const/16 v1, 0x80

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    const-string v1, "Bundle[{"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {p0, v0}, Llyiahf/vczjk/qqa;->OooOOo0(Landroid/os/Bundle;Ljava/lang/StringBuilder;)V

    const-string p0, "}]"

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static OooOOo0(Landroid/os/Bundle;Ljava/lang/StringBuilder;)V
    .locals 3

    invoke-virtual {p0}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    const/4 v1, 0x1

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_c

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    if-nez v1, :cond_0

    const-string v1, ", "

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_0
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x3d

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p0, v2}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v1

    instance-of v2, v1, [I

    if-eqz v2, :cond_1

    check-cast v1, [I

    invoke-static {v1}, Ljava/util/Arrays;->toString([I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto/16 :goto_1

    :cond_1
    instance-of v2, v1, [B

    if-eqz v2, :cond_2

    check-cast v1, [B

    invoke-static {v1}, Ljava/util/Arrays;->toString([B)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto/16 :goto_1

    :cond_2
    instance-of v2, v1, [Z

    if-eqz v2, :cond_3

    check-cast v1, [Z

    invoke-static {v1}, Ljava/util/Arrays;->toString([Z)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto/16 :goto_1

    :cond_3
    instance-of v2, v1, [S

    if-eqz v2, :cond_4

    check-cast v1, [S

    invoke-static {v1}, Ljava/util/Arrays;->toString([S)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_1

    :cond_4
    instance-of v2, v1, [J

    if-eqz v2, :cond_5

    check-cast v1, [J

    invoke-static {v1}, Ljava/util/Arrays;->toString([J)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_1

    :cond_5
    instance-of v2, v1, [F

    if-eqz v2, :cond_6

    check-cast v1, [F

    invoke-static {v1}, Ljava/util/Arrays;->toString([F)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_1

    :cond_6
    instance-of v2, v1, [D

    if-eqz v2, :cond_7

    check-cast v1, [D

    invoke-static {v1}, Ljava/util/Arrays;->toString([D)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_1

    :cond_7
    instance-of v2, v1, [Ljava/lang/String;

    if-eqz v2, :cond_8

    check-cast v1, [Ljava/lang/String;

    invoke-static {v1}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_1

    :cond_8
    instance-of v2, v1, [Ljava/lang/CharSequence;

    if-eqz v2, :cond_9

    check-cast v1, [Ljava/lang/CharSequence;

    invoke-static {v1}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_1

    :cond_9
    instance-of v2, v1, [Landroid/os/Parcelable;

    if-eqz v2, :cond_a

    check-cast v1, [Landroid/os/Parcelable;

    invoke-static {v1}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_1

    :cond_a
    instance-of v2, v1, Landroid/os/Bundle;

    if-eqz v2, :cond_b

    check-cast v1, Landroid/os/Bundle;

    invoke-static {v1}, Llyiahf/vczjk/qqa;->OooOOo(Landroid/os/Bundle;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_1

    :cond_b
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    :goto_1
    const/4 v1, 0x0

    goto/16 :goto_0

    :cond_c
    return-void
.end method

.method public static synthetic OooOOoo(Llyiahf/vczjk/v74;)V
    .locals 1

    const/4 v0, 0x0

    invoke-interface {p0, v0}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    return-void
.end method

.method public static OooOo(JJ)J
    .locals 10

    sub-long v0, p0, p2

    xor-long v2, p0, p2

    const-wide/16 v4, 0x0

    cmp-long v2, v2, v4

    const/4 v3, 0x0

    const/4 v6, 0x1

    if-ltz v2, :cond_0

    move v2, v6

    goto :goto_0

    :cond_0
    move v2, v3

    :goto_0
    xor-long v7, p0, v0

    cmp-long v4, v7, v4

    if-ltz v4, :cond_1

    move v3, v6

    :cond_1
    or-int v4, v2, v3

    const-string v5, "checkedSubtract"

    move-wide v6, p0

    move-wide v8, p2

    invoke-static/range {v4 .. v9}, Llyiahf/vczjk/jp8;->OooOOOo(ZLjava/lang/String;JJ)V

    return-wide v0
.end method

.method public static OooOo0(Landroid/content/Context;Ljava/lang/String;)I
    .locals 2

    if-eqz p1, :cond_2

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x21

    if-ge v0, v1, :cond_1

    const-string v0, "android.permission.POST_NOTIFICATIONS"

    invoke-static {v0, p1}, Landroid/text/TextUtils;->equals(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_1

    new-instance p1, Llyiahf/vczjk/e36;

    invoke-direct {p1, p0}, Llyiahf/vczjk/e36;-><init>(Landroid/content/Context;)V

    iget-object p0, p1, Llyiahf/vczjk/e36;->OooO00o:Landroid/app/NotificationManager;

    invoke-virtual {p0}, Landroid/app/NotificationManager;->areNotificationsEnabled()Z

    move-result p0

    if-eqz p0, :cond_0

    const/4 p0, 0x0

    return p0

    :cond_0
    const/4 p0, -0x1

    return p0

    :cond_1
    invoke-static {}, Landroid/os/Process;->myPid()I

    move-result v0

    invoke-static {}, Landroid/os/Process;->myUid()I

    move-result v1

    invoke-virtual {p0, p1, v0, v1}, Landroid/content/Context;->checkPermission(Ljava/lang/String;II)I

    move-result p0

    return p0

    :cond_2
    new-instance p0, Ljava/lang/NullPointerException;

    const-string p1, "permission must be non-null"

    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static OooOo00(Z)V
    .locals 0

    if-eqz p0, :cond_0

    return-void

    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    throw p0
.end method

.method public static OooOo0O(JJ)J
    .locals 10

    add-long v0, p0, p2

    xor-long v2, p0, p2

    const-wide/16 v4, 0x0

    cmp-long v2, v2, v4

    const/4 v3, 0x0

    const/4 v6, 0x1

    if-gez v2, :cond_0

    move v2, v6

    goto :goto_0

    :cond_0
    move v2, v3

    :goto_0
    xor-long v7, p0, v0

    cmp-long v4, v7, v4

    if-ltz v4, :cond_1

    move v3, v6

    :cond_1
    or-int v4, v2, v3

    const-string v5, "checkedAdd"

    move-wide v6, p0

    move-wide v8, p2

    invoke-static/range {v4 .. v9}, Llyiahf/vczjk/jp8;->OooOOOo(ZLjava/lang/String;JJ)V

    return-wide v0
.end method

.method public static OooOo0o(JJ)J
    .locals 12

    invoke-static {p0, p1}, Ljava/lang/Long;->numberOfLeadingZeros(J)I

    move-result v0

    not-long v1, p0

    invoke-static {v1, v2}, Ljava/lang/Long;->numberOfLeadingZeros(J)I

    move-result v1

    add-int/2addr v1, v0

    invoke-static {p2, p3}, Ljava/lang/Long;->numberOfLeadingZeros(J)I

    move-result v0

    add-int/2addr v0, v1

    not-long v1, p2

    invoke-static {v1, v2}, Ljava/lang/Long;->numberOfLeadingZeros(J)I

    move-result v1

    add-int/2addr v1, v0

    const/16 v0, 0x41

    if-le v1, v0, :cond_0

    mul-long/2addr p0, p2

    return-wide p0

    :cond_0
    const/16 v0, 0x40

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-lt v1, v0, :cond_1

    move v4, v3

    goto :goto_0

    :cond_1
    move v4, v2

    :goto_0
    const-string v5, "checkedMultiply"

    move-wide v6, p0

    move-wide v8, p2

    invoke-static/range {v4 .. v9}, Llyiahf/vczjk/jp8;->OooOOOo(ZLjava/lang/String;JJ)V

    move-wide v10, v8

    move-wide v8, v6

    const-wide/16 p0, 0x0

    cmp-long p0, v8, p0

    if-ltz p0, :cond_2

    move p1, v3

    goto :goto_1

    :cond_2
    move p1, v2

    :goto_1
    const-wide/high16 p2, -0x8000000000000000L

    cmp-long p2, v10, p2

    if-eqz p2, :cond_3

    move p2, v3

    goto :goto_2

    :cond_3
    move p2, v2

    :goto_2
    or-int v6, p1, p2

    const-string v7, "checkedMultiply"

    invoke-static/range {v6 .. v11}, Llyiahf/vczjk/jp8;->OooOOOo(ZLjava/lang/String;JJ)V

    mul-long p1, v8, v10

    if-eqz p0, :cond_5

    div-long v0, p1, v8

    cmp-long p0, v0, v10

    if-nez p0, :cond_4

    goto :goto_3

    :cond_4
    move v6, v2

    goto :goto_4

    :cond_5
    :goto_3
    move v6, v3

    :goto_4
    const-string v7, "checkedMultiply"

    invoke-static/range {v6 .. v11}, Llyiahf/vczjk/jp8;->OooOOOo(ZLjava/lang/String;JJ)V

    return-wide p1
.end method

.method public static final OooOoO(Landroid/content/Context;Llyiahf/vczjk/wh1;)Llyiahf/vczjk/oqa;
    .locals 13

    const/4 v0, 0x2

    const/4 v1, 0x0

    const/4 v2, 0x1

    const-string v3, "context"

    invoke-static {p0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v7, Llyiahf/vczjk/rqa;

    iget-object v3, p1, Llyiahf/vczjk/wh1;->OooO0OO:Ljava/util/concurrent/ExecutorService;

    invoke-direct {v7, v3}, Llyiahf/vczjk/rqa;-><init>(Ljava/util/concurrent/ExecutorService;)V

    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v3

    const-string v4, "context.applicationContext"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v5, v7, Llyiahf/vczjk/rqa;->OooO00o:Llyiahf/vczjk/vq;

    const-string v6, "workTaskExecutor.serialTaskExecutor"

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v6

    sget v8, Landroidx/work/R$bool;->workmanager_test_configuration:I

    invoke-virtual {v6, v8}, Landroid/content/res/Resources;->getBoolean(I)Z

    move-result v6

    iget-object v8, p1, Llyiahf/vczjk/wh1;->OooO0Oo:Llyiahf/vczjk/vp3;

    const-string v9, "clock"

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-class v9, Landroidx/work/impl/WorkDatabase;

    if-eqz v6, :cond_0

    new-instance v6, Llyiahf/vczjk/lu7;

    const/4 v10, 0x0

    invoke-direct {v6, v3, v9, v10}, Llyiahf/vczjk/lu7;-><init>(Landroid/content/Context;Ljava/lang/Class;Ljava/lang/String;)V

    iput-boolean v2, v6, Llyiahf/vczjk/lu7;->OooO:Z

    goto :goto_0

    :cond_0
    const-string v6, "androidx.work.workdb"

    invoke-static {v3, v9, v6}, Llyiahf/vczjk/rd3;->OooOOOo(Landroid/content/Context;Ljava/lang/Class;Ljava/lang/String;)Llyiahf/vczjk/lu7;

    move-result-object v6

    new-instance v9, Llyiahf/vczjk/cl4;

    invoke-direct {v9, v3}, Llyiahf/vczjk/cl4;-><init>(Landroid/content/Context;)V

    iput-object v9, v6, Llyiahf/vczjk/lu7;->OooO0oo:Llyiahf/vczjk/cl4;

    :goto_0
    iput-object v5, v6, Llyiahf/vczjk/lu7;->OooO0o:Ljava/util/concurrent/Executor;

    new-instance v5, Llyiahf/vczjk/lz0;

    invoke-direct {v5, v8}, Llyiahf/vczjk/lz0;-><init>(Llyiahf/vczjk/vp3;)V

    iget-object v8, v6, Llyiahf/vczjk/lu7;->OooO0Oo:Ljava/util/ArrayList;

    invoke-virtual {v8, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-array v5, v2, [Llyiahf/vczjk/ej5;

    sget-object v8, Llyiahf/vczjk/fj5;->OooO0o:Llyiahf/vczjk/fj5;

    aput-object v8, v5, v1

    invoke-virtual {v6, v5}, Llyiahf/vczjk/lu7;->OooO00o([Llyiahf/vczjk/ej5;)V

    new-instance v5, Llyiahf/vczjk/kr7;

    const/4 v8, 0x3

    invoke-direct {v5, v3, v0, v8}, Llyiahf/vczjk/kr7;-><init>(Landroid/content/Context;II)V

    new-array v8, v2, [Llyiahf/vczjk/ej5;

    aput-object v5, v8, v1

    invoke-virtual {v6, v8}, Llyiahf/vczjk/lu7;->OooO00o([Llyiahf/vczjk/ej5;)V

    new-array v5, v2, [Llyiahf/vczjk/ej5;

    sget-object v8, Llyiahf/vczjk/fj5;->OooO0oO:Llyiahf/vczjk/fj5;

    aput-object v8, v5, v1

    invoke-virtual {v6, v5}, Llyiahf/vczjk/lu7;->OooO00o([Llyiahf/vczjk/ej5;)V

    new-array v5, v2, [Llyiahf/vczjk/ej5;

    sget-object v8, Llyiahf/vczjk/fj5;->OooO0oo:Llyiahf/vczjk/fj5;

    aput-object v8, v5, v1

    invoke-virtual {v6, v5}, Llyiahf/vczjk/lu7;->OooO00o([Llyiahf/vczjk/ej5;)V

    new-instance v5, Llyiahf/vczjk/kr7;

    const/4 v8, 0x5

    const/4 v9, 0x6

    invoke-direct {v5, v3, v8, v9}, Llyiahf/vczjk/kr7;-><init>(Landroid/content/Context;II)V

    new-array v8, v2, [Llyiahf/vczjk/ej5;

    aput-object v5, v8, v1

    invoke-virtual {v6, v8}, Llyiahf/vczjk/lu7;->OooO00o([Llyiahf/vczjk/ej5;)V

    new-array v5, v2, [Llyiahf/vczjk/ej5;

    sget-object v8, Llyiahf/vczjk/fj5;->OooO:Llyiahf/vczjk/fj5;

    aput-object v8, v5, v1

    invoke-virtual {v6, v5}, Llyiahf/vczjk/lu7;->OooO00o([Llyiahf/vczjk/ej5;)V

    new-array v5, v2, [Llyiahf/vczjk/ej5;

    sget-object v8, Llyiahf/vczjk/fj5;->OooOO0:Llyiahf/vczjk/fj5;

    aput-object v8, v5, v1

    invoke-virtual {v6, v5}, Llyiahf/vczjk/lu7;->OooO00o([Llyiahf/vczjk/ej5;)V

    new-array v5, v2, [Llyiahf/vczjk/ej5;

    sget-object v8, Llyiahf/vczjk/fj5;->OooOO0O:Llyiahf/vczjk/fj5;

    aput-object v8, v5, v1

    invoke-virtual {v6, v5}, Llyiahf/vczjk/lu7;->OooO00o([Llyiahf/vczjk/ej5;)V

    new-instance v5, Llyiahf/vczjk/kr7;

    invoke-direct {v5, v3}, Llyiahf/vczjk/kr7;-><init>(Landroid/content/Context;)V

    new-array v8, v2, [Llyiahf/vczjk/ej5;

    aput-object v5, v8, v1

    invoke-virtual {v6, v8}, Llyiahf/vczjk/lu7;->OooO00o([Llyiahf/vczjk/ej5;)V

    new-instance v5, Llyiahf/vczjk/kr7;

    const/16 v8, 0xa

    const/16 v9, 0xb

    invoke-direct {v5, v3, v8, v9}, Llyiahf/vczjk/kr7;-><init>(Landroid/content/Context;II)V

    new-array v8, v2, [Llyiahf/vczjk/ej5;

    aput-object v5, v8, v1

    invoke-virtual {v6, v8}, Llyiahf/vczjk/lu7;->OooO00o([Llyiahf/vczjk/ej5;)V

    new-array v5, v2, [Llyiahf/vczjk/ej5;

    sget-object v8, Llyiahf/vczjk/fj5;->OooO0O0:Llyiahf/vczjk/fj5;

    aput-object v8, v5, v1

    invoke-virtual {v6, v5}, Llyiahf/vczjk/lu7;->OooO00o([Llyiahf/vczjk/ej5;)V

    new-array v5, v2, [Llyiahf/vczjk/ej5;

    sget-object v8, Llyiahf/vczjk/fj5;->OooO0OO:Llyiahf/vczjk/fj5;

    aput-object v8, v5, v1

    invoke-virtual {v6, v5}, Llyiahf/vczjk/lu7;->OooO00o([Llyiahf/vczjk/ej5;)V

    new-array v5, v2, [Llyiahf/vczjk/ej5;

    sget-object v8, Llyiahf/vczjk/fj5;->OooO0Oo:Llyiahf/vczjk/fj5;

    aput-object v8, v5, v1

    invoke-virtual {v6, v5}, Llyiahf/vczjk/lu7;->OooO00o([Llyiahf/vczjk/ej5;)V

    new-array v5, v2, [Llyiahf/vczjk/ej5;

    sget-object v8, Llyiahf/vczjk/fj5;->OooO0o0:Llyiahf/vczjk/fj5;

    aput-object v8, v5, v1

    invoke-virtual {v6, v5}, Llyiahf/vczjk/lu7;->OooO00o([Llyiahf/vczjk/ej5;)V

    new-instance v5, Llyiahf/vczjk/kr7;

    const/16 v8, 0x15

    const/16 v9, 0x16

    invoke-direct {v5, v3, v8, v9}, Llyiahf/vczjk/kr7;-><init>(Landroid/content/Context;II)V

    new-array v3, v2, [Llyiahf/vczjk/ej5;

    aput-object v5, v3, v1

    invoke-virtual {v6, v3}, Llyiahf/vczjk/lu7;->OooO00o([Llyiahf/vczjk/ej5;)V

    invoke-virtual {v6}, Llyiahf/vczjk/lu7;->OooO0OO()V

    invoke-virtual {v6}, Llyiahf/vczjk/lu7;->OooO0O0()Llyiahf/vczjk/ru7;

    move-result-object v3

    check-cast v3, Landroidx/work/impl/WorkDatabase;

    new-instance v11, Llyiahf/vczjk/qx9;

    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v5

    invoke-static {v5, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v11, v5, v7}, Llyiahf/vczjk/qx9;-><init>(Landroid/content/Context;Llyiahf/vczjk/rqa;)V

    new-instance v8, Llyiahf/vczjk/n77;

    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v4

    invoke-direct {v8, v4, p1, v7, v3}, Llyiahf/vczjk/n77;-><init>(Landroid/content/Context;Llyiahf/vczjk/wh1;Llyiahf/vczjk/rqa;Landroidx/work/impl/WorkDatabase;)V

    sget-object v4, Llyiahf/vczjk/pqa;->OooOOO:Llyiahf/vczjk/pqa;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v4, "p0"

    invoke-static {p0, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "p1"

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "p2"

    invoke-static {v7, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "p3"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "p4"

    invoke-static {v11, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v4, Llyiahf/vczjk/t88;->OooO00o:Ljava/lang/String;

    new-instance v12, Llyiahf/vczjk/od9;

    invoke-direct {v12, p0, v3, p1}, Llyiahf/vczjk/od9;-><init>(Landroid/content/Context;Landroidx/work/impl/WorkDatabase;Llyiahf/vczjk/wh1;)V

    const-class v4, Landroidx/work/impl/background/systemjob/SystemJobService;

    invoke-static {p0, v4, v2}, Llyiahf/vczjk/nh6;->OooO00o(Landroid/content/Context;Ljava/lang/Class;Z)V

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/t88;->OooO00o:Ljava/lang/String;

    const-string v6, "Created SystemJobScheduler and enabled SystemJobService"

    invoke-virtual {v4, v5, v6}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    new-instance v4, Llyiahf/vczjk/xj3;

    new-instance v9, Llyiahf/vczjk/bp8;

    invoke-direct {v9, v8, v7}, Llyiahf/vczjk/bp8;-><init>(Llyiahf/vczjk/n77;Llyiahf/vczjk/rqa;)V

    move-object v5, p0

    move-object v6, p1

    move-object v10, v7

    move-object v7, v11

    invoke-direct/range {v4 .. v10}, Llyiahf/vczjk/xj3;-><init>(Landroid/content/Context;Llyiahf/vczjk/wh1;Llyiahf/vczjk/qx9;Llyiahf/vczjk/n77;Llyiahf/vczjk/bp8;Llyiahf/vczjk/rqa;)V

    move-object v7, v10

    new-array p0, v0, [Llyiahf/vczjk/j88;

    aput-object v12, p0, v1

    aput-object v4, p0, v2

    invoke-static {p0}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p0

    move-object v9, p0

    check-cast v9, Ljava/util/List;

    new-instance v4, Llyiahf/vczjk/oqa;

    invoke-virtual {v5}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v5

    move-object v10, v8

    move-object v8, v3

    invoke-direct/range {v4 .. v11}, Llyiahf/vczjk/oqa;-><init>(Landroid/content/Context;Llyiahf/vczjk/wh1;Llyiahf/vczjk/rqa;Landroidx/work/impl/WorkDatabase;Ljava/util/List;Llyiahf/vczjk/n77;Llyiahf/vczjk/qx9;)V

    return-object v4
.end method

.method public static final OooOoO0(Llyiahf/vczjk/by0;Ljava/util/LinkedHashSet;Llyiahf/vczjk/jg5;Z)V
    .locals 5

    sget-object v0, Llyiahf/vczjk/e72;->OooOOOO:Llyiahf/vczjk/e72;

    const/4 v1, 0x2

    invoke-static {p2, v0, v1}, Llyiahf/vczjk/kh6;->OooOo0(Llyiahf/vczjk/mr7;Llyiahf/vczjk/e72;I)Ljava/util/Collection;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_8

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/v02;

    instance-of v2, v1, Llyiahf/vczjk/by0;

    if-eqz v2, :cond_0

    check-cast v1, Llyiahf/vczjk/by0;

    invoke-interface {v1}, Llyiahf/vczjk/yf5;->Oooo0()Z

    move-result v2

    const/4 v3, 0x0

    if-eqz v2, :cond_3

    invoke-interface {v1}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v1

    const-string v2, "getName(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v2, Llyiahf/vczjk/h16;->OooOOOo:Llyiahf/vczjk/h16;

    invoke-interface {p2, v1, v2}, Llyiahf/vczjk/mr7;->OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;

    move-result-object v1

    instance-of v2, v1, Llyiahf/vczjk/by0;

    if-eqz v2, :cond_1

    check-cast v1, Llyiahf/vczjk/by0;

    goto :goto_1

    :cond_1
    instance-of v2, v1, Llyiahf/vczjk/a3a;

    if-eqz v2, :cond_2

    check-cast v1, Llyiahf/vczjk/a3a;

    check-cast v1, Llyiahf/vczjk/v82;

    invoke-virtual {v1}, Llyiahf/vczjk/v82;->o0000O0()Llyiahf/vczjk/by0;

    move-result-object v1

    goto :goto_1

    :cond_2
    move-object v1, v3

    :cond_3
    :goto_1
    if-nez v1, :cond_4

    goto :goto_0

    :cond_4
    if-eqz p0, :cond_7

    sget v2, Llyiahf/vczjk/n72;->OooO00o:I

    invoke-interface {v1}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/n3a;->OooO0O0()Ljava/util/Collection;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_5
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_6

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/uk4;

    invoke-interface {p0}, Llyiahf/vczjk/by0;->OooO00o()Llyiahf/vczjk/by0;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/n72;->OooOOOo(Llyiahf/vczjk/uk4;Llyiahf/vczjk/by0;)Z

    move-result v3

    if-eqz v3, :cond_5

    invoke-virtual {p1, v1}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z

    :cond_6
    if-eqz p3, :cond_0

    invoke-interface {v1}, Llyiahf/vczjk/by0;->o0ooOO0()Llyiahf/vczjk/jg5;

    move-result-object v1

    const-string v2, "getUnsubstitutedInnerClassesScope(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, p1, v1, p3}, Llyiahf/vczjk/qqa;->OooOoO0(Llyiahf/vczjk/by0;Ljava/util/LinkedHashSet;Llyiahf/vczjk/jg5;Z)V

    goto :goto_0

    :cond_7
    const/16 p0, 0x1b

    invoke-static {p0}, Llyiahf/vczjk/n72;->OooO00o(I)V

    throw v3

    :cond_8
    return-void
.end method

.method public static OooOoOO(Ljava/lang/String;Llyiahf/vczjk/og8;)Llyiahf/vczjk/lz1;
    .locals 5

    sget-object v0, Llyiahf/vczjk/ke0;->OooOooo:Llyiahf/vczjk/ke0;

    sget-object v1, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v1, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    invoke-static {}, Llyiahf/vczjk/vl6;->OooO0O0()Llyiahf/vczjk/u99;

    move-result-object v2

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1, v2}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooO0oO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/to1;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/lz1;

    new-instance v3, Llyiahf/vczjk/uz5;

    const/16 v4, 0x1b

    invoke-direct {v3, p1, v4}, Llyiahf/vczjk/uz5;-><init>(Ljava/lang/Object;I)V

    invoke-direct {v2, p0, v3, v0, v1}, Llyiahf/vczjk/lz1;-><init>(Ljava/lang/String;Llyiahf/vczjk/uz5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/xr1;)V

    return-object v2
.end method

.method public static final OooOoo(Landroid/content/Context;Landroid/net/Uri;)Llyiahf/vczjk/op8;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "fileUri"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :try_start_0
    invoke-static {p0, p1}, Llyiahf/vczjk/jd2;->OooO0Oo(Landroid/content/Context;Landroid/net/Uri;)Llyiahf/vczjk/op8;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public static final OooOoo0(Landroid/net/Uri;Landroidx/activity/ComponentActivity;)Llyiahf/vczjk/op8;
    .locals 2

    const-string v0, "<this>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :try_start_0
    new-instance v0, Llyiahf/vczjk/op8;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/op8;-><init>(I)V

    iput-object p1, v0, Llyiahf/vczjk/op8;->OooO0OO:Landroid/content/Context;

    iput-object p0, v0, Llyiahf/vczjk/op8;->OooO0O0:Landroid/net/Uri;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public static OooOooo(Landroid/content/Context;I)Landroid/content/res/ColorStateList;
    .locals 8

    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    invoke-virtual {p0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object p0

    new-instance v1, Llyiahf/vczjk/ds7;

    invoke-direct {v1, v0, p0}, Llyiahf/vczjk/ds7;-><init>(Landroid/content/res/Resources;Landroid/content/res/Resources$Theme;)V

    sget-object v2, Llyiahf/vczjk/es7;->OooO0OO:Ljava/lang/Object;

    monitor-enter v2

    :try_start_0
    sget-object v3, Llyiahf/vczjk/es7;->OooO0O0:Ljava/util/WeakHashMap;

    invoke-virtual {v3, v1}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/util/SparseArray;

    const/4 v4, 0x0

    if-eqz v3, :cond_3

    invoke-virtual {v3}, Landroid/util/SparseArray;->size()I

    move-result v5

    if-lez v5, :cond_3

    invoke-virtual {v3, p1}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/cs7;

    if-eqz v5, :cond_3

    iget-object v6, v5, Llyiahf/vczjk/cs7;->OooO0O0:Landroid/content/res/Configuration;

    invoke-virtual {v0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object v7

    invoke-virtual {v6, v7}, Landroid/content/res/Configuration;->equals(Landroid/content/res/Configuration;)Z

    move-result v6

    if-eqz v6, :cond_2

    if-nez p0, :cond_0

    iget v6, v5, Llyiahf/vczjk/cs7;->OooO0OO:I

    if-eqz v6, :cond_1

    goto :goto_0

    :catchall_0
    move-exception p0

    goto/16 :goto_6

    :cond_0
    :goto_0
    if-eqz p0, :cond_2

    iget v6, v5, Llyiahf/vczjk/cs7;->OooO0OO:I

    invoke-virtual {p0}, Landroid/content/res/Resources$Theme;->hashCode()I

    move-result v7

    if-ne v6, v7, :cond_2

    :cond_1
    iget-object v3, v5, Llyiahf/vczjk/cs7;->OooO00o:Landroid/content/res/ColorStateList;

    monitor-exit v2

    goto :goto_1

    :cond_2
    invoke-virtual {v3, p1}, Landroid/util/SparseArray;->remove(I)V

    :cond_3
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    move-object v3, v4

    :goto_1
    if-eqz v3, :cond_4

    return-object v3

    :cond_4
    sget-object v2, Llyiahf/vczjk/es7;->OooO00o:Ljava/lang/ThreadLocal;

    invoke-virtual {v2}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/util/TypedValue;

    if-nez v3, :cond_5

    new-instance v3, Landroid/util/TypedValue;

    invoke-direct {v3}, Landroid/util/TypedValue;-><init>()V

    invoke-virtual {v2, v3}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    :cond_5
    const/4 v2, 0x1

    invoke-virtual {v0, p1, v3, v2}, Landroid/content/res/Resources;->getValue(ILandroid/util/TypedValue;Z)V

    iget v2, v3, Landroid/util/TypedValue;->type:I

    const/16 v3, 0x1c

    if-lt v2, v3, :cond_6

    const/16 v3, 0x1f

    if-gt v2, v3, :cond_6

    goto :goto_2

    :cond_6
    invoke-virtual {v0, p1}, Landroid/content/res/Resources;->getXml(I)Landroid/content/res/XmlResourceParser;

    move-result-object v2

    :try_start_1
    invoke-static {v0, v2, p0}, Llyiahf/vczjk/f31;->OooO00o(Landroid/content/res/Resources;Landroid/content/res/XmlResourceParser;Landroid/content/res/Resources$Theme;)Landroid/content/res/ColorStateList;

    move-result-object v4
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    goto :goto_2

    :catch_0
    move-exception v2

    const-string v3, "ResourcesCompat"

    const-string v5, "Failed to inflate ColorStateList, leaving it to the framework"

    invoke-static {v3, v5, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :goto_2
    if-eqz v4, :cond_8

    sget-object v2, Llyiahf/vczjk/es7;->OooO0OO:Ljava/lang/Object;

    monitor-enter v2

    :try_start_2
    sget-object v0, Llyiahf/vczjk/es7;->OooO0O0:Ljava/util/WeakHashMap;

    invoke-virtual {v0, v1}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/util/SparseArray;

    if-nez v3, :cond_7

    new-instance v3, Landroid/util/SparseArray;

    invoke-direct {v3}, Landroid/util/SparseArray;-><init>()V

    invoke-virtual {v0, v1, v3}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_3

    :catchall_1
    move-exception p0

    goto :goto_4

    :cond_7
    :goto_3
    new-instance v0, Llyiahf/vczjk/cs7;

    iget-object v1, v1, Llyiahf/vczjk/ds7;->OooO00o:Landroid/content/res/Resources;

    invoke-virtual {v1}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object v1

    invoke-direct {v0, v4, v1, p0}, Llyiahf/vczjk/cs7;-><init>(Landroid/content/res/ColorStateList;Landroid/content/res/Configuration;Landroid/content/res/Resources$Theme;)V

    invoke-virtual {v3, p1, v0}, Landroid/util/SparseArray;->append(ILjava/lang/Object;)V

    monitor-exit v2

    goto :goto_5

    :goto_4
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    throw p0

    :cond_8
    invoke-virtual {v0, p1, p0}, Landroid/content/res/Resources;->getColorStateList(ILandroid/content/res/Resources$Theme;)Landroid/content/res/ColorStateList;

    move-result-object v4

    :goto_5
    return-object v4

    :goto_6
    :try_start_3
    monitor-exit v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    throw p0
.end method

.method public static Oooo0(Landroid/content/Intent;Ljava/lang/StringBuilder;)V
    .locals 7

    invoke-virtual {p0}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-eqz v0, :cond_0

    const-string v3, "act="

    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move v0, v1

    goto :goto_0

    :cond_0
    move v0, v2

    :goto_0
    invoke-virtual {p0}, Landroid/content/Intent;->getCategories()Ljava/util/Set;

    move-result-object v3

    const/16 v4, 0x20

    if-eqz v3, :cond_4

    if-nez v0, :cond_1

    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    :cond_1
    const-string v0, "cat=["

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    move v3, v2

    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/String;

    if-nez v3, :cond_2

    const/16 v3, 0x2c

    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    :cond_2
    invoke-virtual {p1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move v3, v1

    goto :goto_1

    :cond_3
    const-string v0, "]"

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move v0, v1

    :cond_4
    invoke-virtual {p0}, Landroid/content/Intent;->getData()Landroid/net/Uri;

    move-result-object v3

    if-eqz v3, :cond_6

    if-nez v0, :cond_5

    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    :cond_5
    const-string v0, "dat="

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :try_start_0
    const-class v0, Landroid/net/Uri;

    const-string v5, "toSafeString"

    const/4 v6, 0x0

    invoke-virtual {v0, v5, v6}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    invoke-virtual {v0, v2}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    invoke-virtual {v0, v3, v6}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_6

    :catch_0
    move-exception v0

    goto :goto_2

    :catch_1
    move-exception v0

    goto :goto_3

    :catch_2
    move-exception v0

    goto :goto_4

    :goto_2
    invoke-virtual {v0}, Ljava/lang/Throwable;->printStackTrace()V

    goto :goto_5

    :goto_3
    invoke-virtual {v0}, Ljava/lang/Throwable;->printStackTrace()V

    goto :goto_5

    :goto_4
    invoke-virtual {v0}, Ljava/lang/Throwable;->printStackTrace()V

    :goto_5
    invoke-virtual {v3}, Landroid/net/Uri;->toString()Ljava/lang/String;

    move-result-object v0

    :goto_6
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move v0, v1

    :cond_6
    invoke-virtual {p0}, Landroid/content/Intent;->getType()Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_8

    if-nez v0, :cond_7

    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    :cond_7
    const-string v0, "typ="

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move v0, v1

    :cond_8
    invoke-virtual {p0}, Landroid/content/Intent;->getFlags()I

    move-result v2

    if-eqz v2, :cond_a

    if-nez v0, :cond_9

    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    :cond_9
    const-string v0, "flg=0x"

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {v2}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move v0, v1

    :cond_a
    invoke-virtual {p0}, Landroid/content/Intent;->getPackage()Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_c

    if-nez v0, :cond_b

    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    :cond_b
    const-string v0, "pkg="

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move v0, v1

    :cond_c
    invoke-virtual {p0}, Landroid/content/Intent;->getComponent()Landroid/content/ComponentName;

    move-result-object v2

    if-eqz v2, :cond_e

    if-nez v0, :cond_d

    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    :cond_d
    const-string v0, "cmp="

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Landroid/content/ComponentName;->flattenToShortString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move v0, v1

    :cond_e
    invoke-virtual {p0}, Landroid/content/Intent;->getSourceBounds()Landroid/graphics/Rect;

    move-result-object v2

    if-eqz v2, :cond_10

    if-nez v0, :cond_f

    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    :cond_f
    const-string v0, "bnds="

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Landroid/graphics/Rect;->toShortString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move v0, v1

    :cond_10
    invoke-virtual {p0}, Landroid/content/Intent;->getClipData()Landroid/content/ClipData;

    move-result-object v2

    if-eqz v2, :cond_12

    if-nez v0, :cond_11

    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    :cond_11
    const-string v0, "(has clip)"

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_7

    :cond_12
    move v1, v0

    :goto_7
    invoke-virtual {p0}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    move-result-object v0

    if-eqz v0, :cond_14

    if-nez v1, :cond_13

    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    :cond_13
    const-string v1, "extras={"

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {v0, p1}, Llyiahf/vczjk/qqa;->OooOOo0(Landroid/os/Bundle;Ljava/lang/StringBuilder;)V

    const/16 v0, 0x7d

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    :cond_14
    invoke-virtual {p0}, Landroid/content/Intent;->getSelector()Landroid/content/Intent;

    move-result-object p0

    if-eqz p0, :cond_15

    const-string v0, " sel="

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {p0, p1}, Llyiahf/vczjk/qqa;->Oooo0(Landroid/content/Intent;Ljava/lang/StringBuilder;)V

    const-string p0, "}"

    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_15
    return-void
.end method

.method public static final Oooo000()Llyiahf/vczjk/qv3;
    .locals 12

    sget-object v0, Llyiahf/vczjk/qqa;->OooO0oo:Llyiahf/vczjk/qv3;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v1, Llyiahf/vczjk/pv3;

    const/4 v9, 0x0

    const/4 v10, 0x0

    const-string v2, "Outlined.LabelImportant"

    const/high16 v3, 0x41c00000    # 24.0f

    const/high16 v4, 0x41c00000    # 24.0f

    const/high16 v5, 0x41c00000    # 24.0f

    const/high16 v6, 0x41c00000    # 24.0f

    const-wide/16 v7, 0x0

    const/16 v11, 0x60

    invoke-direct/range {v1 .. v11}, Llyiahf/vczjk/pv3;-><init>(Ljava/lang/String;FFFFJIZI)V

    sget v0, Llyiahf/vczjk/tda;->OooO00o:I

    new-instance v0, Llyiahf/vczjk/gx8;

    sget-wide v2, Llyiahf/vczjk/n21;->OooO0O0:J

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/gx8;-><init>(J)V

    new-instance v4, Llyiahf/vczjk/jq;

    const/4 v2, 0x1

    invoke-direct {v4, v2}, Llyiahf/vczjk/jq;-><init>(I)V

    const/high16 v2, 0x40800000    # 4.0f

    const v3, 0x4197eb85    # 18.99f

    invoke-virtual {v4, v2, v3}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v3, 0x41300000    # 11.0f

    invoke-virtual {v4, v3}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const v7, 0x3fa28f5c    # 1.27f

    const v8, -0x415c28f6    # -0.32f

    const v5, 0x3f2b851f    # 0.67f

    const/4 v6, 0x0

    const v9, 0x3fd0a3d7    # 1.63f

    const v10, -0x40ab851f    # -0.83f

    invoke-virtual/range {v4 .. v10}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    const/high16 v3, 0x41a80000    # 21.0f

    const/high16 v5, 0x41400000    # 12.0f

    invoke-virtual {v4, v3, v5}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    const v3, -0x3f7428f6    # -4.37f

    const v5, -0x3f3ae148    # -6.16f

    invoke-virtual {v4, v3, v5}, Llyiahf/vczjk/jq;->OooO0oo(FF)V

    const v7, 0x417ab852    # 15.67f

    const/high16 v8, 0x40a00000    # 5.0f

    const v5, 0x418228f6    # 16.27f

    const v6, 0x40aa8f5c    # 5.33f

    const/high16 v9, 0x41700000    # 15.0f

    const/high16 v10, 0x40a00000    # 5.0f

    invoke-virtual/range {v4 .. v10}, Llyiahf/vczjk/jq;->OooO0OO(FFFFFF)V

    invoke-virtual {v4, v2}, Llyiahf/vczjk/jq;->OooO0o0(F)V

    const/high16 v2, 0x40a00000    # 5.0f

    const/high16 v3, 0x40e00000    # 7.0f

    invoke-virtual {v4, v2, v3}, Llyiahf/vczjk/jq;->OooO0oo(FF)V

    const/high16 v2, -0x3f600000    # -5.0f

    const v3, 0x40dfae14    # 6.99f

    invoke-virtual {v4, v2, v3}, Llyiahf/vczjk/jq;->OooO0oo(FF)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    iget-object v2, v4, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/pv3;->OooO00o(Llyiahf/vczjk/pv3;Ljava/util/ArrayList;Llyiahf/vczjk/gx8;)V

    invoke-virtual {v1}, Llyiahf/vczjk/pv3;->OooO0O0()Llyiahf/vczjk/qv3;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/qqa;->OooO0oo:Llyiahf/vczjk/qv3;

    return-object v0
.end method

.method public static final Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;
    .locals 4

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/qqa;->OooO0o0:Llyiahf/vczjk/pp3;

    monitor-enter v0

    :try_start_0
    const-string v1, "androidx.lifecycle.viewmodel.internal.ViewModelCoroutineScope.JOB_KEY"

    invoke-virtual {p0, v1}, Llyiahf/vczjk/dha;->OooO0OO(Ljava/lang/String;)Ljava/lang/AutoCloseable;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/k01;

    if-nez v1, :cond_0

    sget-object v1, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :try_start_1
    sget-object v2, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v2, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    iget-object v1, v2, Llyiahf/vczjk/xl3;->OooOOo:Llyiahf/vczjk/xl3;
    :try_end_1
    .catch Llyiahf/vczjk/s26; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :catch_0
    :try_start_2
    new-instance v2, Llyiahf/vczjk/k01;

    invoke-static {}, Llyiahf/vczjk/vl6;->OooO0O0()Llyiahf/vczjk/u99;

    move-result-object v3

    invoke-interface {v1, v3}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v1

    invoke-direct {v2, v1}, Llyiahf/vczjk/k01;-><init>(Llyiahf/vczjk/or1;)V

    const-string v1, "androidx.lifecycle.viewmodel.internal.ViewModelCoroutineScope.JOB_KEY"

    invoke-virtual {p0, v1, v2}, Llyiahf/vczjk/dha;->OooO00o(Ljava/lang/String;Ljava/lang/AutoCloseable;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    move-object v1, v2

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit v0

    return-object v1

    :goto_1
    monitor-exit v0

    throw p0
.end method

.method public static final Oooo00o(Llyiahf/vczjk/fy9;Llyiahf/vczjk/uf8;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 10

    instance-of v0, p2, Llyiahf/vczjk/vf8;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/vf8;

    iget v1, v0, Llyiahf/vczjk/vf8;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/vf8;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/vf8;

    invoke-direct {v0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/vf8;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/vf8;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget p0, v0, Llyiahf/vczjk/vf8;->I$1:I

    iget p1, v0, Llyiahf/vczjk/vf8;->I$0:I

    iget-object v2, v0, Llyiahf/vczjk/vf8;->L$4:Ljava/lang/Object;

    iget-object v4, v0, Llyiahf/vczjk/vf8;->L$3:Ljava/lang/Object;

    check-cast v4, Ljava/util/ArrayList;

    iget-object v5, v0, Llyiahf/vczjk/vf8;->L$2:Ljava/lang/Object;

    check-cast v5, Ljava/util/ArrayList;

    iget-object v6, v0, Llyiahf/vczjk/vf8;->L$1:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/bf3;

    iget-object v7, v0, Llyiahf/vczjk/vf8;->L$0:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/fy9;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v9, v4

    move-object v4, v0

    move-object v0, v6

    :goto_1
    move-object v6, v5

    move-object v5, v9

    goto/16 :goto_4

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/fy9;->OooO0O0:Ljava/util/List;

    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    move-result p2

    if-eqz p2, :cond_3

    return-object p0

    :cond_3
    iget-object p2, p0, Llyiahf/vczjk/fy9;->OooO0O0:Ljava/util/List;

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result v2

    add-int/lit8 v2, v2, 0x4

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4, v2}, Ljava/util/ArrayList;-><init>(I)V

    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-static {p2}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object v2, p0, Llyiahf/vczjk/fy9;->OooO0Oo:Ljava/util/List;

    if-eqz v2, :cond_4

    invoke-static {v2}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    goto :goto_2

    :cond_4
    const/4 v2, 0x0

    :goto_2
    new-instance v6, Ljava/lang/Integer;

    invoke-direct {v6, v2}, Ljava/lang/Integer;-><init>(I)V

    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result p2

    move-object v2, v5

    move-object v5, v4

    move-object v4, v2

    move-object v2, v0

    move-object v0, p1

    move-object p1, p0

    move p0, p2

    move p2, v3

    :goto_3
    if-ge p2, p0, :cond_7

    iget-object v6, p1, Llyiahf/vczjk/fy9;->OooO0O0:Ljava/util/List;

    invoke-interface {v6, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    add-int/lit8 v7, p2, -0x1

    iget-object v8, p1, Llyiahf/vczjk/fy9;->OooO0O0:Ljava/util/List;

    invoke-interface {v8, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v7

    iput-object p1, v2, Llyiahf/vczjk/vf8;->L$0:Ljava/lang/Object;

    iput-object v0, v2, Llyiahf/vczjk/vf8;->L$1:Ljava/lang/Object;

    iput-object v5, v2, Llyiahf/vczjk/vf8;->L$2:Ljava/lang/Object;

    iput-object v4, v2, Llyiahf/vczjk/vf8;->L$3:Ljava/lang/Object;

    iput-object v6, v2, Llyiahf/vczjk/vf8;->L$4:Ljava/lang/Object;

    iput p2, v2, Llyiahf/vczjk/vf8;->I$0:I

    iput p0, v2, Llyiahf/vczjk/vf8;->I$1:I

    iput v3, v2, Llyiahf/vczjk/vf8;->label:I

    invoke-interface {v0, v7, v6, v2}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v7

    if-ne v7, v1, :cond_5

    return-object v1

    :cond_5
    move-object v9, v7

    move-object v7, p1

    move p1, p2

    move-object p2, v9

    move-object v9, v4

    move-object v4, v2

    move-object v2, v6

    goto/16 :goto_1

    :goto_4
    if-eqz p2, :cond_6

    invoke-virtual {v6, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance p2, Ljava/lang/Integer;

    invoke-direct {p2, p1}, Ljava/lang/Integer;-><init>(I)V

    invoke-virtual {v5, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_6
    invoke-virtual {v6, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance p2, Ljava/lang/Integer;

    invoke-direct {p2, p1}, Ljava/lang/Integer;-><init>(I)V

    invoke-virtual {v5, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 p2, p1, 0x1

    move-object v2, v4

    move-object v4, v5

    move-object v5, v6

    move-object p1, v7

    goto :goto_3

    :cond_7
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    move-result p0

    iget-object p2, p1, Llyiahf/vczjk/fy9;->OooO0O0:Ljava/util/List;

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result p2

    if-ne p0, p2, :cond_8

    return-object p1

    :cond_8
    new-instance p0, Llyiahf/vczjk/fy9;

    iget-object p2, p1, Llyiahf/vczjk/fy9;->OooO00o:[I

    iget p1, p1, Llyiahf/vczjk/fy9;->OooO0OO:I

    invoke-direct {p0, p2, v5, p1, v4}, Llyiahf/vczjk/fy9;-><init>([ILjava/util/List;ILjava/util/List;)V

    return-object p0
.end method

.method public static Oooo0O0(ILandroid/graphics/Rect;Landroid/graphics/Rect;)Z
    .locals 1

    const/16 v0, 0x11

    if-eq p0, v0, :cond_6

    const/16 v0, 0x21

    if-eq p0, v0, :cond_4

    const/16 v0, 0x42

    if-eq p0, v0, :cond_2

    const/16 v0, 0x82

    if-ne p0, v0, :cond_1

    iget p0, p1, Landroid/graphics/Rect;->top:I

    iget v0, p2, Landroid/graphics/Rect;->top:I

    if-lt p0, v0, :cond_0

    iget p0, p1, Landroid/graphics/Rect;->bottom:I

    if-gt p0, v0, :cond_8

    :cond_0
    iget p0, p1, Landroid/graphics/Rect;->bottom:I

    iget p1, p2, Landroid/graphics/Rect;->bottom:I

    if-ge p0, p1, :cond_8

    goto :goto_0

    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    iget p0, p1, Landroid/graphics/Rect;->left:I

    iget v0, p2, Landroid/graphics/Rect;->left:I

    if-lt p0, v0, :cond_3

    iget p0, p1, Landroid/graphics/Rect;->right:I

    if-gt p0, v0, :cond_8

    :cond_3
    iget p0, p1, Landroid/graphics/Rect;->right:I

    iget p1, p2, Landroid/graphics/Rect;->right:I

    if-ge p0, p1, :cond_8

    goto :goto_0

    :cond_4
    iget p0, p1, Landroid/graphics/Rect;->bottom:I

    iget v0, p2, Landroid/graphics/Rect;->bottom:I

    if-gt p0, v0, :cond_5

    iget p0, p1, Landroid/graphics/Rect;->top:I

    if-lt p0, v0, :cond_8

    :cond_5
    iget p0, p1, Landroid/graphics/Rect;->top:I

    iget p1, p2, Landroid/graphics/Rect;->top:I

    if-le p0, p1, :cond_8

    goto :goto_0

    :cond_6
    iget p0, p1, Landroid/graphics/Rect;->right:I

    iget v0, p2, Landroid/graphics/Rect;->right:I

    if-gt p0, v0, :cond_7

    iget p0, p1, Landroid/graphics/Rect;->left:I

    if-lt p0, v0, :cond_8

    :cond_7
    iget p0, p1, Landroid/graphics/Rect;->left:I

    iget p1, p2, Landroid/graphics/Rect;->left:I

    if-le p0, p1, :cond_8

    :goto_0
    const/4 p0, 0x1

    return p0

    :cond_8
    const/4 p0, 0x0

    return p0
.end method

.method public static final Oooo0OO(Ljava/lang/Class;Ljava/lang/Class;)Z
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result p0

    if-eqz p0, :cond_0

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    return p0

    :cond_1
    :goto_0
    const/4 p0, 0x1

    return p0
.end method

.method public static Oooo0o(Llyiahf/vczjk/zh;Llyiahf/vczjk/aw7;)Llyiahf/vczjk/qf5;
    .locals 12

    const-string v0, "polygon"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iget-object p1, p1, Llyiahf/vczjk/aw7;->OooO00o:Ljava/util/AbstractList;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v2

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    const/4 v5, 0x2

    if-ge v4, v2, :cond_2

    invoke-interface {p1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/jw2;

    iget-object v7, v6, Llyiahf/vczjk/jw2;->OooO00o:Ljava/util/List;

    invoke-interface {v7}, Ljava/util/List;->size()I

    move-result v7

    move v8, v3

    :goto_1
    if-ge v8, v7, :cond_1

    instance-of v9, v6, Llyiahf/vczjk/hw2;

    iget-object v10, v6, Llyiahf/vczjk/jw2;->OooO00o:Ljava/util/List;

    if-eqz v9, :cond_0

    invoke-interface {v10}, Ljava/util/List;->size()I

    move-result v9

    div-int/2addr v9, v5

    if-ne v8, v9, :cond_0

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v9

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    new-instance v11, Llyiahf/vczjk/xn6;

    invoke-direct {v11, v6, v9}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v1, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_0
    invoke-interface {v10, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v9

    invoke-virtual {v0, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v8, v8, 0x1

    goto :goto_1

    :cond_1
    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    const/16 v4, 0x9

    invoke-static {v0, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    if-nez v4, :cond_3

    invoke-static {v2}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    goto :goto_3

    :cond_3
    new-instance v6, Ljava/util/ArrayList;

    add-int/lit8 v4, v4, 0x1

    invoke-direct {v6, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v6, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_5

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/bu1;

    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    move-result v2

    invoke-virtual {p0, v7}, Llyiahf/vczjk/zh;->OooO0OO(Llyiahf/vczjk/bu1;)F

    move-result v7

    cmpl-float v8, v7, p1

    if-ltz v8, :cond_4

    add-float/2addr v2, v7

    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    invoke-virtual {v6, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Measured cubic is expected to be greater or equal to zero"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_5
    move-object p1, v6

    :goto_3
    invoke-static {p1}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    move-result v2

    new-instance v4, Llyiahf/vczjk/kr5;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v6

    invoke-direct {v4, v6}, Llyiahf/vczjk/kr5;-><init>(I)V

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v6

    move v7, v3

    :goto_4
    if-ge v7, v6, :cond_6

    invoke-interface {p1, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/lang/Number;

    invoke-virtual {v8}, Ljava/lang/Number;->floatValue()F

    move-result v8

    div-float/2addr v8, v2

    invoke-virtual {v4, v8}, Llyiahf/vczjk/kr5;->OooO00o(F)V

    add-int/lit8 v7, v7, 0x1

    goto :goto_4

    :cond_6
    invoke-static {}, Llyiahf/vczjk/r02;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object p1

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v2

    :goto_5
    if-ge v3, v2, :cond_7

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/xn6;

    invoke-virtual {v6}, Llyiahf/vczjk/xn6;->OooO0Oo()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/Number;

    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    move-result v6

    new-instance v7, Llyiahf/vczjk/ia7;

    invoke-virtual {v4, v6}, Llyiahf/vczjk/kr5;->OooO0O0(I)F

    move-result v8

    add-int/lit8 v6, v6, 0x1

    invoke-virtual {v4, v6}, Llyiahf/vczjk/kr5;->OooO0O0(I)F

    move-result v6

    add-float/2addr v6, v8

    int-to-float v8, v5

    div-float/2addr v6, v8

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/xn6;

    invoke-virtual {v8}, Llyiahf/vczjk/xn6;->OooO0OO()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/jw2;

    invoke-direct {v7, v6, v8}, Llyiahf/vczjk/ia7;-><init>(FLlyiahf/vczjk/jw2;)V

    invoke-virtual {p1, v7}, Llyiahf/vczjk/y05;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_5

    :cond_7
    invoke-virtual {p1}, Llyiahf/vczjk/y05;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/qf5;

    invoke-direct {v1, p0, p1, v0, v4}, Llyiahf/vczjk/qf5;-><init>(Llyiahf/vczjk/zh;Llyiahf/vczjk/y05;Ljava/util/ArrayList;Llyiahf/vczjk/kr5;)V

    return-object v1
.end method

.method public static Oooo0o0(ILandroid/graphics/Rect;Landroid/graphics/Rect;)I
    .locals 1

    const/16 v0, 0x11

    if-eq p0, v0, :cond_3

    const/16 v0, 0x21

    if-eq p0, v0, :cond_2

    const/16 v0, 0x42

    if-eq p0, v0, :cond_1

    const/16 v0, 0x82

    if-ne p0, v0, :cond_0

    iget p0, p2, Landroid/graphics/Rect;->top:I

    iget p1, p1, Landroid/graphics/Rect;->bottom:I

    :goto_0
    sub-int/2addr p0, p1

    goto :goto_1

    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_1
    iget p0, p2, Landroid/graphics/Rect;->left:I

    iget p1, p1, Landroid/graphics/Rect;->right:I

    goto :goto_0

    :cond_2
    iget p0, p1, Landroid/graphics/Rect;->top:I

    iget p1, p2, Landroid/graphics/Rect;->bottom:I

    goto :goto_0

    :cond_3
    iget p0, p1, Landroid/graphics/Rect;->left:I

    iget p1, p2, Landroid/graphics/Rect;->right:I

    goto :goto_0

    :goto_1
    const/4 p1, 0x0

    invoke-static {p1, p0}, Ljava/lang/Math;->max(II)I

    move-result p0

    return p0
.end method

.method public static Oooo0oO(ILandroid/graphics/Rect;Landroid/graphics/Rect;)I
    .locals 1

    const/16 v0, 0x11

    if-eq p0, v0, :cond_2

    const/16 v0, 0x21

    if-eq p0, v0, :cond_1

    const/16 v0, 0x42

    if-eq p0, v0, :cond_2

    const/16 v0, 0x82

    if-ne p0, v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_1
    :goto_0
    iget p0, p1, Landroid/graphics/Rect;->left:I

    invoke-virtual {p1}, Landroid/graphics/Rect;->width()I

    move-result p1

    div-int/lit8 p1, p1, 0x2

    add-int/2addr p1, p0

    iget p0, p2, Landroid/graphics/Rect;->left:I

    invoke-virtual {p2}, Landroid/graphics/Rect;->width()I

    move-result p2

    div-int/lit8 p2, p2, 0x2

    add-int/2addr p2, p0

    sub-int/2addr p1, p2

    invoke-static {p1}, Ljava/lang/Math;->abs(I)I

    move-result p0

    return p0

    :cond_2
    iget p0, p1, Landroid/graphics/Rect;->top:I

    invoke-virtual {p1}, Landroid/graphics/Rect;->height()I

    move-result p1

    div-int/lit8 p1, p1, 0x2

    add-int/2addr p1, p0

    iget p0, p2, Landroid/graphics/Rect;->top:I

    invoke-virtual {p2}, Landroid/graphics/Rect;->height()I

    move-result p2

    div-int/lit8 p2, p2, 0x2

    add-int/2addr p2, p0

    sub-int/2addr p1, p2

    invoke-static {p1}, Ljava/lang/Math;->abs(I)I

    move-result p0

    return p0
.end method

.method public static Oooo0oo(Landroid/widget/ImageView;Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V
    .locals 5

    sget-object v0, Llyiahf/vczjk/qqa;->OooO00o:Llyiahf/vczjk/uj3;

    if-eqz p1, :cond_1

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getIconDrawable()I

    move-result v1

    if-lez v1, :cond_1

    invoke-static {p0}, Lcom/bumptech/glide/Glide;->with(Landroid/view/View;)Lcom/bumptech/glide/RequestManager;

    move-result-object v1

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getIconDrawable()I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v1, v2}, Lcom/bumptech/glide/RequestManager;->load(Ljava/lang/Integer;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v1

    sget v2, Lgithub/tornaco/android/thanos/module/common/R$mipmap;->ic_fallback_app_icon:I

    invoke-virtual {v1, v2}, Lcom/bumptech/glide/request/BaseRequestOptions;->error(I)Lcom/bumptech/glide/request/BaseRequestOptions;

    move-result-object v1

    check-cast v1, Lcom/bumptech/glide/RequestBuilder;

    sget v2, Lgithub/tornaco/android/thanos/module/common/R$mipmap;->ic_fallback_app_icon:I

    invoke-virtual {v1, v2}, Lcom/bumptech/glide/request/BaseRequestOptions;->fallback(I)Lcom/bumptech/glide/request/BaseRequestOptions;

    move-result-object v1

    check-cast v1, Lcom/bumptech/glide/RequestBuilder;

    sget v2, Lgithub/tornaco/android/thanos/module/common/R$anim;->grow_fade_in:I

    invoke-static {v2}, Lcom/bumptech/glide/GenericTransitionOptions;->with(I)Lcom/bumptech/glide/GenericTransitionOptions;

    move-result-object v2

    invoke-virtual {v1, v2}, Lcom/bumptech/glide/RequestBuilder;->transition(Lcom/bumptech/glide/TransitionOptions;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v1

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->disabled()Z

    move-result p1

    if-eqz p1, :cond_0

    invoke-virtual {v1, v0}, Lcom/bumptech/glide/request/BaseRequestOptions;->transform(Lcom/bumptech/glide/load/Transformation;)Lcom/bumptech/glide/request/BaseRequestOptions;

    move-result-object p1

    move-object v1, p1

    check-cast v1, Lcom/bumptech/glide/RequestBuilder;

    :cond_0
    invoke-virtual {v1, p0}, Lcom/bumptech/glide/RequestBuilder;->into(Landroid/widget/ImageView;)Lcom/bumptech/glide/request/target/ViewTarget;

    return-void

    :cond_1
    if-eqz p1, :cond_2

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getIconUrl()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v1

    if-nez v1, :cond_2

    invoke-static {p0}, Lcom/bumptech/glide/Glide;->with(Landroid/view/View;)Lcom/bumptech/glide/RequestManager;

    move-result-object v0

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getIconUrl()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Lcom/bumptech/glide/RequestManager;->load(Ljava/lang/String;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object p1

    sget v0, Lgithub/tornaco/android/thanos/module/common/R$mipmap;->ic_fallback_app_icon:I

    invoke-virtual {p1, v0}, Lcom/bumptech/glide/request/BaseRequestOptions;->error(I)Lcom/bumptech/glide/request/BaseRequestOptions;

    move-result-object p1

    check-cast p1, Lcom/bumptech/glide/RequestBuilder;

    sget v0, Lgithub/tornaco/android/thanos/module/common/R$mipmap;->ic_fallback_app_icon:I

    invoke-virtual {p1, v0}, Lcom/bumptech/glide/request/BaseRequestOptions;->fallback(I)Lcom/bumptech/glide/request/BaseRequestOptions;

    move-result-object p1

    check-cast p1, Lcom/bumptech/glide/RequestBuilder;

    sget v0, Lgithub/tornaco/android/thanos/module/common/R$anim;->grow_fade_in:I

    invoke-static {v0}, Lcom/bumptech/glide/GenericTransitionOptions;->with(I)Lcom/bumptech/glide/GenericTransitionOptions;

    move-result-object v0

    invoke-virtual {p1, v0}, Lcom/bumptech/glide/RequestBuilder;->transition(Lcom/bumptech/glide/TransitionOptions;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object p1

    invoke-virtual {p1, p0}, Lcom/bumptech/glide/RequestBuilder;->into(Landroid/widget/ImageView;)Lcom/bumptech/glide/request/target/ViewTarget;

    return-void

    :cond_2
    invoke-static {p0}, Lcom/bumptech/glide/Glide;->with(Landroid/view/View;)Lcom/bumptech/glide/RequestManager;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ci3;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ci3;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/ai3;

    move-result-object v1

    sget v2, Lgithub/tornaco/android/thanos/module/common/R$mipmap;->ic_fallback_app_icon:I

    invoke-virtual {v1, v2}, Llyiahf/vczjk/ai3;->OooO0OO(I)Llyiahf/vczjk/ai3;

    move-result-object v1

    sget v2, Lgithub/tornaco/android/thanos/module/common/R$mipmap;->ic_fallback_app_icon:I

    invoke-virtual {v1, v2}, Llyiahf/vczjk/ai3;->OooO0Oo(I)Llyiahf/vczjk/ai3;

    move-result-object v1

    sget v2, Lgithub/tornaco/android/thanos/module/common/R$anim;->grow_fade_in:I

    invoke-static {v2}, Lcom/bumptech/glide/GenericTransitionOptions;->with(I)Lcom/bumptech/glide/GenericTransitionOptions;

    move-result-object v2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/ai3;->OooO(Lcom/bumptech/glide/TransitionOptions;)Llyiahf/vczjk/ai3;

    move-result-object v1

    invoke-static {}, Llyiahf/vczjk/v41;->OooO00o()Llyiahf/vczjk/v41;

    move-result-object v2

    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v3

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v3

    const/4 v4, 0x0

    if-nez v3, :cond_3

    goto :goto_0

    :cond_3
    :try_start_0
    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPrefManager()Lgithub/tornaco/android/thanos/core/pref/PrefManager;

    move-result-object v2

    const-string v3, "github.tornaco.android.thanos.ui.used_round_icon"

    invoke-virtual {v2, v3, v4}, Lgithub/tornaco/android/thanos/core/pref/PrefManager;->getBoolean(Ljava/lang/String;Z)Z

    move-result v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :catchall_0
    :goto_0
    if-eqz v4, :cond_4

    invoke-virtual {v1}, Llyiahf/vczjk/ai3;->OooO00o()Llyiahf/vczjk/ai3;

    move-result-object v1

    :cond_4
    if-eqz p1, :cond_5

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->disabled()Z

    move-result p1

    if-eqz p1, :cond_5

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ai3;->OooO0oo(Llyiahf/vczjk/uj3;)Llyiahf/vczjk/ai3;

    move-result-object v1

    :cond_5
    invoke-virtual {v1, p0}, Lcom/bumptech/glide/RequestBuilder;->into(Landroid/widget/ImageView;)Lcom/bumptech/glide/request/target/ViewTarget;

    return-void
.end method

.method public static OoooO0(Landroidx/fragment/app/FragmentActivity;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/r71;)V
    .locals 2

    new-instance v0, Landroid/content/Intent;

    const-class v1, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;

    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    const-string v1, "app"

    invoke-virtual {v0, v1, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    const-string p1, "type"

    invoke-virtual {p2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {v0, p1, p2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    invoke-virtual {p0, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    return-void
.end method

.method public static OoooO00(Landroidx/activity/ComponentActivity;Ljava/lang/String;)Z
    .locals 4

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x21

    if-ge v0, v1, :cond_0

    const-string v1, "android.permission.POST_NOTIFICATIONS"

    invoke-static {v1, p1}, Landroid/text/TextUtils;->equals(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 p0, 0x0

    return p0

    :cond_0
    const/16 v1, 0x20

    if-lt v0, v1, :cond_1

    invoke-virtual {p0, p1}, Landroid/app/Activity;->shouldShowRequestPermissionRationale(Ljava/lang/String;)Z

    move-result p0

    return p0

    :cond_1
    const/16 v1, 0x1f

    if-ne v0, v1, :cond_2

    :try_start_0
    invoke-virtual {p0}, Landroid/app/Activity;->getApplication()Landroid/app/Application;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v0

    const-class v1, Landroid/content/pm/PackageManager;

    const-string v2, "shouldShowRequestPermissionRationale"

    const-class v3, Ljava/lang/String;

    filled-new-array {v3}, [Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v1, v0, v2}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p0
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0

    return p0

    :catch_0
    invoke-virtual {p0, p1}, Landroid/app/Activity;->shouldShowRequestPermissionRationale(Ljava/lang/String;)Z

    move-result p0

    return p0

    :cond_2
    invoke-virtual {p0, p1}, Landroid/app/Activity;->shouldShowRequestPermissionRationale(Ljava/lang/String;)Z

    move-result p0

    return p0
.end method

.method public static OoooO0O(FFFI)F
    .locals 0

    if-lez p3, :cond_0

    const/high16 p0, 0x40000000    # 2.0f

    div-float/2addr p2, p0

    add-float/2addr p2, p1

    return p2

    :cond_0
    return p0
.end method


# virtual methods
.method public OooOOO0(Landroid/view/Window;)V
    .locals 0

    return-void
.end method

.method public abstract OooOooO()Llyiahf/vczjk/wj7;
.end method

.method public abstract Oooo(Llyiahf/vczjk/fd9;Llyiahf/vczjk/fd9;Landroid/view/Window;Landroid/view/View;ZZ)V
.end method
