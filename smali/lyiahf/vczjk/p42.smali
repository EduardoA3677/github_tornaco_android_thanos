.class public final Llyiahf/vczjk/p42;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/p42;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/p42;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/p42;->OooO00o:Llyiahf/vczjk/p42;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/l1a;Llyiahf/vczjk/rf1;I)V
    .locals 44

    move-object/from16 v0, p1

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/zf1;

    const v3, -0x61ca9250

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    const/4 v4, 0x2

    const/4 v5, 0x4

    if-eqz v3, :cond_0

    move v3, v5

    goto :goto_0

    :cond_0
    move v3, v4

    :goto_0
    or-int v3, p3, v3

    and-int/lit8 v6, v3, 0x3

    const/4 v7, 0x1

    const/4 v8, 0x0

    if-eq v6, v4, :cond_1

    move v4, v7

    goto :goto_1

    :cond_1
    move v4, v8

    :goto_1
    and-int/lit8 v6, v3, 0x1

    invoke-virtual {v2, v6, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v4

    if-eqz v4, :cond_28

    iget v4, v0, Llyiahf/vczjk/l1a;->OooOOO0:F

    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    move-result v6

    if-nez v6, :cond_27

    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v6

    const v9, 0x7fffffff

    and-int/2addr v6, v9

    const/high16 v10, 0x7f800000    # Float.POSITIVE_INFINITY

    if-ge v6, v10, :cond_27

    iget v6, v0, Llyiahf/vczjk/l1a;->OooOOO:F

    invoke-static {v6}, Ljava/lang/Float;->isNaN(F)Z

    move-result v11

    if-nez v11, :cond_26

    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v11

    and-int/2addr v9, v11

    if-ge v9, v10, :cond_26

    invoke-static {v6, v4}, Ljava/lang/Float;->compare(FF)I

    move-result v9

    if-ltz v9, :cond_25

    sget-object v9, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/f62;

    iget v10, v0, Llyiahf/vczjk/l1a;->OooO0Oo:F

    invoke-interface {v9, v10}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v26

    and-int/lit8 v3, v3, 0xe

    if-ne v3, v5, :cond_2

    move v9, v7

    goto :goto_2

    :cond_2
    move v9, v8

    :goto_2
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    sget-object v11, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v9, :cond_3

    if-ne v10, v11, :cond_4

    :cond_3
    new-instance v10, Llyiahf/vczjk/k1;

    const/16 v9, 0x17

    invoke-direct {v10, v0, v9}, Llyiahf/vczjk/k1;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v10, Llyiahf/vczjk/le3;

    if-ne v3, v5, :cond_5

    move v9, v7

    goto :goto_3

    :cond_5
    move v9, v8

    :goto_3
    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v12

    or-int/2addr v9, v12

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    if-nez v9, :cond_6

    if-ne v12, v11, :cond_7

    :cond_6
    new-instance v12, Llyiahf/vczjk/o0O000;

    const/16 v9, 0xa

    const/4 v13, 0x0

    invoke-direct {v12, v9, v0, v10, v13}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    invoke-virtual {v2, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v12, Llyiahf/vczjk/le3;

    new-instance v9, Llyiahf/vczjk/f5;

    const/16 v13, 0xc

    invoke-direct {v9, v0, v13}, Llyiahf/vczjk/f5;-><init>(Ljava/lang/Object;I)V

    const v13, -0x4f7e3ec7

    invoke-static {v13, v9, v2}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v21

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v9, :cond_8

    if-ne v13, v11, :cond_9

    :cond_8
    new-instance v13, Llyiahf/vczjk/a5;

    const/16 v9, 0xc

    invoke-direct {v13, v9, v10}, Llyiahf/vczjk/a5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v2, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    move-object/from16 v16, v13

    check-cast v16, Llyiahf/vczjk/le3;

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v9, :cond_a

    if-ne v13, v11, :cond_b

    :cond_a
    new-instance v13, Llyiahf/vczjk/a5;

    const/16 v9, 0xd

    invoke-direct {v13, v9, v10}, Llyiahf/vczjk/a5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v2, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    move-object/from16 v27, v13

    check-cast v27, Llyiahf/vczjk/le3;

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v9, :cond_c

    if-ne v13, v11, :cond_d

    :cond_c
    new-instance v9, Llyiahf/vczjk/a5;

    const/16 v13, 0xe

    invoke-direct {v9, v13, v10}, Llyiahf/vczjk/a5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-static {v9}, Landroidx/compose/runtime/OooO0o;->OooO0Oo(Llyiahf/vczjk/le3;)Llyiahf/vczjk/w62;

    move-result-object v13

    invoke-virtual {v2, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    check-cast v13, Llyiahf/vczjk/p29;

    invoke-interface {v13}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Boolean;

    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v9

    xor-int/lit8 v28, v9, 0x1

    sget-object v29, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iget-object v9, v0, Llyiahf/vczjk/l1a;->OooOOo0:Llyiahf/vczjk/jx9;

    if-eqz v9, :cond_14

    invoke-interface {v9}, Llyiahf/vczjk/jx9;->OooO0OO()Z

    move-result v10

    if-nez v10, :cond_14

    const v10, -0x145563a1

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v31, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    if-ne v3, v5, :cond_e

    move v10, v7

    goto :goto_4

    :cond_e
    move v10, v8

    :goto_4
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v10, :cond_f

    if-ne v14, v11, :cond_10

    :cond_f
    new-instance v14, Llyiahf/vczjk/o000OO;

    const/16 v10, 0x15

    invoke-direct {v14, v0, v10}, Llyiahf/vczjk/o000OO;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v2, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_10
    check-cast v14, Llyiahf/vczjk/oe3;

    invoke-static {v14, v2}, Llyiahf/vczjk/uf2;->OooO0O0(Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/ag2;

    move-result-object v30

    if-ne v3, v5, :cond_11

    move v10, v7

    goto :goto_5

    :cond_11
    move v10, v8

    :goto_5
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v10, :cond_12

    if-ne v14, v11, :cond_13

    :cond_12
    new-instance v14, Llyiahf/vczjk/o42;

    const/4 v10, 0x0

    invoke-direct {v14, v0, v10}, Llyiahf/vczjk/o42;-><init>(Llyiahf/vczjk/l1a;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v2, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    move-object/from16 v35, v14

    check-cast v35, Llyiahf/vczjk/bf3;

    const/16 v34, 0x0

    const/16 v36, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const/16 v37, 0xbc

    invoke-static/range {v29 .. v37}, Llyiahf/vczjk/uf2;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ag2;Llyiahf/vczjk/nf6;ZLlyiahf/vczjk/rr5;ZLlyiahf/vczjk/bf3;ZI)Llyiahf/vczjk/kl5;

    move-result-object v10

    move-object/from16 v14, v29

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_6

    :cond_14
    move-object/from16 v14, v29

    const v10, -0x144b9db6

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v10, v14

    :goto_6
    iget-object v15, v0, Llyiahf/vczjk/l1a;->OooO00o:Llyiahf/vczjk/hl5;

    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2, v12}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v15

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v15, :cond_15

    if-ne v5, v11, :cond_16

    :cond_15
    new-instance v5, Llyiahf/vczjk/hp;

    const/4 v15, 0x3

    invoke-direct {v5, v15, v12}, Llyiahf/vczjk/hp;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_16
    check-cast v5, Llyiahf/vczjk/oe3;

    invoke-static {v10, v5}, Landroidx/compose/ui/draw/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-ne v10, v11, :cond_17

    new-instance v10, Llyiahf/vczjk/ow;

    const/16 v12, 0x17

    invoke-direct {v10, v12}, Llyiahf/vczjk/ow;-><init>(I)V

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_17
    check-cast v10, Llyiahf/vczjk/oe3;

    invoke-static {v5, v8, v10}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v10, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    if-ne v12, v11, :cond_18

    sget-object v12, Llyiahf/vczjk/y32;->OooOOOO:Llyiahf/vczjk/y32;

    invoke-virtual {v2, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_18
    check-cast v12, Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

    invoke-static {v5, v10, v12}, Llyiahf/vczjk/gb9;->OooO00o(Llyiahf/vczjk/kl5;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v10, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v10, v8}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v10

    iget v12, v2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v15

    invoke-static {v2, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v17, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v8, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_19

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_19
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v10, v2, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v15, v2, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v15, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    move/from16 v19, v3

    iget-boolean v3, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_1a

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    move/from16 v20, v4

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_1b

    goto :goto_8

    :cond_1a
    move/from16 v20, v4

    :goto_8
    invoke-static {v12, v2, v12, v15}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1b
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v5, v2, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v5, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v12, 0x0

    invoke-static {v4, v5, v2, v12}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v4

    iget v5, v2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    move/from16 v22, v6

    invoke-static {v2, v14}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v23, v9

    iget-boolean v9, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_1c

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_9

    :cond_1c
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_9
    invoke-static {v4, v2, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v12, v2, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v4, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_1d

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v4, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_1e

    :cond_1d
    invoke-static {v5, v2, v5, v15}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1e
    invoke-static {v6, v2, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v3, v0, Llyiahf/vczjk/l1a;->OooOOOO:Llyiahf/vczjk/zy4;

    invoke-static {v14, v3}, Llyiahf/vczjk/uoa;->OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/kna;)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/zsa;->Oooo000(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v11, :cond_1f

    new-instance v5, Llyiahf/vczjk/x32;

    const/4 v6, 0x1

    invoke-direct {v5, v6}, Llyiahf/vczjk/x32;-><init>(I)V

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1f
    check-cast v5, Llyiahf/vczjk/z23;

    iget-object v6, v0, Llyiahf/vczjk/l1a;->OooOOOo:Llyiahf/vczjk/fx9;

    move-object v8, v3

    move-object v3, v5

    move-object/from16 v7, v23

    move-object/from16 v23, v2

    move-object v2, v4

    iget-wide v4, v6, Llyiahf/vczjk/fx9;->OooO0OO:J

    const/4 v9, 0x1

    sget-object v17, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    invoke-interface {v13}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ljava/lang/Boolean;

    invoke-virtual {v10}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v10

    iget-object v12, v0, Llyiahf/vczjk/l1a;->OooO0o0:Llyiahf/vczjk/a91;

    iget-object v13, v0, Llyiahf/vczjk/l1a;->OooOO0O:Llyiahf/vczjk/a91;

    const/16 v24, 0x0

    const v25, 0x180c30

    move/from16 v29, v10

    iget-wide v9, v6, Llyiahf/vczjk/fx9;->OooO0Oo:J

    move-wide/from16 v30, v9

    move-object v10, v8

    iget-wide v8, v6, Llyiahf/vczjk/fx9;->OooO0o:J

    move-object/from16 v33, v10

    move-object/from16 v32, v11

    iget-wide v10, v6, Llyiahf/vczjk/fx9;->OooO0o0:J

    move/from16 v34, v20

    move-object/from16 v20, v13

    iget-object v13, v0, Llyiahf/vczjk/l1a;->OooO0o:Llyiahf/vczjk/rn9;

    move-object/from16 v35, v14

    iget-object v14, v0, Llyiahf/vczjk/l1a;->OooO:Llyiahf/vczjk/ze3;

    const/16 v36, 0x1

    iget-object v15, v0, Llyiahf/vczjk/l1a;->OooOO0:Llyiahf/vczjk/rn9;

    const/16 v37, 0x0

    const/16 v18, 0x0

    move-object/from16 v38, v2

    iget v2, v0, Llyiahf/vczjk/l1a;->OooOOO0:F

    move-object/from16 v40, v6

    move-object/from16 v39, v32

    move-object/from16 v0, v33

    move-object/from16 v1, v35

    move/from16 v41, v22

    move/from16 v22, v2

    move-object/from16 v2, v38

    move-wide/from16 v42, v30

    move-object/from16 v30, v7

    move/from16 v31, v19

    move/from16 v19, v29

    move-wide/from16 v6, v42

    move/from16 v29, v41

    invoke-static/range {v2 .. v25}, Llyiahf/vczjk/up;->OooO0o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/z23;JJJJLlyiahf/vczjk/a91;Llyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/le3;Llyiahf/vczjk/px;IZLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;FLlyiahf/vczjk/rf1;II)V

    move-object/from16 v2, v23

    new-instance v3, Llyiahf/vczjk/zy4;

    sget v4, Llyiahf/vczjk/rd3;->OooOO0:I

    invoke-direct {v3, v0, v4}, Llyiahf/vczjk/zy4;-><init>(Llyiahf/vczjk/kna;I)V

    invoke-static {v1, v3}, Llyiahf/vczjk/uoa;->OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/kna;)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/zsa;->Oooo000(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    if-eqz v30, :cond_21

    invoke-interface/range {v30 .. v30}, Llyiahf/vczjk/jx9;->getState()Llyiahf/vczjk/kx9;

    move-result-object v1

    if-eqz v1, :cond_21

    new-instance v3, Llyiahf/vczjk/jp;

    const/4 v4, 0x0

    invoke-direct {v3, v1, v4}, Llyiahf/vczjk/jp;-><init>(Llyiahf/vczjk/kx9;I)V

    invoke-static {v0, v3}, Landroidx/compose/ui/layout/OooO00o;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v1

    if-nez v1, :cond_20

    goto :goto_a

    :cond_20
    move-object v0, v1

    :cond_21
    :goto_a
    move/from16 v3, v31

    const/4 v1, 0x4

    if-ne v3, v1, :cond_22

    const/4 v7, 0x1

    goto :goto_b

    :cond_22
    move/from16 v7, v37

    :goto_b
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez v7, :cond_24

    move-object/from16 v3, v39

    if-ne v1, v3, :cond_23

    goto :goto_c

    :cond_23
    move-object/from16 v3, p1

    goto :goto_d

    :cond_24
    :goto_c
    new-instance v1, Llyiahf/vczjk/n42;

    move-object/from16 v3, p1

    invoke-direct {v1, v3}, Llyiahf/vczjk/n42;-><init>(Llyiahf/vczjk/l1a;)V

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_d
    check-cast v1, Llyiahf/vczjk/z23;

    sget-object v17, Llyiahf/vczjk/tx;->OooO0Oo:Llyiahf/vczjk/wp3;

    sub-float v22, v29, v34

    sget-object v20, Llyiahf/vczjk/i91;->OooO0o0:Llyiahf/vczjk/a91;

    sget-object v21, Llyiahf/vczjk/i91;->OooO0o:Llyiahf/vczjk/a91;

    iget-object v12, v3, Llyiahf/vczjk/l1a;->OooO0O0:Llyiahf/vczjk/a91;

    const/16 v24, 0x0

    const v25, 0x1b0030

    move-object/from16 v4, v40

    iget-wide v5, v4, Llyiahf/vczjk/fx9;->OooO0OO:J

    move-wide v8, v5

    iget-wide v6, v4, Llyiahf/vczjk/fx9;->OooO0Oo:J

    move-wide v10, v8

    iget-wide v8, v4, Llyiahf/vczjk/fx9;->OooO0o:J

    iget-wide v4, v4, Llyiahf/vczjk/fx9;->OooO0o0:J

    iget-object v13, v3, Llyiahf/vczjk/l1a;->OooO0OO:Llyiahf/vczjk/rn9;

    iget-object v14, v3, Llyiahf/vczjk/l1a;->OooO0oO:Llyiahf/vczjk/ze3;

    iget-object v15, v3, Llyiahf/vczjk/l1a;->OooO0oo:Llyiahf/vczjk/rn9;

    move-wide/from16 v18, v10

    move-wide v10, v4

    move-wide/from16 v4, v18

    move-object/from16 v23, v2

    move/from16 v18, v26

    move-object/from16 v16, v27

    move/from16 v19, v28

    move-object v2, v0

    move-object v0, v3

    move-object v3, v1

    invoke-static/range {v2 .. v25}, Llyiahf/vczjk/up;->OooO0o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/z23;JJJJLlyiahf/vczjk/a91;Llyiahf/vczjk/rn9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/le3;Llyiahf/vczjk/px;IZLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;FLlyiahf/vczjk/rf1;II)V

    move-object/from16 v2, v23

    const/4 v15, 0x1

    invoke-virtual {v2, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v2, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_e

    :cond_25
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "The expandedHeight is expected to be greater or equal to the collapsedHeight"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_26
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "The expandedHeight is expected to be specified and finite"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_27
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "The collapsedHeight is expected to be specified and finite"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_28
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_e
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v1

    if-eqz v1, :cond_29

    new-instance v2, Llyiahf/vczjk/e2;

    const/16 v3, 0xf

    move-object/from16 v4, p0

    move/from16 v5, p3

    invoke-direct {v2, v4, v0, v5, v3}, Llyiahf/vczjk/e2;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v2, v1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    return-void

    :cond_29
    move-object/from16 v4, p0

    return-void
.end method
