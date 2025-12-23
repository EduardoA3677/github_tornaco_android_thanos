.class public abstract Llyiahf/vczjk/dr6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:I

.field public static final synthetic OooO0O0:I

.field public static final synthetic OooO0OO:I

.field public static OooO0Oo:Ljava/lang/String;


# direct methods
.method public static final OooO(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 8

    const-string v0, "current"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    return v1

    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    const/4 v2, 0x0

    if-nez v0, :cond_1

    goto :goto_2

    :cond_1
    move v0, v2

    move v3, v0

    move v4, v3

    :goto_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v5

    if-ge v0, v5, :cond_6

    invoke-virtual {p0, v0}, Ljava/lang/String;->charAt(I)C

    move-result v5

    add-int/lit8 v6, v4, 0x1

    const/16 v7, 0x28

    if-nez v4, :cond_2

    if-eq v5, v7, :cond_2

    goto :goto_2

    :cond_2
    if-eq v5, v7, :cond_4

    const/16 v7, 0x29

    if-eq v5, v7, :cond_3

    goto :goto_1

    :cond_3
    add-int/lit8 v3, v3, -0x1

    if-nez v3, :cond_5

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v5

    sub-int/2addr v5, v1

    if-eq v4, v5, :cond_5

    goto :goto_2

    :cond_4
    add-int/lit8 v3, v3, 0x1

    :cond_5
    :goto_1
    add-int/lit8 v0, v0, 0x1

    move v4, v6

    goto :goto_0

    :cond_6
    if-nez v3, :cond_7

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v0

    sub-int/2addr v0, v1

    invoke-virtual {p0, v1, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object p0

    const-string v0, "substring(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/z69;->o00o0O(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p0

    return p0

    :cond_7
    :goto_2
    return v2
.end method

.method public static synthetic OooO00o(I)V
    .locals 3

    const/4 v0, 0x3

    new-array v0, v0, [Ljava/lang/Object;

    const/4 v1, 0x0

    packed-switch p0, :pswitch_data_0

    :pswitch_0
    const-string v2, "a"

    aput-object v2, v0, v1

    goto :goto_0

    :pswitch_1
    const-string v2, "typeProjection"

    aput-object v2, v0, v1

    goto :goto_0

    :pswitch_2
    const-string v2, "type"

    aput-object v2, v0, v1

    goto :goto_0

    :pswitch_3
    const-string v2, "supertype"

    aput-object v2, v0, v1

    goto :goto_0

    :pswitch_4
    const-string v2, "subtype"

    aput-object v2, v0, v1

    goto :goto_0

    :pswitch_5
    const-string v2, "typeCheckingProcedure"

    aput-object v2, v0, v1

    goto :goto_0

    :pswitch_6
    const-string v2, "b"

    aput-object v2, v0, v1

    :goto_0
    const/4 v1, 0x1

    const-string v2, "kotlin/reflect/jvm/internal/impl/types/checker/TypeCheckerProcedureCallbacksImpl"

    aput-object v2, v0, v1

    const/4 v1, 0x2

    packed-switch p0, :pswitch_data_1

    const-string p0, "assertEqualTypes"

    aput-object p0, v0, v1

    goto :goto_1

    :pswitch_7
    const-string p0, "noCorrespondingSupertype"

    aput-object p0, v0, v1

    goto :goto_1

    :pswitch_8
    const-string p0, "capture"

    aput-object p0, v0, v1

    goto :goto_1

    :pswitch_9
    const-string p0, "assertSubtype"

    aput-object p0, v0, v1

    goto :goto_1

    :pswitch_a
    const-string p0, "assertEqualTypeConstructors"

    aput-object p0, v0, v1

    :goto_1
    const-string p0, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {p0, v0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_6
        :pswitch_5
        :pswitch_0
        :pswitch_6
        :pswitch_4
        :pswitch_3
        :pswitch_5
        :pswitch_2
        :pswitch_1
        :pswitch_4
        :pswitch_3
    .end packed-switch

    :pswitch_data_1
    .packed-switch 0x3
        :pswitch_a
        :pswitch_a
        :pswitch_9
        :pswitch_9
        :pswitch_9
        :pswitch_8
        :pswitch_8
        :pswitch_7
        :pswitch_7
    .end packed-switch
.end method

.method public static final OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V
    .locals 16

    move-object/from16 v0, p1

    move/from16 v1, p3

    move/from16 v2, p4

    move-object/from16 v3, p2

    check-cast v3, Llyiahf/vczjk/zf1;

    const v4, 0x795cf2bd

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v4, v2, 0x1

    const/4 v5, 0x0

    if-eqz v4, :cond_0

    or-int/lit8 v4, v1, 0x6

    goto :goto_2

    :cond_0
    and-int/lit8 v4, v1, 0x6

    if-nez v4, :cond_3

    and-int/lit8 v4, v1, 0x8

    if-nez v4, :cond_1

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    goto :goto_0

    :cond_1
    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    :goto_0
    if-eqz v4, :cond_2

    const/4 v4, 0x4

    goto :goto_1

    :cond_2
    const/4 v4, 0x2

    :goto_1
    or-int/2addr v4, v1

    goto :goto_2

    :cond_3
    move v4, v1

    :goto_2
    and-int/lit8 v6, v2, 0x2

    if-eqz v6, :cond_5

    or-int/lit8 v4, v4, 0x30

    :cond_4
    move-object/from16 v7, p0

    goto :goto_4

    :cond_5
    and-int/lit8 v7, v1, 0x30

    if-nez v7, :cond_4

    move-object/from16 v7, p0

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_6

    const/16 v8, 0x20

    goto :goto_3

    :cond_6
    const/16 v8, 0x10

    :goto_3
    or-int/2addr v4, v8

    :goto_4
    and-int/lit8 v8, v2, 0x4

    if-eqz v8, :cond_7

    or-int/lit16 v4, v4, 0x180

    goto :goto_6

    :cond_7
    and-int/lit16 v8, v1, 0x180

    if-nez v8, :cond_9

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_8

    const/16 v8, 0x100

    goto :goto_5

    :cond_8
    const/16 v8, 0x80

    :goto_5
    or-int/2addr v4, v8

    :cond_9
    :goto_6
    and-int/lit16 v8, v4, 0x93

    const/4 v9, 0x1

    const/16 v10, 0x92

    const/4 v11, 0x0

    if-eq v8, v10, :cond_a

    move v8, v9

    goto :goto_7

    :cond_a
    move v8, v11

    :goto_7
    and-int/2addr v4, v9

    invoke-virtual {v3, v4, v8}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v4

    if-eqz v4, :cond_16

    if-eqz v6, :cond_b

    sget-object v4, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_8

    :cond_b
    move-object v4, v7

    :goto_8
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v6, v7, :cond_c

    new-instance v6, Llyiahf/vczjk/mv2;

    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    new-instance v7, Ljava/lang/Object;

    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    iput-object v7, v6, Llyiahf/vczjk/mv2;->OooO00o:Ljava/lang/Object;

    new-instance v7, Ljava/util/ArrayList;

    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    iput-object v7, v6, Llyiahf/vczjk/mv2;->OooO0O0:Ljava/util/ArrayList;

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    check-cast v6, Llyiahf/vczjk/mv2;

    const/4 v7, 0x7

    invoke-static {v7, v3}, Llyiahf/vczjk/kh6;->OooOooo(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v7

    iget-object v8, v6, Llyiahf/vczjk/mv2;->OooO00o:Ljava/lang/Object;

    invoke-static {v5, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    iget-object v10, v6, Llyiahf/vczjk/mv2;->OooO0O0:Ljava/util/ArrayList;

    if-nez v8, :cond_11

    const v8, 0x5ab8317b    # 2.59229E16f

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iput-object v5, v6, Llyiahf/vczjk/mv2;->OooO00o:Ljava/lang/Object;

    new-instance v8, Ljava/util/ArrayList;

    invoke-virtual {v10}, Ljava/util/ArrayList;->size()I

    move-result v12

    invoke-direct {v8, v12}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v10}, Ljava/util/ArrayList;->size()I

    move-result v12

    move v13, v11

    :goto_9
    if-ge v13, v12, :cond_d

    invoke-virtual {v10, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/kv2;

    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v8, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v13, v13, 0x1

    goto :goto_9

    :cond_d
    invoke-static {v8}, Llyiahf/vczjk/d21;->o0000OO0(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v8

    invoke-virtual {v8, v5}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    move-result v12

    if-nez v12, :cond_e

    invoke-virtual {v8, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_e
    invoke-virtual {v10}, Ljava/util/ArrayList;->clear()V

    invoke-static {v8}, Llyiahf/vczjk/r15;->OooO00o(Ljava/util/List;)Ljava/util/ArrayList;

    move-result-object v12

    invoke-virtual {v12}, Ljava/util/ArrayList;->size()I

    move-result v13

    move v14, v11

    :goto_a
    if-ge v14, v13, :cond_10

    invoke-virtual {v12, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v15

    if-nez v15, :cond_f

    new-instance v15, Llyiahf/vczjk/kv2;

    new-instance v9, Llyiahf/vczjk/ot8;

    invoke-direct {v9, v8, v6, v7}, Llyiahf/vczjk/ot8;-><init>(Ljava/util/ArrayList;Llyiahf/vczjk/mv2;Ljava/lang/String;)V

    const v5, 0x57ae4c82

    invoke-static {v5, v9, v3}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v5

    invoke-direct {v15, v5}, Llyiahf/vczjk/kv2;-><init>(Llyiahf/vczjk/a91;)V

    invoke-virtual {v10, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v14, v14, 0x1

    const/4 v5, 0x0

    const/4 v9, 0x1

    goto :goto_a

    :cond_f
    new-instance v0, Ljava/lang/ClassCastException;

    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    throw v0

    :cond_10
    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_b

    :cond_11
    const v5, 0x5adfd089

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_b
    sget-object v5, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v5, v11}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v5

    iget v7, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v3, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v9

    sget-object v12, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v12, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v13, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v13, :cond_12

    invoke-virtual {v3, v12}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_c

    :cond_12
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_c
    sget-object v12, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v3, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v8, v3, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v8, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v8, :cond_13

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    invoke-static {v8, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_14

    :cond_13
    invoke-static {v7, v3, v7, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_14
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v9, v3, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v3}, Llyiahf/vczjk/sb;->Oooo000(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/aj7;

    move-result-object v5

    iput-object v5, v6, Llyiahf/vczjk/mv2;->OooO0OO:Llyiahf/vczjk/aj7;

    const v5, 0x6b5ff204

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10}, Ljava/util/ArrayList;->size()I

    move-result v5

    move v6, v11

    :goto_d
    if-ge v6, v5, :cond_15

    invoke-virtual {v10, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/kv2;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const v8, 0x7e999400

    const/4 v9, 0x0

    invoke-virtual {v3, v8, v9}, Llyiahf/vczjk/zf1;->OoooO0(ILjava/lang/Object;)V

    new-instance v8, Llyiahf/vczjk/qt8;

    invoke-direct {v8, v0}, Llyiahf/vczjk/qt8;-><init>(Llyiahf/vczjk/bf3;)V

    const v12, 0x79b62c7c

    invoke-static {v12, v8, v3}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    const/4 v12, 0x6

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    iget-object v7, v7, Llyiahf/vczjk/kv2;->OooO00o:Llyiahf/vczjk/a91;

    invoke-virtual {v7, v8, v3, v12}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    add-int/lit8 v6, v6, 0x1

    goto :goto_d

    :cond_15
    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v5, 0x1

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_e

    :cond_16
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v4, v7

    :goto_e
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v3

    if-eqz v3, :cond_17

    new-instance v5, Llyiahf/vczjk/rt8;

    invoke-direct {v5, v4, v0, v1, v2}, Llyiahf/vczjk/rt8;-><init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;II)V

    iput-object v5, v3, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_17
    return-void
.end method

.method public static final OooO0OO(ILlyiahf/vczjk/rf1;)V
    .locals 36

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/zf1;

    const v2, 0x3a7a08ce

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    if-nez p0, :cond_1

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_2

    :cond_1
    :goto_0
    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v3, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v4, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v5, 0x0

    invoke-static {v3, v4, v1, v5}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v3

    iget v4, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v1, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_2

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_2
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v1, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v6, v1, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v6, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_3

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v6, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_4

    :cond_3
    invoke-static {v4, v1, v4, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_4
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v7, v1, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v3, 0x10

    int-to-float v3, v3

    const/4 v4, 0x0

    const/4 v6, 0x2

    move-object v7, v2

    invoke-static {v7, v3, v4, v6}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v8, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/n6a;

    iget-object v10, v9, Llyiahf/vczjk/n6a;->OooOO0o:Llyiahf/vczjk/rn9;

    const/16 v25, 0xb

    invoke-static/range {v25 .. v25}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v13

    new-instance v9, Llyiahf/vczjk/cb3;

    const/4 v11, 0x1

    invoke-direct {v9, v11}, Llyiahf/vczjk/cb3;-><init>(I)V

    const/16 v22, 0x0

    const/16 v23, 0x0

    move v15, v11

    const-wide/16 v11, 0x0

    move/from16 v16, v15

    const/4 v15, 0x0

    const/16 v17, 0x0

    const-wide/16 v18, 0x0

    const-wide/16 v20, 0x0

    const v24, 0xfffff5

    move/from16 v35, v16

    move-object/from16 v16, v9

    move/from16 v9, v35

    invoke-static/range {v10 .. v24}, Llyiahf/vczjk/rn9;->OooO00o(Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/ba3;JJLlyiahf/vczjk/vx6;Llyiahf/vczjk/jz4;I)Llyiahf/vczjk/rn9;

    move-result-object v19

    const/16 v18, 0x0

    const/16 v21, 0x36

    move-object/from16 v20, v1

    const-string v1, "Since 2016"

    move v10, v3

    move v11, v4

    const-wide/16 v3, 0x0

    move v12, v5

    move v13, v6

    const-wide/16 v5, 0x0

    move-object v14, v7

    const/4 v7, 0x0

    move-object v15, v8

    const/4 v8, 0x0

    move/from16 v17, v9

    move/from16 v16, v10

    const-wide/16 v9, 0x0

    move/from16 v22, v11

    const/4 v11, 0x0

    move/from16 v23, v12

    move/from16 v24, v13

    const-wide/16 v12, 0x0

    move-object/from16 v26, v14

    const/4 v14, 0x0

    move-object/from16 v27, v15

    const/4 v15, 0x0

    move/from16 v28, v16

    const/16 v16, 0x0

    move/from16 v29, v17

    const/16 v17, 0x0

    move/from16 v30, v22

    const/16 v22, 0x0

    move/from16 v31, v23

    const v23, 0x1fffc

    move-object/from16 v33, v27

    move/from16 v32, v28

    move/from16 v0, v31

    invoke-static/range {v1 .. v23}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v1, v20

    invoke-static {v0, v1}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    const v2, -0x527b00b5

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object/from16 v14, v26

    move/from16 v10, v32

    const/4 v11, 0x0

    const/4 v13, 0x2

    invoke-static {v14, v10, v11, v13}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    move-object/from16 v15, v33

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/n6a;

    iget-object v4, v3, Llyiahf/vczjk/n6a;->OooOO0o:Llyiahf/vczjk/rn9;

    invoke-static/range {v25 .. v25}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v7

    new-instance v10, Llyiahf/vczjk/cb3;

    const/4 v3, 0x1

    invoke-direct {v10, v3}, Llyiahf/vczjk/cb3;-><init>(I)V

    const/16 v16, 0x0

    const/16 v17, 0x0

    const-wide/16 v5, 0x0

    const/4 v9, 0x0

    const/4 v11, 0x0

    const-wide/16 v12, 0x0

    const-wide/16 v14, 0x0

    const v18, 0xfffff5

    invoke-static/range {v4 .. v18}, Llyiahf/vczjk/rn9;->OooO00o(Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/ba3;JJLlyiahf/vczjk/vx6;Llyiahf/vczjk/jz4;I)Llyiahf/vczjk/rn9;

    move-result-object v19

    const/16 v18, 0x0

    const/16 v21, 0x36

    move-object/from16 v20, v1

    const-string v1, "\u5907\u6848\u53f7\uff1a\u9655ICP\u590720012350\u53f7-3A"

    move v15, v3

    const-wide/16 v3, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const-wide/16 v9, 0x0

    const/4 v14, 0x0

    move/from16 v16, v15

    const/4 v15, 0x0

    move/from16 v17, v16

    const/16 v16, 0x0

    move/from16 v34, v17

    const/16 v17, 0x0

    const/16 v22, 0x0

    const v23, 0x1fffc

    invoke-static/range {v1 .. v23}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v1, v20

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v15, 0x1

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_2
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_5

    new-instance v1, Llyiahf/vczjk/jm4;

    const/16 v2, 0x15

    move/from16 v3, p0

    invoke-direct {v1, v3, v2}, Llyiahf/vczjk/jm4;-><init>(II)V

    iput-object v1, v0, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_5
    return-void
.end method

.method public static final OooO0Oo(ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V
    .locals 9

    check-cast p2, Llyiahf/vczjk/zf1;

    const v0, -0x264426c9

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p4, 0x1

    const/4 v1, 0x4

    if-eqz v0, :cond_0

    or-int/lit8 v2, p3, 0x6

    goto :goto_1

    :cond_0
    and-int/lit8 v2, p3, 0x6

    if-nez v2, :cond_2

    invoke-virtual {p2, p0}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v2

    if-eqz v2, :cond_1

    move v2, v1

    goto :goto_0

    :cond_1
    const/4 v2, 0x2

    :goto_0
    or-int/2addr v2, p3

    goto :goto_1

    :cond_2
    move v2, p3

    :goto_1
    and-int/lit8 v3, p4, 0x2

    if-eqz v3, :cond_3

    or-int/lit8 v2, v2, 0x30

    goto :goto_3

    :cond_3
    and-int/lit8 v3, p3, 0x30

    if-nez v3, :cond_5

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_4

    const/16 v3, 0x20

    goto :goto_2

    :cond_4
    const/16 v3, 0x10

    :goto_2
    or-int/2addr v2, v3

    :cond_5
    :goto_3
    and-int/lit8 v3, v2, 0x13

    const/16 v4, 0x12

    if-ne v3, v4, :cond_7

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_6

    goto :goto_4

    :cond_6
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_6

    :cond_7
    :goto_4
    const/4 v3, 0x1

    if-eqz v0, :cond_8

    move p0, v3

    :cond_8
    invoke-static {p1, p2}, Landroidx/compose/runtime/OooO0o;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v4, v5, :cond_9

    invoke-static {p2}, Llyiahf/vczjk/c6a;->Oooo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/xr1;

    move-result-object v4

    new-instance v6, Llyiahf/vczjk/dh1;

    invoke-direct {v6, v4}, Llyiahf/vczjk/dh1;-><init>(Llyiahf/vczjk/xr1;)V

    invoke-virtual {p2, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v4, v6

    :cond_9
    check-cast v4, Llyiahf/vczjk/dh1;

    iget-object v4, v4, Llyiahf/vczjk/dh1;->OooOOO0:Llyiahf/vczjk/xr1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-ne v6, v5, :cond_a

    new-instance v6, Llyiahf/vczjk/d17;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/ze3;

    invoke-direct {v6, p0}, Llyiahf/vczjk/y96;-><init>(Z)V

    iput-object v4, v6, Llyiahf/vczjk/d17;->OooO0Oo:Llyiahf/vczjk/xr1;

    iput-object v7, v6, Llyiahf/vczjk/d17;->OooO0o0:Llyiahf/vczjk/ze3;

    invoke-virtual {p2, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    check-cast v6, Llyiahf/vczjk/d17;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/ze3;

    invoke-virtual {p2, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {p2, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v7, v8

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v7, :cond_b

    if-ne v8, v5, :cond_c

    :cond_b
    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ze3;

    iput-object v0, v6, Llyiahf/vczjk/d17;->OooO0o0:Llyiahf/vczjk/ze3;

    iput-object v4, v6, Llyiahf/vczjk/d17;->OooO0Oo:Llyiahf/vczjk/xr1;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {p2, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    and-int/lit8 v2, v2, 0xe

    if-ne v2, v1, :cond_d

    goto :goto_5

    :cond_d
    const/4 v3, 0x0

    :goto_5
    or-int v1, v4, v3

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_e

    if-ne v2, v5, :cond_f

    :cond_e
    new-instance v2, Llyiahf/vczjk/e17;

    const/4 v1, 0x0

    invoke-direct {v2, v6, p0, v1}, Llyiahf/vczjk/e17;-><init>(Llyiahf/vczjk/d17;ZLlyiahf/vczjk/yo1;)V

    invoke-virtual {p2, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_f
    check-cast v2, Llyiahf/vczjk/ze3;

    invoke-static {v0, p2, v2}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {p2}, Llyiahf/vczjk/w35;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/ia6;

    move-result-object v0

    if-eqz v0, :cond_13

    invoke-interface {v0}, Llyiahf/vczjk/ia6;->OooO00o()Llyiahf/vczjk/ha6;

    move-result-object v0

    invoke-static {}, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->getLocalLifecycleOwner()Landroidx/compose/runtime/OooO;

    move-result-object v1

    invoke-virtual {p2, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/uy4;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {p2, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    invoke-virtual {p2, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_10

    if-ne v3, v5, :cond_11

    :cond_10
    new-instance v3, Llyiahf/vczjk/f17;

    invoke-direct {v3, v0, v1, v6}, Llyiahf/vczjk/f17;-><init>(Llyiahf/vczjk/ha6;Llyiahf/vczjk/uy4;Llyiahf/vczjk/d17;)V

    invoke-virtual {p2, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_11
    check-cast v3, Llyiahf/vczjk/oe3;

    invoke-static {v1, v0, v3, p2}, Llyiahf/vczjk/c6a;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)V

    :goto_6
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_12

    new-instance v0, Llyiahf/vczjk/g17;

    invoke-direct {v0, p0, p1, p3, p4}, Llyiahf/vczjk/g17;-><init>(ZLlyiahf/vczjk/ze3;II)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_12
    return-void

    :cond_13
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "No OnBackPressedDispatcherOwner was provided via LocalOnBackPressedDispatcherOwner"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooO0o(Llyiahf/vczjk/du8;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V
    .locals 6

    check-cast p3, Llyiahf/vczjk/zf1;

    const v0, 0x19b0b9fc

    invoke-virtual {p3, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p5, 0x1

    if-eqz v0, :cond_0

    or-int/lit8 v0, p4, 0x6

    goto :goto_1

    :cond_0
    and-int/lit8 v0, p4, 0x6

    if-nez v0, :cond_2

    invoke-virtual {p3, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    const/4 v0, 0x4

    goto :goto_0

    :cond_1
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p4

    goto :goto_1

    :cond_2
    move v0, p4

    :goto_1
    and-int/lit8 v1, p5, 0x2

    if-eqz v1, :cond_3

    or-int/lit8 v0, v0, 0x30

    goto :goto_3

    :cond_3
    and-int/lit8 v2, p4, 0x30

    if-nez v2, :cond_5

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_4

    const/16 v2, 0x20

    goto :goto_2

    :cond_4
    const/16 v2, 0x10

    :goto_2
    or-int/2addr v0, v2

    :cond_5
    :goto_3
    and-int/lit8 v2, p5, 0x4

    if-eqz v2, :cond_6

    or-int/lit16 v0, v0, 0x180

    goto :goto_5

    :cond_6
    and-int/lit16 v3, p4, 0x180

    if-nez v3, :cond_8

    invoke-virtual {p3, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_7

    const/16 v3, 0x100

    goto :goto_4

    :cond_7
    const/16 v3, 0x80

    :goto_4
    or-int/2addr v0, v3

    :cond_8
    :goto_5
    and-int/lit16 v3, v0, 0x93

    const/16 v4, 0x92

    const/4 v5, 0x0

    if-eq v3, v4, :cond_9

    const/4 v3, 0x1

    goto :goto_6

    :cond_9
    move v3, v5

    :goto_6
    and-int/lit8 v4, v0, 0x1

    invoke-virtual {p3, v4, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v3

    if-eqz v3, :cond_10

    if-eqz v1, :cond_a

    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    :cond_a
    if-eqz v2, :cond_b

    sget-object p2, Llyiahf/vczjk/ad1;->OooO00o:Llyiahf/vczjk/a91;

    :cond_b
    iget-object v1, p0, Llyiahf/vczjk/du8;->OooO00o:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_f

    sget-object v1, Llyiahf/vczjk/ch1;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {p3, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/o0O0O0Oo;

    const/4 v2, 0x0

    invoke-virtual {p3, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {p3, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v3, v4

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_c

    sget-object v3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v4, v3, :cond_d

    :cond_c
    new-instance v4, Llyiahf/vczjk/tt8;

    invoke-direct {v4, v1, v2}, Llyiahf/vczjk/tt8;-><init>(Llyiahf/vczjk/o0O0O0Oo;Llyiahf/vczjk/yo1;)V

    invoke-virtual {p3, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    check-cast v4, Llyiahf/vczjk/ze3;

    invoke-static {v2, p3, v4}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v1, p0, Llyiahf/vczjk/du8;->OooO00o:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_e

    and-int/lit16 v0, v0, 0x3f0

    invoke-static {p1, p2, p3, v0, v5}, Llyiahf/vczjk/dr6;->OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_7
    move-object v2, p1

    move-object v3, p2

    goto :goto_8

    :cond_e
    new-instance p0, Ljava/lang/ClassCastException;

    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    throw p0

    :cond_f
    new-instance p0, Ljava/lang/ClassCastException;

    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    throw p0

    :cond_10
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_7

    :goto_8
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_11

    new-instance v0, Llyiahf/vczjk/ut8;

    move-object v1, p0

    move v4, p4

    move v5, p5

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/ut8;-><init>(Llyiahf/vczjk/du8;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;II)V

    iput-object v0, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_11
    return-void
.end method

.method public static final OooO0o0(ILlyiahf/vczjk/rf1;)V
    .locals 12

    move-object v9, p1

    check-cast v9, Llyiahf/vczjk/zf1;

    const p1, 0x31ff3895

    invoke-virtual {v9, p1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    if-nez p0, :cond_1

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    sget-object v0, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    sget-object v8, Llyiahf/vczjk/xc1;->OooO0OO:Llyiahf/vczjk/a91;

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v1, 0x0

    const-wide/16 v2, 0x0

    const-wide/16 v4, 0x0

    const v10, 0xc00006

    const/16 v11, 0x7e

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/ua9;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_1
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_2

    new-instance v0, Llyiahf/vczjk/jm4;

    const/16 v1, 0x13

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/jm4;-><init>(II)V

    iput-object v0, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_2
    return-void
.end method

.method public static final OooO0oO(Llyiahf/vczjk/cm4;Llyiahf/vczjk/rf1;I)V
    .locals 11

    const/4 v0, 0x0

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    const p1, -0x6ebe0886

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v8, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p1

    const/4 v1, 0x2

    if-eqz p1, :cond_0

    const/4 p1, 0x4

    goto :goto_0

    :cond_0
    move p1, v1

    :goto_0
    or-int/2addr p1, p2

    and-int/lit8 p1, p1, 0x3

    if-ne p1, v1, :cond_2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p1

    if-nez p1, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_3

    :cond_2
    :goto_1
    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v1, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v1, v0}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v1

    iget v2, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {v8, p1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_3

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_3
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v1, v8, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, v8, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v3, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_4

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_5

    :cond_4
    invoke-static {v2, v8, v2, v1}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_5
    sget-object v1, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p1, v8, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/content/Context;

    const v1, -0x2aaa278

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-boolean v1, p0, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz v1, :cond_8

    sget v1, Llyiahf/vczjk/rk0;->OooO00o:F

    sget-object v1, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/x21;

    iget-wide v1, v1, Llyiahf/vczjk/x21;->OooO0Oo:J

    invoke-static {v1, v2, v8}, Llyiahf/vczjk/rk0;->OooO0oo(JLlyiahf/vczjk/rf1;)Llyiahf/vczjk/qk0;

    move-result-object v5

    const v1, 0x4c5de2

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_6

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, v1, :cond_7

    :cond_6
    new-instance v2, Llyiahf/vczjk/kt;

    const/16 v1, 0xa

    invoke-direct {v2, p1, v1}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    move-object v1, v2

    check-cast v1, Llyiahf/vczjk/le3;

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/xc1;->OooO0Oo:Llyiahf/vczjk/a91;

    const/4 v4, 0x0

    const/4 v6, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/high16 v9, 0x30000000

    const/16 v10, 0x1ee

    invoke-static/range {v1 .. v10}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :cond_8
    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 p1, 0x1

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_9

    new-instance v1, Llyiahf/vczjk/ci8;

    invoke-direct {v1, p0, p2, v0}, Llyiahf/vczjk/ci8;-><init>(Llyiahf/vczjk/cm4;II)V

    iput-object v1, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_9
    return-void
.end method

.method public static final OooO0oo([B)Ljava/util/LinkedHashSet;
    .locals 8

    const-string v0, "bytes"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/util/LinkedHashSet;

    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    array-length v1, p0

    if-nez v1, :cond_0

    goto :goto_3

    :cond_0
    new-instance v1, Ljava/io/ByteArrayInputStream;

    invoke-direct {v1, p0}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    :try_start_0
    new-instance p0, Ljava/io/ObjectInputStream;

    invoke-direct {p0, v1}, Ljava/io/ObjectInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    :try_start_1
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readInt()I

    move-result v2

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_1

    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readUTF()Ljava/lang/String;

    move-result-object v4

    invoke-static {v4}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    move-result-object v4

    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readBoolean()Z

    move-result v5

    new-instance v6, Llyiahf/vczjk/pk1;

    const-string v7, "uri"

    invoke-static {v4, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v6, v5, v4}, Llyiahf/vczjk/pk1;-><init>(ZLandroid/net/Uri;)V

    invoke-interface {v0, v6}, Ljava/util/Set;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :catchall_0
    move-exception v2

    goto :goto_1

    :cond_1
    :try_start_2
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->close()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    goto :goto_2

    :goto_1
    :try_start_3
    throw v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    :catchall_1
    move-exception v3

    :try_start_4
    invoke-static {p0, v2}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v3
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    :catchall_2
    move-exception p0

    goto :goto_4

    :catch_0
    move-exception p0

    :try_start_5
    invoke-virtual {p0}, Ljava/lang/Throwable;->printStackTrace()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    :goto_2
    invoke-virtual {v1}, Ljava/io/ByteArrayInputStream;->close()V

    :goto_3
    return-object v0

    :goto_4
    :try_start_6
    throw p0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    :catchall_3
    move-exception v0

    invoke-static {v1, p0}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v0
.end method

.method public static OooOO0(Ljava/lang/Class;Ljava/lang/reflect/Method;)Z
    .locals 1

    const-string v0, "clazz"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p0

    return p0
.end method

.method public static OooOO0O(Ljava/lang/reflect/Method;Llyiahf/vczjk/gf4;)Z
    .locals 1

    const-string v0, "clazz"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object p1

    invoke-static {p1, p0}, Llyiahf/vczjk/dr6;->OooOO0(Ljava/lang/Class;Ljava/lang/reflect/Method;)Z

    move-result p0

    return p0
.end method

.method public static final OooOO0o(Llyiahf/vczjk/bq6;DDDDDDDZZ)V
    .locals 50

    move-wide/from16 v1, p1

    move-wide/from16 v5, p5

    move-wide/from16 v3, p9

    const/16 v0, 0xb4

    int-to-double v7, v0

    div-double v7, p13, v7

    const-wide v9, 0x400921fb54442d18L    # Math.PI

    mul-double/2addr v7, v9

    invoke-static {v7, v8}, Ljava/lang/Math;->cos(D)D

    move-result-wide v11

    invoke-static {v7, v8}, Ljava/lang/Math;->sin(D)D

    move-result-wide v13

    mul-double v15, v1, v11

    mul-double v17, p3, v13

    add-double v17, v17, v15

    div-double v17, v17, v3

    move-wide v15, v9

    neg-double v9, v1

    mul-double/2addr v9, v13

    mul-double v19, p3, v11

    add-double v19, v19, v9

    div-double v19, v19, p11

    mul-double v9, v5, v11

    mul-double v21, p7, v13

    add-double v21, v21, v9

    div-double v21, v21, v3

    neg-double v9, v5

    mul-double/2addr v9, v13

    mul-double v23, p7, v11

    add-double v23, v23, v9

    div-double v23, v23, p11

    sub-double v9, v17, v21

    sub-double v25, v19, v23

    add-double v27, v17, v21

    const/4 v0, 0x2

    int-to-double v0, v0

    div-double v27, v27, v0

    add-double v29, v19, v23

    div-double v29, v29, v0

    mul-double v31, v9, v9

    mul-double v33, v25, v25

    add-double v33, v33, v31

    const-wide/16 v31, 0x0

    cmpg-double v2, v33, v31

    if-nez v2, :cond_0

    goto/16 :goto_4

    :cond_0
    const-wide/high16 v35, 0x3ff0000000000000L    # 1.0

    div-double v35, v35, v33

    const-wide/high16 v37, 0x3fd0000000000000L    # 0.25

    sub-double v35, v35, v37

    cmpg-double v2, v35, v31

    if-gez v2, :cond_1

    invoke-static/range {v33 .. v34}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v0

    const-wide v7, 0x3ffffff583a53b8eL    # 1.99999

    div-double/2addr v0, v7

    double-to-float v0, v0

    float-to-double v0, v0

    mul-double v9, v3, v0

    mul-double v11, p11, v0

    move-object/from16 v0, p0

    move-wide/from16 v1, p1

    move-wide/from16 v3, p3

    move-wide/from16 v7, p7

    move-wide/from16 v13, p13

    move/from16 v15, p15

    move/from16 v16, p16

    invoke-static/range {v0 .. v16}, Llyiahf/vczjk/dr6;->OooOO0o(Llyiahf/vczjk/bq6;DDDDDDDZZ)V

    return-void

    :cond_1
    move/from16 v2, p16

    invoke-static/range {v35 .. v36}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v5

    mul-double/2addr v9, v5

    mul-double v5, v5, v25

    move-wide/from16 v25, v15

    move/from16 v15, p15

    if-ne v15, v2, :cond_2

    sub-double v27, v27, v5

    add-double v29, v29, v9

    goto :goto_0

    :cond_2
    add-double v27, v27, v5

    sub-double v29, v29, v9

    :goto_0
    sub-double v5, v19, v29

    sub-double v9, v17, v27

    invoke-static {v5, v6, v9, v10}, Ljava/lang/Math;->atan2(DD)D

    move-result-wide v5

    sub-double v9, v23, v29

    move-wide v15, v0

    sub-double v0, v21, v27

    invoke-static {v9, v10, v0, v1}, Ljava/lang/Math;->atan2(DD)D

    move-result-wide v0

    sub-double/2addr v0, v5

    cmpl-double v9, v0, v31

    const/16 v17, 0x0

    if-ltz v9, :cond_3

    const/4 v10, 0x1

    goto :goto_1

    :cond_3
    move/from16 v10, v17

    :goto_1
    if-eq v2, v10, :cond_5

    const-wide v18, 0x401921fb54442d18L    # 6.283185307179586

    if-lez v9, :cond_4

    sub-double v0, v0, v18

    goto :goto_2

    :cond_4
    add-double v0, v0, v18

    :cond_5
    :goto_2
    mul-double v27, v27, v3

    mul-double v29, v29, p11

    mul-double v9, v27, v11

    mul-double v18, v29, v13

    sub-double v9, v9, v18

    mul-double v27, v27, v13

    mul-double v29, v29, v11

    add-double v29, v29, v27

    const/4 v2, 0x4

    int-to-double v11, v2

    mul-double v13, v0, v11

    div-double v13, v13, v25

    invoke-static {v13, v14}, Ljava/lang/Math;->abs(D)D

    move-result-wide v13

    invoke-static {v13, v14}, Ljava/lang/Math;->ceil(D)D

    move-result-wide v13

    double-to-int v2, v13

    invoke-static {v7, v8}, Ljava/lang/Math;->cos(D)D

    move-result-wide v13

    invoke-static {v7, v8}, Ljava/lang/Math;->sin(D)D

    move-result-wide v7

    invoke-static {v5, v6}, Ljava/lang/Math;->cos(D)D

    move-result-wide v18

    invoke-static {v5, v6}, Ljava/lang/Math;->sin(D)D

    move-result-wide v20

    move-wide/from16 p6, v0

    neg-double v0, v3

    mul-double v22, v0, v13

    mul-double v24, v22, v20

    mul-double v26, p11, v7

    mul-double v31, v26, v18

    sub-double v24, v24, v31

    mul-double/2addr v0, v7

    mul-double v20, v20, v0

    mul-double v31, p11, v13

    mul-double v18, v18, v31

    add-double v18, v18, v20

    move-wide/from16 p13, v0

    int-to-double v0, v2

    div-double v0, p6, v0

    move-wide/from16 p6, v0

    move/from16 v0, v17

    move-wide/from16 v33, v24

    move-wide/from16 v24, v18

    move-wide/from16 v17, p3

    move-wide/from16 v19, v5

    move-wide/from16 v5, p1

    :goto_3
    if-ge v0, v2, :cond_6

    add-double v35, v19, p6

    invoke-static/range {v35 .. v36}, Ljava/lang/Math;->sin(D)D

    move-result-wide v37

    invoke-static/range {v35 .. v36}, Ljava/lang/Math;->cos(D)D

    move-result-wide v39

    mul-double v41, v3, v13

    mul-double v41, v41, v39

    add-double v41, v41, v9

    mul-double v43, v26, v37

    move/from16 v21, v0

    sub-double v0, v41, v43

    mul-double v41, v3, v7

    mul-double v41, v41, v39

    add-double v41, v41, v29

    mul-double v43, v31, v37

    move v4, v2

    add-double v2, v43, v41

    mul-double v41, v22, v37

    mul-double v43, v26, v39

    sub-double v41, v41, v43

    mul-double v37, v37, p13

    mul-double v39, v39, v31

    add-double v37, v39, v37

    sub-double v19, v35, v19

    div-double v39, v19, v15

    invoke-static/range {v39 .. v40}, Ljava/lang/Math;->tan(D)D

    move-result-wide v39

    invoke-static/range {v19 .. v20}, Ljava/lang/Math;->sin(D)D

    move-result-wide v19

    const-wide/high16 v43, 0x4008000000000000L    # 3.0

    mul-double v43, v43, v39

    mul-double v43, v43, v39

    add-double v43, v43, v11

    invoke-static/range {v43 .. v44}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v39

    move/from16 p1, v4

    move-wide/from16 p2, v5

    const/4 v4, 0x1

    int-to-double v5, v4

    sub-double v39, v39, v5

    mul-double v39, v39, v19

    const/4 v5, 0x3

    int-to-double v5, v5

    div-double v39, v39, v5

    mul-double v33, v33, v39

    add-double v5, v33, p2

    mul-double v24, v24, v39

    move-wide/from16 p2, v5

    add-double v4, v24, v17

    mul-double v17, v39, v41

    move-wide/from16 p15, v7

    sub-double v6, v0, v17

    mul-double v39, v39, v37

    move-wide/from16 v17, v9

    sub-double v8, v2, v39

    move-wide/from16 v19, v11

    move-wide/from16 v10, p2

    double-to-float v10, v10

    double-to-float v4, v4

    double-to-float v5, v6

    double-to-float v6, v8

    double-to-float v7, v0

    double-to-float v8, v2

    move-object/from16 v9, p0

    check-cast v9, Llyiahf/vczjk/qe;

    iget-object v9, v9, Llyiahf/vczjk/qe;->OooO00o:Landroid/graphics/Path;

    move/from16 v45, v4

    move/from16 v46, v5

    move/from16 v47, v6

    move/from16 v48, v7

    move/from16 v49, v8

    move-object/from16 v43, v9

    move/from16 v44, v10

    invoke-virtual/range {v43 .. v49}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    add-int/lit8 v4, v21, 0x1

    move-wide/from16 v7, p15

    move-wide v5, v0

    move v0, v4

    move-wide/from16 v9, v17

    move-wide/from16 v11, v19

    move-wide/from16 v19, v35

    move-wide/from16 v24, v37

    move-wide/from16 v33, v41

    move-wide/from16 v17, v2

    move/from16 v2, p1

    move-wide/from16 v3, p9

    goto/16 :goto_3

    :cond_6
    :goto_4
    return-void
.end method

.method public static final OooOOO(Landroid/view/View;)Llyiahf/vczjk/uy4;
    .locals 3

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :goto_0
    const/4 v0, 0x0

    if-eqz p0, :cond_3

    sget v1, Landroidx/lifecycle/runtime/R$id;->view_tree_lifecycle_owner:I

    invoke-virtual {p0, v1}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    move-result-object v1

    instance-of v2, v1, Llyiahf/vczjk/uy4;

    if-eqz v2, :cond_0

    check-cast v1, Llyiahf/vczjk/uy4;

    goto :goto_1

    :cond_0
    move-object v1, v0

    :goto_1
    if-eqz v1, :cond_1

    return-object v1

    :cond_1
    invoke-static {p0}, Llyiahf/vczjk/br6;->OooOo0O(Landroid/view/View;)Landroid/view/ViewParent;

    move-result-object p0

    instance-of v1, p0, Landroid/view/View;

    if-eqz v1, :cond_2

    check-cast p0, Landroid/view/View;

    goto :goto_0

    :cond_2
    move-object p0, v0

    goto :goto_0

    :cond_3
    return-object v0
.end method

.method public static final OooOOO0(Ljava/util/Collection;)Ljava/lang/String;
    .locals 7

    const-string v0, "collection"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_0

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    move-object v1, p0

    check-cast v1, Ljava/lang/Iterable;

    const-string v4, "\n"

    const/4 v5, 0x0

    const-string v2, ",\n"

    const-string v3, "\n"

    const/16 v6, 0x38

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/d21;->o0ooOoO(Ljava/lang/Iterable;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/a79;->OooOo(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p0, "},"

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_0
    const-string p0, " }"

    return-object p0
.end method

.method public static final OooOOOO(Llyiahf/vczjk/ro9;)Llyiahf/vczjk/xr1;
    .locals 6

    const-string v0, "appScope"

    iget-object v1, p0, Llyiahf/vczjk/ro9;->OooO0O0:Ljava/util/LinkedHashMap;

    monitor-enter v1

    :try_start_0
    iget-object v2, p0, Llyiahf/vczjk/ro9;->OooO0O0:Ljava/util/LinkedHashMap;

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

    iget-object v2, p0, Llyiahf/vczjk/ro9;->OooO0OO:Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/os/Handler;

    const-string v3, "<get-handler>(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "App#Scope"

    sget v4, Llyiahf/vczjk/yl3;->OooO00o:I

    new-instance v4, Llyiahf/vczjk/xl3;

    const/4 v5, 0x0

    invoke-direct {v4, v2, v3, v5}, Llyiahf/vczjk/xl3;-><init>(Landroid/os/Handler;Ljava/lang/String;Z)V

    invoke-static {v1, v4}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooO0oO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/to1;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/ro9;->OooO0O0:Ljava/util/LinkedHashMap;

    monitor-enter v2

    :try_start_1
    iget-object v3, p0, Llyiahf/vczjk/ro9;->OooO0O0:Ljava/util/LinkedHashMap;

    invoke-interface {v3, v0}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_1

    iget-object p0, p0, Llyiahf/vczjk/ro9;->OooO0O0:Ljava/util/LinkedHashMap;

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
.end method

.method public static OooOOOo(Ljava/lang/String;)Ljava/lang/String;
    .locals 5

    const-string v0, "Unable to read prop "

    const-string v1, "getprop "

    const/4 v2, 0x0

    :try_start_0
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v3

    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v3, v1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;

    move-result-object v1

    new-instance v3, Ljava/io/BufferedReader;

    new-instance v4, Ljava/io/InputStreamReader;

    invoke-virtual {v1}, Ljava/lang/Process;->getInputStream()Ljava/io/InputStream;

    move-result-object v1

    invoke-direct {v4, v1}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    const/16 v1, 0x400

    invoke-direct {v3, v4, v1}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;I)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_2
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    :try_start_1
    invoke-virtual {v3}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v3}, Ljava/io/BufferedReader;->close()V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :try_start_2
    invoke-virtual {v3}, Ljava/io/BufferedReader;->close()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    return-object v1

    :catch_0
    move-exception p0

    invoke-virtual {p0}, Ljava/lang/Throwable;->printStackTrace()V

    return-object v1

    :catchall_0
    move-exception p0

    move-object v2, v3

    goto :goto_2

    :catch_1
    move-exception v1

    goto :goto_0

    :catchall_1
    move-exception p0

    goto :goto_2

    :catch_2
    move-exception v1

    move-object v3, v2

    :goto_0
    :try_start_3
    const-string v4, "Rom"

    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-static {v4, p0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    if-eqz v3, :cond_0

    :try_start_4
    invoke-virtual {v3}, Ljava/io/BufferedReader;->close()V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_3

    goto :goto_1

    :catch_3
    move-exception p0

    invoke-virtual {p0}, Ljava/lang/Throwable;->printStackTrace()V

    :cond_0
    :goto_1
    return-object v2

    :goto_2
    if-eqz v2, :cond_1

    :try_start_5
    invoke-virtual {v2}, Ljava/io/BufferedReader;->close()V
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_4

    goto :goto_3

    :catch_4
    move-exception v0

    invoke-virtual {v0}, Ljava/lang/Throwable;->printStackTrace()V

    :cond_1
    :goto_3
    throw p0
.end method

.method public static final OooOOo(I)I
    .locals 3

    const/4 v0, 0x1

    if-eqz p0, :cond_5

    const/4 v1, 0x2

    if-eq p0, v0, :cond_4

    const/4 v0, 0x3

    if-eq p0, v1, :cond_3

    const/4 v1, 0x4

    if-eq p0, v0, :cond_2

    const/4 v0, 0x5

    if-eq p0, v1, :cond_1

    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v2, 0x1e

    if-lt v1, v2, :cond_0

    if-ne p0, v0, :cond_0

    const/4 p0, 0x6

    return p0

    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Could not convert "

    const-string v2, " to NetworkType"

    invoke-static {p0, v1, v2}, Llyiahf/vczjk/ii5;->OooO0o(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    return v0

    :cond_2
    return v1

    :cond_3
    return v0

    :cond_4
    return v1

    :cond_5
    return v0
.end method

.method public static final OooOOo0(I)I
    .locals 3

    const/4 v0, 0x1

    if-eqz p0, :cond_1

    if-ne p0, v0, :cond_0

    const/4 p0, 0x2

    return p0

    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Could not convert "

    const-string v2, " to BackoffPolicy"

    invoke-static {p0, v1, v2}, Llyiahf/vczjk/ii5;->OooO0o(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    return v0
.end method

.method public static final OooOOoo(I)I
    .locals 3

    const/4 v0, 0x1

    if-eqz p0, :cond_1

    if-ne p0, v0, :cond_0

    const/4 p0, 0x2

    return p0

    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Could not convert "

    const-string v2, " to OutOfQuotaPolicy"

    invoke-static {p0, v1, v2}, Llyiahf/vczjk/ii5;->OooO0o(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    return v0
.end method

.method public static final OooOo([B)Llyiahf/vczjk/c06;
    .locals 6

    const-string v0, "bytes"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1c

    if-lt v0, v1, :cond_3

    array-length v0, p0

    if-nez v0, :cond_0

    goto :goto_3

    :cond_0
    new-instance v0, Ljava/io/ByteArrayInputStream;

    invoke-direct {v0, p0}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    :try_start_0
    new-instance p0, Ljava/io/ObjectInputStream;

    invoke-direct {p0, v0}, Ljava/io/ObjectInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    :try_start_1
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readInt()I

    move-result v1

    new-array v2, v1, [I

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v4, v1, :cond_1

    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readInt()I

    move-result v5

    aput v5, v2, v4

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :catchall_0
    move-exception v1

    goto :goto_2

    :cond_1
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readInt()I

    move-result v1

    new-array v4, v1, [I

    :goto_1
    if-ge v3, v1, :cond_2

    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readInt()I

    move-result v5

    aput v5, v4, v3

    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_2
    invoke-static {v4, v2}, Llyiahf/vczjk/so8;->OooOoO0([I[I)Llyiahf/vczjk/c06;

    move-result-object v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :try_start_2
    invoke-virtual {p0}, Ljava/io/ObjectInputStream;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    invoke-virtual {v0}, Ljava/io/ByteArrayInputStream;->close()V

    return-object v1

    :goto_2
    :try_start_3
    throw v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    :catchall_1
    move-exception v2

    :try_start_4
    invoke-static {p0, v1}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    :catchall_2
    move-exception p0

    :try_start_5
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    :catchall_3
    move-exception v1

    invoke-static {v0, p0}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v1

    :cond_3
    :goto_3
    new-instance p0, Llyiahf/vczjk/c06;

    const/4 v0, 0x0

    invoke-direct {p0, v0}, Llyiahf/vczjk/c06;-><init>(Landroid/net/NetworkRequest;)V

    return-object p0
.end method

.method public static final OooOo0(Landroid/view/View;Llyiahf/vczjk/uy4;)V
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Landroidx/lifecycle/runtime/R$id;->view_tree_lifecycle_owner:I

    invoke-virtual {p0, v0, p1}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    return-void
.end method

.method public static final OooOo00(I)Llyiahf/vczjk/lqa;
    .locals 3

    if-eqz p0, :cond_5

    const/4 v0, 0x1

    if-eq p0, v0, :cond_4

    const/4 v0, 0x2

    if-eq p0, v0, :cond_3

    const/4 v0, 0x3

    if-eq p0, v0, :cond_2

    const/4 v0, 0x4

    if-eq p0, v0, :cond_1

    const/4 v0, 0x5

    if-ne p0, v0, :cond_0

    sget-object p0, Llyiahf/vczjk/lqa;->OooOOo:Llyiahf/vczjk/lqa;

    return-object p0

    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Could not convert "

    const-string v2, " to State"

    invoke-static {p0, v1, v2}, Llyiahf/vczjk/ii5;->OooO0o(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    sget-object p0, Llyiahf/vczjk/lqa;->OooOOo0:Llyiahf/vczjk/lqa;

    return-object p0

    :cond_2
    sget-object p0, Llyiahf/vczjk/lqa;->OooOOOo:Llyiahf/vczjk/lqa;

    return-object p0

    :cond_3
    sget-object p0, Llyiahf/vczjk/lqa;->OooOOOO:Llyiahf/vczjk/lqa;

    return-object p0

    :cond_4
    sget-object p0, Llyiahf/vczjk/lqa;->OooOOO:Llyiahf/vczjk/lqa;

    return-object p0

    :cond_5
    sget-object p0, Llyiahf/vczjk/lqa;->OooOOO0:Llyiahf/vczjk/lqa;

    return-object p0
.end method

.method public static final OooOo0O(Llyiahf/vczjk/lqa;)I
    .locals 1

    const-string v0, "state"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    move-result p0

    if-eqz p0, :cond_2

    const/4 v0, 0x1

    if-eq p0, v0, :cond_1

    const/4 v0, 0x2

    if-eq p0, v0, :cond_1

    const/4 v0, 0x3

    if-eq p0, v0, :cond_1

    const/4 v0, 0x4

    if-eq p0, v0, :cond_1

    const/4 v0, 0x5

    if-ne p0, v0, :cond_0

    return v0

    :cond_0
    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_1
    return v0

    :cond_2
    const/4 p0, 0x0

    return p0
.end method

.method public static final OooOo0o(JJ)J
    .locals 5

    const/16 v0, 0x20

    shr-long v1, p0, v0

    long-to-int v1, v1

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    shr-long v2, p2, v0

    long-to-int v2, v2

    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    mul-float/2addr v2, v1

    const-wide v3, 0xffffffffL

    and-long/2addr p0, v3

    long-to-int p0, p0

    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p0

    and-long p1, p2, v3

    long-to-int p1, p1

    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p1

    mul-float/2addr p1, p0

    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p0

    int-to-long p2, p0

    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p0

    int-to-long p0, p0

    shl-long/2addr p2, v0

    and-long/2addr p0, v3

    or-long/2addr p0, p2

    return-wide p0
.end method

.method public static final OooOoO(Ljava/lang/String;Llyiahf/vczjk/le3;)Z
    .locals 2

    const-string v0, "ReflectionGuard"

    const-string v1, "errorMessage"

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :try_start_0
    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-nez p1, :cond_0

    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/NoSuchFieldException; {:try_start_0 .. :try_end_0} :catch_0

    :cond_0
    return p1

    :catch_0
    const-string p1, "NoSuchField: "

    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_0

    :catch_1
    const-string p1, "NoSuchMethod: "

    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_0

    :catch_2
    const-string p1, "ClassNotFound: "

    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-static {v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    :goto_0
    const/4 p0, 0x0

    return p0
.end method

.method public static final OooOoO0(Ljava/util/List;Llyiahf/vczjk/bq6;)V
    .locals 29

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/qe;

    iget-object v2, v1, Llyiahf/vczjk/qe;->OooO00o:Landroid/graphics/Path;

    invoke-virtual {v2}, Landroid/graphics/Path;->getFillType()Landroid/graphics/Path$FillType;

    move-result-object v2

    sget-object v3, Landroid/graphics/Path$FillType;->EVEN_ODD:Landroid/graphics/Path$FillType;

    const/4 v4, 0x0

    if-ne v2, v3, :cond_0

    const/4 v2, 0x1

    goto :goto_0

    :cond_0
    move v2, v4

    :goto_0
    invoke-virtual {v1}, Llyiahf/vczjk/qe;->OooO()V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/qe;->OooOO0(I)V

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_1

    sget-object v2, Llyiahf/vczjk/hq6;->OooO0OO:Llyiahf/vczjk/hq6;

    goto :goto_1

    :cond_1
    invoke-interface {v0, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/zq6;

    :goto_1
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    move-result v3

    const/4 v5, 0x0

    move v6, v5

    move v7, v6

    move v8, v7

    move v9, v8

    move/from16 v18, v9

    move/from16 v19, v18

    :goto_2
    if-ge v4, v3, :cond_19

    invoke-interface {v0, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/zq6;

    instance-of v11, v10, Llyiahf/vczjk/hq6;

    iget-object v12, v1, Llyiahf/vczjk/qe;->OooO00o:Landroid/graphics/Path;

    if-eqz v11, :cond_2

    invoke-virtual {v12}, Landroid/graphics/Path;->close()V

    move/from16 p1, v3

    move/from16 v21, v4

    move/from16 v20, v5

    move-object/from16 v22, v10

    move/from16 v6, v18

    move v8, v6

    move/from16 v7, v19

    :goto_3
    move v9, v7

    goto/16 :goto_c

    :cond_2
    instance-of v11, v10, Llyiahf/vczjk/tq6;

    if-eqz v11, :cond_3

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/tq6;

    iget v11, v2, Llyiahf/vczjk/tq6;->OooO0OO:F

    add-float/2addr v6, v11

    iget v2, v2, Llyiahf/vczjk/tq6;->OooO0Oo:F

    add-float/2addr v7, v2

    invoke-virtual {v12, v11, v2}, Landroid/graphics/Path;->rMoveTo(FF)V

    move/from16 p1, v3

    move/from16 v21, v4

    move/from16 v20, v5

    move/from16 v18, v6

    move/from16 v19, v7

    :goto_4
    move-object/from16 v22, v10

    goto/16 :goto_c

    :cond_3
    instance-of v11, v10, Llyiahf/vczjk/lq6;

    if-eqz v11, :cond_4

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/lq6;

    iget v6, v2, Llyiahf/vczjk/lq6;->OooO0OO:F

    iget v2, v2, Llyiahf/vczjk/lq6;->OooO0Oo:F

    invoke-virtual {v1, v6, v2}, Llyiahf/vczjk/qe;->OooO0o(FF)V

    move v7, v2

    move/from16 v19, v7

    move/from16 p1, v3

    move/from16 v21, v4

    move/from16 v20, v5

    move/from16 v18, v6

    goto :goto_4

    :cond_4
    instance-of v11, v10, Llyiahf/vczjk/sq6;

    if-eqz v11, :cond_5

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/sq6;

    iget v11, v2, Llyiahf/vczjk/sq6;->OooO0OO:F

    iget v13, v2, Llyiahf/vczjk/sq6;->OooO0Oo:F

    invoke-virtual {v12, v11, v13}, Landroid/graphics/Path;->rLineTo(FF)V

    iget v2, v2, Llyiahf/vczjk/sq6;->OooO0OO:F

    add-float/2addr v6, v2

    add-float/2addr v7, v13

    :goto_5
    move/from16 p1, v3

    move/from16 v21, v4

    move/from16 v20, v5

    goto :goto_4

    :cond_5
    instance-of v11, v10, Llyiahf/vczjk/kq6;

    if-eqz v11, :cond_6

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/kq6;

    iget v6, v2, Llyiahf/vczjk/kq6;->OooO0OO:F

    iget v7, v2, Llyiahf/vczjk/kq6;->OooO0Oo:F

    invoke-virtual {v1, v6, v7}, Llyiahf/vczjk/qe;->OooO0o0(FF)V

    iget v2, v2, Llyiahf/vczjk/kq6;->OooO0OO:F

    :goto_6
    move v6, v2

    goto :goto_5

    :cond_6
    instance-of v11, v10, Llyiahf/vczjk/rq6;

    if-eqz v11, :cond_7

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/rq6;

    iget v11, v2, Llyiahf/vczjk/rq6;->OooO0OO:F

    invoke-virtual {v12, v11, v5}, Landroid/graphics/Path;->rLineTo(FF)V

    iget v2, v2, Llyiahf/vczjk/rq6;->OooO0OO:F

    add-float/2addr v6, v2

    goto :goto_5

    :cond_7
    instance-of v11, v10, Llyiahf/vczjk/jq6;

    if-eqz v11, :cond_8

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/jq6;

    iget v6, v2, Llyiahf/vczjk/jq6;->OooO0OO:F

    invoke-virtual {v1, v6, v7}, Llyiahf/vczjk/qe;->OooO0o0(FF)V

    iget v2, v2, Llyiahf/vczjk/jq6;->OooO0OO:F

    goto :goto_6

    :cond_8
    instance-of v11, v10, Llyiahf/vczjk/xq6;

    if-eqz v11, :cond_9

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/xq6;

    iget v11, v2, Llyiahf/vczjk/xq6;->OooO0OO:F

    invoke-virtual {v12, v5, v11}, Landroid/graphics/Path;->rLineTo(FF)V

    iget v2, v2, Llyiahf/vczjk/xq6;->OooO0OO:F

    :goto_7
    add-float/2addr v7, v2

    goto :goto_5

    :cond_9
    instance-of v11, v10, Llyiahf/vczjk/yq6;

    if-eqz v11, :cond_a

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/yq6;

    iget v7, v2, Llyiahf/vczjk/yq6;->OooO0OO:F

    invoke-virtual {v1, v6, v7}, Llyiahf/vczjk/qe;->OooO0o0(FF)V

    iget v2, v2, Llyiahf/vczjk/yq6;->OooO0OO:F

    move v7, v2

    goto :goto_5

    :cond_a
    instance-of v11, v10, Llyiahf/vczjk/qq6;

    if-eqz v11, :cond_b

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/qq6;

    iget v8, v2, Llyiahf/vczjk/qq6;->OooO0OO:F

    iget v9, v2, Llyiahf/vczjk/qq6;->OooO0Oo:F

    iget v11, v2, Llyiahf/vczjk/qq6;->OooO0o0:F

    iget v13, v2, Llyiahf/vczjk/qq6;->OooO0o:F

    iget v14, v2, Llyiahf/vczjk/qq6;->OooO0oO:F

    iget v15, v2, Llyiahf/vczjk/qq6;->OooO0oo:F

    move/from16 v21, v8

    move/from16 v22, v9

    move/from16 v23, v11

    move-object/from16 v20, v12

    move/from16 v24, v13

    move/from16 v25, v14

    move/from16 v26, v15

    invoke-virtual/range {v20 .. v26}, Landroid/graphics/Path;->rCubicTo(FFFFFF)V

    iget v8, v2, Llyiahf/vczjk/qq6;->OooO0o0:F

    add-float/2addr v8, v6

    iget v9, v2, Llyiahf/vczjk/qq6;->OooO0o:F

    add-float/2addr v9, v7

    iget v11, v2, Llyiahf/vczjk/qq6;->OooO0oO:F

    add-float/2addr v6, v11

    iget v2, v2, Llyiahf/vczjk/qq6;->OooO0oo:F

    goto :goto_7

    :cond_b
    move-object/from16 v20, v12

    instance-of v11, v10, Llyiahf/vczjk/iq6;

    if-eqz v11, :cond_c

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/iq6;

    iget v6, v2, Llyiahf/vczjk/iq6;->OooO0OO:F

    iget v7, v2, Llyiahf/vczjk/iq6;->OooO0Oo:F

    iget v8, v2, Llyiahf/vczjk/iq6;->OooO0o0:F

    iget v9, v2, Llyiahf/vczjk/iq6;->OooO0o:F

    iget v11, v2, Llyiahf/vczjk/iq6;->OooO0oO:F

    iget v12, v2, Llyiahf/vczjk/iq6;->OooO0oo:F

    move/from16 v21, v6

    move/from16 v22, v7

    move/from16 v23, v8

    move/from16 v24, v9

    move/from16 v25, v11

    move/from16 v26, v12

    invoke-virtual/range {v20 .. v26}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    iget v6, v2, Llyiahf/vczjk/iq6;->OooO0o0:F

    iget v7, v2, Llyiahf/vczjk/iq6;->OooO0o:F

    iget v8, v2, Llyiahf/vczjk/iq6;->OooO0oO:F

    iget v2, v2, Llyiahf/vczjk/iq6;->OooO0oo:F

    :goto_8
    move/from16 p1, v8

    move v8, v6

    move/from16 v6, p1

    move/from16 p1, v3

    move/from16 v21, v4

    move/from16 v20, v5

    move v9, v7

    move-object/from16 v22, v10

    move v7, v2

    goto/16 :goto_c

    :cond_c
    instance-of v11, v10, Llyiahf/vczjk/vq6;

    if-eqz v11, :cond_e

    iget-boolean v2, v2, Llyiahf/vczjk/zq6;->OooO00o:Z

    if-eqz v2, :cond_d

    sub-float v2, v6, v8

    sub-float v8, v7, v9

    move/from16 v21, v2

    move/from16 v22, v8

    goto :goto_9

    :cond_d
    move/from16 v21, v5

    move/from16 v22, v21

    :goto_9
    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/vq6;

    iget v8, v2, Llyiahf/vczjk/vq6;->OooO0OO:F

    iget v9, v2, Llyiahf/vczjk/vq6;->OooO0Oo:F

    iget v11, v2, Llyiahf/vczjk/vq6;->OooO0o0:F

    iget v12, v2, Llyiahf/vczjk/vq6;->OooO0o:F

    move/from16 v23, v8

    move/from16 v24, v9

    move/from16 v25, v11

    move/from16 v26, v12

    invoke-virtual/range {v20 .. v26}, Landroid/graphics/Path;->rCubicTo(FFFFFF)V

    iget v8, v2, Llyiahf/vczjk/vq6;->OooO0OO:F

    add-float/2addr v8, v6

    iget v9, v2, Llyiahf/vczjk/vq6;->OooO0Oo:F

    add-float/2addr v9, v7

    iget v11, v2, Llyiahf/vczjk/vq6;->OooO0o0:F

    add-float/2addr v6, v11

    iget v2, v2, Llyiahf/vczjk/vq6;->OooO0o:F

    goto/16 :goto_7

    :cond_e
    instance-of v11, v10, Llyiahf/vczjk/nq6;

    const/4 v12, 0x2

    if-eqz v11, :cond_10

    iget-boolean v2, v2, Llyiahf/vczjk/zq6;->OooO00o:Z

    if-eqz v2, :cond_f

    int-to-float v2, v12

    mul-float/2addr v6, v2

    sub-float/2addr v6, v8

    mul-float/2addr v2, v7

    sub-float v7, v2, v9

    :cond_f
    move/from16 v21, v6

    move/from16 v22, v7

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/nq6;

    iget v6, v2, Llyiahf/vczjk/nq6;->OooO0OO:F

    iget v7, v2, Llyiahf/vczjk/nq6;->OooO0Oo:F

    iget v8, v2, Llyiahf/vczjk/nq6;->OooO0o0:F

    iget v9, v2, Llyiahf/vczjk/nq6;->OooO0o:F

    move/from16 v23, v6

    move/from16 v24, v7

    move/from16 v25, v8

    move/from16 v26, v9

    invoke-virtual/range {v20 .. v26}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    iget v6, v2, Llyiahf/vczjk/nq6;->OooO0OO:F

    iget v7, v2, Llyiahf/vczjk/nq6;->OooO0Oo:F

    iget v8, v2, Llyiahf/vczjk/nq6;->OooO0o0:F

    iget v2, v2, Llyiahf/vczjk/nq6;->OooO0o:F

    goto :goto_8

    :cond_10
    move-object/from16 v11, v20

    instance-of v13, v10, Llyiahf/vczjk/uq6;

    if-eqz v13, :cond_11

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/uq6;

    iget v8, v2, Llyiahf/vczjk/uq6;->OooO0OO:F

    iget v9, v2, Llyiahf/vczjk/uq6;->OooO0Oo:F

    iget v12, v2, Llyiahf/vczjk/uq6;->OooO0o0:F

    iget v13, v2, Llyiahf/vczjk/uq6;->OooO0o:F

    invoke-virtual {v11, v8, v9, v12, v13}, Landroid/graphics/Path;->rQuadTo(FFFF)V

    iget v2, v2, Llyiahf/vczjk/uq6;->OooO0OO:F

    add-float/2addr v2, v6

    add-float/2addr v9, v7

    add-float/2addr v6, v12

    add-float/2addr v7, v13

    move v8, v2

    goto/16 :goto_5

    :cond_11
    instance-of v13, v10, Llyiahf/vczjk/mq6;

    if-eqz v13, :cond_12

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/mq6;

    iget v6, v2, Llyiahf/vczjk/mq6;->OooO0OO:F

    iget v7, v2, Llyiahf/vczjk/mq6;->OooO0Oo:F

    iget v8, v2, Llyiahf/vczjk/mq6;->OooO0o0:F

    iget v9, v2, Llyiahf/vczjk/mq6;->OooO0o:F

    invoke-virtual {v11, v6, v7, v8, v9}, Landroid/graphics/Path;->quadTo(FFFF)V

    iget v2, v2, Llyiahf/vczjk/mq6;->OooO0OO:F

    move/from16 p1, v9

    move v9, v7

    move/from16 v7, p1

    move/from16 p1, v3

    move/from16 v21, v4

    move/from16 v20, v5

    move v6, v8

    :goto_a
    move-object/from16 v22, v10

    move v8, v2

    goto/16 :goto_c

    :cond_12
    instance-of v13, v10, Llyiahf/vczjk/wq6;

    if-eqz v13, :cond_14

    iget-boolean v2, v2, Llyiahf/vczjk/zq6;->OooO0O0:Z

    if-eqz v2, :cond_13

    sub-float v2, v6, v8

    sub-float v8, v7, v9

    goto :goto_b

    :cond_13
    move v2, v5

    move v8, v2

    :goto_b
    move-object v9, v10

    check-cast v9, Llyiahf/vczjk/wq6;

    iget v12, v9, Llyiahf/vczjk/wq6;->OooO0OO:F

    iget v13, v9, Llyiahf/vczjk/wq6;->OooO0Oo:F

    invoke-virtual {v11, v2, v8, v12, v13}, Landroid/graphics/Path;->rQuadTo(FFFF)V

    add-float/2addr v2, v6

    add-float/2addr v8, v7

    iget v9, v9, Llyiahf/vczjk/wq6;->OooO0OO:F

    add-float/2addr v6, v9

    add-float/2addr v7, v13

    move/from16 p1, v3

    move/from16 v21, v4

    move/from16 v20, v5

    move v9, v8

    goto :goto_a

    :cond_14
    instance-of v13, v10, Llyiahf/vczjk/oq6;

    if-eqz v13, :cond_16

    iget-boolean v2, v2, Llyiahf/vczjk/zq6;->OooO0O0:Z

    if-eqz v2, :cond_15

    int-to-float v2, v12

    mul-float/2addr v6, v2

    sub-float/2addr v6, v8

    mul-float/2addr v2, v7

    sub-float v7, v2, v9

    :cond_15
    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/oq6;

    iget v8, v2, Llyiahf/vczjk/oq6;->OooO0OO:F

    iget v9, v2, Llyiahf/vczjk/oq6;->OooO0Oo:F

    invoke-virtual {v11, v6, v7, v8, v9}, Landroid/graphics/Path;->quadTo(FFFF)V

    iget v2, v2, Llyiahf/vczjk/oq6;->OooO0OO:F

    move/from16 p1, v9

    move v9, v7

    move/from16 v7, p1

    move/from16 p1, v3

    move/from16 v21, v4

    move/from16 v20, v5

    move v8, v6

    move-object/from16 v22, v10

    move v6, v2

    goto/16 :goto_c

    :cond_16
    instance-of v2, v10, Llyiahf/vczjk/pq6;

    if-eqz v2, :cond_18

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/pq6;

    iget v8, v2, Llyiahf/vczjk/pq6;->OooO0oo:F

    add-float/2addr v8, v6

    iget v9, v2, Llyiahf/vczjk/pq6;->OooO:F

    add-float/2addr v9, v7

    float-to-double v11, v6

    move v13, v4

    move v6, v5

    float-to-double v4, v7

    move v14, v6

    float-to-double v6, v8

    move v15, v8

    move v14, v9

    float-to-double v8, v14

    iget v0, v2, Llyiahf/vczjk/pq6;->OooO0OO:F

    move-object/from16 v16, v1

    float-to-double v0, v0

    move-wide/from16 v20, v0

    iget v0, v2, Llyiahf/vczjk/pq6;->OooO0Oo:F

    float-to-double v0, v0

    move-wide/from16 v22, v0

    iget v0, v2, Llyiahf/vczjk/pq6;->OooO0o0:F

    float-to-double v0, v0

    move-wide/from16 v24, v0

    iget-boolean v0, v2, Llyiahf/vczjk/pq6;->OooO0o:Z

    iget-boolean v1, v2, Llyiahf/vczjk/pq6;->OooO0oO:Z

    move/from16 v17, v1

    move/from16 p1, v3

    move-wide v2, v11

    move-object/from16 v1, v16

    move/from16 v16, v0

    move-object v0, v10

    move-wide/from16 v10, v20

    const/16 v20, 0x0

    move/from16 v21, v13

    move-wide/from16 v12, v22

    move/from16 v23, v14

    move/from16 v22, v15

    move-wide/from16 v14, v24

    invoke-static/range {v1 .. v17}, Llyiahf/vczjk/dr6;->OooOO0o(Llyiahf/vczjk/bq6;DDDDDDDZZ)V

    move/from16 v6, v22

    move v8, v6

    move/from16 v7, v23

    move v9, v7

    :cond_17
    move-object/from16 v22, v0

    goto :goto_c

    :cond_18
    move/from16 p1, v3

    move/from16 v21, v4

    move/from16 v20, v5

    move-object v0, v10

    instance-of v2, v0, Llyiahf/vczjk/gq6;

    if-eqz v2, :cond_17

    float-to-double v2, v6

    float-to-double v4, v7

    move-object v6, v0

    check-cast v6, Llyiahf/vczjk/gq6;

    iget v7, v6, Llyiahf/vczjk/gq6;->OooO0oo:F

    float-to-double v7, v7

    iget v9, v6, Llyiahf/vczjk/gq6;->OooO:F

    move-wide v10, v7

    move v7, v9

    float-to-double v8, v7

    iget v12, v6, Llyiahf/vczjk/gq6;->OooO0OO:F

    float-to-double v12, v12

    iget v14, v6, Llyiahf/vczjk/gq6;->OooO0Oo:F

    float-to-double v14, v14

    move-object/from16 v22, v0

    iget v0, v6, Llyiahf/vczjk/gq6;->OooO0o0:F

    move-object/from16 v16, v1

    float-to-double v0, v0

    move-wide/from16 v23, v0

    iget-boolean v0, v6, Llyiahf/vczjk/gq6;->OooO0o:Z

    iget-boolean v1, v6, Llyiahf/vczjk/gq6;->OooO0oO:Z

    move/from16 v17, v1

    move-object/from16 v1, v16

    move/from16 v16, v0

    move-object v0, v6

    move-wide/from16 v27, v23

    move/from16 v23, v7

    move-wide v6, v10

    move-wide v10, v12

    move-wide v12, v14

    move-wide/from16 v14, v27

    invoke-static/range {v1 .. v17}, Llyiahf/vczjk/dr6;->OooOO0o(Llyiahf/vczjk/bq6;DDDDDDDZZ)V

    iget v0, v0, Llyiahf/vczjk/gq6;->OooO0oo:F

    move v6, v0

    move v8, v6

    move/from16 v7, v23

    goto/16 :goto_3

    :goto_c
    add-int/lit8 v4, v21, 0x1

    move-object/from16 v0, p0

    move/from16 v3, p1

    move/from16 v5, v20

    move-object/from16 v2, v22

    goto/16 :goto_2

    :cond_19
    return-void
.end method
