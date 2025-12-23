.class public final Llyiahf/vczjk/oq5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/do6;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/an;

.field public final OooO0O0:Ljava/util/List;

.field public final OooO0OO:Ljava/lang/Object;

.field public final OooO0Oo:Ljava/lang/Object;

.field public final OooO0o0:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/an;Llyiahf/vczjk/rn9;Ljava/util/List;Llyiahf/vczjk/f62;Llyiahf/vczjk/aa3;)V
    .locals 29

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v1, v0, Llyiahf/vczjk/oq5;->OooO00o:Llyiahf/vczjk/an;

    move-object/from16 v3, p3

    iput-object v3, v0, Llyiahf/vczjk/oq5;->OooO0O0:Ljava/util/List;

    sget-object v3, Llyiahf/vczjk/ww4;->OooOOO:Llyiahf/vczjk/ww4;

    new-instance v4, Llyiahf/vczjk/nq5;

    invoke-direct {v4, v0}, Llyiahf/vczjk/nq5;-><init>(Llyiahf/vczjk/oq5;)V

    invoke-static {v3, v4}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object v4

    iput-object v4, v0, Llyiahf/vczjk/oq5;->OooO0OO:Ljava/lang/Object;

    new-instance v4, Llyiahf/vczjk/mq5;

    invoke-direct {v4, v0}, Llyiahf/vczjk/mq5;-><init>(Llyiahf/vczjk/oq5;)V

    invoke-static {v3, v4}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object v3

    iput-object v3, v0, Llyiahf/vczjk/oq5;->OooO0Oo:Ljava/lang/Object;

    sget-object v3, Llyiahf/vczjk/cn;->OooO00o:Llyiahf/vczjk/an;

    iget-object v3, v1, Llyiahf/vczjk/an;->OooOOOo:Ljava/util/ArrayList;

    sget-object v4, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    if-eqz v3, :cond_0

    new-instance v5, Llyiahf/vczjk/h93;

    const/16 v6, 0xb

    invoke-direct {v5, v6}, Llyiahf/vczjk/h93;-><init>(I)V

    invoke-static {v3, v5}, Llyiahf/vczjk/d21;->o0000O00(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    move-result-object v3

    goto :goto_0

    :cond_0
    move-object v3, v4

    :goto_0
    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    new-instance v6, Llyiahf/vczjk/xx;

    invoke-direct {v6}, Llyiahf/vczjk/xx;-><init>()V

    invoke-interface {v3}, Ljava/util/Collection;->size()I

    move-result v7

    const/4 v8, 0x0

    move v9, v8

    move v10, v9

    :goto_1
    iget-object v11, v2, Llyiahf/vczjk/rn9;->OooO0O0:Llyiahf/vczjk/ho6;

    if-ge v9, v7, :cond_9

    invoke-interface {v3, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/zm;

    iget-object v13, v12, Llyiahf/vczjk/zm;->OooO00o:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/ho6;

    invoke-virtual {v11, v13}, Llyiahf/vczjk/ho6;->OooO00o(Llyiahf/vczjk/ho6;)Llyiahf/vczjk/ho6;

    move-result-object v13

    const/16 v14, 0xe

    invoke-static {v12, v13, v8, v14}, Llyiahf/vczjk/zm;->OooO00o(Llyiahf/vczjk/zm;Llyiahf/vczjk/wm;II)Llyiahf/vczjk/zm;

    move-result-object v12

    :goto_2
    iget v13, v12, Llyiahf/vczjk/zm;->OooO0O0:I

    if-ge v10, v13, :cond_3

    invoke-virtual {v6}, Llyiahf/vczjk/xx;->isEmpty()Z

    move-result v14

    if-nez v14, :cond_3

    invoke-virtual {v6}, Llyiahf/vczjk/xx;->last()Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/zm;

    iget v15, v14, Llyiahf/vczjk/zm;->OooO0OO:I

    iget-object v8, v14, Llyiahf/vczjk/zm;->OooO00o:Ljava/lang/Object;

    if-ge v13, v15, :cond_2

    new-instance v14, Llyiahf/vczjk/zm;

    invoke-direct {v14, v10, v13, v8}, Llyiahf/vczjk/zm;-><init>(IILjava/lang/Object;)V

    invoke-virtual {v5, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move v10, v13

    :cond_1
    const/4 v8, 0x0

    goto :goto_2

    :cond_2
    new-instance v13, Llyiahf/vczjk/zm;

    invoke-direct {v13, v10, v15, v8}, Llyiahf/vczjk/zm;-><init>(IILjava/lang/Object;)V

    invoke-virtual {v5, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_3
    invoke-virtual {v6}, Llyiahf/vczjk/xx;->isEmpty()Z

    move-result v8

    iget v10, v14, Llyiahf/vczjk/zm;->OooO0OO:I

    if-nez v8, :cond_1

    invoke-virtual {v6}, Llyiahf/vczjk/xx;->last()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/zm;

    iget v8, v8, Llyiahf/vczjk/zm;->OooO0OO:I

    if-ne v10, v8, :cond_1

    invoke-virtual {v6}, Llyiahf/vczjk/xx;->removeLast()Ljava/lang/Object;

    goto :goto_3

    :cond_3
    if-ge v10, v13, :cond_4

    new-instance v8, Llyiahf/vczjk/zm;

    invoke-direct {v8, v10, v13, v11}, Llyiahf/vczjk/zm;-><init>(IILjava/lang/Object;)V

    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move v10, v13

    :cond_4
    invoke-virtual {v6}, Llyiahf/vczjk/xx;->OooOO0O()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/zm;

    iget-object v11, v12, Llyiahf/vczjk/zm;->OooO00o:Ljava/lang/Object;

    iget v12, v12, Llyiahf/vczjk/zm;->OooO0OO:I

    if-eqz v8, :cond_8

    iget v14, v8, Llyiahf/vczjk/zm;->OooO0OO:I

    iget-object v15, v8, Llyiahf/vczjk/zm;->OooO00o:Ljava/lang/Object;

    iget v8, v8, Llyiahf/vczjk/zm;->OooO0O0:I

    if-ne v8, v13, :cond_5

    if-ne v14, v12, :cond_5

    invoke-virtual {v6}, Llyiahf/vczjk/xx;->removeLast()Ljava/lang/Object;

    new-instance v8, Llyiahf/vczjk/zm;

    check-cast v15, Llyiahf/vczjk/ho6;

    check-cast v11, Llyiahf/vczjk/ho6;

    invoke-virtual {v15, v11}, Llyiahf/vczjk/ho6;->OooO00o(Llyiahf/vczjk/ho6;)Llyiahf/vczjk/ho6;

    move-result-object v11

    invoke-direct {v8, v13, v12, v11}, Llyiahf/vczjk/zm;-><init>(IILjava/lang/Object;)V

    invoke-virtual {v6, v8}, Llyiahf/vczjk/xx;->addLast(Ljava/lang/Object;)V

    move-object/from16 v16, v3

    goto :goto_4

    :cond_5
    if-ne v8, v14, :cond_6

    move-object/from16 v16, v3

    new-instance v3, Llyiahf/vczjk/zm;

    invoke-direct {v3, v8, v14, v15}, Llyiahf/vczjk/zm;-><init>(IILjava/lang/Object;)V

    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {v6}, Llyiahf/vczjk/xx;->removeLast()Ljava/lang/Object;

    new-instance v3, Llyiahf/vczjk/zm;

    invoke-direct {v3, v13, v12, v11}, Llyiahf/vczjk/zm;-><init>(IILjava/lang/Object;)V

    invoke-virtual {v6, v3}, Llyiahf/vczjk/xx;->addLast(Ljava/lang/Object;)V

    goto :goto_4

    :cond_6
    move-object/from16 v16, v3

    if-lt v14, v12, :cond_7

    new-instance v3, Llyiahf/vczjk/zm;

    check-cast v15, Llyiahf/vczjk/ho6;

    check-cast v11, Llyiahf/vczjk/ho6;

    invoke-virtual {v15, v11}, Llyiahf/vczjk/ho6;->OooO00o(Llyiahf/vczjk/ho6;)Llyiahf/vczjk/ho6;

    move-result-object v8

    invoke-direct {v3, v13, v12, v8}, Llyiahf/vczjk/zm;-><init>(IILjava/lang/Object;)V

    invoke-virtual {v6, v3}, Llyiahf/vczjk/xx;->addLast(Ljava/lang/Object;)V

    goto :goto_4

    :cond_7
    new-instance v1, Ljava/lang/IllegalArgumentException;

    invoke-direct {v1}, Ljava/lang/IllegalArgumentException;-><init>()V

    throw v1

    :cond_8
    move-object/from16 v16, v3

    new-instance v3, Llyiahf/vczjk/zm;

    invoke-direct {v3, v13, v12, v11}, Llyiahf/vczjk/zm;-><init>(IILjava/lang/Object;)V

    invoke-virtual {v6, v3}, Llyiahf/vczjk/xx;->addLast(Ljava/lang/Object;)V

    :goto_4
    add-int/lit8 v9, v9, 0x1

    move-object/from16 v3, v16

    const/4 v8, 0x0

    goto/16 :goto_1

    :cond_9
    :goto_5
    iget-object v3, v1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v7

    if-gt v10, v7, :cond_b

    invoke-virtual {v6}, Llyiahf/vczjk/xx;->isEmpty()Z

    move-result v7

    if-nez v7, :cond_b

    invoke-virtual {v6}, Llyiahf/vczjk/xx;->last()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/zm;

    new-instance v7, Llyiahf/vczjk/zm;

    iget-object v8, v3, Llyiahf/vczjk/zm;->OooO00o:Ljava/lang/Object;

    iget v3, v3, Llyiahf/vczjk/zm;->OooO0OO:I

    invoke-direct {v7, v10, v3, v8}, Llyiahf/vczjk/zm;-><init>(IILjava/lang/Object;)V

    invoke-virtual {v5, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_6
    invoke-virtual {v6}, Llyiahf/vczjk/xx;->isEmpty()Z

    move-result v7

    if-nez v7, :cond_a

    invoke-virtual {v6}, Llyiahf/vczjk/xx;->last()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/zm;

    iget v7, v7, Llyiahf/vczjk/zm;->OooO0OO:I

    if-ne v3, v7, :cond_a

    invoke-virtual {v6}, Llyiahf/vczjk/xx;->removeLast()Ljava/lang/Object;

    goto :goto_6

    :cond_a
    move v10, v3

    goto :goto_5

    :cond_b
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v6

    if-ge v10, v6, :cond_c

    new-instance v6, Llyiahf/vczjk/zm;

    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v7

    invoke-direct {v6, v10, v7, v11}, Llyiahf/vczjk/zm;-><init>(IILjava/lang/Object;)V

    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_c
    invoke-virtual {v5}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v6

    if-eqz v6, :cond_d

    new-instance v6, Llyiahf/vczjk/zm;

    const/4 v7, 0x0

    invoke-direct {v6, v7, v7, v11}, Llyiahf/vczjk/zm;-><init>(IILjava/lang/Object;)V

    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_7

    :cond_d
    const/4 v7, 0x0

    :goto_7
    new-instance v6, Ljava/util/ArrayList;

    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    move-result v8

    invoke-direct {v6, v8}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    move-result v8

    move v9, v7

    :goto_8
    if-ge v9, v8, :cond_15

    invoke-virtual {v5, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/zm;

    iget v12, v10, Llyiahf/vczjk/zm;->OooO0O0:I

    new-instance v13, Llyiahf/vczjk/an;

    iget v14, v10, Llyiahf/vczjk/zm;->OooO0OO:I

    if-eq v12, v14, :cond_e

    invoke-virtual {v3, v12, v14}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v15

    const-string v7, "substring(...)"

    invoke-static {v15, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_9

    :cond_e
    const-string v15, ""

    :goto_9
    sget-object v7, Llyiahf/vczjk/o6;->Oooo0OO:Llyiahf/vczjk/o6;

    invoke-static {v1, v12, v14, v7}, Llyiahf/vczjk/cn;->OooO0O0(Llyiahf/vczjk/an;IILlyiahf/vczjk/o6;)Ljava/util/List;

    move-result-object v7

    if-nez v7, :cond_f

    move-object v7, v4

    :cond_f
    invoke-direct {v13, v15, v7}, Llyiahf/vczjk/an;-><init>(Ljava/lang/String;Ljava/util/List;)V

    iget-object v7, v10, Llyiahf/vczjk/zm;->OooO00o:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/ho6;

    iget v12, v7, Llyiahf/vczjk/ho6;->OooO0O0:I

    const/high16 v1, -0x80000000

    if-ne v12, v1, :cond_10

    iget v1, v11, Llyiahf/vczjk/ho6;->OooO0O0:I

    new-instance v16, Llyiahf/vczjk/ho6;

    iget v12, v7, Llyiahf/vczjk/ho6;->OooO0oo:I

    move/from16 v18, v1

    iget-object v1, v7, Llyiahf/vczjk/ho6;->OooO:Llyiahf/vczjk/dn9;

    move-object/from16 v26, v1

    iget v1, v7, Llyiahf/vczjk/ho6;->OooO00o:I

    move-object/from16 v28, v3

    move-object/from16 v27, v4

    iget-wide v3, v7, Llyiahf/vczjk/ho6;->OooO0OO:J

    move/from16 v17, v1

    iget-object v1, v7, Llyiahf/vczjk/ho6;->OooO0Oo:Llyiahf/vczjk/ol9;

    move-object/from16 v21, v1

    iget-object v1, v7, Llyiahf/vczjk/ho6;->OooO0o0:Llyiahf/vczjk/lx6;

    move-object/from16 v22, v1

    iget-object v1, v7, Llyiahf/vczjk/ho6;->OooO0o:Llyiahf/vczjk/jz4;

    iget v7, v7, Llyiahf/vczjk/ho6;->OooO0oO:I

    move-object/from16 v23, v1

    move-wide/from16 v19, v3

    move/from16 v24, v7

    move/from16 v25, v12

    invoke-direct/range {v16 .. v26}, Llyiahf/vczjk/ho6;-><init>(IIJLlyiahf/vczjk/ol9;Llyiahf/vczjk/lx6;Llyiahf/vczjk/jz4;IILlyiahf/vczjk/dn9;)V

    move-object/from16 v7, v16

    goto :goto_a

    :cond_10
    move-object/from16 v28, v3

    move-object/from16 v27, v4

    :goto_a
    new-instance v1, Llyiahf/vczjk/co6;

    new-instance v3, Llyiahf/vczjk/rn9;

    invoke-virtual {v11, v7}, Llyiahf/vczjk/ho6;->OooO00o(Llyiahf/vczjk/ho6;)Llyiahf/vczjk/ho6;

    move-result-object v4

    iget-object v7, v2, Llyiahf/vczjk/rn9;->OooO00o:Llyiahf/vczjk/dy8;

    invoke-direct {v3, v7, v4}, Llyiahf/vczjk/rn9;-><init>(Llyiahf/vczjk/dy8;Llyiahf/vczjk/ho6;)V

    iget-object v4, v13, Llyiahf/vczjk/an;->OooOOO0:Ljava/util/List;

    if-nez v4, :cond_11

    move-object/from16 v19, v27

    goto :goto_b

    :cond_11
    move-object/from16 v19, v4

    :goto_b
    iget-object v4, v0, Llyiahf/vczjk/oq5;->OooO0O0:Ljava/util/List;

    new-instance v7, Ljava/util/ArrayList;

    invoke-interface {v4}, Ljava/util/List;->size()I

    move-result v12

    invoke-direct {v7, v12}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v4}, Ljava/util/Collection;->size()I

    move-result v12

    const/4 v13, 0x0

    :goto_c
    iget v2, v10, Llyiahf/vczjk/zm;->OooO0O0:I

    if-ge v13, v12, :cond_14

    invoke-interface {v4, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v16

    move-object/from16 v18, v3

    move-object/from16 v3, v16

    check-cast v3, Llyiahf/vczjk/zm;

    move-object/from16 v16, v4

    iget v4, v3, Llyiahf/vczjk/zm;->OooO0O0:I

    move-object/from16 v23, v5

    iget v5, v3, Llyiahf/vczjk/zm;->OooO0OO:I

    invoke-static {v2, v14, v4, v5}, Llyiahf/vczjk/cn;->OooO0OO(IIII)Z

    move-result v4

    if-eqz v4, :cond_13

    iget v4, v3, Llyiahf/vczjk/zm;->OooO0O0:I

    if-gt v2, v4, :cond_12

    if-gt v5, v14, :cond_12

    :goto_d
    move/from16 v17, v4

    goto :goto_e

    :cond_12
    const-string v17, "placeholder can not overlap with paragraph."

    invoke-static/range {v17 .. v17}, Llyiahf/vczjk/qz3;->OooO00o(Ljava/lang/String;)V

    goto :goto_d

    :goto_e
    new-instance v4, Llyiahf/vczjk/zm;

    move/from16 v20, v5

    sub-int v5, v17, v2

    sub-int v2, v20, v2

    iget-object v3, v3, Llyiahf/vczjk/zm;->OooO00o:Ljava/lang/Object;

    invoke-direct {v4, v5, v2, v3}, Llyiahf/vczjk/zm;-><init>(IILjava/lang/Object;)V

    invoke-virtual {v7, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_13
    add-int/lit8 v13, v13, 0x1

    move-object/from16 v4, v16

    move-object/from16 v3, v18

    move-object/from16 v5, v23

    goto :goto_c

    :cond_14
    move-object/from16 v18, v3

    move-object/from16 v23, v5

    new-instance v16, Llyiahf/vczjk/pe;

    move-object/from16 v22, p4

    move-object/from16 v21, p5

    move-object/from16 v20, v7

    move-object/from16 v17, v15

    invoke-direct/range {v16 .. v22}, Llyiahf/vczjk/pe;-><init>(Ljava/lang/String;Llyiahf/vczjk/rn9;Ljava/util/List;Ljava/util/List;Llyiahf/vczjk/aa3;Llyiahf/vczjk/f62;)V

    move-object/from16 v3, v16

    invoke-direct {v1, v3, v2, v14}, Llyiahf/vczjk/co6;-><init>(Llyiahf/vczjk/pe;II)V

    invoke-virtual {v6, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v9, v9, 0x1

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move-object/from16 v5, v23

    move-object/from16 v4, v27

    move-object/from16 v3, v28

    const/4 v7, 0x0

    goto/16 :goto_8

    :cond_15
    iput-object v6, v0, Llyiahf/vczjk/oq5;->OooO0o0:Ljava/util/ArrayList;

    return-void
.end method


# virtual methods
.method public final OooO00o()Z
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/oq5;->OooO0o0:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v1

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    if-ge v3, v1, :cond_1

    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/co6;

    iget-object v4, v4, Llyiahf/vczjk/co6;->OooO00o:Llyiahf/vczjk/pe;

    invoke-virtual {v4}, Llyiahf/vczjk/pe;->OooO00o()Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    return v2
.end method

.method public final OooO0O0()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/oq5;->OooO0OO:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    return v0
.end method

.method public final OooO0OO()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/oq5;->OooO0Oo:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    return v0
.end method
