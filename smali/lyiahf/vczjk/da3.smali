.class public final Llyiahf/vczjk/da3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $typefaceRequest:Llyiahf/vczjk/d6a;

.field final synthetic this$0:Llyiahf/vczjk/ea3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ea3;Llyiahf/vczjk/d6a;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/da3;->this$0:Llyiahf/vczjk/ea3;

    iput-object p2, p0, Llyiahf/vczjk/da3;->$typefaceRequest:Llyiahf/vczjk/d6a;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v1, p0

    move-object/from16 v7, p1

    check-cast v7, Llyiahf/vczjk/oe3;

    iget-object v0, v1, Llyiahf/vczjk/da3;->this$0:Llyiahf/vczjk/ea3;

    iget-object v9, v0, Llyiahf/vczjk/ea3;->OooO0Oo:Llyiahf/vczjk/ja3;

    iget-object v5, v1, Llyiahf/vczjk/da3;->$typefaceRequest:Llyiahf/vczjk/d6a;

    iget-object v8, v0, Llyiahf/vczjk/ea3;->OooO00o:Llyiahf/vczjk/hd;

    iget-object v0, v0, Llyiahf/vczjk/ea3;->OooO0o:Llyiahf/vczjk/ca3;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, v5, Llyiahf/vczjk/d6a;->OooO00o:Llyiahf/vczjk/ba3;

    instance-of v3, v2, Llyiahf/vczjk/ga3;

    if-nez v3, :cond_0

    const/4 v3, 0x0

    :goto_0
    const/4 v6, 0x0

    goto/16 :goto_1b

    :cond_0
    check-cast v2, Llyiahf/vczjk/ga3;

    iget-object v2, v2, Llyiahf/vczjk/ga3;->OooOOOO:Ljava/util/List;

    iget-object v3, v5, Llyiahf/vczjk/d6a;->OooO0O0:Llyiahf/vczjk/ib3;

    iget v4, v5, Llyiahf/vczjk/d6a;->OooO0OO:I

    new-instance v6, Ljava/util/ArrayList;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v12

    invoke-direct {v6, v12}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/util/Collection;->size()I

    move-result v12

    const/4 v14, 0x0

    :goto_1
    if-ge v14, v12, :cond_2

    invoke-interface {v2, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v15

    move-object v11, v15

    check-cast v11, Llyiahf/vczjk/n9;

    iget-object v11, v11, Llyiahf/vczjk/n9;->OooO0O0:Llyiahf/vczjk/ib3;

    invoke-static {v11, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_1

    if-nez v4, :cond_1

    invoke-virtual {v6, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_1
    add-int/lit8 v14, v14, 0x1

    goto :goto_1

    :cond_2
    invoke-virtual {v6}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v11

    if-nez v11, :cond_3

    goto/16 :goto_13

    :cond_3
    new-instance v6, Ljava/util/ArrayList;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v11

    invoke-direct {v6, v11}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/util/Collection;->size()I

    move-result v11

    const/4 v12, 0x0

    :goto_2
    if-ge v12, v11, :cond_5

    invoke-interface {v2, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v14

    move-object v15, v14

    check-cast v15, Llyiahf/vczjk/n9;

    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-nez v4, :cond_4

    invoke-virtual {v6, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_4
    add-int/lit8 v12, v12, 0x1

    goto :goto_2

    :cond_5
    invoke-virtual {v6}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v4

    if-eqz v4, :cond_6

    goto :goto_3

    :cond_6
    move-object v2, v6

    :goto_3
    sget-object v4, Llyiahf/vczjk/ib3;->OooOOO:Llyiahf/vczjk/ib3;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/ib3;->OooO00o(Llyiahf/vczjk/ib3;)I

    move-result v4

    iget v6, v3, Llyiahf/vczjk/ib3;->OooOOO0:I

    if-gez v4, :cond_f

    invoke-interface {v2}, Ljava/util/Collection;->size()I

    move-result v3

    const/4 v4, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    :goto_4
    if-ge v4, v3, :cond_c

    invoke-interface {v2, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/n9;

    iget-object v14, v14, Llyiahf/vczjk/n9;->OooO0O0:Llyiahf/vczjk/ib3;

    iget v15, v14, Llyiahf/vczjk/ib3;->OooOOO0:I

    invoke-static {v15, v6}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v15

    iget v10, v14, Llyiahf/vczjk/ib3;->OooOOO0:I

    if-gez v15, :cond_8

    if-eqz v11, :cond_7

    iget v15, v11, Llyiahf/vczjk/ib3;->OooOOO0:I

    invoke-static {v10, v15}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v10

    if-lez v10, :cond_a

    :cond_7
    move-object v11, v14

    goto :goto_5

    :cond_8
    invoke-static {v10, v6}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v15

    if-lez v15, :cond_b

    if-eqz v12, :cond_9

    iget v15, v12, Llyiahf/vczjk/ib3;->OooOOO0:I

    invoke-static {v10, v15}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v10

    if-gez v10, :cond_a

    :cond_9
    move-object v12, v14

    :cond_a
    :goto_5
    add-int/lit8 v4, v4, 0x1

    goto :goto_4

    :cond_b
    move-object v11, v14

    move-object v12, v11

    :cond_c
    if-nez v11, :cond_d

    move-object v11, v12

    :cond_d
    new-instance v6, Ljava/util/ArrayList;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v3

    invoke-direct {v6, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/util/Collection;->size()I

    move-result v3

    const/4 v4, 0x0

    :goto_6
    if-ge v4, v3, :cond_2d

    invoke-interface {v2, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v10

    move-object v12, v10

    check-cast v12, Llyiahf/vczjk/n9;

    iget-object v12, v12, Llyiahf/vczjk/n9;->OooO0O0:Llyiahf/vczjk/ib3;

    invoke-static {v12, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_e

    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_e
    add-int/lit8 v4, v4, 0x1

    goto :goto_6

    :cond_f
    sget-object v4, Llyiahf/vczjk/ib3;->OooOOOO:Llyiahf/vczjk/ib3;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/ib3;->OooO00o(Llyiahf/vczjk/ib3;)I

    move-result v3

    if-lez v3, :cond_18

    invoke-interface {v2}, Ljava/util/Collection;->size()I

    move-result v3

    const/4 v4, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    :goto_7
    if-ge v11, v3, :cond_15

    invoke-interface {v2, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/n9;

    iget-object v12, v12, Llyiahf/vczjk/n9;->OooO0O0:Llyiahf/vczjk/ib3;

    iget v14, v12, Llyiahf/vczjk/ib3;->OooOOO0:I

    invoke-static {v14, v6}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v14

    iget v15, v12, Llyiahf/vczjk/ib3;->OooOOO0:I

    if-gez v14, :cond_11

    if-eqz v4, :cond_10

    iget v14, v4, Llyiahf/vczjk/ib3;->OooOOO0:I

    invoke-static {v15, v14}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v14

    if-lez v14, :cond_13

    :cond_10
    move-object v4, v12

    goto :goto_8

    :cond_11
    invoke-static {v15, v6}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v14

    if-lez v14, :cond_14

    if-eqz v10, :cond_12

    iget v14, v10, Llyiahf/vczjk/ib3;->OooOOO0:I

    invoke-static {v15, v14}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v14

    if-gez v14, :cond_13

    :cond_12
    move-object v10, v12

    :cond_13
    :goto_8
    add-int/lit8 v11, v11, 0x1

    goto :goto_7

    :cond_14
    move-object v4, v12

    move-object v10, v4

    :cond_15
    if-nez v10, :cond_16

    goto :goto_9

    :cond_16
    move-object v4, v10

    :goto_9
    new-instance v6, Ljava/util/ArrayList;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v3

    invoke-direct {v6, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/util/Collection;->size()I

    move-result v3

    const/4 v10, 0x0

    :goto_a
    if-ge v10, v3, :cond_2d

    invoke-interface {v2, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v11

    move-object v12, v11

    check-cast v12, Llyiahf/vczjk/n9;

    iget-object v12, v12, Llyiahf/vczjk/n9;->OooO0O0:Llyiahf/vczjk/ib3;

    invoke-static {v12, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_17

    invoke-virtual {v6, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_17
    add-int/lit8 v10, v10, 0x1

    goto :goto_a

    :cond_18
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    move-result v3

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    :goto_b
    if-ge v12, v3, :cond_1f

    invoke-interface {v2, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/n9;

    iget-object v14, v14, Llyiahf/vczjk/n9;->OooO0O0:Llyiahf/vczjk/ib3;

    iget v15, v14, Llyiahf/vczjk/ib3;->OooOOO0:I

    iget v13, v4, Llyiahf/vczjk/ib3;->OooOOO0:I

    invoke-static {v15, v13}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v13

    if-lez v13, :cond_19

    goto :goto_c

    :cond_19
    iget v13, v14, Llyiahf/vczjk/ib3;->OooOOO0:I

    invoke-static {v13, v6}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v13

    iget v15, v14, Llyiahf/vczjk/ib3;->OooOOO0:I

    if-gez v13, :cond_1b

    if-eqz v10, :cond_1a

    iget v13, v10, Llyiahf/vczjk/ib3;->OooOOO0:I

    invoke-static {v15, v13}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v13

    if-lez v13, :cond_1d

    :cond_1a
    move-object v10, v14

    goto :goto_c

    :cond_1b
    invoke-static {v15, v6}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v13

    if-lez v13, :cond_1e

    if-eqz v11, :cond_1c

    iget v13, v11, Llyiahf/vczjk/ib3;->OooOOO0:I

    invoke-static {v15, v13}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v13

    if-gez v13, :cond_1d

    :cond_1c
    move-object v11, v14

    :cond_1d
    :goto_c
    add-int/lit8 v12, v12, 0x1

    goto :goto_b

    :cond_1e
    move-object v10, v14

    move-object v11, v10

    :cond_1f
    if-nez v11, :cond_20

    goto :goto_d

    :cond_20
    move-object v10, v11

    :goto_d
    new-instance v3, Ljava/util/ArrayList;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v4

    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/util/Collection;->size()I

    move-result v4

    const/4 v11, 0x0

    :goto_e
    if-ge v11, v4, :cond_22

    invoke-interface {v2, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v12

    move-object v13, v12

    check-cast v13, Llyiahf/vczjk/n9;

    iget-object v13, v13, Llyiahf/vczjk/n9;->OooO0O0:Llyiahf/vczjk/ib3;

    invoke-static {v13, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_21

    invoke-virtual {v3, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_21
    add-int/lit8 v11, v11, 0x1

    goto :goto_e

    :cond_22
    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v4

    if-eqz v4, :cond_2c

    sget-object v3, Llyiahf/vczjk/ib3;->OooOOOO:Llyiahf/vczjk/ib3;

    invoke-interface {v2}, Ljava/util/Collection;->size()I

    move-result v4

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    :goto_f
    if-ge v12, v4, :cond_29

    invoke-interface {v2, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/n9;

    iget-object v13, v13, Llyiahf/vczjk/n9;->OooO0O0:Llyiahf/vczjk/ib3;

    if-eqz v3, :cond_23

    iget v14, v13, Llyiahf/vczjk/ib3;->OooOOO0:I

    iget v15, v3, Llyiahf/vczjk/ib3;->OooOOO0:I

    invoke-static {v14, v15}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v14

    if-gez v14, :cond_23

    goto :goto_10

    :cond_23
    iget v14, v13, Llyiahf/vczjk/ib3;->OooOOO0:I

    invoke-static {v14, v6}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v14

    iget v15, v13, Llyiahf/vczjk/ib3;->OooOOO0:I

    if-gez v14, :cond_25

    if-eqz v10, :cond_24

    iget v14, v10, Llyiahf/vczjk/ib3;->OooOOO0:I

    invoke-static {v15, v14}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v14

    if-lez v14, :cond_27

    :cond_24
    move-object v10, v13

    goto :goto_10

    :cond_25
    invoke-static {v15, v6}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v14

    if-lez v14, :cond_28

    if-eqz v11, :cond_26

    iget v14, v11, Llyiahf/vczjk/ib3;->OooOOO0:I

    invoke-static {v15, v14}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result v14

    if-gez v14, :cond_27

    :cond_26
    move-object v11, v13

    :cond_27
    :goto_10
    add-int/lit8 v12, v12, 0x1

    goto :goto_f

    :cond_28
    move-object v10, v13

    move-object v11, v10

    :cond_29
    if-nez v11, :cond_2a

    goto :goto_11

    :cond_2a
    move-object v10, v11

    :goto_11
    new-instance v6, Ljava/util/ArrayList;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v3

    invoke-direct {v6, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/util/Collection;->size()I

    move-result v3

    const/4 v4, 0x0

    :goto_12
    if-ge v4, v3, :cond_2d

    invoke-interface {v2, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v11

    move-object v12, v11

    check-cast v12, Llyiahf/vczjk/n9;

    iget-object v12, v12, Llyiahf/vczjk/n9;->OooO0O0:Llyiahf/vczjk/ib3;

    invoke-static {v12, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_2b

    invoke-virtual {v6, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_2b
    add-int/lit8 v4, v4, 0x1

    goto :goto_12

    :cond_2c
    move-object v6, v3

    :cond_2d
    :goto_13
    iget-object v2, v9, Llyiahf/vczjk/ja3;->OooO00o:Llyiahf/vczjk/uqa;

    invoke-interface {v6}, Ljava/util/Collection;->size()I

    move-result v3

    if-lez v3, :cond_32

    const/4 v3, 0x0

    invoke-interface {v6, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/n9;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v4, v2, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/sp3;

    monitor-enter v4

    :try_start_0
    new-instance v6, Llyiahf/vczjk/c10;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-direct {v6, v3}, Llyiahf/vczjk/c10;-><init>(Llyiahf/vczjk/n9;)V

    iget-object v10, v2, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/i95;

    invoke-virtual {v10, v6}, Llyiahf/vczjk/i95;->OooO0O0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/b10;

    if-nez v10, :cond_2e

    iget-object v10, v2, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/js5;

    invoke-virtual {v10, v6}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    move-object v10, v6

    check-cast v10, Llyiahf/vczjk/b10;

    goto :goto_14

    :catchall_0
    move-exception v0

    goto :goto_19

    :cond_2e
    :goto_14
    if-eqz v10, :cond_2f

    iget-object v2, v10, Llyiahf/vczjk/b10;->OooO00o:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v4

    goto :goto_17

    :cond_2f
    monitor-exit v4

    :try_start_1
    invoke-virtual {v8, v3}, Llyiahf/vczjk/hd;->OooO0O0(Llyiahf/vczjk/n9;)Landroid/graphics/Typeface;

    move-result-object v4
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    goto :goto_15

    :catch_0
    invoke-virtual {v0, v5}, Llyiahf/vczjk/ca3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    :goto_15
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v6, Llyiahf/vczjk/c10;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-direct {v6, v3}, Llyiahf/vczjk/c10;-><init>(Llyiahf/vczjk/n9;)V

    iget-object v10, v2, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/sp3;

    monitor-enter v10

    if-nez v4, :cond_30

    :try_start_2
    iget-object v2, v2, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/js5;

    new-instance v11, Llyiahf/vczjk/b10;

    const/4 v12, 0x0

    invoke-direct {v11, v12}, Llyiahf/vczjk/b10;-><init>(Ljava/lang/Object;)V

    invoke-virtual {v2, v6, v11}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_16

    :catchall_1
    move-exception v0

    goto :goto_18

    :cond_30
    iget-object v2, v2, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/i95;

    new-instance v11, Llyiahf/vczjk/b10;

    invoke-direct {v11, v4}, Llyiahf/vczjk/b10;-><init>(Ljava/lang/Object;)V

    invoke-virtual {v2, v6, v11}, Llyiahf/vczjk/i95;->OooO0OO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :goto_16
    monitor-exit v10

    move-object v2, v4

    :goto_17
    if-nez v2, :cond_31

    invoke-virtual {v0, v5}, Llyiahf/vczjk/ca3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    :cond_31
    iget v0, v5, Llyiahf/vczjk/d6a;->OooO0Oo:I

    iget-object v4, v5, Llyiahf/vczjk/d6a;->OooO0O0:Llyiahf/vczjk/ib3;

    iget v6, v5, Llyiahf/vczjk/d6a;->OooO0OO:I

    invoke-static {v0, v2, v3, v4, v6}, Llyiahf/vczjk/tg0;->Oooo0o(ILjava/lang/Object;Llyiahf/vczjk/n9;Llyiahf/vczjk/ib3;I)Ljava/lang/Object;

    move-result-object v0

    new-instance v2, Llyiahf/vczjk/xn6;

    const/4 v3, 0x0

    invoke-direct {v2, v3, v0}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_1a

    :goto_18
    monitor-exit v10

    throw v0

    :goto_19
    monitor-exit v4

    throw v0

    :cond_32
    invoke-virtual {v0, v5}, Llyiahf/vczjk/ca3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    new-instance v2, Llyiahf/vczjk/xn6;

    const/4 v3, 0x0

    invoke-direct {v2, v3, v0}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    :goto_1a
    invoke-virtual {v2}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    move-object v3, v0

    check-cast v3, Ljava/util/List;

    invoke-virtual {v2}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_33

    new-instance v3, Llyiahf/vczjk/h6a;

    const/4 v0, 0x1

    invoke-direct {v3, v4, v0}, Llyiahf/vczjk/h6a;-><init>(Ljava/lang/Object;Z)V

    goto/16 :goto_0

    :cond_33
    const/4 v0, 0x1

    new-instance v2, Llyiahf/vczjk/uz;

    iget-object v6, v9, Llyiahf/vczjk/ja3;->OooO00o:Llyiahf/vczjk/uqa;

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/uz;-><init>(Ljava/util/List;Ljava/lang/Object;Llyiahf/vczjk/d6a;Llyiahf/vczjk/uqa;Llyiahf/vczjk/oe3;Llyiahf/vczjk/hd;)V

    iget-object v3, v9, Llyiahf/vczjk/ja3;->OooO0O0:Llyiahf/vczjk/to1;

    sget-object v4, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v5, Llyiahf/vczjk/ha3;

    const/4 v6, 0x0

    invoke-direct {v5, v2, v6}, Llyiahf/vczjk/ha3;-><init>(Llyiahf/vczjk/uz;Llyiahf/vczjk/yo1;)V

    invoke-static {v3, v6, v4, v5, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    new-instance v3, Llyiahf/vczjk/g6a;

    invoke-direct {v3, v2}, Llyiahf/vczjk/g6a;-><init>(Llyiahf/vczjk/uz;)V

    :goto_1b
    if-nez v3, :cond_38

    iget-object v0, v1, Llyiahf/vczjk/da3;->this$0:Llyiahf/vczjk/ea3;

    iget-object v0, v0, Llyiahf/vczjk/ea3;->OooO0o0:Llyiahf/vczjk/uz5;

    iget-object v2, v1, Llyiahf/vczjk/da3;->$typefaceRequest:Llyiahf/vczjk/d6a;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v3, v2, Llyiahf/vczjk/d6a;->OooO00o:Llyiahf/vczjk/ba3;

    if-nez v3, :cond_34

    const/4 v4, 0x1

    goto :goto_1c

    :cond_34
    instance-of v4, v3, Llyiahf/vczjk/g22;

    :goto_1c
    iget-object v0, v0, Llyiahf/vczjk/uz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/xx6;

    iget v5, v2, Llyiahf/vczjk/d6a;->OooO0OO:I

    iget-object v2, v2, Llyiahf/vczjk/d6a;->OooO0O0:Llyiahf/vczjk/ib3;

    if-eqz v4, :cond_35

    invoke-interface {v0, v2, v5}, Llyiahf/vczjk/xx6;->OooOOO0(Llyiahf/vczjk/ib3;I)Landroid/graphics/Typeface;

    move-result-object v0

    goto :goto_1d

    :cond_35
    instance-of v4, v3, Llyiahf/vczjk/bh3;

    if-eqz v4, :cond_36

    check-cast v3, Llyiahf/vczjk/bh3;

    invoke-interface {v0, v3, v2, v5}, Llyiahf/vczjk/xx6;->OooO00o(Llyiahf/vczjk/bh3;Llyiahf/vczjk/ib3;I)Landroid/graphics/Typeface;

    move-result-object v0

    :goto_1d
    new-instance v10, Llyiahf/vczjk/h6a;

    const/4 v2, 0x1

    invoke-direct {v10, v0, v2}, Llyiahf/vczjk/h6a;-><init>(Ljava/lang/Object;Z)V

    goto :goto_1e

    :cond_36
    move-object v10, v6

    :goto_1e
    if-eqz v10, :cond_37

    move-object v3, v10

    goto :goto_1f

    :cond_37
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v2, "Could not load font"

    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_38
    :goto_1f
    return-object v3
.end method
