.class public final Llyiahf/vczjk/ag0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/zp5;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/zl8;

.field public final synthetic OooO0O0:Llyiahf/vczjk/le3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zl8;Llyiahf/vczjk/le3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ag0;->OooO00o:Llyiahf/vczjk/zl8;

    iput-object p2, p0, Llyiahf/vczjk/ag0;->OooO0O0:Llyiahf/vczjk/le3;

    return-void
.end method


# virtual methods
.method public final OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;
    .locals 28

    move-object/from16 v0, p0

    move-object/from16 v1, p2

    check-cast v1, Ljava/util/ArrayList;

    const/4 v2, 0x0

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/List;

    const/4 v4, 0x1

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/List;

    const/4 v6, 0x2

    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/util/List;

    const/4 v7, 0x3

    invoke-virtual {v1, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/List;

    invoke-static/range {p3 .. p4}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v9

    invoke-static/range {p3 .. p4}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v13

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v20, 0xa

    move-wide/from16 v14, p3

    invoke-static/range {v14 .. v20}, Llyiahf/vczjk/rk1;->OooO00o(JIIIII)J

    move-result-wide v7

    new-instance v10, Ljava/util/ArrayList;

    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v11

    invoke-direct {v10, v11}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v6}, Ljava/util/Collection;->size()I

    move-result v11

    move v12, v2

    :goto_0
    if-ge v12, v11, :cond_0

    invoke-interface {v6, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/ef5;

    invoke-interface {v14, v7, v8}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v14

    invoke-virtual {v10, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v12, v12, 0x1

    goto :goto_0

    :cond_0
    new-instance v15, Ljava/util/ArrayList;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v6

    invoke-direct {v15, v6}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v3}, Ljava/util/Collection;->size()I

    move-result v6

    move v11, v2

    :goto_1
    if-ge v11, v6, :cond_1

    invoke-interface {v3, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/ef5;

    invoke-interface {v12, v7, v8}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v12

    invoke-virtual {v15, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v11, v11, 0x1

    goto :goto_1

    :cond_1
    invoke-virtual {v15}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_2

    const/4 v3, 0x0

    goto :goto_3

    :cond_2
    invoke-virtual {v15, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ow6;

    iget v3, v3, Llyiahf/vczjk/ow6;->OooOOO:I

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v15}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v6

    if-gt v4, v6, :cond_4

    :goto_2
    invoke-virtual {v15, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/ow6;

    iget v11, v11, Llyiahf/vczjk/ow6;->OooOOO:I

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-virtual {v11, v3}, Ljava/lang/Integer;->compareTo(Ljava/lang/Object;)I

    move-result v12

    if-lez v12, :cond_3

    move-object v3, v11

    :cond_3
    if-eq v4, v6, :cond_4

    add-int/lit8 v4, v4, 0x1

    goto :goto_2

    :cond_4
    :goto_3
    if-eqz v3, :cond_5

    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    move-result v3

    move/from16 v16, v3

    goto :goto_4

    :cond_5
    move/from16 v16, v2

    :goto_4
    sub-int v26, v13, v16

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v23, 0x0

    const/16 v27, 0x7

    move-wide/from16 v21, v7

    invoke-static/range {v21 .. v27}, Llyiahf/vczjk/rk1;->OooO00o(JIIIII)J

    move-result-wide v3

    move-wide/from16 v6, v21

    new-instance v14, Ljava/util/ArrayList;

    invoke-interface {v5}, Ljava/util/List;->size()I

    move-result v8

    invoke-direct {v14, v8}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v5}, Ljava/util/Collection;->size()I

    move-result v8

    move v11, v2

    :goto_5
    if-ge v11, v8, :cond_6

    invoke-interface {v5, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/ef5;

    invoke-interface {v12, v3, v4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v12

    invoke-virtual {v14, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v11, v11, 0x1

    goto :goto_5

    :cond_6
    new-instance v3, Ljava/util/ArrayList;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v4

    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v4

    :goto_6
    if-ge v2, v4, :cond_7

    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ef5;

    invoke-interface {v5, v6, v7}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v5

    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v2, v2, 0x1

    goto :goto_6

    :cond_7
    new-instance v7, Llyiahf/vczjk/zf0;

    iget-object v11, v0, Llyiahf/vczjk/ag0;->OooO00o:Llyiahf/vczjk/zl8;

    iget-object v12, v0, Llyiahf/vczjk/ag0;->OooO0O0:Llyiahf/vczjk/le3;

    move-object v8, v10

    move-object v10, v3

    invoke-direct/range {v7 .. v16}, Llyiahf/vczjk/zf0;-><init>(Ljava/util/ArrayList;ILjava/util/ArrayList;Llyiahf/vczjk/zl8;Llyiahf/vczjk/le3;ILjava/util/ArrayList;Ljava/util/ArrayList;I)V

    sget-object v1, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    move-object/from16 v2, p1

    invoke-interface {v2, v9, v13, v1, v7}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object v1

    return-object v1
.end method
