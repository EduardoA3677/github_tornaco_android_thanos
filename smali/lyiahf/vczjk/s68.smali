.class public final synthetic Llyiahf/vczjk/s68;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ze3;

.field public final synthetic OooOOO0:Llyiahf/vczjk/kna;

.field public final synthetic OooOOOO:Llyiahf/vczjk/ze3;

.field public final synthetic OooOOOo:Llyiahf/vczjk/ze3;

.field public final synthetic OooOOo:Llyiahf/vczjk/ze3;

.field public final synthetic OooOOo0:I

.field public final synthetic OooOOoo:Llyiahf/vczjk/h78;

.field public final synthetic OooOo00:Llyiahf/vczjk/ze3;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kna;Llyiahf/vczjk/ze3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/ze3;ILlyiahf/vczjk/ze3;Llyiahf/vczjk/h78;Llyiahf/vczjk/ze3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/s68;->OooOOO0:Llyiahf/vczjk/kna;

    iput-object p2, p0, Llyiahf/vczjk/s68;->OooOOO:Llyiahf/vczjk/ze3;

    iput-object p3, p0, Llyiahf/vczjk/s68;->OooOOOO:Llyiahf/vczjk/ze3;

    iput-object p4, p0, Llyiahf/vczjk/s68;->OooOOOo:Llyiahf/vczjk/ze3;

    iput p5, p0, Llyiahf/vczjk/s68;->OooOOo0:I

    iput-object p6, p0, Llyiahf/vczjk/s68;->OooOOo:Llyiahf/vczjk/ze3;

    iput-object p7, p0, Llyiahf/vczjk/s68;->OooOOoo:Llyiahf/vczjk/h78;

    iput-object p8, p0, Llyiahf/vczjk/s68;->OooOo00:Llyiahf/vczjk/ze3;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    move-object/from16 v0, p0

    move-object/from16 v7, p1

    check-cast v7, Llyiahf/vczjk/e89;

    move-object/from16 v1, p2

    check-cast v1, Llyiahf/vczjk/rk1;

    iget-wide v2, v1, Llyiahf/vczjk/rk1;->OooO00o:J

    invoke-static {v2, v3}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v5

    iget-wide v2, v1, Llyiahf/vczjk/rk1;->OooO00o:J

    invoke-static {v2, v3}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v8

    const/4 v13, 0x0

    const/4 v14, 0x0

    iget-wide v9, v1, Llyiahf/vczjk/rk1;->OooO00o:J

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/16 v15, 0xa

    invoke-static/range {v9 .. v15}, Llyiahf/vczjk/rk1;->OooO00o(JIIIII)J

    move-result-wide v1

    invoke-interface {v7}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v3

    iget-object v6, v0, Llyiahf/vczjk/s68;->OooOOO0:Llyiahf/vczjk/kna;

    invoke-interface {v6, v7, v3}, Llyiahf/vczjk/kna;->OooO0O0(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I

    move-result v3

    invoke-interface {v7}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v4

    invoke-interface {v6, v7, v4}, Llyiahf/vczjk/kna;->OooO0Oo(Llyiahf/vczjk/f62;Llyiahf/vczjk/yn4;)I

    move-result v4

    invoke-interface {v6, v7}, Llyiahf/vczjk/kna;->OooO00o(Llyiahf/vczjk/f62;)I

    move-result v9

    sget-object v10, Llyiahf/vczjk/l78;->OooOOO0:Llyiahf/vczjk/l78;

    iget-object v11, v0, Llyiahf/vczjk/s68;->OooOOO:Llyiahf/vczjk/ze3;

    invoke-interface {v7, v10, v11}, Llyiahf/vczjk/e89;->OooO(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/util/List;

    move-result-object v10

    invoke-static {v10}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/ef5;

    invoke-interface {v10, v1, v2}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v10

    sget-object v11, Llyiahf/vczjk/l78;->OooOOOO:Llyiahf/vczjk/l78;

    iget-object v12, v0, Llyiahf/vczjk/s68;->OooOOOO:Llyiahf/vczjk/ze3;

    invoke-interface {v7, v11, v12}, Llyiahf/vczjk/e89;->OooO(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/util/List;

    move-result-object v11

    invoke-static {v11}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/ef5;

    neg-int v12, v3

    sub-int/2addr v12, v4

    neg-int v9, v9

    invoke-static {v12, v9, v1, v2}, Llyiahf/vczjk/uk1;->OooO(IIJ)J

    move-result-wide v13

    invoke-interface {v11, v13, v14}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v11

    sget-object v13, Llyiahf/vczjk/l78;->OooOOOo:Llyiahf/vczjk/l78;

    iget-object v14, v0, Llyiahf/vczjk/s68;->OooOOOo:Llyiahf/vczjk/ze3;

    invoke-interface {v7, v13, v14}, Llyiahf/vczjk/e89;->OooO(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/util/List;

    move-result-object v13

    invoke-static {v13}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/ef5;

    invoke-static {v12, v9, v1, v2}, Llyiahf/vczjk/uk1;->OooO(IIJ)J

    move-result-wide v14

    invoke-interface {v13, v14, v15}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v12

    iget v9, v12, Llyiahf/vczjk/ow6;->OooOOO0:I

    sget v13, Llyiahf/vczjk/j78;->OooO00o:F

    iget v14, v0, Llyiahf/vczjk/s68;->OooOOo0:I

    const/16 v16, 0x0

    if-nez v9, :cond_0

    iget v15, v12, Llyiahf/vczjk/ow6;->OooOOO:I

    if-nez v15, :cond_0

    move-object/from16 v4, v16

    goto :goto_4

    :cond_0
    iget v15, v12, Llyiahf/vczjk/ow6;->OooOOO:I

    if-nez v14, :cond_2

    move/from16 p2, v3

    invoke-interface {v7}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v3

    move/from16 v17, v4

    sget-object v4, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    if-ne v3, v4, :cond_1

    invoke-interface {v7, v13}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v3

    :goto_0
    add-int v3, v3, p2

    goto :goto_3

    :cond_1
    invoke-interface {v7, v13}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v3

    :goto_1
    sub-int v3, v5, v3

    sub-int/2addr v3, v9

    sub-int v3, v3, v17

    goto :goto_3

    :cond_2
    move/from16 p2, v3

    move/from16 v17, v4

    const/4 v3, 0x2

    if-ne v14, v3, :cond_3

    goto :goto_2

    :cond_3
    const/4 v4, 0x3

    if-ne v14, v4, :cond_5

    :goto_2
    invoke-interface {v7}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    if-ne v3, v4, :cond_4

    invoke-interface {v7, v13}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v3

    goto :goto_1

    :cond_4
    invoke-interface {v7, v13}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v3

    goto :goto_0

    :cond_5
    sub-int v4, v5, v9

    add-int v4, v4, p2

    sub-int v4, v4, v17

    div-int/lit8 v3, v4, 0x2

    :goto_3
    new-instance v4, Llyiahf/vczjk/yu2;

    invoke-direct {v4, v3, v15}, Llyiahf/vczjk/yu2;-><init>(II)V

    :goto_4
    sget-object v3, Llyiahf/vczjk/l78;->OooOOo0:Llyiahf/vczjk/l78;

    iget-object v9, v0, Llyiahf/vczjk/s68;->OooOOo:Llyiahf/vczjk/ze3;

    invoke-interface {v7, v3, v9}, Llyiahf/vczjk/e89;->OooO(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/util/List;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ef5;

    invoke-interface {v3, v1, v2}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v3

    iget v9, v3, Llyiahf/vczjk/ow6;->OooOOO0:I

    if-nez v9, :cond_6

    iget v9, v3, Llyiahf/vczjk/ow6;->OooOOO:I

    if-nez v9, :cond_6

    const/4 v9, 0x1

    goto :goto_5

    :cond_6
    const/4 v9, 0x0

    :goto_5
    if-eqz v4, :cond_9

    iget v15, v4, Llyiahf/vczjk/yu2;->OooOOO:I

    move-object/from16 v17, v4

    if-nez v9, :cond_8

    const/4 v4, 0x3

    if-ne v14, v4, :cond_7

    goto :goto_7

    :cond_7
    iget v4, v3, Llyiahf/vczjk/ow6;->OooOOO:I

    add-int/2addr v4, v15

    invoke-interface {v7, v13}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v13

    :goto_6
    add-int/2addr v13, v4

    goto :goto_8

    :cond_8
    :goto_7
    invoke-interface {v7, v13}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v4

    add-int/2addr v4, v15

    invoke-interface {v6, v7}, Llyiahf/vczjk/kna;->OooO00o(Llyiahf/vczjk/f62;)I

    move-result v13

    goto :goto_6

    :goto_8
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    move-object v13, v4

    goto :goto_9

    :cond_9
    move-object/from16 v17, v4

    move-object/from16 v13, v16

    :goto_9
    iget v4, v11, Llyiahf/vczjk/ow6;->OooOOO:I

    if-eqz v4, :cond_d

    if-eqz v13, :cond_a

    invoke-virtual {v13}, Ljava/lang/Integer;->intValue()I

    move-result v14

    goto :goto_a

    :cond_a
    iget v14, v3, Llyiahf/vczjk/ow6;->OooOOO:I

    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    if-nez v9, :cond_b

    move-object/from16 v16, v14

    :cond_b
    if-eqz v16, :cond_c

    invoke-virtual/range {v16 .. v16}, Ljava/lang/Integer;->intValue()I

    move-result v14

    goto :goto_a

    :cond_c
    invoke-interface {v6, v7}, Llyiahf/vczjk/kna;->OooO00o(Llyiahf/vczjk/f62;)I

    move-result v14

    :goto_a
    add-int v15, v4, v14

    goto :goto_b

    :cond_d
    const/4 v15, 0x0

    :goto_b
    new-instance v4, Llyiahf/vczjk/d14;

    invoke-direct {v4, v6, v7}, Llyiahf/vczjk/d14;-><init>(Llyiahf/vczjk/kna;Llyiahf/vczjk/e89;)V

    iget v14, v10, Llyiahf/vczjk/ow6;->OooOOO0:I

    if-nez v14, :cond_e

    iget v14, v10, Llyiahf/vczjk/ow6;->OooOOO:I

    if-nez v14, :cond_e

    invoke-virtual {v4}, Llyiahf/vczjk/d14;->OooO0OO()F

    move-result v14

    goto :goto_c

    :cond_e
    iget v14, v10, Llyiahf/vczjk/ow6;->OooOOO:I

    invoke-interface {v7, v14}, Llyiahf/vczjk/f62;->Oooo0OO(I)F

    move-result v14

    :goto_c
    if-eqz v9, :cond_f

    invoke-virtual {v4}, Llyiahf/vczjk/d14;->OooO00o()F

    move-result v9

    :goto_d
    move-object/from16 p1, v3

    goto :goto_e

    :cond_f
    iget v9, v3, Llyiahf/vczjk/ow6;->OooOOO:I

    invoke-interface {v7, v9}, Llyiahf/vczjk/f62;->Oooo0OO(I)F

    move-result v9

    goto :goto_d

    :goto_e
    invoke-interface {v7}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v3

    invoke-static {v4, v3}, Landroidx/compose/foundation/layout/OooO00o;->OooO0o(Llyiahf/vczjk/bi6;Llyiahf/vczjk/yn4;)F

    move-result v3

    move/from16 p2, v5

    invoke-interface {v7}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v5

    invoke-static {v4, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooO0o0(Llyiahf/vczjk/bi6;Llyiahf/vczjk/yn4;)F

    move-result v4

    new-instance v5, Llyiahf/vczjk/di6;

    invoke-direct {v5, v3, v14, v4, v9}, Llyiahf/vczjk/di6;-><init>(FFFF)V

    iget-object v3, v0, Llyiahf/vczjk/s68;->OooOOoo:Llyiahf/vczjk/h78;

    iget-object v3, v3, Llyiahf/vczjk/h78;->OooO00o:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3, v5}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    sget-object v3, Llyiahf/vczjk/l78;->OooOOO:Llyiahf/vczjk/l78;

    iget-object v4, v0, Llyiahf/vczjk/s68;->OooOo00:Llyiahf/vczjk/ze3;

    invoke-interface {v7, v3, v4}, Llyiahf/vczjk/e89;->OooO(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/util/List;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ef5;

    invoke-interface {v3, v1, v2}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v2

    new-instance v1, Llyiahf/vczjk/t68;

    move/from16 v5, p2

    move-object v3, v10

    move-object v4, v11

    move v9, v15

    move-object/from16 v11, v17

    move-object/from16 v10, p1

    invoke-direct/range {v1 .. v13}, Llyiahf/vczjk/t68;-><init>(Llyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;ILlyiahf/vczjk/kna;Llyiahf/vczjk/e89;IILlyiahf/vczjk/ow6;Llyiahf/vczjk/yu2;Llyiahf/vczjk/ow6;Ljava/lang/Integer;)V

    sget-object v2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {v7, v5, v8, v2, v1}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object v1

    return-object v1
.end method
