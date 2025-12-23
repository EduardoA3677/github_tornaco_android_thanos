.class public final Llyiahf/vczjk/ov4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $beyondBoundsItemCount:I

.field final synthetic $contentPadding:Llyiahf/vczjk/bi6;

.field final synthetic $coroutineScope:Llyiahf/vczjk/xr1;

.field final synthetic $graphicsContext:Llyiahf/vczjk/ij3;

.field final synthetic $horizontalAlignment:Llyiahf/vczjk/m4;

.field final synthetic $horizontalArrangement:Llyiahf/vczjk/nx;

.field final synthetic $isVertical:Z

.field final synthetic $itemProviderLambda:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $reverseLayout:Z

.field final synthetic $state:Llyiahf/vczjk/dw4;

.field final synthetic $stickyItemsPlacement:Llyiahf/vczjk/q59;

.field final synthetic $verticalAlignment:Llyiahf/vczjk/n4;

.field final synthetic $verticalArrangement:Llyiahf/vczjk/px;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dw4;ZLlyiahf/vczjk/bi6;ZLlyiahf/vczjk/hh4;Llyiahf/vczjk/px;Llyiahf/vczjk/nx;ILlyiahf/vczjk/xr1;Llyiahf/vczjk/ij3;Llyiahf/vczjk/xj0;Llyiahf/vczjk/m4;Llyiahf/vczjk/n4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ov4;->$state:Llyiahf/vczjk/dw4;

    iput-boolean p2, p0, Llyiahf/vczjk/ov4;->$isVertical:Z

    iput-object p3, p0, Llyiahf/vczjk/ov4;->$contentPadding:Llyiahf/vczjk/bi6;

    iput-boolean p4, p0, Llyiahf/vczjk/ov4;->$reverseLayout:Z

    iput-object p5, p0, Llyiahf/vczjk/ov4;->$itemProviderLambda:Llyiahf/vczjk/le3;

    iput-object p6, p0, Llyiahf/vczjk/ov4;->$verticalArrangement:Llyiahf/vczjk/px;

    iput-object p7, p0, Llyiahf/vczjk/ov4;->$horizontalArrangement:Llyiahf/vczjk/nx;

    iput p8, p0, Llyiahf/vczjk/ov4;->$beyondBoundsItemCount:I

    iput-object p9, p0, Llyiahf/vczjk/ov4;->$coroutineScope:Llyiahf/vczjk/xr1;

    iput-object p10, p0, Llyiahf/vczjk/ov4;->$graphicsContext:Llyiahf/vczjk/ij3;

    iput-object p11, p0, Llyiahf/vczjk/ov4;->$stickyItemsPlacement:Llyiahf/vczjk/q59;

    iput-object p12, p0, Llyiahf/vczjk/ov4;->$horizontalAlignment:Llyiahf/vczjk/m4;

    iput-object p13, p0, Llyiahf/vczjk/ov4;->$verticalAlignment:Llyiahf/vczjk/n4;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 60

    move-object/from16 v1, p0

    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/st4;

    move-object/from16 v0, p2

    check-cast v0, Llyiahf/vczjk/rk1;

    iget-wide v4, v0, Llyiahf/vczjk/rk1;->OooO00o:J

    iget-object v0, v1, Llyiahf/vczjk/ov4;->$state:Llyiahf/vczjk/dw4;

    iget-object v0, v0, Llyiahf/vczjk/dw4;->OooOOo:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    iget-object v0, v1, Llyiahf/vczjk/ov4;->$state:Llyiahf/vczjk/dw4;

    iget-boolean v0, v0, Llyiahf/vczjk/dw4;->OooO0O0:Z

    const/16 v18, 0x1

    if-nez v0, :cond_1

    move-object v0, v3

    check-cast v0, Llyiahf/vczjk/tt4;

    iget-object v0, v0, Llyiahf/vczjk/tt4;->OooOOO:Llyiahf/vczjk/e89;

    invoke-interface {v0}, Llyiahf/vczjk/o34;->OoooOo0()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/16 v29, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    move/from16 v29, v18

    :goto_1
    iget-boolean v0, v1, Llyiahf/vczjk/ov4;->$isVertical:Z

    if-eqz v0, :cond_2

    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    goto :goto_2

    :cond_2
    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    :goto_2
    invoke-static {v4, v5, v0}, Llyiahf/vczjk/vc6;->OooOOO(JLlyiahf/vczjk/nf6;)V

    iget-boolean v0, v1, Llyiahf/vczjk/ov4;->$isVertical:Z

    if-eqz v0, :cond_3

    iget-object v0, v1, Llyiahf/vczjk/ov4;->$contentPadding:Llyiahf/vczjk/bi6;

    move-object v6, v3

    check-cast v6, Llyiahf/vczjk/tt4;

    iget-object v7, v6, Llyiahf/vczjk/tt4;->OooOOO:Llyiahf/vczjk/e89;

    invoke-interface {v7}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v7

    invoke-interface {v0, v7}, Llyiahf/vczjk/bi6;->OooO0O0(Llyiahf/vczjk/yn4;)F

    move-result v0

    iget-object v6, v6, Llyiahf/vczjk/tt4;->OooOOO:Llyiahf/vczjk/e89;

    invoke-interface {v6, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    goto :goto_3

    :cond_3
    iget-object v0, v1, Llyiahf/vczjk/ov4;->$contentPadding:Llyiahf/vczjk/bi6;

    move-object v6, v3

    check-cast v6, Llyiahf/vczjk/tt4;

    iget-object v7, v6, Llyiahf/vczjk/tt4;->OooOOO:Llyiahf/vczjk/e89;

    invoke-interface {v7}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v7

    invoke-static {v0, v7}, Landroidx/compose/foundation/layout/OooO00o;->OooO0o(Llyiahf/vczjk/bi6;Llyiahf/vczjk/yn4;)F

    move-result v0

    iget-object v6, v6, Llyiahf/vczjk/tt4;->OooOOO:Llyiahf/vczjk/e89;

    invoke-interface {v6, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    :goto_3
    iget-boolean v6, v1, Llyiahf/vczjk/ov4;->$isVertical:Z

    if-eqz v6, :cond_4

    iget-object v6, v1, Llyiahf/vczjk/ov4;->$contentPadding:Llyiahf/vczjk/bi6;

    move-object v7, v3

    check-cast v7, Llyiahf/vczjk/tt4;

    iget-object v8, v7, Llyiahf/vczjk/tt4;->OooOOO:Llyiahf/vczjk/e89;

    invoke-interface {v8}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v8

    invoke-interface {v6, v8}, Llyiahf/vczjk/bi6;->OooO0Oo(Llyiahf/vczjk/yn4;)F

    move-result v6

    iget-object v7, v7, Llyiahf/vczjk/tt4;->OooOOO:Llyiahf/vczjk/e89;

    invoke-interface {v7, v6}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v6

    goto :goto_4

    :cond_4
    iget-object v6, v1, Llyiahf/vczjk/ov4;->$contentPadding:Llyiahf/vczjk/bi6;

    move-object v7, v3

    check-cast v7, Llyiahf/vczjk/tt4;

    iget-object v8, v7, Llyiahf/vczjk/tt4;->OooOOO:Llyiahf/vczjk/e89;

    invoke-interface {v8}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v8

    invoke-static {v6, v8}, Landroidx/compose/foundation/layout/OooO00o;->OooO0o0(Llyiahf/vczjk/bi6;Llyiahf/vczjk/yn4;)F

    move-result v6

    iget-object v7, v7, Llyiahf/vczjk/tt4;->OooOOO:Llyiahf/vczjk/e89;

    invoke-interface {v7, v6}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v6

    :goto_4
    iget-object v7, v1, Llyiahf/vczjk/ov4;->$contentPadding:Llyiahf/vczjk/bi6;

    invoke-interface {v7}, Llyiahf/vczjk/bi6;->OooO0OO()F

    move-result v7

    move-object v8, v3

    check-cast v8, Llyiahf/vczjk/tt4;

    iget-object v9, v8, Llyiahf/vczjk/tt4;->OooOOO:Llyiahf/vczjk/e89;

    invoke-interface {v9, v7}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v7

    iget-object v9, v1, Llyiahf/vczjk/ov4;->$contentPadding:Llyiahf/vczjk/bi6;

    invoke-interface {v9}, Llyiahf/vczjk/bi6;->OooO00o()F

    move-result v9

    iget-object v8, v8, Llyiahf/vczjk/tt4;->OooOOO:Llyiahf/vczjk/e89;

    invoke-interface {v8, v9}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v9

    add-int v10, v7, v9

    add-int v11, v0, v6

    iget-boolean v12, v1, Llyiahf/vczjk/ov4;->$isVertical:Z

    if-eqz v12, :cond_5

    move v13, v10

    goto :goto_5

    :cond_5
    move v13, v11

    :goto_5
    if-eqz v12, :cond_6

    iget-boolean v14, v1, Llyiahf/vczjk/ov4;->$reverseLayout:Z

    if-nez v14, :cond_6

    move/from16 v22, v7

    goto :goto_6

    :cond_6
    if-eqz v12, :cond_7

    iget-boolean v14, v1, Llyiahf/vczjk/ov4;->$reverseLayout:Z

    if-eqz v14, :cond_7

    move/from16 v22, v9

    goto :goto_6

    :cond_7
    if-nez v12, :cond_8

    iget-boolean v9, v1, Llyiahf/vczjk/ov4;->$reverseLayout:Z

    if-nez v9, :cond_8

    move/from16 v22, v0

    goto :goto_6

    :cond_8
    move/from16 v22, v6

    :goto_6
    sub-int v20, v13, v22

    neg-int v6, v11

    neg-int v9, v10

    invoke-static {v6, v9, v4, v5}, Llyiahf/vczjk/uk1;->OooO(IIJ)J

    move-result-wide v12

    iget-object v6, v1, Llyiahf/vczjk/ov4;->$itemProviderLambda:Llyiahf/vczjk/le3;

    invoke-interface {v6}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/iv4;

    iget-object v9, v6, Llyiahf/vczjk/iv4;->OooO0OO:Llyiahf/vczjk/ir4;

    invoke-static {v12, v13}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v14

    invoke-static {v12, v13}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v15

    iget-object v2, v9, Llyiahf/vczjk/ir4;->OooO00o:Llyiahf/vczjk/qr5;

    check-cast v2, Llyiahf/vczjk/bw8;

    invoke-virtual {v2, v14}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    iget-object v2, v9, Llyiahf/vczjk/ir4;->OooO0O0:Llyiahf/vczjk/qr5;

    check-cast v2, Llyiahf/vczjk/bw8;

    invoke-virtual {v2, v15}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    iget-boolean v2, v1, Llyiahf/vczjk/ov4;->$isVertical:Z

    const-string v19, "null verticalArrangement when isVertical == true"

    if-eqz v2, :cond_a

    iget-object v2, v1, Llyiahf/vczjk/ov4;->$verticalArrangement:Llyiahf/vczjk/px;

    if-eqz v2, :cond_9

    invoke-interface {v2}, Llyiahf/vczjk/px;->OooO0O0()F

    move-result v2

    goto :goto_7

    :cond_9
    invoke-static/range {v19 .. v19}, Llyiahf/vczjk/sz3;->OooO0O0(Ljava/lang/String;)Ljava/lang/Void;

    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :cond_a
    iget-object v2, v1, Llyiahf/vczjk/ov4;->$horizontalArrangement:Llyiahf/vczjk/nx;

    if-eqz v2, :cond_7a

    invoke-interface {v2}, Llyiahf/vczjk/nx;->OooO0O0()F

    move-result v2

    :goto_7
    invoke-interface {v8, v2}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v21

    iget-object v2, v6, Llyiahf/vczjk/iv4;->OooO0O0:Llyiahf/vczjk/fv4;

    invoke-virtual {v2}, Llyiahf/vczjk/fv4;->OooO0O0()Llyiahf/vczjk/yw;

    move-result-object v2

    iget v2, v2, Llyiahf/vczjk/yw;->OooO0O0:I

    iget-boolean v9, v1, Llyiahf/vczjk/ov4;->$isVertical:Z

    if-eqz v9, :cond_b

    invoke-static {v4, v5}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v9

    sub-int/2addr v9, v10

    :goto_8
    move-wide/from16 v57, v4

    move-object v5, v3

    move-wide v3, v12

    move-wide/from16 v13, v57

    goto :goto_9

    :cond_b
    invoke-static {v4, v5}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v9

    sub-int/2addr v9, v11

    goto :goto_8

    :goto_9
    iget-boolean v12, v1, Llyiahf/vczjk/ov4;->$reverseLayout:Z

    const-wide v34, 0xffffffffL

    const/16 v36, 0x20

    if-eqz v12, :cond_e

    if-lez v9, :cond_c

    goto :goto_b

    :cond_c
    iget-boolean v15, v1, Llyiahf/vczjk/ov4;->$isVertical:Z

    if-eqz v15, :cond_d

    goto :goto_a

    :cond_d
    add-int/2addr v0, v9

    :goto_a
    if-eqz v15, :cond_e

    add-int/2addr v7, v9

    :cond_e
    :goto_b
    move/from16 v17, v2

    move-wide v15, v3

    int-to-long v2, v0

    shl-long v2, v2, v36

    move-wide/from16 v23, v2

    int-to-long v2, v7

    and-long v2, v2, v34

    or-long v2, v23, v2

    new-instance v25, Llyiahf/vczjk/nv4;

    move-object v7, v5

    iget-boolean v5, v1, Llyiahf/vczjk/ov4;->$isVertical:Z

    move v0, v10

    iget-object v10, v1, Llyiahf/vczjk/ov4;->$horizontalAlignment:Llyiahf/vczjk/m4;

    move v4, v11

    iget-object v11, v1, Llyiahf/vczjk/ov4;->$verticalAlignment:Llyiahf/vczjk/n4;

    move/from16 p2, v0

    iget-object v0, v1, Llyiahf/vczjk/ov4;->$state:Llyiahf/vczjk/dw4;

    move/from16 v23, v4

    move-object/from16 v37, v8

    move/from16 v8, v17

    move-object/from16 v17, v0

    move v0, v9

    move/from16 v9, v21

    move/from16 v57, v22

    move/from16 v22, p2

    move-wide/from16 v58, v13

    move/from16 v14, v20

    move-wide/from16 v20, v58

    move/from16 v13, v57

    move-wide/from16 v57, v2

    move-object/from16 v2, v25

    move-wide v3, v15

    move-wide/from16 v15, v57

    invoke-direct/range {v2 .. v17}, Llyiahf/vczjk/nv4;-><init>(JZLlyiahf/vczjk/iv4;Llyiahf/vczjk/st4;IILlyiahf/vczjk/m4;Llyiahf/vczjk/n4;ZIIJLlyiahf/vczjk/dw4;)V

    move-object v10, v6

    move v12, v8

    move v11, v9

    move-wide v8, v3

    move-object v3, v7

    iget-object v2, v1, Llyiahf/vczjk/ov4;->$state:Llyiahf/vczjk/dw4;

    invoke-static {}, Llyiahf/vczjk/wr6;->OooOOO0()Llyiahf/vczjk/nv8;

    move-result-object v4

    if-eqz v4, :cond_f

    invoke-virtual {v4}, Llyiahf/vczjk/nv8;->OooO0o0()Llyiahf/vczjk/oe3;

    move-result-object v5

    goto :goto_c

    :cond_f
    const/4 v5, 0x0

    :goto_c
    invoke-static {v4}, Llyiahf/vczjk/wr6;->OooOOOo(Llyiahf/vczjk/nv8;)Llyiahf/vczjk/nv8;

    move-result-object v6

    :try_start_0
    iget-object v2, v2, Llyiahf/vczjk/dw4;->OooO0Oo:Llyiahf/vczjk/tq4;

    invoke-virtual {v2}, Llyiahf/vczjk/tq4;->OooO00o()I

    move-result v7

    iget-object v15, v2, Llyiahf/vczjk/tq4;->OooO0o0:Ljava/lang/Object;

    invoke-static {v7, v15, v10}, Llyiahf/vczjk/c6a;->Oooo(ILjava/lang/Object;Llyiahf/vczjk/nt4;)I

    move-result v15

    if-eq v7, v15, :cond_10

    move-object/from16 v16, v3

    iget-object v3, v2, Llyiahf/vczjk/tq4;->OooO0O0:Llyiahf/vczjk/qr5;

    check-cast v3, Llyiahf/vczjk/bw8;

    invoke-virtual {v3, v15}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    iget-object v3, v2, Llyiahf/vczjk/tq4;->OooO0o:Llyiahf/vczjk/wt4;

    invoke-virtual {v3, v7}, Llyiahf/vczjk/wt4;->OooO00o(I)V

    goto :goto_d

    :catchall_0
    move-exception v0

    goto/16 :goto_64

    :cond_10
    move-object/from16 v16, v3

    :goto_d
    invoke-virtual {v2}, Llyiahf/vczjk/tq4;->OooO0O0()I

    move-result v17
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-static {v4, v6, v5}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    iget-object v2, v1, Llyiahf/vczjk/ov4;->$state:Llyiahf/vczjk/dw4;

    iget-object v3, v2, Llyiahf/vczjk/dw4;->OooOOo0:Llyiahf/vczjk/hu4;

    iget-object v2, v2, Llyiahf/vczjk/dw4;->OooOOO:Llyiahf/vczjk/vz5;

    invoke-static {v10, v3, v2}, Llyiahf/vczjk/os9;->OooOOo0(Llyiahf/vczjk/nt4;Llyiahf/vczjk/hu4;Llyiahf/vczjk/vz5;)Ljava/util/List;

    move-result-object v2

    invoke-interface/range {v37 .. v37}, Llyiahf/vczjk/o34;->OoooOo0()Z

    move-result v3

    if-nez v3, :cond_12

    if-nez v29, :cond_11

    goto :goto_f

    :cond_11
    iget-object v3, v1, Llyiahf/vczjk/ov4;->$state:Llyiahf/vczjk/dw4;

    iget-object v3, v3, Llyiahf/vczjk/dw4;->OooOo0O:Llyiahf/vczjk/ou4;

    iget-object v3, v3, Llyiahf/vczjk/ou4;->OooO00o:Llyiahf/vczjk/xl;

    iget-object v3, v3, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    move-result v3

    :goto_e
    move/from16 v24, v3

    goto :goto_10

    :cond_12
    :goto_f
    iget-object v3, v1, Llyiahf/vczjk/ov4;->$state:Llyiahf/vczjk/dw4;

    iget v3, v3, Llyiahf/vczjk/dw4;->OooO0oO:F

    goto :goto_e

    :goto_10
    iget-boolean v3, v1, Llyiahf/vczjk/ov4;->$isVertical:Z

    iget-object v4, v1, Llyiahf/vczjk/ov4;->$verticalArrangement:Llyiahf/vczjk/px;

    iget-object v5, v1, Llyiahf/vczjk/ov4;->$horizontalArrangement:Llyiahf/vczjk/nx;

    iget-boolean v6, v1, Llyiahf/vczjk/ov4;->$reverseLayout:Z

    iget-object v7, v1, Llyiahf/vczjk/ov4;->$state:Llyiahf/vczjk/dw4;

    iget-object v7, v7, Llyiahf/vczjk/dw4;->OooOOO0:Landroidx/compose/foundation/lazy/layout/OooO0OO;

    move/from16 v38, v11

    iget v11, v1, Llyiahf/vczjk/ov4;->$beyondBoundsItemCount:I

    invoke-interface/range {v37 .. v37}, Llyiahf/vczjk/o34;->OoooOo0()Z

    move-result v27

    move/from16 v26, v11

    iget-object v11, v1, Llyiahf/vczjk/ov4;->$state:Llyiahf/vczjk/dw4;

    move/from16 v39, v14

    iget-object v14, v11, Llyiahf/vczjk/dw4;->OooO0OO:Llyiahf/vczjk/sv4;

    move-object/from16 v40, v11

    iget-object v11, v1, Llyiahf/vczjk/ov4;->$coroutineScope:Llyiahf/vczjk/xr1;

    move-object/from16 v32, v11

    iget-object v11, v1, Llyiahf/vczjk/ov4;->$graphicsContext:Llyiahf/vczjk/ij3;

    move-object/from16 v33, v11

    iget-object v11, v1, Llyiahf/vczjk/ov4;->$stickyItemsPlacement:Llyiahf/vczjk/q59;

    move-object/from16 v28, v2

    new-instance v2, Llyiahf/vczjk/mv4;

    move/from16 v41, v18

    move-object/from16 v30, v28

    move/from16 v18, v6

    move/from16 v6, v23

    move/from16 v57, v26

    move/from16 v26, v3

    move-object/from16 v3, v16

    move-object/from16 v16, v11

    move-object v11, v4

    move-wide/from16 v58, v20

    move-object/from16 v20, v5

    move-object/from16 v21, v19

    move-wide/from16 v4, v58

    move-object/from16 v19, v7

    move/from16 v7, v22

    move/from16 v22, v57

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/mv4;-><init>(Llyiahf/vczjk/st4;JII)V

    if-ltz v13, :cond_13

    goto :goto_11

    :cond_13
    const-string v4, "invalid beforeContentPadding"

    invoke-static {v4}, Llyiahf/vczjk/sz3;->OooO00o(Ljava/lang/String;)V

    :goto_11
    if-ltz v39, :cond_14

    :goto_12
    move-object v4, v14

    goto :goto_13

    :cond_14
    const-string v4, "invalid afterContentPadding"

    invoke-static {v4}, Llyiahf/vczjk/sz3;->OooO00o(Ljava/lang/String;)V

    goto :goto_12

    :goto_13
    sget-object v14, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    const-wide/16 v5, 0x0

    if-gtz v12, :cond_17

    invoke-static {v8, v9}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v21

    invoke-static {v8, v9}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v22

    new-instance v23, Ljava/util/ArrayList;

    invoke-direct/range {v23 .. v23}, Ljava/util/ArrayList;-><init>()V

    iget-object v4, v10, Llyiahf/vczjk/iv4;->OooO0Oo:Llyiahf/vczjk/uy5;

    const/16 v28, 0x1

    const/16 v20, 0x0

    const/16 v30, 0x0

    const/16 v31, 0x0

    move-object/from16 v24, v4

    invoke-virtual/range {v19 .. v33}, Landroidx/compose/foundation/lazy/layout/OooO0OO;->OooO0Oo(IIILjava/util/ArrayList;Llyiahf/vczjk/uy5;Llyiahf/vczjk/vt4;ZZIZIILlyiahf/vczjk/xr1;Llyiahf/vczjk/ij3;)V

    move-object/from16 v10, v25

    if-nez v27, :cond_15

    invoke-virtual/range {v19 .. v19}, Landroidx/compose/foundation/lazy/layout/OooO0OO;->OooO0O0()J

    move-result-wide v11

    invoke-static {v11, v12, v5, v6}, Llyiahf/vczjk/b24;->OooO00o(JJ)Z

    move-result v4

    if-nez v4, :cond_15

    shr-long v4, v11, v36

    long-to-int v4, v4

    invoke-static {v4, v8, v9}, Llyiahf/vczjk/uk1;->OooO0oO(IJ)I

    move-result v21

    and-long v4, v11, v34

    long-to-int v4, v4

    invoke-static {v4, v8, v9}, Llyiahf/vczjk/uk1;->OooO0o(IJ)I

    move-result v22

    :cond_15
    invoke-static/range {v21 .. v21}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static/range {v22 .. v22}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/mo2;->Oooo0:Llyiahf/vczjk/mo2;

    invoke-virtual {v2, v4, v5, v6}, Llyiahf/vczjk/mv4;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    move-object v7, v2

    check-cast v7, Llyiahf/vczjk/mf5;

    neg-int v15, v13

    add-int v16, v0, v39

    if-eqz v26, :cond_16

    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    :goto_14
    move-object/from16 v19, v0

    goto :goto_15

    :cond_16
    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    goto :goto_14

    :goto_15
    new-instance v2, Llyiahf/vczjk/sv4;

    const/4 v9, 0x0

    iget-wide v12, v10, Llyiahf/vczjk/uv4;->OooO0OO:J

    move-object v11, v3

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v8, 0x0

    const/16 v17, 0x0

    move-object/from16 v10, v32

    move/from16 v21, v38

    move/from16 v20, v39

    invoke-direct/range {v2 .. v21}, Llyiahf/vczjk/sv4;-><init>(Llyiahf/vczjk/tv4;IZFLlyiahf/vczjk/mf5;FZLlyiahf/vczjk/xr1;Llyiahf/vczjk/f62;JLjava/util/List;IIIZLlyiahf/vczjk/nf6;II)V

    goto/16 :goto_63

    :cond_17
    move-object/from16 v10, v25

    if-lt v15, v12, :cond_18

    add-int/lit8 v15, v12, -0x1

    const/16 v17, 0x0

    :cond_18
    invoke-static/range {v24 .. v24}, Ljava/lang/Math;->round(F)I

    move-result v7

    sub-int v17, v17, v7

    if-nez v15, :cond_19

    if-gez v17, :cond_19

    add-int v7, v7, v17

    const/16 v17, 0x0

    :cond_19
    move-object/from16 v23, v14

    new-instance v14, Llyiahf/vczjk/xx;

    invoke-direct {v14}, Llyiahf/vczjk/xx;-><init>()V

    move/from16 v25, v15

    neg-int v15, v13

    if-gez v38, :cond_1a

    move/from16 v28, v38

    goto :goto_16

    :cond_1a
    const/16 v28, 0x0

    :goto_16
    add-int v5, v15, v28

    add-int v17, v17, v5

    move/from16 v6, v17

    move-object/from16 v17, v2

    move v2, v6

    move-wide/from16 v44, v8

    const/4 v6, 0x0

    move v9, v7

    :goto_17
    iget-wide v7, v10, Llyiahf/vczjk/uv4;->OooO0OO:J

    if-gez v2, :cond_1b

    if-lez v25, :cond_1b

    move/from16 v28, v9

    add-int/lit8 v9, v25, -0x1

    invoke-virtual {v10, v9, v7, v8}, Llyiahf/vczjk/uv4;->OooO0O0(IJ)Llyiahf/vczjk/tv4;

    move-result-object v7

    const/4 v8, 0x0

    invoke-virtual {v14, v8, v7}, Llyiahf/vczjk/xx;->add(ILjava/lang/Object;)V

    iget v8, v7, Llyiahf/vczjk/tv4;->OooOOoo:I

    invoke-static {v6, v8}, Ljava/lang/Math;->max(II)I

    move-result v6

    iget v7, v7, Llyiahf/vczjk/tv4;->OooOOo:I

    add-int/2addr v2, v7

    move/from16 v25, v9

    move/from16 v9, v28

    goto :goto_17

    :cond_1b
    move/from16 v28, v9

    if-ge v2, v5, :cond_1c

    sub-int v2, v5, v2

    sub-int v2, v28, v2

    move v9, v2

    move v2, v5

    goto :goto_18

    :cond_1c
    move/from16 v9, v28

    :goto_18
    sub-int/2addr v2, v5

    move-object/from16 v46, v16

    add-int v16, v0, v39

    move/from16 v28, v6

    if-gez v16, :cond_1d

    const/4 v6, 0x0

    :goto_19
    move/from16 v47, v15

    goto :goto_1a

    :cond_1d
    move/from16 v6, v16

    goto :goto_19

    :goto_1a
    neg-int v15, v2

    move/from16 v48, v2

    move v2, v15

    move/from16 v49, v25

    const/4 v15, 0x0

    const/16 v31, 0x0

    :goto_1b
    iget v1, v14, Llyiahf/vczjk/xx;->OooOOOO:I

    if-ge v15, v1, :cond_1f

    if-lt v2, v6, :cond_1e

    invoke-virtual {v14, v15}, Llyiahf/vczjk/xx;->OooO0O0(I)Ljava/lang/Object;

    move/from16 v31, v41

    goto :goto_1b

    :cond_1e
    add-int/lit8 v49, v49, 0x1

    invoke-virtual {v14, v15}, Llyiahf/vczjk/xx;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/tv4;

    iget v1, v1, Llyiahf/vczjk/tv4;->OooOOo:I

    add-int/2addr v2, v1

    add-int/lit8 v15, v15, 0x1

    goto :goto_1b

    :cond_1f
    move/from16 v1, v28

    move/from16 v15, v49

    move/from16 v49, v31

    :goto_1c
    if-ge v15, v12, :cond_21

    if-lt v2, v6, :cond_20

    if-lez v2, :cond_20

    invoke-virtual {v14}, Llyiahf/vczjk/xx;->isEmpty()Z

    move-result v28

    if-eqz v28, :cond_21

    :cond_20
    move/from16 v28, v6

    goto :goto_1d

    :cond_21
    move-object/from16 v31, v3

    goto :goto_1f

    :goto_1d
    invoke-virtual {v10, v15, v7, v8}, Llyiahf/vczjk/uv4;->OooO0O0(IJ)Llyiahf/vczjk/tv4;

    move-result-object v6

    move-object/from16 v31, v3

    iget v3, v6, Llyiahf/vczjk/tv4;->OooOOo:I

    add-int/2addr v2, v3

    if-gt v2, v5, :cond_22

    move/from16 v50, v2

    add-int/lit8 v2, v12, -0x1

    if-eq v15, v2, :cond_23

    add-int/lit8 v2, v15, 0x1

    sub-int v48, v48, v3

    move/from16 v25, v2

    move/from16 v49, v41

    goto :goto_1e

    :cond_22
    move/from16 v50, v2

    :cond_23
    iget v2, v6, Llyiahf/vczjk/tv4;->OooOOoo:I

    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    move-result v1

    invoke-virtual {v14, v6}, Llyiahf/vczjk/xx;->addLast(Ljava/lang/Object;)V

    :goto_1e
    add-int/lit8 v15, v15, 0x1

    move/from16 v6, v28

    move-object/from16 v3, v31

    move/from16 v2, v50

    goto :goto_1c

    :goto_1f
    if-ge v2, v0, :cond_26

    sub-int v3, v0, v2

    sub-int v48, v48, v3

    add-int/2addr v2, v3

    move/from16 v5, v48

    :goto_20
    if-ge v5, v13, :cond_24

    if-lez v25, :cond_24

    add-int/lit8 v6, v25, -0x1

    move/from16 v28, v2

    invoke-virtual {v10, v6, v7, v8}, Llyiahf/vczjk/uv4;->OooO0O0(IJ)Llyiahf/vczjk/tv4;

    move-result-object v2

    move/from16 v50, v3

    const/4 v3, 0x0

    invoke-virtual {v14, v3, v2}, Llyiahf/vczjk/xx;->add(ILjava/lang/Object;)V

    iget v3, v2, Llyiahf/vczjk/tv4;->OooOOoo:I

    invoke-static {v1, v3}, Ljava/lang/Math;->max(II)I

    move-result v1

    iget v2, v2, Llyiahf/vczjk/tv4;->OooOOo:I

    add-int/2addr v5, v2

    move/from16 v25, v6

    move/from16 v2, v28

    move/from16 v3, v50

    goto :goto_20

    :cond_24
    move/from16 v28, v2

    move/from16 v50, v3

    add-int v3, v9, v50

    if-gez v5, :cond_25

    add-int/2addr v3, v5

    add-int v2, v28, v5

    move v5, v3

    move v3, v2

    const/4 v2, 0x0

    goto :goto_21

    :cond_25
    move v2, v5

    move v5, v3

    move/from16 v3, v28

    goto :goto_21

    :cond_26
    move v3, v2

    move v5, v9

    move/from16 v2, v48

    :goto_21
    invoke-static/range {v24 .. v24}, Ljava/lang/Math;->round(F)I

    move-result v6

    invoke-static {v6}, Ljava/lang/Integer;->signum(I)I

    move-result v6

    move/from16 v28, v1

    invoke-static {v5}, Ljava/lang/Integer;->signum(I)I

    move-result v1

    if-ne v6, v1, :cond_27

    invoke-static/range {v24 .. v24}, Ljava/lang/Math;->round(F)I

    move-result v1

    invoke-static {v1}, Ljava/lang/Math;->abs(I)I

    move-result v1

    invoke-static {v5}, Ljava/lang/Math;->abs(I)I

    move-result v6

    if-lt v1, v6, :cond_27

    int-to-float v1, v5

    goto :goto_22

    :cond_27
    move/from16 v1, v24

    :goto_22
    sub-float v24, v24, v1

    const/4 v6, 0x0

    if-eqz v27, :cond_28

    if-le v5, v9, :cond_28

    cmpg-float v48, v24, v6

    if-gtz v48, :cond_28

    sub-int/2addr v5, v9

    int-to-float v5, v5

    add-float v5, v5, v24

    move v9, v5

    goto :goto_23

    :cond_28
    move v9, v6

    :goto_23
    if-ltz v2, :cond_29

    goto :goto_24

    :cond_29
    const-string v5, "negative currentFirstItemScrollOffset"

    invoke-static {v5}, Llyiahf/vczjk/sz3;->OooO00o(Ljava/lang/String;)V

    :goto_24
    neg-int v5, v2

    invoke-virtual {v14}, Llyiahf/vczjk/xx;->first()Ljava/lang/Object;

    move-result-object v24

    check-cast v24, Llyiahf/vczjk/tv4;

    if-gtz v13, :cond_2a

    if-gez v38, :cond_2b

    :cond_2a
    move/from16 v48, v6

    goto :goto_25

    :cond_2b
    move/from16 v51, v2

    move/from16 v48, v6

    move-object/from16 v2, v24

    move/from16 v24, v5

    goto :goto_27

    :goto_25
    invoke-virtual {v14}, Llyiahf/vczjk/xx;->OooO00o()I

    move-result v6

    move-object/from16 v50, v24

    move/from16 v24, v5

    move v5, v2

    const/4 v2, 0x0

    :goto_26
    if-ge v2, v6, :cond_2c

    invoke-virtual {v14, v2}, Llyiahf/vczjk/xx;->get(I)Ljava/lang/Object;

    move-result-object v51

    move/from16 v52, v6

    move-object/from16 v6, v51

    check-cast v6, Llyiahf/vczjk/tv4;

    iget v6, v6, Llyiahf/vczjk/tv4;->OooOOo:I

    if-eqz v5, :cond_2c

    if-gt v6, v5, :cond_2c

    move/from16 v51, v5

    invoke-static {v14}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v5

    if-eq v2, v5, :cond_2d

    sub-int v5, v51, v6

    add-int/lit8 v2, v2, 0x1

    invoke-virtual {v14, v2}, Llyiahf/vczjk/xx;->get(I)Ljava/lang/Object;

    move-result-object v6

    move-object/from16 v50, v6

    check-cast v50, Llyiahf/vczjk/tv4;

    move/from16 v6, v52

    goto :goto_26

    :cond_2c
    move/from16 v51, v5

    :cond_2d
    move-object/from16 v2, v50

    :goto_27
    sub-int v5, v25, v22

    const/4 v6, 0x0

    invoke-static {v6, v5}, Ljava/lang/Math;->max(II)I

    move-result v5

    add-int/lit8 v6, v25, -0x1

    if-gt v5, v6, :cond_2f

    const/16 v25, 0x0

    :goto_28
    if-nez v25, :cond_2e

    new-instance v25, Ljava/util/ArrayList;

    invoke-direct/range {v25 .. v25}, Ljava/util/ArrayList;-><init>()V

    :cond_2e
    move/from16 v50, v9

    move/from16 v52, v13

    move-object/from16 v9, v25

    invoke-virtual {v10, v6, v7, v8}, Llyiahf/vczjk/uv4;->OooO0O0(IJ)Llyiahf/vczjk/tv4;

    move-result-object v13

    invoke-interface {v9, v13}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    if-eq v6, v5, :cond_30

    add-int/lit8 v6, v6, -0x1

    move-object/from16 v25, v9

    move/from16 v9, v50

    move/from16 v13, v52

    goto :goto_28

    :cond_2f
    move/from16 v50, v9

    move/from16 v52, v13

    const/4 v9, 0x0

    :cond_30
    invoke-interface/range {v30 .. v30}, Ljava/util/Collection;->size()I

    move-result v6

    const/4 v13, -0x1

    add-int/2addr v6, v13

    if-ltz v6, :cond_34

    :goto_29
    add-int/lit8 v25, v6, -0x1

    move-object/from16 v13, v30

    invoke-interface {v13, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/Number;

    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    move-result v6

    if-ge v6, v5, :cond_32

    if-nez v9, :cond_31

    new-instance v9, Ljava/util/ArrayList;

    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    :cond_31
    invoke-virtual {v10, v6, v7, v8}, Llyiahf/vczjk/uv4;->OooO0O0(IJ)Llyiahf/vczjk/tv4;

    move-result-object v6

    invoke-interface {v9, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :cond_32
    if-gez v25, :cond_33

    goto :goto_2a

    :cond_33
    move-object/from16 v30, v13

    move/from16 v6, v25

    const/4 v13, -0x1

    goto :goto_29

    :cond_34
    move-object/from16 v13, v30

    :goto_2a
    if-nez v9, :cond_35

    move-object/from16 v9, v23

    :cond_35
    invoke-interface {v9}, Ljava/util/Collection;->size()I

    move-result v5

    move/from16 v54, v15

    move/from16 v6, v28

    const/4 v15, 0x0

    :goto_2b
    if-ge v15, v5, :cond_36

    invoke-interface {v9, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v25

    move/from16 v28, v5

    move-object/from16 v5, v25

    check-cast v5, Llyiahf/vczjk/tv4;

    iget v5, v5, Llyiahf/vczjk/tv4;->OooOOoo:I

    invoke-static {v6, v5}, Ljava/lang/Math;->max(II)I

    move-result v6

    add-int/lit8 v15, v15, 0x1

    move/from16 v5, v28

    goto :goto_2b

    :cond_36
    invoke-static {v14}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/tv4;

    iget v5, v5, Llyiahf/vczjk/tv4;->OooO00o:I

    add-int v5, v5, v22

    add-int/lit8 v15, v12, -0x1

    invoke-static {v5, v15}, Ljava/lang/Math;->min(II)I

    move-result v5

    invoke-static {v14}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v22

    move/from16 v25, v6

    move-object/from16 v6, v22

    check-cast v6, Llyiahf/vczjk/tv4;

    iget v6, v6, Llyiahf/vczjk/tv4;->OooO00o:I

    add-int/lit8 v6, v6, 0x1

    if-gt v6, v5, :cond_38

    const/16 v22, 0x0

    :goto_2c
    if-nez v22, :cond_37

    new-instance v22, Ljava/util/ArrayList;

    invoke-direct/range {v22 .. v22}, Ljava/util/ArrayList;-><init>()V

    :cond_37
    move/from16 v55, v1

    move-object/from16 v1, v22

    move-object/from16 v22, v9

    invoke-virtual {v10, v6, v7, v8}, Llyiahf/vczjk/uv4;->OooO0O0(IJ)Llyiahf/vczjk/tv4;

    move-result-object v9

    invoke-interface {v1, v9}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    if-eq v6, v5, :cond_39

    add-int/lit8 v6, v6, 0x1

    move-object/from16 v9, v22

    move-object/from16 v22, v1

    move/from16 v1, v55

    goto :goto_2c

    :cond_38
    move/from16 v55, v1

    move-object/from16 v22, v9

    const/4 v1, 0x0

    :cond_39
    if-eqz v27, :cond_4d

    if-eqz v4, :cond_4d

    iget-object v6, v4, Llyiahf/vczjk/sv4;->OooOO0O:Ljava/lang/Object;

    invoke-interface {v6}, Ljava/util/Collection;->isEmpty()Z

    move-result v9

    if-nez v9, :cond_4d

    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v9

    add-int/lit8 v9, v9, -0x1

    move-object/from16 v28, v1

    :goto_2d
    const/4 v1, -0x1

    if-ge v1, v9, :cond_3c

    invoke-interface {v6, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v30

    check-cast v30, Llyiahf/vczjk/gv4;

    move-object/from16 v1, v30

    check-cast v1, Llyiahf/vczjk/tv4;

    iget v1, v1, Llyiahf/vczjk/tv4;->OooO00o:I

    if-le v1, v5, :cond_3b

    if-eqz v9, :cond_3a

    add-int/lit8 v1, v9, -0x1

    invoke-interface {v6, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/gv4;

    check-cast v1, Llyiahf/vczjk/tv4;

    iget v1, v1, Llyiahf/vczjk/tv4;->OooO00o:I

    if-gt v1, v5, :cond_3b

    :cond_3a
    invoke-interface {v6, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/gv4;

    goto :goto_2e

    :cond_3b
    add-int/lit8 v9, v9, -0x1

    goto :goto_2d

    :cond_3c
    const/4 v1, 0x0

    :goto_2e
    invoke-static {v6}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/gv4;

    if-eqz v1, :cond_42

    check-cast v1, Llyiahf/vczjk/tv4;

    move-object v9, v6

    check-cast v9, Llyiahf/vczjk/tv4;

    iget v9, v9, Llyiahf/vczjk/tv4;->OooO00o:I

    invoke-static {v9, v15}, Ljava/lang/Math;->min(II)I

    move-result v9

    iget v1, v1, Llyiahf/vczjk/tv4;->OooO00o:I

    if-gt v1, v9, :cond_42

    move v15, v1

    move-object/from16 v1, v28

    :goto_2f
    if-eqz v1, :cond_3f

    move-object/from16 v30, v6

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v6

    move-object/from16 v53, v11

    const/4 v11, 0x0

    :goto_30
    if-ge v11, v6, :cond_3e

    invoke-interface {v1, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v28

    move-object/from16 v56, v1

    move-object/from16 v1, v28

    check-cast v1, Llyiahf/vczjk/tv4;

    iget v1, v1, Llyiahf/vczjk/tv4;->OooO00o:I

    if-ne v1, v15, :cond_3d

    goto :goto_31

    :cond_3d
    add-int/lit8 v11, v11, 0x1

    move-object/from16 v1, v56

    goto :goto_30

    :cond_3e
    move-object/from16 v56, v1

    const/16 v28, 0x0

    :goto_31
    check-cast v28, Llyiahf/vczjk/tv4;

    goto :goto_32

    :cond_3f
    move-object/from16 v56, v1

    move-object/from16 v30, v6

    move-object/from16 v53, v11

    const/16 v28, 0x0

    :goto_32
    if-nez v28, :cond_41

    if-nez v56, :cond_40

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    goto :goto_33

    :cond_40
    move-object/from16 v1, v56

    :goto_33
    invoke-virtual {v10, v15, v7, v8}, Llyiahf/vczjk/uv4;->OooO0O0(IJ)Llyiahf/vczjk/tv4;

    move-result-object v6

    invoke-interface {v1, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_34

    :cond_41
    move-object/from16 v1, v56

    :goto_34
    if-eq v15, v9, :cond_43

    add-int/lit8 v15, v15, 0x1

    move-object/from16 v6, v30

    move-object/from16 v11, v53

    goto :goto_2f

    :cond_42
    move-object/from16 v30, v6

    move-object/from16 v53, v11

    move-object/from16 v1, v28

    :cond_43
    move-object/from16 v6, v30

    check-cast v6, Llyiahf/vczjk/tv4;

    iget v9, v6, Llyiahf/vczjk/tv4;->OooOOOo:I

    iget v4, v4, Llyiahf/vczjk/sv4;->OooOOO0:I

    sub-int/2addr v4, v9

    iget v9, v6, Llyiahf/vczjk/tv4;->OooOOo0:I

    sub-int/2addr v4, v9

    int-to-float v4, v4

    sub-float v4, v4, v55

    cmpl-float v9, v4, v48

    if-lez v9, :cond_4e

    iget v6, v6, Llyiahf/vczjk/tv4;->OooO00o:I

    add-int/lit8 v6, v6, 0x1

    move v9, v6

    const/4 v6, 0x0

    :goto_35
    if-ge v9, v12, :cond_4c

    int-to-float v11, v6

    cmpg-float v11, v11, v4

    if-gez v11, :cond_4c

    if-gt v9, v5, :cond_46

    invoke-virtual {v14}, Llyiahf/vczjk/xx;->OooO00o()I

    move-result v11

    const/4 v15, 0x0

    :goto_36
    if-ge v15, v11, :cond_45

    invoke-virtual {v14, v15}, Llyiahf/vczjk/xx;->get(I)Ljava/lang/Object;

    move-result-object v28

    move/from16 v30, v4

    move-object/from16 v4, v28

    check-cast v4, Llyiahf/vczjk/tv4;

    iget v4, v4, Llyiahf/vczjk/tv4;->OooO00o:I

    if-ne v4, v9, :cond_44

    goto :goto_37

    :cond_44
    add-int/lit8 v15, v15, 0x1

    move/from16 v4, v30

    goto :goto_36

    :cond_45
    move/from16 v30, v4

    const/16 v28, 0x0

    :goto_37
    check-cast v28, Llyiahf/vczjk/tv4;

    move-object/from16 v57, v28

    move-object/from16 v28, v1

    move-object/from16 v1, v57

    goto :goto_3a

    :cond_46
    move/from16 v30, v4

    if-eqz v1, :cond_49

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v4

    const/4 v11, 0x0

    :goto_38
    if-ge v11, v4, :cond_48

    invoke-interface {v1, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v15

    move-object/from16 v28, v1

    move-object v1, v15

    check-cast v1, Llyiahf/vczjk/tv4;

    iget v1, v1, Llyiahf/vczjk/tv4;->OooO00o:I

    if-ne v1, v9, :cond_47

    goto :goto_39

    :cond_47
    add-int/lit8 v11, v11, 0x1

    move-object/from16 v1, v28

    goto :goto_38

    :cond_48
    move-object/from16 v28, v1

    const/4 v15, 0x0

    :goto_39
    move-object v1, v15

    check-cast v1, Llyiahf/vczjk/tv4;

    goto :goto_3a

    :cond_49
    move-object/from16 v28, v1

    const/4 v1, 0x0

    :goto_3a
    if-eqz v1, :cond_4a

    add-int/lit8 v9, v9, 0x1

    iget v1, v1, Llyiahf/vczjk/tv4;->OooOOo:I

    add-int/2addr v6, v1

    move-object/from16 v1, v28

    :goto_3b
    move/from16 v4, v30

    goto :goto_35

    :cond_4a
    if-nez v28, :cond_4b

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    goto :goto_3c

    :cond_4b
    move-object/from16 v1, v28

    :goto_3c
    invoke-virtual {v10, v9, v7, v8}, Llyiahf/vczjk/uv4;->OooO0O0(IJ)Llyiahf/vczjk/tv4;

    move-result-object v4

    invoke-interface {v1, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    add-int/lit8 v9, v9, 0x1

    invoke-static {v1}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/tv4;

    iget v4, v4, Llyiahf/vczjk/tv4;->OooOOo:I

    add-int/2addr v6, v4

    goto :goto_3b

    :cond_4c
    move-object/from16 v28, v1

    :goto_3d
    move-object/from16 v1, v28

    goto :goto_3e

    :cond_4d
    move-object/from16 v28, v1

    move-object/from16 v53, v11

    goto :goto_3d

    :cond_4e
    :goto_3e
    if-eqz v1, :cond_4f

    invoke-static {v1}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/tv4;

    iget v4, v4, Llyiahf/vczjk/tv4;->OooO00o:I

    if-le v4, v5, :cond_4f

    invoke-static {v1}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/tv4;

    iget v5, v4, Llyiahf/vczjk/tv4;->OooO00o:I

    :cond_4f
    invoke-interface {v13}, Ljava/util/Collection;->size()I

    move-result v4

    move-object v6, v1

    const/4 v1, 0x0

    :goto_3f
    if-ge v1, v4, :cond_52

    invoke-interface {v13, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Number;

    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    move-result v9

    if-le v9, v5, :cond_51

    if-nez v6, :cond_50

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    :cond_50
    invoke-virtual {v10, v9, v7, v8}, Llyiahf/vczjk/uv4;->OooO0O0(IJ)Llyiahf/vczjk/tv4;

    move-result-object v9

    invoke-interface {v6, v9}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :cond_51
    add-int/lit8 v1, v1, 0x1

    goto :goto_3f

    :cond_52
    if-nez v6, :cond_53

    move-object/from16 v6, v23

    :cond_53
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    move-result v1

    move/from16 v5, v25

    const/4 v4, 0x0

    :goto_40
    if-ge v4, v1, :cond_54

    invoke-interface {v6, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/tv4;

    iget v7, v7, Llyiahf/vczjk/tv4;->OooOOoo:I

    invoke-static {v5, v7}, Ljava/lang/Math;->max(II)I

    move-result v5

    add-int/lit8 v4, v4, 0x1

    goto :goto_40

    :cond_54
    invoke-virtual {v14}, Llyiahf/vczjk/xx;->first()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_55

    invoke-interface/range {v22 .. v22}, Ljava/util/List;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_55

    invoke-interface {v6}, Ljava/util/List;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_55

    move/from16 v1, v41

    goto :goto_41

    :cond_55
    const/4 v1, 0x0

    :goto_41
    if-eqz v26, :cond_56

    move v4, v5

    :goto_42
    move-wide/from16 v8, v44

    goto :goto_43

    :cond_56
    move v4, v3

    goto :goto_42

    :goto_43
    invoke-static {v4, v8, v9}, Llyiahf/vczjk/uk1;->OooO0oO(IJ)I

    move-result v11

    if-eqz v26, :cond_57

    move v5, v3

    :cond_57
    invoke-static {v5, v8, v9}, Llyiahf/vczjk/uk1;->OooO0o(IJ)I

    move-result v13

    if-eqz v26, :cond_58

    move v4, v13

    goto :goto_44

    :cond_58
    move v4, v11

    :goto_44
    invoke-static {v4, v0}, Ljava/lang/Math;->min(II)I

    move-result v5

    if-ge v3, v5, :cond_59

    move/from16 v5, v41

    goto :goto_45

    :cond_59
    const/4 v5, 0x0

    :goto_45
    if-eqz v5, :cond_5b

    if-nez v24, :cond_5a

    goto :goto_46

    :cond_5a
    const-string v7, "non-zero itemsScrollOffset"

    invoke-static {v7}, Llyiahf/vczjk/sz3;->OooO0OO(Ljava/lang/String;)V

    :cond_5b
    :goto_46
    new-instance v15, Ljava/util/ArrayList;

    invoke-virtual {v14}, Llyiahf/vczjk/xx;->OooO00o()I

    move-result v7

    invoke-interface/range {v22 .. v22}, Ljava/util/List;->size()I

    move-result v23

    add-int v23, v23, v7

    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v7

    add-int v7, v7, v23

    invoke-direct {v15, v7}, Ljava/util/ArrayList;-><init>(I)V

    if-eqz v5, :cond_68

    invoke-interface/range {v22 .. v22}, Ljava/util/List;->isEmpty()Z

    move-result v5

    if-eqz v5, :cond_5c

    invoke-interface {v6}, Ljava/util/List;->isEmpty()Z

    move-result v5

    if-eqz v5, :cond_5c

    goto :goto_47

    :cond_5c
    const-string v5, "no extra items"

    invoke-static {v5}, Llyiahf/vczjk/sz3;->OooO00o(Ljava/lang/String;)V

    :goto_47
    invoke-virtual {v14}, Llyiahf/vczjk/xx;->OooO00o()I

    move-result v5

    new-array v6, v5, [I

    const/4 v7, 0x0

    :goto_48
    if-ge v7, v5, :cond_5e

    if-nez v18, :cond_5d

    move/from16 v44, v1

    move v1, v7

    goto :goto_49

    :cond_5d
    sub-int v22, v5, v7

    add-int/lit8 v22, v22, -0x1

    move/from16 v44, v1

    move/from16 v1, v22

    :goto_49
    invoke-virtual {v14, v1}, Llyiahf/vczjk/xx;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/tv4;

    iget v1, v1, Llyiahf/vczjk/tv4;->OooOOo0:I

    aput v1, v6, v7

    add-int/lit8 v7, v7, 0x1

    move/from16 v1, v44

    goto :goto_48

    :cond_5e
    move/from16 v44, v1

    new-array v7, v5, [I

    if-eqz v26, :cond_60

    if-eqz v53, :cond_5f

    move-object/from16 v23, v2

    move-object/from16 v1, v31

    move-object/from16 v2, v53

    invoke-interface {v2, v1, v4, v6, v7}, Llyiahf/vczjk/px;->OooO(Llyiahf/vczjk/f62;I[I[I)V

    move/from16 v31, v3

    move/from16 v20, v5

    move-object/from16 v42, v17

    move-object/from16 v43, v23

    move/from16 v17, v0

    move-object v3, v1

    const-wide/16 v0, 0x0

    goto :goto_4a

    :cond_5f
    invoke-static/range {v21 .. v21}, Llyiahf/vczjk/sz3;->OooO0O0(Ljava/lang/String;)Ljava/lang/Void;

    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :cond_60
    move-object/from16 v23, v2

    move-object/from16 v1, v31

    if-eqz v20, :cond_67

    move v2, v5

    move-object v5, v6

    sget-object v6, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    move-object/from16 v31, v20

    move/from16 v20, v2

    move-object/from16 v2, v31

    move/from16 v31, v3

    move-object/from16 v42, v17

    move-object/from16 v43, v23

    move/from16 v17, v0

    move-object v3, v1

    const-wide/16 v0, 0x0

    invoke-interface/range {v2 .. v7}, Llyiahf/vczjk/nx;->OooO0o0(Llyiahf/vczjk/f62;I[ILlyiahf/vczjk/yn4;[I)V

    :goto_4a
    invoke-static {v7}, Llyiahf/vczjk/sy;->o000000([I)Llyiahf/vczjk/x14;

    move-result-object v2

    if-nez v18, :cond_61

    goto :goto_4b

    :cond_61
    invoke-static {v2}, Llyiahf/vczjk/vt6;->Oooo000(Llyiahf/vczjk/x14;)Llyiahf/vczjk/v14;

    move-result-object v2

    :goto_4b
    iget v5, v2, Llyiahf/vczjk/v14;->OooOOO0:I

    iget v6, v2, Llyiahf/vczjk/v14;->OooOOO:I

    iget v2, v2, Llyiahf/vczjk/v14;->OooOOOO:I

    if-lez v2, :cond_62

    if-le v5, v6, :cond_63

    :cond_62
    if-gez v2, :cond_66

    if-gt v6, v5, :cond_66

    :cond_63
    :goto_4c
    aget v21, v7, v5

    if-nez v18, :cond_64

    move v0, v5

    goto :goto_4d

    :cond_64
    sub-int v22, v20, v5

    add-int/lit8 v22, v22, -0x1

    move/from16 v0, v22

    :goto_4d
    invoke-virtual {v14, v0}, Llyiahf/vczjk/xx;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/tv4;

    if-eqz v18, :cond_65

    sub-int v1, v4, v21

    move/from16 v21, v1

    iget v1, v0, Llyiahf/vczjk/tv4;->OooOOo0:I

    sub-int v21, v21, v1

    :cond_65
    move/from16 v1, v21

    invoke-virtual {v0, v1, v11, v13}, Llyiahf/vczjk/tv4;->OooOOO0(III)V

    invoke-virtual {v15, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    if-eq v5, v6, :cond_66

    add-int/2addr v5, v2

    const-wide/16 v0, 0x0

    goto :goto_4c

    :cond_66
    move/from16 v6, v55

    goto/16 :goto_51

    :cond_67
    const-string v0, "null horizontalArrangement when isVertical == false"

    invoke-static {v0}, Llyiahf/vczjk/sz3;->OooO0O0(Ljava/lang/String;)Ljava/lang/Void;

    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :cond_68
    move-object/from16 v42, v31

    move/from16 v31, v3

    move-object/from16 v3, v42

    move/from16 v44, v1

    move-object/from16 v43, v2

    move-object/from16 v42, v17

    move/from16 v17, v0

    invoke-interface/range {v22 .. v22}, Ljava/util/Collection;->size()I

    move-result v0

    move/from16 v1, v24

    const/4 v2, 0x0

    :goto_4e
    if-ge v2, v0, :cond_69

    move-object/from16 v4, v22

    invoke-interface {v4, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/tv4;

    iget v7, v5, Llyiahf/vczjk/tv4;->OooOOo:I

    sub-int/2addr v1, v7

    invoke-virtual {v5, v1, v11, v13}, Llyiahf/vczjk/tv4;->OooOOO0(III)V

    invoke-virtual {v15, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v2, v2, 0x1

    move-object/from16 v22, v4

    goto :goto_4e

    :cond_69
    invoke-virtual {v14}, Llyiahf/vczjk/xx;->OooO00o()I

    move-result v0

    move/from16 v5, v24

    const/4 v2, 0x0

    :goto_4f
    if-ge v2, v0, :cond_6a

    invoke-virtual {v14, v2}, Llyiahf/vczjk/xx;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/tv4;

    invoke-virtual {v1, v5, v11, v13}, Llyiahf/vczjk/tv4;->OooOOO0(III)V

    invoke-virtual {v15, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget v1, v1, Llyiahf/vczjk/tv4;->OooOOo:I

    add-int/2addr v5, v1

    add-int/lit8 v2, v2, 0x1

    goto :goto_4f

    :cond_6a
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    move-result v0

    const/4 v2, 0x0

    :goto_50
    if-ge v2, v0, :cond_66

    invoke-interface {v6, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/tv4;

    invoke-virtual {v1, v5, v11, v13}, Llyiahf/vczjk/tv4;->OooOOO0(III)V

    invoke-virtual {v15, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget v1, v1, Llyiahf/vczjk/tv4;->OooOOo:I

    add-int/2addr v5, v1

    add-int/lit8 v2, v2, 0x1

    goto :goto_50

    :goto_51
    float-to-int v0, v6

    iget-object v1, v10, Llyiahf/vczjk/uv4;->OooO00o:Llyiahf/vczjk/iv4;

    iget-object v2, v1, Llyiahf/vczjk/iv4;->OooO0Oo:Llyiahf/vczjk/uy5;

    const/16 v28, 0x1

    move/from16 v20, v0

    move-object/from16 v24, v2

    move-object/from16 v25, v10

    move/from16 v21, v11

    move/from16 v22, v13

    move-object/from16 v23, v15

    move/from16 v30, v51

    invoke-virtual/range {v19 .. v33}, Landroidx/compose/foundation/lazy/layout/OooO0OO;->OooO0Oo(IIILjava/util/ArrayList;Llyiahf/vczjk/uy5;Llyiahf/vczjk/vt4;ZZIZIILlyiahf/vczjk/xr1;Llyiahf/vczjk/ij3;)V

    move/from16 v0, v22

    move-object/from16 v7, v23

    move-object/from16 v2, v25

    move/from16 v4, v27

    move/from16 v5, v31

    if-nez v4, :cond_6e

    move-object v10, v14

    invoke-virtual/range {v19 .. v19}, Landroidx/compose/foundation/lazy/layout/OooO0OO;->OooO0O0()J

    move-result-wide v13

    move-object/from16 v31, v3

    move/from16 v27, v4

    const-wide/16 v3, 0x0

    invoke-static {v13, v14, v3, v4}, Llyiahf/vczjk/b24;->OooO00o(JJ)Z

    move-result v3

    if-nez v3, :cond_6f

    if-eqz v26, :cond_6b

    move v3, v0

    :goto_52
    move-wide/from16 v19, v13

    goto :goto_53

    :cond_6b
    move v3, v11

    goto :goto_52

    :goto_53
    shr-long v13, v19, v36

    long-to-int v4, v13

    invoke-static {v11, v4}, Ljava/lang/Math;->max(II)I

    move-result v4

    invoke-static {v4, v8, v9}, Llyiahf/vczjk/uk1;->OooO0oO(IJ)I

    move-result v11

    and-long v13, v19, v34

    long-to-int v4, v13

    invoke-static {v0, v4}, Ljava/lang/Math;->max(II)I

    move-result v0

    invoke-static {v0, v8, v9}, Llyiahf/vczjk/uk1;->OooO0o(IJ)I

    move-result v13

    if-eqz v26, :cond_6c

    move v0, v13

    goto :goto_54

    :cond_6c
    move v0, v11

    :goto_54
    if-eq v0, v3, :cond_6d

    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    move-result v3

    const/4 v4, 0x0

    :goto_55
    if-ge v4, v3, :cond_6d

    invoke-virtual {v7, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/tv4;

    iput v0, v8, Llyiahf/vczjk/tv4;->OooOo0:I

    iget v9, v8, Llyiahf/vczjk/tv4;->OooO:I

    add-int/2addr v9, v0

    iput v9, v8, Llyiahf/vczjk/tv4;->OooOo0o:I

    add-int/lit8 v4, v4, 0x1

    goto :goto_55

    :cond_6d
    move/from16 v24, v13

    :goto_56
    move/from16 v23, v11

    goto :goto_57

    :cond_6e
    move-object/from16 v31, v3

    move/from16 v27, v4

    move-object v10, v14

    :cond_6f
    move/from16 v24, v0

    goto :goto_56

    :goto_57
    iget-object v0, v1, Llyiahf/vczjk/iv4;->OooO0O0:Llyiahf/vczjk/fv4;

    iget-object v0, v0, Llyiahf/vczjk/fv4;->OooO0O0:Llyiahf/vczjk/nr5;

    if-eqz v0, :cond_70

    :goto_58
    move-object/from16 v21, v0

    goto :goto_59

    :cond_70
    sget-object v0, Llyiahf/vczjk/p14;->OooO00o:Llyiahf/vczjk/nr5;

    goto :goto_58

    :goto_59
    new-instance v0, Llyiahf/vczjk/rv4;

    invoke-direct {v0, v2}, Llyiahf/vczjk/rv4;-><init>(Llyiahf/vczjk/nv4;)V

    move-object/from16 v25, v0

    move-object/from16 v20, v7

    move-object/from16 v19, v46

    move/from16 v22, v52

    invoke-static/range {v19 .. v25}, Llyiahf/vczjk/zsa;->OooOoO0(Llyiahf/vczjk/q59;Ljava/util/ArrayList;Llyiahf/vczjk/nr5;IIILlyiahf/vczjk/oe3;)Ljava/util/List;

    move-result-object v0

    if-eqz v44, :cond_72

    invoke-static {v7}, Llyiahf/vczjk/d21;->oo000o(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/tv4;

    if-eqz v1, :cond_71

    iget v1, v1, Llyiahf/vczjk/tv4;->OooO00o:I

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    goto :goto_5a

    :cond_71
    const/4 v1, 0x0

    goto :goto_5a

    :cond_72
    invoke-virtual {v10}, Llyiahf/vczjk/xx;->OooO()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/tv4;

    if-eqz v1, :cond_71

    iget v1, v1, Llyiahf/vczjk/tv4;->OooO00o:I

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    :goto_5a
    if-eqz v44, :cond_74

    invoke-static {v7}, Llyiahf/vczjk/d21;->o0OO00O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/tv4;

    if-eqz v3, :cond_73

    iget v3, v3, Llyiahf/vczjk/tv4;->OooO00o:I

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v15

    :goto_5b
    move/from16 v3, v54

    goto :goto_5c

    :cond_73
    move/from16 v3, v54

    const/4 v15, 0x0

    goto :goto_5c

    :cond_74
    invoke-virtual {v10}, Llyiahf/vczjk/xx;->OooOO0O()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/tv4;

    if-eqz v3, :cond_73

    iget v3, v3, Llyiahf/vczjk/tv4;->OooO00o:I

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v15

    goto :goto_5b

    :goto_5c
    if-lt v3, v12, :cond_76

    move/from16 v9, v17

    if-le v5, v9, :cond_75

    goto :goto_5d

    :cond_75
    const/4 v5, 0x0

    goto :goto_5e

    :cond_76
    :goto_5d
    move/from16 v5, v41

    :goto_5e
    invoke-static/range {v23 .. v23}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static/range {v24 .. v24}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    new-instance v8, Llyiahf/vczjk/qv4;

    move-object/from16 v9, v40

    iget-object v9, v9, Llyiahf/vczjk/dw4;->OooOo0:Llyiahf/vczjk/qs5;

    move/from16 v10, v27

    invoke-direct {v8, v9, v7, v0, v10}, Llyiahf/vczjk/qv4;-><init>(Llyiahf/vczjk/qs5;Ljava/util/ArrayList;Ljava/util/List;Z)V

    move-object/from16 v9, v42

    invoke-virtual {v9, v3, v4, v8}, Llyiahf/vczjk/mv4;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/mf5;

    if-eqz v1, :cond_77

    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result v1

    goto :goto_5f

    :cond_77
    const/4 v1, 0x0

    :goto_5f
    if-eqz v15, :cond_78

    invoke-virtual {v15}, Ljava/lang/Integer;->intValue()I

    move-result v4

    goto :goto_60

    :cond_78
    const/4 v4, 0x0

    :goto_60
    invoke-static {v1, v4, v7, v0}, Llyiahf/vczjk/c6a;->o0Oo0oo(IILjava/util/ArrayList;Ljava/util/List;)Ljava/util/List;

    move-result-object v14

    if-eqz v26, :cond_79

    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    :goto_61
    move-object/from16 v19, v0

    goto :goto_62

    :cond_79
    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    goto :goto_61

    :goto_62
    new-instance v0, Llyiahf/vczjk/sv4;

    iget-wide v1, v2, Llyiahf/vczjk/uv4;->OooO0OO:J

    move-object v7, v3

    move/from16 v17, v12

    move/from16 v4, v30

    move-object/from16 v11, v31

    move-object/from16 v10, v32

    move/from16 v21, v38

    move/from16 v20, v39

    move-object/from16 v3, v43

    move/from16 v15, v47

    move/from16 v9, v49

    move/from16 v8, v50

    move-wide v12, v1

    move-object v2, v0

    invoke-direct/range {v2 .. v21}, Llyiahf/vczjk/sv4;-><init>(Llyiahf/vczjk/tv4;IZFLlyiahf/vczjk/mf5;FZLlyiahf/vczjk/xr1;Llyiahf/vczjk/f62;JLjava/util/List;IIIZLlyiahf/vczjk/nf6;II)V

    move-object/from16 v1, p0

    :goto_63
    iget-object v0, v1, Llyiahf/vczjk/ov4;->$state:Llyiahf/vczjk/dw4;

    invoke-interface/range {v37 .. v37}, Llyiahf/vczjk/o34;->OoooOo0()Z

    move-result v3

    const/4 v6, 0x0

    invoke-virtual {v0, v2, v3, v6}, Llyiahf/vczjk/dw4;->OooO0o(Llyiahf/vczjk/sv4;ZZ)V

    return-object v2

    :goto_64
    invoke-static {v4, v6, v5}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    throw v0

    :cond_7a
    const-string v0, "null horizontalAlignment when isVertical == false"

    invoke-static {v0}, Llyiahf/vczjk/sz3;->OooO0O0(Ljava/lang/String;)Ljava/lang/Void;

    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0
.end method
