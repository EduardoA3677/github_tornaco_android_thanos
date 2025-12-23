.class public final Llyiahf/vczjk/b6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/b6;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/b6;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/b6;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/qr5;)V
    .locals 1

    const/16 v0, 0x1a

    iput v0, p0, Llyiahf/vczjk/b6;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/b6;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/b6;->OooOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 71

    move-object/from16 v0, p0

    const-string v1, "app"

    const/16 v3, 0x14

    const/16 v4, 0x30

    const/4 v5, 0x4

    const v6, -0x615d173a

    sget-object v7, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const v8, 0x4c5de2

    const/4 v9, 0x1

    sget-object v10, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/4 v11, 0x0

    sget-object v13, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v14, v0, Llyiahf/vczjk/b6;->OooOOOO:Ljava/lang/Object;

    iget-object v15, v0, Llyiahf/vczjk/b6;->OooOOO:Ljava/lang/Object;

    const/16 v16, 0x3

    const/4 v12, 0x2

    iget v2, v0, Llyiahf/vczjk/b6;->OooOOO0:I

    packed-switch v2, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    sget-object v18, Llyiahf/vczjk/ob1;->OooO0OO:Llyiahf/vczjk/a91;

    sget-object v19, Llyiahf/vczjk/ob1;->OooO0Oo:Llyiahf/vczjk/a91;

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v15, Llyiahf/vczjk/qs5;

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    check-cast v14, Llyiahf/vczjk/a77;

    invoke-virtual {v1, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_2

    if-ne v3, v10, :cond_3

    :cond_2
    new-instance v3, Llyiahf/vczjk/a67;

    invoke-direct {v3, v14, v15}, Llyiahf/vczjk/a67;-><init>(Llyiahf/vczjk/a77;Llyiahf/vczjk/qs5;)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    move-object/from16 v20, v3

    check-cast v20, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v17, 0x0

    const/16 v22, 0xdb0

    const/16 v16, 0x0

    move-object/from16 v21, v1

    invoke-static/range {v16 .. v22}, Llyiahf/vczjk/wt2;->OooO00o(Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    :goto_1
    return-object v13

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_5

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_4

    goto :goto_2

    :cond_4
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3

    :cond_5
    :goto_2
    sget-object v18, Llyiahf/vczjk/bb1;->OooO0OO:Llyiahf/vczjk/a91;

    sget-object v19, Llyiahf/vczjk/bb1;->OooO0Oo:Llyiahf/vczjk/a91;

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v15, Llyiahf/vczjk/ld9;

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    check-cast v14, Lgithub/tornaco/thanos/android/module/profile/engine/NewRegularIntervalActivity;

    invoke-virtual {v1, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v2, v4

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v2, :cond_6

    if-ne v4, v10, :cond_7

    :cond_6
    new-instance v4, Llyiahf/vczjk/oo0oO0;

    invoke-direct {v4, v3, v15, v14}, Llyiahf/vczjk/oo0oO0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    move-object/from16 v20, v4

    check-cast v20, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v17, 0x1

    const/16 v22, 0xdb0

    const/16 v16, 0x0

    move-object/from16 v21, v1

    invoke-static/range {v16 .. v22}, Llyiahf/vczjk/wt2;->OooO00o(Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    :goto_3
    return-object v13

    :pswitch_1
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v3, v2, 0x3

    if-eq v3, v12, :cond_8

    move v3, v9

    goto :goto_4

    :cond_8
    move v3, v11

    :goto_4
    and-int/2addr v2, v9

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_b

    const-string v2, "indicator"

    invoke-static {v7, v2}, Landroidx/compose/ui/layout/OooO00o;->OooO0OO(Llyiahf/vczjk/kl5;Ljava/lang/Object;)Llyiahf/vczjk/kl5;

    move-result-object v2

    check-cast v15, Llyiahf/vczjk/p29;

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_9

    if-ne v4, v10, :cond_a

    :cond_9
    new-instance v4, Llyiahf/vczjk/fl0;

    invoke-direct {v4, v15, v12}, Llyiahf/vczjk/fl0;-><init>(Llyiahf/vczjk/p29;I)V

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    check-cast v4, Llyiahf/vczjk/oe3;

    invoke-static {v2, v4}, Landroidx/compose/ui/graphics/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v2

    check-cast v14, Llyiahf/vczjk/yw5;

    iget-wide v3, v14, Llyiahf/vczjk/yw5;->OooO0OO:J

    sget-object v5, Llyiahf/vczjk/px5;->OooO0Oo:Llyiahf/vczjk/dk8;

    invoke-static {v5, v1}, Llyiahf/vczjk/cl8;->OooO0O0(Llyiahf/vczjk/dk8;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qj8;

    move-result-object v5

    invoke-static {v2, v3, v4, v5}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v2, v1, v11}, Llyiahf/vczjk/ch0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/rf1;I)V

    goto :goto_5

    :cond_b
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_5
    return-object v13

    :pswitch_2
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_d

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_c

    goto :goto_6

    :cond_c
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_8

    :cond_d
    :goto_6
    const/16 v2, 0x40

    int-to-float v2, v2

    const/4 v3, 0x0

    invoke-static {v7, v2, v3, v12}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOo(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v17

    check-cast v15, Llyiahf/vczjk/qr5;

    move-object v2, v15

    check-cast v2, Llyiahf/vczjk/bw8;

    invoke-virtual {v2}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v2

    if-gtz v2, :cond_e

    move/from16 v18, v9

    goto :goto_7

    :cond_e
    move/from16 v18, v11

    :goto_7
    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v14, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_f

    if-ne v3, v10, :cond_10

    :cond_f
    new-instance v3, Llyiahf/vczjk/ok5;

    const/16 v2, 0xb

    invoke-direct {v3, v2, v14}, Llyiahf/vczjk/ok5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_10
    move-object/from16 v16, v3

    check-cast v16, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v2, Llyiahf/vczjk/jw5;

    invoke-direct {v2, v15, v11}, Llyiahf/vczjk/jw5;-><init>(Llyiahf/vczjk/qr5;I)V

    const v3, -0x5fb65b93

    invoke-static {v3, v2, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v22

    const v24, 0x30000030

    const/16 v25, 0x1f8

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    move-object/from16 v23, v1

    invoke-static/range {v16 .. v25}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_8
    return-object v13

    :pswitch_3
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_12

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_11

    goto :goto_9

    :cond_11
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_a

    :cond_12
    :goto_9
    check-cast v15, Llyiahf/vczjk/ku5;

    iget-object v2, v15, Llyiahf/vczjk/ku5;->OooOOO:Llyiahf/vczjk/av5;

    const-string v3, "null cannot be cast to non-null type androidx.navigation.compose.ComposeNavigator.Destination"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Llyiahf/vczjk/zd1;

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    iget-object v2, v2, Llyiahf/vczjk/zd1;->OooOOo:Llyiahf/vczjk/a91;

    check-cast v14, Llyiahf/vczjk/kj;

    invoke-virtual {v2, v14, v15, v1, v3}, Llyiahf/vczjk/a91;->OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :goto_a
    return-object v13

    :pswitch_4
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_14

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_13

    goto :goto_b

    :cond_13
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_c

    :cond_14
    :goto_b
    check-cast v14, Llyiahf/vczjk/a91;

    check-cast v15, Llyiahf/vczjk/r58;

    invoke-static {v15, v14, v1, v11}, Llyiahf/vczjk/nqa;->OooO(Llyiahf/vczjk/r58;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    :goto_c
    return-object v13

    :pswitch_5
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v3, v2, 0x3

    if-eq v3, v12, :cond_15

    move v3, v9

    goto :goto_d

    :cond_15
    move v3, v11

    :goto_d
    and-int/2addr v2, v9

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_16

    check-cast v15, Llyiahf/vczjk/n6a;

    iget-object v2, v15, Llyiahf/vczjk/n6a;->OooOO0:Llyiahf/vczjk/rn9;

    check-cast v14, Llyiahf/vczjk/a91;

    invoke-static {v2, v14, v1, v11}, Llyiahf/vczjk/gm9;->OooO00o(Llyiahf/vczjk/rn9;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    goto :goto_e

    :cond_16
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_e
    return-object v13

    :pswitch_6
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_18

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_17

    goto :goto_f

    :cond_17
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_10

    :cond_18
    :goto_f
    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v15, Llyiahf/vczjk/ua5;

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_19

    if-ne v3, v10, :cond_1a

    :cond_19
    new-instance v3, Llyiahf/vczjk/fz3;

    const/4 v2, 0x7

    invoke-direct {v3, v15, v2}, Llyiahf/vczjk/fz3;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1a
    move-object/from16 v16, v3

    check-cast v16, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v2, Llyiahf/vczjk/ou;

    check-cast v14, Llyiahf/vczjk/qs5;

    invoke-direct {v2, v14, v5}, Llyiahf/vczjk/ou;-><init>(Llyiahf/vczjk/qs5;I)V

    const v3, -0x5ad2a5be

    invoke-static {v3, v2, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v24

    const/high16 v26, 0xc00000

    const/16 v27, 0x7e

    const/16 v17, 0x0

    const/16 v18, 0x0

    const-wide/16 v19, 0x0

    const-wide/16 v21, 0x0

    const/16 v23, 0x0

    move-object/from16 v25, v1

    invoke-static/range {v16 .. v27}, Llyiahf/vczjk/v33;->OooO0OO(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJLlyiahf/vczjk/h33;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_10
    return-object v13

    :pswitch_7
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_1c

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_1b

    goto :goto_11

    :cond_1b
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_13

    :cond_1c
    :goto_11
    sget-object v2, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v3, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    invoke-static {v3, v2, v1, v4}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/zf1;

    iget v4, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v1, v7}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v12, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v12, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_1d

    invoke-virtual {v3, v12}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_12

    :cond_1d
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_12
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v1, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v6, v1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v6, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_1e

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v6, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_1f

    :cond_1e
    invoke-static {v4, v3, v4, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1f
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v7, v1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v2, Lgithub/tornaco/android/thanos/lite/app/R$string;->thanox_lite_app_name:I

    invoke-static {v2, v1}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v28

    const/16 v49, 0x0

    const v50, 0x3fffe

    const/16 v29, 0x0

    const-wide/16 v30, 0x0

    const-wide/16 v32, 0x0

    const/16 v34, 0x0

    const/16 v35, 0x0

    const-wide/16 v36, 0x0

    const/16 v38, 0x0

    const-wide/16 v39, 0x0

    const/16 v41, 0x0

    const/16 v42, 0x0

    const/16 v43, 0x0

    const/16 v44, 0x0

    const/16 v45, 0x0

    const/16 v46, 0x0

    const/16 v48, 0x0

    move-object/from16 v47, v1

    invoke-static/range {v28 .. v50}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    invoke-static {v11, v1}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    const v2, -0x7b3fa4a6

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v14, Llyiahf/vczjk/qs5;

    invoke-interface {v14}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/cm4;

    iget-boolean v2, v2, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz v2, :cond_22

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->badge_paid_app:I

    invoke-static {v2, v1}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v15, Landroid/content/Context;

    invoke-virtual {v3, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v4, :cond_20

    if-ne v6, v10, :cond_21

    :cond_20
    new-instance v6, Llyiahf/vczjk/kt;

    invoke-direct {v6, v15, v5}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_21
    check-cast v6, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v2, v6, v1, v11}, Llyiahf/vczjk/nqa;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    :cond_22
    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v1, 0x1

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_13
    return-object v13

    :pswitch_8
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_24

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_23

    goto :goto_14

    :cond_23
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_15

    :cond_24
    :goto_14
    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v15, Llyiahf/vczjk/on4;

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    check-cast v14, Llyiahf/vczjk/ex7;

    invoke-virtual {v1, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_25

    if-ne v3, v10, :cond_26

    :cond_25
    new-instance v3, Llyiahf/vczjk/o0O000;

    const/16 v2, 0x15

    invoke-direct {v3, v2, v15, v14, v11}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_26
    move-object/from16 v16, v3

    check-cast v16, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v21, Llyiahf/vczjk/qa1;->OooO0o0:Llyiahf/vczjk/a91;

    const/high16 v23, 0x180000

    const/16 v24, 0x3e

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    move-object/from16 v22, v1

    invoke-static/range {v16 .. v24}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    :goto_15
    return-object v13

    :pswitch_9
    move-object/from16 v44, p1

    check-cast v44, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    and-int/lit8 v1, v1, 0x3

    if-ne v1, v12, :cond_28

    move-object/from16 v1, v44

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_27

    goto :goto_16

    :cond_27
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_17

    :cond_28
    :goto_16
    check-cast v15, Llyiahf/vczjk/w03;

    invoke-interface {v15}, Llyiahf/vczjk/w03;->getLabel()Llyiahf/vczjk/oe3;

    move-result-object v1

    check-cast v14, Landroid/content/Context;

    invoke-interface {v1, v14}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    move-object/from16 v25, v1

    check-cast v25, Ljava/lang/String;

    const/16 v46, 0x0

    const v47, 0x3fffe

    const/16 v26, 0x0

    const-wide/16 v27, 0x0

    const-wide/16 v29, 0x0

    const/16 v31, 0x0

    const/16 v32, 0x0

    const-wide/16 v33, 0x0

    const/16 v35, 0x0

    const-wide/16 v36, 0x0

    const/16 v38, 0x0

    const/16 v39, 0x0

    const/16 v40, 0x0

    const/16 v41, 0x0

    const/16 v42, 0x0

    const/16 v43, 0x0

    const/16 v45, 0x0

    invoke-static/range {v25 .. v47}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_17
    return-object v13

    :pswitch_a
    move-object/from16 v67, p1

    check-cast v67, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    and-int/lit8 v1, v1, 0x3

    if-ne v1, v12, :cond_2a

    move-object/from16 v1, v67

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_29

    goto :goto_18

    :cond_29
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_19

    :cond_2a
    :goto_18
    check-cast v15, Llyiahf/vczjk/oe3;

    invoke-interface {v15, v14}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    move-object/from16 v48, v1

    check-cast v48, Ljava/lang/String;

    const/16 v69, 0x0

    const v70, 0x3fffe

    const/16 v49, 0x0

    const-wide/16 v50, 0x0

    const-wide/16 v52, 0x0

    const/16 v54, 0x0

    const/16 v55, 0x0

    const-wide/16 v56, 0x0

    const/16 v58, 0x0

    const-wide/16 v59, 0x0

    const/16 v61, 0x0

    const/16 v62, 0x0

    const/16 v63, 0x0

    const/16 v64, 0x0

    const/16 v65, 0x0

    const/16 v66, 0x0

    const/16 v68, 0x0

    invoke-static/range {v48 .. v70}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_19
    return-object v13

    :pswitch_b
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_2c

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_2b

    goto :goto_1a

    :cond_2b
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1b

    :cond_2c
    :goto_1a
    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v15, Llyiahf/vczjk/zh1;

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_2d

    if-ne v3, v10, :cond_2e

    :cond_2d
    new-instance v3, Llyiahf/vczjk/na2;

    const/4 v2, 0x1

    invoke-direct {v3, v15, v2}, Llyiahf/vczjk/na2;-><init>(Llyiahf/vczjk/zh1;I)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2e
    move-object/from16 v19, v3

    check-cast v19, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v2, Llyiahf/vczjk/v5;

    check-cast v14, Ljava/lang/String;

    invoke-direct {v2, v14, v5}, Llyiahf/vczjk/v5;-><init>(Ljava/lang/String;I)V

    const v3, -0x490222f7

    invoke-static {v3, v2, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v25

    const/high16 v27, 0x30000000

    const/16 v28, 0x1fe

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    move-object/from16 v26, v1

    invoke-static/range {v19 .. v28}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_1b
    return-object v13

    :pswitch_c
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_30

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_2f

    goto :goto_1c

    :cond_2f
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1d

    :cond_30
    :goto_1c
    check-cast v15, Llyiahf/vczjk/ya2;

    iget-object v2, v15, Llyiahf/vczjk/ya2;->OooOOoo:Llyiahf/vczjk/a91;

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    check-cast v14, Llyiahf/vczjk/ku5;

    invoke-virtual {v2, v14, v1, v3}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :goto_1d
    return-object v13

    :pswitch_d
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/v02;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/v02;

    check-cast v15, Llyiahf/vczjk/co0;

    invoke-static {v1, v15}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_31

    check-cast v14, Llyiahf/vczjk/co0;

    invoke-static {v2, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_31

    const/4 v9, 0x1

    goto :goto_1e

    :cond_31
    move v9, v11

    :goto_1e
    invoke-static {v9}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    return-object v1

    :pswitch_e
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_33

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_32

    goto :goto_1f

    :cond_32
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_20

    :cond_33
    :goto_1f
    check-cast v15, Llyiahf/vczjk/qs5;

    check-cast v15, Llyiahf/vczjk/fw8;

    invoke-virtual {v15}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/rq9;

    iget-boolean v2, v2, Llyiahf/vczjk/rq9;->OooO00o:Z

    invoke-virtual {v15}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/rq9;

    iget-boolean v3, v3, Llyiahf/vczjk/rq9;->OooO0O0:Z

    new-instance v4, Llyiahf/vczjk/e4;

    check-cast v14, Llyiahf/vczjk/a91;

    invoke-direct {v4, v14, v5}, Llyiahf/vczjk/e4;-><init>(Llyiahf/vczjk/a91;I)V

    const v5, -0x814c3cd

    invoke-static {v5, v4, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v4

    const/16 v5, 0x180

    invoke-static {v2, v3, v4, v1, v5}, Llyiahf/vczjk/ls6;->OooO00o(ZZLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    :goto_20
    return-object v13

    :pswitch_f
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_35

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_34

    goto :goto_21

    :cond_34
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_22

    :cond_35
    :goto_21
    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v10, :cond_36

    new-instance v2, Llyiahf/vczjk/l5;

    check-cast v14, Llyiahf/vczjk/qs5;

    const/16 v3, 0x10

    invoke-direct {v2, v14, v3}, Llyiahf/vczjk/l5;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_36
    check-cast v2, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    check-cast v15, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;

    invoke-static {v15, v2, v1, v4}, Llyiahf/vczjk/c6a;->OooOOOO(Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    :goto_22
    return-object v13

    :pswitch_10
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_38

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_37

    goto :goto_23

    :cond_37
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_24

    :cond_38
    :goto_23
    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v10, :cond_39

    new-instance v2, Llyiahf/vczjk/l5;

    check-cast v14, Llyiahf/vczjk/qs5;

    const/16 v3, 0xf

    invoke-direct {v2, v14, v3}, Llyiahf/vczjk/l5;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_39
    check-cast v2, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    check-cast v15, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;

    invoke-static {v15, v2, v1, v4}, Llyiahf/vczjk/ye5;->OooO0OO(Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    :goto_24
    return-object v13

    :pswitch_11
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_3b

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_3a

    goto :goto_25

    :cond_3a
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_26

    :cond_3b
    :goto_25
    sget v2, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OoooO0O:I

    check-cast v15, Llyiahf/vczjk/qs5;

    invoke-interface {v15}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/cr5;

    iget-boolean v2, v2, Llyiahf/vczjk/cr5;->OooO00o:Z

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v16

    new-instance v2, Llyiahf/vczjk/u71;

    check-cast v14, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-direct {v2, v11, v15, v14}, Llyiahf/vczjk/u71;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v3, 0x5a3f90a0

    invoke-static {v3, v2, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v22

    const/high16 v24, 0x180000

    const/16 v25, 0x3e

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    move-object/from16 v23, v1

    invoke-static/range {v16 .. v25}, Landroidx/compose/animation/OooO00o;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o4;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;II)V

    :goto_26
    return-object v13

    :pswitch_12
    move-object/from16 v9, p1

    check-cast v9, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    and-int/lit8 v1, v1, 0x3

    if-ne v1, v12, :cond_3d

    move-object v1, v9

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_3c

    goto :goto_27

    :cond_3c
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_28

    :cond_3d
    :goto_27
    sget-object v2, Llyiahf/vczjk/x91;->OooO00o:Llyiahf/vczjk/a91;

    new-instance v1, Llyiahf/vczjk/r6;

    check-cast v15, Llyiahf/vczjk/p51;

    check-cast v14, Llyiahf/vczjk/qs5;

    move/from16 v3, v16

    invoke-direct {v1, v3, v15, v14}, Llyiahf/vczjk/r6;-><init>(ILjava/lang/Object;Llyiahf/vczjk/qs5;)V

    const v3, -0x7194da61

    invoke-static {v3, v1, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v5

    const/16 v10, 0xc06

    const/16 v11, 0xf6

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    invoke-static/range {v2 .. v11}, Llyiahf/vczjk/up;->OooO0o0(Llyiahf/vczjk/a91;Llyiahf/vczjk/hl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;FLlyiahf/vczjk/zy4;Llyiahf/vczjk/fx9;Llyiahf/vczjk/rf1;II)V

    :goto_28
    return-object v13

    :pswitch_13
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v16, 0x3

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_3f

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_3e

    goto :goto_29

    :cond_3e
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_2a

    :cond_3f
    :goto_29
    check-cast v14, Ljava/util/ArrayList;

    check-cast v15, Llyiahf/vczjk/p51;

    invoke-static {v15, v14, v1, v11}, Llyiahf/vczjk/so8;->OooO0Oo(Llyiahf/vczjk/p51;Ljava/util/ArrayList;Llyiahf/vczjk/rf1;I)V

    :goto_2a
    return-object v13

    :pswitch_14
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v16, 0x3

    and-int/lit8 v3, v2, 0x3

    if-eq v3, v12, :cond_40

    const/4 v11, 0x1

    :cond_40
    const/16 v18, 0x1

    and-int/lit8 v2, v2, 0x1

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2, v11}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_44

    sget v2, Llyiahf/vczjk/rk0;->OooO0o:F

    sget v3, Llyiahf/vczjk/rk0;->OooO0oO:F

    invoke-static {v7, v2, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO00o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v2

    check-cast v15, Llyiahf/vczjk/di6;

    invoke-static {v2, v15}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v4, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v5, 0x36

    invoke-static {v3, v4, v1, v5}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    iget v4, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v1, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v6, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_41

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2b

    :cond_41
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2b
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v1, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v1, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_42

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_43

    :cond_42
    invoke-static {v4, v1, v4, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_43
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v1, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/jw7;->OooO00o:Llyiahf/vczjk/jw7;

    const/4 v3, 0x6

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    check-cast v14, Llyiahf/vczjk/bf3;

    invoke-interface {v14, v2, v1, v3}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v2, 0x1

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_2c

    :cond_44
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_2c
    return-object v13

    :pswitch_15
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v16, 0x3

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_46

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_45

    goto :goto_2d

    :cond_45
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_2e

    :cond_46
    :goto_2d
    const/16 v2, 0x82

    int-to-float v2, v2

    invoke-static {v7, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0o0(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v16

    const/16 v2, 0x28

    int-to-float v2, v2

    new-instance v4, Llyiahf/vczjk/n62;

    new-instance v17, Llyiahf/vczjk/rn9;

    sget-object v5, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/x21;

    iget-wide v7, v7, Llyiahf/vczjk/x21;->OooOOo0:J

    const/16 v9, 0x12

    invoke-static {v9}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v20

    sget-object v22, Llyiahf/vczjk/ib3;->OooOo00:Llyiahf/vczjk/ib3;

    const-wide/16 v27, 0x0

    const v29, 0xfffff8

    const/16 v23, 0x0

    const-wide/16 v24, 0x0

    const/16 v26, 0x0

    move-wide/from16 v18, v7

    invoke-direct/range {v17 .. v29}, Llyiahf/vczjk/rn9;-><init>(JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ba3;JIJI)V

    move-object/from16 v7, v17

    new-instance v17, Llyiahf/vczjk/rn9;

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/x21;

    iget-wide v8, v5, Llyiahf/vczjk/x21;->OooO00o:J

    invoke-static {v3}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v20

    sget-object v22, Llyiahf/vczjk/ib3;->OooOo:Llyiahf/vczjk/ib3;

    const-wide/16 v27, 0x0

    const v29, 0xfffff8

    const/16 v23, 0x0

    const-wide/16 v24, 0x0

    const/16 v26, 0x0

    move-wide/from16 v18, v8

    invoke-direct/range {v17 .. v29}, Llyiahf/vczjk/rn9;-><init>(JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ba3;JIJI)V

    move-object/from16 v3, v17

    invoke-direct {v4, v7, v3}, Llyiahf/vczjk/n62;-><init>(Llyiahf/vczjk/rn9;Llyiahf/vczjk/rn9;)V

    check-cast v14, Llyiahf/vczjk/qs5;

    invoke-interface {v14}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/dd0;->OooOO0O(Ljava/lang/Object;)Ljava/time/LocalTime;

    move-result-object v3

    const-string v5, "access$BottomTimePicker$lambda$1(...)"

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v15, Llyiahf/vczjk/oe3;

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_47

    if-ne v6, v10, :cond_48

    :cond_47
    new-instance v6, Llyiahf/vczjk/mg0;

    invoke-direct {v6, v15, v14}, Llyiahf/vczjk/mg0;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;)V

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_48
    move-object/from16 v21, v6

    check-cast v21, Llyiahf/vczjk/oe3;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v18, 0x0

    const/16 v23, 0x186

    move-object/from16 v22, v1

    move/from16 v17, v2

    move-object/from16 v20, v3

    move-object/from16 v19, v4

    invoke-static/range {v16 .. v23}, Llyiahf/vczjk/fu6;->OooO0o(Llyiahf/vczjk/kl5;FLlyiahf/vczjk/w56;Llyiahf/vczjk/n62;Ljava/time/LocalTime;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    :goto_2e
    return-object v13

    :pswitch_16
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v16, 0x3

    and-int/lit8 v3, v2, 0x3

    if-eq v3, v12, :cond_49

    const/4 v3, 0x1

    :goto_2f
    const/16 v18, 0x1

    goto :goto_30

    :cond_49
    move v3, v11

    goto :goto_2f

    :goto_30
    and-int/lit8 v2, v2, 0x1

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_4a

    check-cast v14, Llyiahf/vczjk/lg0;

    iget-object v2, v14, Llyiahf/vczjk/lg0;->OooO0O0:Llyiahf/vczjk/cu8;

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    check-cast v15, Llyiahf/vczjk/a91;

    invoke-virtual {v15, v2, v1, v3}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_31

    :cond_4a
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_31
    return-object v13

    :pswitch_17
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/xw;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Boolean;

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v15, Llyiahf/vczjk/g70;

    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/z60;

    invoke-direct {v1, v4, v2, v11}, Llyiahf/vczjk/z60;-><init>(ZLlyiahf/vczjk/xw;I)V

    iget-object v4, v15, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/xo8;->OooOOOO(Llyiahf/vczjk/oe3;)V

    check-cast v14, Llyiahf/vczjk/cu;

    check-cast v14, Llyiahf/vczjk/yt;

    iget-object v1, v14, Llyiahf/vczjk/yt;->OooO00o:Llyiahf/vczjk/ze3;

    invoke-interface {v1, v2, v3}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object v13

    :pswitch_18
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v16, 0x3

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_4c

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_4b

    goto :goto_32

    :cond_4b
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_33

    :cond_4c
    :goto_32
    check-cast v14, Llyiahf/vczjk/qs5;

    invoke-interface {v14}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/xw;

    iget-boolean v2, v2, Llyiahf/vczjk/xw;->OooO:Z

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v15, Llyiahf/vczjk/ze3;

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v1, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v3, v4

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_4d

    if-ne v4, v10, :cond_4e

    :cond_4d
    new-instance v4, Llyiahf/vczjk/o0oOO;

    invoke-direct {v4, v12, v15, v14}, Llyiahf/vczjk/o0oOO;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4e
    move-object/from16 v17, v4

    check-cast v17, Llyiahf/vczjk/oe3;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v22, 0x0

    const/16 v23, 0x7c

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    move-object/from16 v21, v1

    move/from16 v16, v2

    invoke-static/range {v16 .. v23}, Landroidx/compose/material3/OooO0O0;->OooO00o(ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/nc9;Llyiahf/vczjk/rf1;II)V

    :goto_33
    return-object v13

    :pswitch_19
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v16, 0x3

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_50

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_4f

    goto :goto_34

    :cond_4f
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_36

    :cond_50
    :goto_34
    check-cast v15, Llyiahf/vczjk/e60;

    iget-object v2, v15, Llyiahf/vczjk/e60;->OooO0o0:Ljava/util/List;

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_35
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_53

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/xu2;

    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_51

    if-ne v6, v10, :cond_52

    :cond_51
    new-instance v6, Llyiahf/vczjk/k1;

    const/16 v5, 0xe

    invoke-direct {v6, v3, v5}, Llyiahf/vczjk/k1;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v4, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_52
    move-object v15, v6

    check-cast v15, Llyiahf/vczjk/le3;

    invoke-virtual {v4, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v5, Llyiahf/vczjk/r6;

    move-object v6, v14

    check-cast v6, Landroid/content/Context;

    invoke-direct {v5, v12, v3, v6}, Llyiahf/vczjk/r6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v3, 0x46df0a6d

    invoke-static {v3, v5, v4}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v23

    const-wide/16 v20, 0x0

    const/high16 v25, 0xc00000

    const/16 v16, 0x0

    const/16 v17, 0x0

    const-wide/16 v18, 0x0

    const/16 v22, 0x0

    move-object/from16 v24, v4

    invoke-static/range {v15 .. v25}, Llyiahf/vczjk/v33;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/hl5;Llyiahf/vczjk/qj8;JJLlyiahf/vczjk/h33;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    goto :goto_35

    :cond_53
    :goto_36
    return-object v13

    :pswitch_1a
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v16, 0x3

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_55

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_54

    goto :goto_37

    :cond_54
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_3a

    :cond_55
    :goto_37
    sget-object v2, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v3, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    invoke-static {v3, v2, v1, v4}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/zf1;

    iget v4, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v1, v7}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v9, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_56

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_38

    :cond_56
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_38
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v1, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_57

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v5, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_58

    :cond_57
    invoke-static {v4, v3, v4, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_58
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v6, v1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    const v4, -0x4021aeb5

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v4, Llyiahf/vczjk/gm9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    move-object/from16 v44, v4

    check-cast v44, Llyiahf/vczjk/rn9;

    invoke-virtual {v2, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v47, 0x0

    const v48, 0x1fffe

    move-object/from16 v26, v15

    check-cast v26, Ljava/lang/String;

    const/16 v27, 0x0

    const-wide/16 v28, 0x0

    const-wide/16 v30, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const-wide/16 v34, 0x0

    const/16 v36, 0x0

    const-wide/16 v37, 0x0

    const/16 v39, 0x0

    const/16 v40, 0x0

    const/16 v41, 0x0

    const/16 v42, 0x0

    const/16 v43, 0x0

    const/16 v46, 0x6

    move-object/from16 v45, v1

    invoke-static/range {v26 .. v48}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v15, v26

    const v1, -0x2733ea47

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v14, Llyiahf/vczjk/e60;

    iget-object v1, v14, Llyiahf/vczjk/e60;->OooO0o:Llyiahf/vczjk/lc9;

    if-nez v1, :cond_5e

    sget-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    iget-object v2, v14, Llyiahf/vczjk/e60;->OooO0Oo:Llyiahf/vczjk/oe3;

    invoke-interface {v2, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    if-nez v1, :cond_59

    goto/16 :goto_39

    :cond_59
    const v2, 0x6e3c21fe

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v10, :cond_5a

    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v2}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v2

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5a
    check-cast v2, Llyiahf/vczjk/qs5;

    invoke-static {v3, v11, v8}, Llyiahf/vczjk/ix8;->OooO0o0(Llyiahf/vczjk/zf1;ZI)Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v10, :cond_5b

    new-instance v4, Llyiahf/vczjk/l5;

    const/16 v5, 0x8

    invoke-direct {v4, v2, v5}, Llyiahf/vczjk/l5;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5b
    move-object/from16 v26, v4

    check-cast v26, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v4, 0x18

    int-to-float v4, v4

    invoke-static {v7, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v27

    sget-object v31, Llyiahf/vczjk/r91;->OooO00o:Llyiahf/vczjk/a91;

    const v33, 0x180036

    const/16 v34, 0x3c

    const/16 v28, 0x0

    const/16 v29, 0x0

    const/16 v30, 0x0

    move-object/from16 v32, v45

    invoke-static/range {v26 .. v34}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    move-object/from16 v4, v32

    const v5, -0x27338951

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Boolean;

    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v5

    if-eqz v5, :cond_5d

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v10, :cond_5c

    new-instance v5, Llyiahf/vczjk/l5;

    const/16 v6, 0x9

    invoke-direct {v5, v2, v6}, Llyiahf/vczjk/l5;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5c
    move-object/from16 v26, v5

    check-cast v26, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v5, Llyiahf/vczjk/ou;

    const/4 v6, 0x1

    invoke-direct {v5, v2, v6}, Llyiahf/vczjk/ou;-><init>(Llyiahf/vczjk/qs5;I)V

    const v2, 0x51e6576f

    invoke-static {v2, v5, v4}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v27

    new-instance v2, Llyiahf/vczjk/k60;

    invoke-direct {v2, v15, v11}, Llyiahf/vczjk/k60;-><init>(Ljava/lang/String;I)V

    const v5, -0x7526688d

    invoke-static {v5, v2, v4}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v30

    new-instance v2, Llyiahf/vczjk/k60;

    invoke-direct {v2, v1, v6}, Llyiahf/vczjk/k60;-><init>(Ljava/lang/String;I)V

    const v1, -0x66e9988c

    invoke-static {v1, v2, v4}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v31

    const/16 v45, 0x0

    const/16 v46, 0x3f9c

    const/16 v28, 0x0

    const/16 v29, 0x0

    const/16 v32, 0x0

    const-wide/16 v33, 0x0

    const-wide/16 v35, 0x0

    const-wide/16 v37, 0x0

    const-wide/16 v39, 0x0

    const/16 v41, 0x0

    const/16 v42, 0x0

    const v44, 0x1b0036

    move-object/from16 v43, v4

    invoke-static/range {v26 .. v46}, Llyiahf/vczjk/mc4;->OooO00o(Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/ze3;Llyiahf/vczjk/a91;Llyiahf/vczjk/qj8;JJJJFLlyiahf/vczjk/ab2;Llyiahf/vczjk/rf1;III)V

    :cond_5d
    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :cond_5e
    :goto_39
    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v2, 0x1

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3a
    return-object v13

    :pswitch_1b
    move-object/from16 v2, p1

    check-cast v2, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-object/from16 v3, p2

    check-cast v3, Lgithub/tornaco/android/thanos/core/ops/PermState;

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "state"

    invoke-static {v3, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v14, Llyiahf/vczjk/qc6;

    iget v1, v14, Llyiahf/vczjk/qc6;->OooO00o:I

    check-cast v15, Llyiahf/vczjk/aw;

    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v15}, Llyiahf/vczjk/aw;->OooO0o0()Lgithub/tornaco/android/thanos/core/ops/OpsManager;

    move-result-object v4

    invoke-static {v2}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v5

    const-string v6, "fromAppInfo(...)"

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v3}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v4, v1, v5, v3}, Lgithub/tornaco/android/thanos/core/ops/OpsManager;->setMode(ILgithub/tornaco/android/thanos/core/pm/Pkg;Ljava/lang/String;)V

    invoke-virtual {v15, v2}, Llyiahf/vczjk/aw;->OooO0o(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V

    return-object v13

    :pswitch_1c
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const/16 v16, 0x3

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v12, :cond_5f

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_60

    :cond_5f
    const/16 v3, 0x10

    goto :goto_3b

    :cond_60
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3c

    :goto_3b
    int-to-float v2, v3

    invoke-static {v7, v2}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    check-cast v15, Llyiahf/vczjk/ow5;

    iget-object v3, v15, Llyiahf/vczjk/ow5;->OooO0OO:Llyiahf/vczjk/x39;

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v14, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v4, :cond_61

    if-ne v5, v10, :cond_62

    :cond_61
    new-instance v5, Llyiahf/vczjk/a5;

    const/4 v4, 0x5

    invoke-direct {v5, v4, v14}, Llyiahf/vczjk/a5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_62
    check-cast v5, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v4, 0x46

    invoke-static {v2, v3, v5, v1, v4}, Llyiahf/vczjk/tg0;->OooOOOO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/x39;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    :goto_3c
    return-object v13

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
