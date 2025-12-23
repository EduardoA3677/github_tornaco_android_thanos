.class public final Llyiahf/vczjk/h4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/a91;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/h4;->OooOOO0:I

    packed-switch p3, :pswitch_data_0

    sget-object p3, Llyiahf/vczjk/ga1;->OooO00o:Llyiahf/vczjk/a91;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/h4;->OooOOO:Llyiahf/vczjk/a91;

    iput-object p2, p0, Llyiahf/vczjk/h4;->OooOOOO:Llyiahf/vczjk/a91;

    return-void

    :pswitch_0
    sget-object p3, Llyiahf/vczjk/ga1;->OooO00o:Llyiahf/vczjk/a91;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/h4;->OooOOO:Llyiahf/vczjk/a91;

    iput-object p2, p0, Llyiahf/vczjk/h4;->OooOOOO:Llyiahf/vczjk/a91;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;IZ)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/h4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/h4;->OooOOO:Llyiahf/vczjk/a91;

    iput-object p2, p0, Llyiahf/vczjk/h4;->OooOOOO:Llyiahf/vczjk/a91;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    move-object/from16 v0, p0

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/4 v2, 0x1

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v4, v0, Llyiahf/vczjk/h4;->OooOOOO:Llyiahf/vczjk/a91;

    iget-object v5, v0, Llyiahf/vczjk/h4;->OooOOO:Llyiahf/vczjk/a91;

    const/4 v6, 0x2

    const/4 v7, 0x0

    iget v8, v0, Llyiahf/vczjk/h4;->OooOOO0:I

    packed-switch v8, :pswitch_data_0

    move-object/from16 v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    move-object/from16 v9, p2

    check-cast v9, Ljava/lang/Number;

    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    move-result v9

    and-int/lit8 v10, v9, 0x3

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    if-eq v10, v6, :cond_0

    move v6, v2

    goto :goto_0

    :cond_0
    move v6, v7

    :goto_0
    and-int/2addr v9, v2

    check-cast v8, Llyiahf/vczjk/zf1;

    invoke-virtual {v8, v9, v6}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v6

    if-eqz v6, :cond_7

    const-string v6, "LeadingButton"

    invoke-static {v1, v6}, Landroidx/compose/ui/layout/OooO00o;->OooO0OO(Llyiahf/vczjk/kl5;Ljava/lang/Object;)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v9, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    invoke-static {v9, v7}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v10

    iget v12, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v13

    invoke-static {v8, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v14, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v14, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_1

    invoke-virtual {v8, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_1
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v15, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v10, v8, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v13, v8, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v7, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-static {v7, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_3

    :cond_2
    invoke-static {v12, v8, v12, v13}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_3
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v6, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v5, v8, v11}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v5, 0x1

    invoke-virtual {v8, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const-string v5, "TrailingButton"

    invoke-static {v1, v5}, Landroidx/compose/ui/layout/OooO00o;->OooO0OO(Llyiahf/vczjk/kl5;Ljava/lang/Object;)Llyiahf/vczjk/kl5;

    move-result-object v1

    const/4 v5, 0x0

    invoke-static {v9, v5}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v5

    iget v6, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v8, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_4

    invoke-virtual {v8, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_4
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    invoke-static {v5, v8, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v7, v8, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v5, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_5

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_6

    :cond_5
    invoke-static {v6, v8, v6, v13}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_6
    invoke-static {v1, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v4, v8, v11}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v5, 0x1

    invoke-virtual {v8, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_7
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_3
    return-object v3

    :pswitch_0
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v7, p2

    check-cast v7, Ljava/lang/Number;

    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    move-result v7

    and-int/lit8 v7, v7, 0x3

    if-ne v7, v6, :cond_9

    move-object v7, v2

    check-cast v7, Llyiahf/vczjk/zf1;

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v8

    if-nez v8, :cond_8

    goto :goto_4

    :cond_8
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_5

    :cond_9
    :goto_4
    const v7, 0x3f51eb85    # 0.82f

    invoke-static {v1, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v9

    sget v1, Llyiahf/vczjk/y3;->OooO00o:F

    sget-object v1, Llyiahf/vczjk/bb2;->OooO0Oo:Llyiahf/vczjk/dk8;

    invoke-static {v1, v2}, Llyiahf/vczjk/cl8;->OooO0O0(Llyiahf/vczjk/dk8;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qj8;

    move-result-object v10

    sget-object v1, Llyiahf/vczjk/bb2;->OooO0OO:Llyiahf/vczjk/y21;

    invoke-static {v1, v2}, Llyiahf/vczjk/z21;->OooO0o0(Llyiahf/vczjk/y21;Llyiahf/vczjk/rf1;)J

    move-result-wide v11

    sget v15, Llyiahf/vczjk/y3;->OooO00o:F

    new-instance v1, Llyiahf/vczjk/h4;

    sget-object v7, Llyiahf/vczjk/ga1;->OooO00o:Llyiahf/vczjk/a91;

    invoke-direct {v1, v5, v4, v6}, Llyiahf/vczjk/h4;-><init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;I)V

    const v4, -0x145b879c

    invoke-static {v4, v1, v2}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v17

    const v19, 0xc00006

    const/16 v20, 0x68

    const-wide/16 v13, 0x0

    const/16 v16, 0x0

    move-object/from16 v18, v2

    invoke-static/range {v9 .. v20}, Llyiahf/vczjk/ua9;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_5
    return-object v3

    :pswitch_1
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v7, p2

    check-cast v7, Ljava/lang/Number;

    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    move-result v7

    and-int/lit8 v7, v7, 0x3

    if-ne v7, v6, :cond_b

    move-object v6, v2

    check-cast v6, Llyiahf/vczjk/zf1;

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v7

    if-nez v7, :cond_a

    goto :goto_6

    :cond_a
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_9

    :cond_b
    :goto_6
    const/high16 v6, 0x3f800000    # 1.0f

    invoke-static {v1, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v7

    const/16 v8, 0x10

    int-to-float v8, v8

    invoke-static {v7, v8}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v9, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v10, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v11, 0x0

    invoke-static {v9, v10, v2, v11}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v9

    move-object v10, v2

    check-cast v10, Llyiahf/vczjk/zf1;

    iget v11, v10, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    invoke-static {v2, v7}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v13, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v14, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v14, :cond_c

    invoke-virtual {v10, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_c
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    sget-object v14, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v9, v2, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v12, v2, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v12, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v15, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v15, :cond_d

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v15

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v15, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_e

    :cond_d
    invoke-static {v11, v10, v11, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_e
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v7, v2, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/r31;->OooO00o:Llyiahf/vczjk/r31;

    const/16 v16, 0x0

    invoke-static/range {v16 .. v16}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-virtual {v5, v2, v11}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-static {v1, v8}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-static {v2, v5}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const/4 v5, 0x6

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-virtual {v4, v7, v2, v8}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/high16 v4, 0x3f800000    # 1.0f

    invoke-static {v1, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v4, Llyiahf/vczjk/tx;->OooO0O0:Llyiahf/vczjk/e86;

    sget-object v7, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v8, 0x36

    invoke-static {v4, v7, v2, v8}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v4

    iget v7, v10, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v2, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v11, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v11, :cond_f

    invoke-virtual {v10, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_8

    :cond_f
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_8
    invoke-static {v4, v2, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v8, v2, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v4, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_10

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v4, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_11

    :cond_10
    invoke-static {v7, v10, v7, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_11
    invoke-static {v1, v2, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/jw7;->OooO00o:Llyiahf/vczjk/jw7;

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/ga1;->OooO0O0:Llyiahf/vczjk/a91;

    invoke-virtual {v5, v1, v2, v4}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v5, 0x1

    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_9
    return-object v3

    :pswitch_2
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v7, v2, 0x3

    if-eq v7, v6, :cond_12

    const/4 v6, 0x1

    :goto_a
    const/16 v17, 0x1

    goto :goto_b

    :cond_12
    const/4 v6, 0x0

    goto :goto_a

    :goto_b
    and-int/lit8 v2, v2, 0x1

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2, v6}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_13

    sget v2, Llyiahf/vczjk/j4;->OooO00o:F

    new-instance v2, Llyiahf/vczjk/h4;

    const/4 v11, 0x0

    invoke-direct {v2, v5, v4, v11, v11}, Llyiahf/vczjk/h4;-><init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;IZ)V

    const v4, -0x1b6383e2

    invoke-static {v4, v2, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    const/16 v4, 0x1b6

    invoke-static {v2, v1, v4}, Llyiahf/vczjk/j4;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    goto :goto_c

    :cond_13
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_c
    return-object v3

    :pswitch_3
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v7, v2, 0x3

    const/16 v16, 0x0

    invoke-static/range {v16 .. v16}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    if-eq v7, v6, :cond_14

    const/4 v6, 0x1

    :goto_d
    const/16 v17, 0x1

    goto :goto_e

    :cond_14
    const/4 v6, 0x0

    goto :goto_d

    :goto_e
    and-int/lit8 v2, v2, 0x1

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2, v6}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_16

    if-nez v5, :cond_15

    const v2, -0x41afc885

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const/4 v11, 0x0

    :goto_f
    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_10

    :cond_15
    const/4 v11, 0x0

    const v2, 0x2f6df146

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v5, v1, v8}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_f

    :goto_10
    invoke-virtual {v4, v1, v8}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_11

    :cond_16
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_11
    return-object v3

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
