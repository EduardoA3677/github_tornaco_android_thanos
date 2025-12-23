.class public final Llyiahf/vczjk/ua2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOo:Llyiahf/vczjk/bf3;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/bf3;I)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/ua2;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ua2;->OooOOO:Llyiahf/vczjk/a91;

    iput-object p2, p0, Llyiahf/vczjk/ua2;->OooOOOO:Llyiahf/vczjk/a91;

    iput-object p3, p0, Llyiahf/vczjk/ua2;->OooOOOo:Llyiahf/vczjk/bf3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    move-object/from16 v0, p0

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v2, 0x0

    iget-object v3, v0, Llyiahf/vczjk/ua2;->OooOOOo:Llyiahf/vczjk/bf3;

    iget-object v4, v0, Llyiahf/vczjk/ua2;->OooOOOO:Llyiahf/vczjk/a91;

    iget-object v5, v0, Llyiahf/vczjk/ua2;->OooOOO:Llyiahf/vczjk/a91;

    sget-object v6, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/4 v7, 0x2

    iget v8, v0, Llyiahf/vczjk/ua2;->OooOOO0:I

    packed-switch v8, :pswitch_data_0

    move-object/from16 v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    move-object/from16 v9, p2

    check-cast v9, Ljava/lang/Number;

    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    move-result v9

    and-int/lit8 v9, v9, 0x3

    if-ne v9, v7, :cond_1

    move-object v7, v8

    check-cast v7, Llyiahf/vczjk/zf1;

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v9

    if-nez v9, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    const v7, 0x3f51eb85    # 0.82f

    invoke-static {v6, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v9

    sget v6, Llyiahf/vczjk/y3;->OooO00o:F

    sget-object v6, Llyiahf/vczjk/bb2;->OooO0Oo:Llyiahf/vczjk/dk8;

    invoke-static {v6, v8}, Llyiahf/vczjk/cl8;->OooO0O0(Llyiahf/vczjk/dk8;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qj8;

    move-result-object v10

    sget-object v6, Llyiahf/vczjk/bb2;->OooO0OO:Llyiahf/vczjk/y21;

    invoke-static {v6, v8}, Llyiahf/vczjk/z21;->OooO0o0(Llyiahf/vczjk/y21;Llyiahf/vczjk/rf1;)J

    move-result-wide v11

    sget v15, Llyiahf/vczjk/y3;->OooO00o:F

    new-instance v6, Llyiahf/vczjk/ua2;

    invoke-direct {v6, v5, v4, v3, v2}, Llyiahf/vczjk/ua2;-><init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/bf3;I)V

    const v2, 0x79b13052

    invoke-static {v2, v6, v8}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v17

    const v19, 0xc00006

    const/16 v20, 0x68

    const-wide/16 v13, 0x0

    const/16 v16, 0x0

    move-object/from16 v18, v8

    invoke-static/range {v9 .. v20}, Llyiahf/vczjk/ua9;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_1
    return-object v1

    :pswitch_0
    move-object/from16 v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    move-object/from16 v9, p2

    check-cast v9, Ljava/lang/Number;

    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    move-result v9

    and-int/lit8 v9, v9, 0x3

    if-ne v9, v7, :cond_3

    move-object v7, v8

    check-cast v7, Llyiahf/vczjk/zf1;

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v9

    if-nez v9, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_5

    :cond_3
    :goto_2
    const/high16 v7, 0x3f800000    # 1.0f

    invoke-static {v6, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v9

    const/16 v10, 0x10

    int-to-float v10, v10

    invoke-static {v9, v10}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v9

    sget-object v11, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v12, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v11, v12, v8, v2}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v11

    move-object v12, v8

    check-cast v12, Llyiahf/vczjk/zf1;

    iget v13, v12, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v8, v9}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v9

    sget-object v15, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v15, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move/from16 v16, v2

    iget-boolean v2, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v2, :cond_4

    invoke-virtual {v12, v15}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_4
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v11, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v14, v8, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v14, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v7, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_5

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-static {v7, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_6

    :cond_5
    invoke-static {v13, v12, v13, v14}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_6
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v9, v8, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/r31;->OooO00o:Llyiahf/vczjk/r31;

    invoke-static/range {v16 .. v16}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-virtual {v5, v8, v9}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-static {v6, v10}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-static {v8, v5}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const/4 v5, 0x6

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-virtual {v4, v7, v8, v9}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/high16 v4, 0x3f800000    # 1.0f

    invoke-static {v6, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v6, Llyiahf/vczjk/tx;->OooO0O0:Llyiahf/vczjk/e86;

    sget-object v7, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v9, 0x36

    invoke-static {v6, v7, v8, v9}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v6

    iget v7, v12, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v9

    invoke-static {v8, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v10, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v10, :cond_7

    invoke-virtual {v12, v15}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_7
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    invoke-static {v6, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v9, v8, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_8

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v2, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_9

    :cond_8
    invoke-static {v7, v12, v7, v14}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_9
    invoke-static {v4, v8, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/jw7;->OooO00o:Llyiahf/vczjk/jw7;

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-interface {v3, v0, v8, v2}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v0, 0x1

    invoke-virtual {v12, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v12, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_5
    return-object v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
