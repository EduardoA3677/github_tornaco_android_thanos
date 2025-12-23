.class public final Llyiahf/vczjk/ql4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Z

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;

.field public final synthetic OooOOoo:Llyiahf/vczjk/cf3;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;ZZLjava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/cf3;I)V
    .locals 0

    iput p7, p0, Llyiahf/vczjk/ql4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ql4;->OooOOOo:Ljava/lang/Object;

    iput-boolean p2, p0, Llyiahf/vczjk/ql4;->OooOOO:Z

    iput-boolean p3, p0, Llyiahf/vczjk/ql4;->OooOOOO:Z

    iput-object p4, p0, Llyiahf/vczjk/ql4;->OooOOo0:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/ql4;->OooOOo:Ljava/lang/Object;

    iput-object p6, p0, Llyiahf/vczjk/ql4;->OooOOoo:Llyiahf/vczjk/cf3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    move-object/from16 v0, p0

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    iget-object v3, v0, Llyiahf/vczjk/ql4;->OooOOo:Ljava/lang/Object;

    iget-object v4, v0, Llyiahf/vczjk/ql4;->OooOOo0:Ljava/lang/Object;

    iget-boolean v5, v0, Llyiahf/vczjk/ql4;->OooOOO:Z

    iget-object v6, v0, Llyiahf/vczjk/ql4;->OooOOOo:Ljava/lang/Object;

    iget-boolean v7, v0, Llyiahf/vczjk/ql4;->OooOOOO:Z

    const/4 v8, 0x0

    const/4 v9, 0x1

    const/4 v10, 0x2

    iget-object v11, v0, Llyiahf/vczjk/ql4;->OooOOoo:Llyiahf/vczjk/cf3;

    iget v12, v0, Llyiahf/vczjk/ql4;->OooOOO0:I

    packed-switch v12, :pswitch_data_0

    move-object/from16 v12, p1

    check-cast v12, Llyiahf/vczjk/rf1;

    move-object/from16 v13, p2

    check-cast v13, Ljava/lang/Number;

    invoke-virtual {v13}, Ljava/lang/Number;->intValue()I

    move-result v13

    and-int/lit8 v14, v13, 0x3

    if-eq v14, v10, :cond_0

    move v10, v9

    goto :goto_0

    :cond_0
    move v10, v8

    :goto_0
    and-int/2addr v13, v9

    check-cast v12, Llyiahf/vczjk/zf1;

    invoke-virtual {v12, v13, v10}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v10

    if-eqz v10, :cond_8

    check-cast v6, Llyiahf/vczjk/yw5;

    if-nez v7, :cond_1

    iget-wide v5, v6, Llyiahf/vczjk/yw5;->OooO0o:J

    goto :goto_1

    :cond_1
    if-eqz v5, :cond_2

    iget-wide v5, v6, Llyiahf/vczjk/yw5;->OooO00o:J

    goto :goto_1

    :cond_2
    iget-wide v5, v6, Llyiahf/vczjk/yw5;->OooO0Oo:J

    :goto_1
    check-cast v4, Llyiahf/vczjk/p13;

    invoke-static {v5, v6, v4, v12}, Llyiahf/vczjk/pq8;->OooO00o(JLlyiahf/vczjk/wl;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p29;

    move-result-object v4

    check-cast v3, Llyiahf/vczjk/a91;

    if-eqz v3, :cond_4

    const v3, -0x25d631ed

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v2, :cond_3

    new-instance v3, Llyiahf/vczjk/ow;

    const/16 v2, 0x1a

    invoke-direct {v3, v2}, Llyiahf/vczjk/ow;-><init>(I)V

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v3, Llyiahf/vczjk/oe3;

    sget-object v2, Llyiahf/vczjk/me8;->OooO00o:Ljava/util/concurrent/atomic/AtomicInteger;

    new-instance v2, Landroidx/compose/ui/semantics/ClearAndSetSemanticsElement;

    invoke-direct {v2, v3}, Landroidx/compose/ui/semantics/ClearAndSetSemanticsElement;-><init>(Llyiahf/vczjk/oe3;)V

    invoke-virtual {v12, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_2

    :cond_4
    const v2, -0x25d62e5c

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    :goto_2
    sget-object v3, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v3, v8}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v3

    iget v5, v12, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v12, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v7, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v8, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_5

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_5
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v12, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v6, v12, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v6, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_6

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_7

    :cond_6
    invoke-static {v5, v12, v5, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_7
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v12, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/km1;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-interface {v4}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/n21;

    iget-wide v3, v3, Llyiahf/vczjk/n21;->OooO00o:J

    new-instance v5, Llyiahf/vczjk/n21;

    invoke-direct {v5, v3, v4}, Llyiahf/vczjk/n21;-><init>(J)V

    invoke-virtual {v2, v5}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v2

    check-cast v11, Llyiahf/vczjk/a91;

    const/16 v3, 0x8

    invoke-static {v2, v11, v12, v3}, Llyiahf/vczjk/r02;->OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v12, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_4

    :cond_8
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_4
    return-object v1

    :pswitch_0
    move-object/from16 v12, p1

    check-cast v12, Llyiahf/vczjk/rf1;

    move-object/from16 v13, p2

    check-cast v13, Ljava/lang/Number;

    invoke-virtual {v13}, Ljava/lang/Number;->intValue()I

    move-result v13

    and-int/lit8 v13, v13, 0x3

    if-ne v13, v10, :cond_a

    move-object v10, v12

    check-cast v10, Llyiahf/vczjk/zf1;

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v13

    if-nez v13, :cond_9

    goto :goto_5

    :cond_9
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_7

    :cond_a
    :goto_5
    check-cast v12, Llyiahf/vczjk/zf1;

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-ne v10, v2, :cond_b

    invoke-static {v12}, Llyiahf/vczjk/c6a;->Oooo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/xr1;

    move-result-object v10

    invoke-virtual {v12, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    check-cast v10, Llyiahf/vczjk/xr1;

    check-cast v6, Llyiahf/vczjk/qs5;

    invoke-interface {v6}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v6

    move-object v14, v6

    check-cast v14, Llyiahf/vczjk/lm4;

    if-eqz v5, :cond_c

    if-eqz v7, :cond_c

    move/from16 v16, v9

    goto :goto_6

    :cond_c
    move/from16 v16, v8

    :goto_6
    const v5, -0x615d173a

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v4, Llyiahf/vczjk/ul4;

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    check-cast v3, Landroid/content/Context;

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v5, v6

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_d

    if-ne v6, v2, :cond_e

    :cond_d
    new-instance v6, Llyiahf/vczjk/oo0oO0;

    const/16 v5, 0xc

    invoke-direct {v6, v5, v4, v3}, Llyiahf/vczjk/oo0oO0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    move-object v15, v6

    check-cast v15, Llyiahf/vczjk/le3;

    invoke-virtual {v12, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v5, -0x48fade91

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    move-object v6, v11

    check-cast v6, Llyiahf/vczjk/le3;

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    or-int/2addr v5, v7

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    or-int/2addr v5, v7

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    or-int/2addr v5, v7

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v5, :cond_f

    if-ne v7, v2, :cond_10

    :cond_f
    new-instance v7, Llyiahf/vczjk/x5;

    invoke-direct {v7, v10, v6, v4, v3}, Llyiahf/vczjk/x5;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/le3;Llyiahf/vczjk/ul4;Landroid/content/Context;)V

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_10
    move-object/from16 v17, v7

    check-cast v17, Llyiahf/vczjk/le3;

    invoke-virtual {v12, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v18, v11

    check-cast v18, Llyiahf/vczjk/le3;

    const/16 v20, 0x0

    move-object/from16 v19, v12

    invoke-static/range {v14 .. v20}, Llyiahf/vczjk/m6a;->OooO(Llyiahf/vczjk/lm4;Llyiahf/vczjk/le3;ZLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    :goto_7
    return-object v1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
