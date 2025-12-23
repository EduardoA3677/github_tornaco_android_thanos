.class public final Llyiahf/vczjk/el0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/el0;->OooOOO0:I

    iput-boolean p5, p0, Llyiahf/vczjk/el0;->OooOOO:Z

    iput-object p2, p0, Llyiahf/vczjk/el0;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/el0;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/el0;->OooOOo0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/el0;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v3, v2, 0x3

    const/4 v4, 0x2

    const/4 v5, 0x1

    if-eq v3, v4, :cond_0

    move v3, v5

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    and-int/2addr v2, v5

    move-object v9, v1

    check-cast v9, Llyiahf/vczjk/zf1;

    invoke-virtual {v9, v2, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_1

    sget-object v4, Llyiahf/vczjk/li9;->OooO00o:Llyiahf/vczjk/li9;

    iget-object v1, v0, Llyiahf/vczjk/el0;->OooOOOo:Ljava/lang/Object;

    move-object v7, v1

    check-cast v7, Llyiahf/vczjk/ei9;

    iget-object v1, v0, Llyiahf/vczjk/el0;->OooOOOO:Ljava/lang/Object;

    move-object v6, v1

    check-cast v6, Llyiahf/vczjk/n24;

    const v10, 0x6d80c00

    iget-boolean v5, v0, Llyiahf/vczjk/el0;->OooOOO:Z

    iget-object v1, v0, Llyiahf/vczjk/el0;->OooOOo0:Ljava/lang/Object;

    move-object v8, v1

    check-cast v8, Llyiahf/vczjk/qj8;

    invoke-virtual/range {v4 .. v10}, Llyiahf/vczjk/li9;->OooO00o(ZLlyiahf/vczjk/n24;Llyiahf/vczjk/ei9;Llyiahf/vczjk/qj8;Llyiahf/vczjk/rf1;I)V

    goto :goto_1

    :cond_1
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    const/4 v3, 0x2

    if-ne v2, v3, :cond_3

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_3

    :cond_3
    :goto_2
    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    iget-boolean v3, v0, Llyiahf/vczjk/el0;->OooOOO:Z

    iget-object v4, v0, Llyiahf/vczjk/el0;->OooOOo0:Ljava/lang/Object;

    check-cast v4, Ljava/lang/String;

    iget-object v5, v0, Llyiahf/vczjk/el0;->OooOOOo:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/qv3;

    const/4 v6, 0x0

    if-eqz v3, :cond_6

    move-object v15, v1

    check-cast v15, Llyiahf/vczjk/zf1;

    const v1, 0x5ea9f6ca

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const v1, 0x4c5de2

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v1, v0, Llyiahf/vczjk/el0;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/le3;

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v3, :cond_4

    if-ne v7, v2, :cond_5

    :cond_4
    new-instance v7, Llyiahf/vczjk/a5;

    const/16 v2, 0xa

    invoke-direct {v7, v2, v1}, Llyiahf/vczjk/a5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v15, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v7, Llyiahf/vczjk/le3;

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v1, Llyiahf/vczjk/dl0;

    const/4 v2, 0x0

    invoke-direct {v1, v5, v4, v2}, Llyiahf/vczjk/dl0;-><init>(Llyiahf/vczjk/qv3;Ljava/lang/String;I)V

    const v2, -0x63331fef

    invoke-static {v2, v1, v15}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v14

    const/high16 v16, 0x30000000

    const/16 v17, 0x1fe

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    invoke-static/range {v7 .. v17}, Llyiahf/vczjk/bua;->OooO0Oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_6
    check-cast v1, Llyiahf/vczjk/zf1;

    const v3, 0x5eaf4d36

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v16, Llyiahf/vczjk/fz8;->OooO00o:Llyiahf/vczjk/fz8;

    const v3, 0x6e3c21fe

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v2, :cond_7

    new-instance v3, Llyiahf/vczjk/oOOO0OO0;

    const/16 v2, 0x16

    invoke-direct {v3, v2}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    move-object/from16 v17, v3

    check-cast v17, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v2, Llyiahf/vczjk/dl0;

    const/4 v3, 0x1

    invoke-direct {v2, v5, v4, v3}, Llyiahf/vczjk/dl0;-><init>(Llyiahf/vczjk/qv3;Ljava/lang/String;I)V

    const v3, 0x49fffb42    # 2097000.2f

    invoke-static {v3, v2, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v24

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const v26, 0x30000006

    move-object/from16 v25, v1

    invoke-virtual/range {v16 .. v26}, Llyiahf/vczjk/fz8;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/kz8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
