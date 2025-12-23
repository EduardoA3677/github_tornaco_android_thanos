.class public final Llyiahf/vczjk/u71;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/u71;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/u71;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/u71;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 33

    move-object/from16 v0, p0

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v2, v0, Llyiahf/vczjk/u71;->OooOOOO:Ljava/lang/Object;

    iget-object v3, v0, Llyiahf/vczjk/u71;->OooOOO:Ljava/lang/Object;

    const/4 v4, 0x0

    const-string v5, "$this$AnimatedContent"

    iget v6, v0, Llyiahf/vczjk/u71;->OooOOO0:I

    packed-switch v6, :pswitch_data_0

    move-object/from16 v6, p1

    check-cast v6, Llyiahf/vczjk/kj;

    move-object/from16 v7, p2

    check-cast v7, Llyiahf/vczjk/ut;

    move-object/from16 v8, p3

    check-cast v8, Llyiahf/vczjk/rf1;

    move-object/from16 v9, p4

    check-cast v9, Ljava/lang/Number;

    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    invoke-static {v6, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "action"

    invoke-static {v7, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v5, Llyiahf/vczjk/st;->OooO00o:Llyiahf/vczjk/st;

    invoke-virtual {v7, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2

    check-cast v8, Llyiahf/vczjk/zf1;

    const v5, 0x5ebaffbf

    invoke-virtual {v8, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const v5, -0x615d173a

    invoke-virtual {v8, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v3, Llyiahf/vczjk/oe3;

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    check-cast v2, Llyiahf/vczjk/uh6;

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v5, v6

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_0

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v6, v5, :cond_1

    :cond_0
    new-instance v6, Llyiahf/vczjk/w77;

    const/16 v5, 0xd

    invoke-direct {v6, v5, v3, v2}, Llyiahf/vczjk/w77;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    move-object v9, v6

    check-cast v9, Llyiahf/vczjk/le3;

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v16, Llyiahf/vczjk/ld1;->OooO0o0:Llyiahf/vczjk/a91;

    const/high16 v18, 0x30000000

    const/16 v19, 0x1fe

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    move-object/from16 v17, v8

    invoke-static/range {v9 .. v19}, Llyiahf/vczjk/bua;->OooO0Oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_1

    :cond_2
    instance-of v2, v7, Llyiahf/vczjk/tt;

    if-eqz v2, :cond_4

    move-object v14, v8

    check-cast v14, Llyiahf/vczjk/zf1;

    const v2, 0x5ec05d12

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v7, Llyiahf/vczjk/tt;

    iget-boolean v2, v7, Llyiahf/vczjk/tt;->OooO00o:Z

    if-eqz v2, :cond_3

    const v2, 0x5ec0fc11

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-static {}, Llyiahf/vczjk/yi4;->OoooO()Llyiahf/vczjk/qv3;

    move-result-object v9

    sget-wide v12, Llyiahf/vczjk/n21;->OooO0oO:J

    const/16 v15, 0xc30

    const/16 v16, 0x4

    const-string v10, "Blocked"

    const/4 v11, 0x0

    invoke-static/range {v9 .. v16}, Llyiahf/vczjk/zt3;->OooO00o(Llyiahf/vczjk/qv3;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    invoke-virtual {v14, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_0

    :cond_3
    const v2, 0x5ec4c4d1

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-static {}, Llyiahf/vczjk/yi4;->OoooO()Llyiahf/vczjk/qv3;

    move-result-object v9

    const/16 v15, 0x30

    const/16 v16, 0xc

    const-string v10, "Blocked"

    const/4 v11, 0x0

    const-wide/16 v12, 0x0

    invoke-static/range {v9 .. v16}, Llyiahf/vczjk/zt3;->OooO00o(Llyiahf/vczjk/qv3;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    invoke-virtual {v14, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_0
    invoke-virtual {v14, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_1

    :cond_4
    sget-object v2, Llyiahf/vczjk/st;->OooO0O0:Llyiahf/vczjk/st;

    invoke-virtual {v7, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_5

    check-cast v8, Llyiahf/vczjk/zf1;

    const v2, 0x5ec777c7

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_1
    return-object v1

    :cond_5
    check-cast v8, Llyiahf/vczjk/zf1;

    const v1, -0x57c871cf

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v1, Llyiahf/vczjk/k61;

    invoke-direct {v1}, Ljava/lang/RuntimeException;-><init>()V

    throw v1

    :pswitch_0
    move-object/from16 v6, p1

    check-cast v6, Llyiahf/vczjk/kj;

    move-object/from16 v7, p2

    check-cast v7, Ljava/lang/Boolean;

    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v7

    move-object/from16 v8, p3

    check-cast v8, Llyiahf/vczjk/rf1;

    move-object/from16 v9, p4

    check-cast v9, Ljava/lang/Number;

    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    invoke-static {v6, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v5, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/4 v6, 0x1

    const v9, -0x4021aeb5

    if-eqz v7, :cond_9

    check-cast v8, Llyiahf/vczjk/zf1;

    const v2, 0x4b1ff618    # 1.0483224E7f

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v2, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v7, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v2, v7, v8, v4}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v2

    iget v7, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v8, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v11, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_6

    invoke-virtual {v8, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_6
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v11, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v8, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v10, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v10, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v10, :cond_7

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v10, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_8

    :cond_7
    invoke-static {v7, v8, v7, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_8
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v5, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->common_menu_title_batch_select:I

    invoke-static {v2, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v2

    sget v5, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OoooO0O:I

    check-cast v3, Llyiahf/vczjk/qs5;

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/cr5;

    iget-object v3, v3, Llyiahf/vczjk/cr5;->OooO0O0:Ljava/util/Set;

    invoke-interface {v3}, Ljava/util/Set;->size()I

    move-result v3

    new-instance v5, Ljava/lang/StringBuilder;

    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, " "

    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v10

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v2, Llyiahf/vczjk/gm9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    move-object/from16 v28, v2

    check-cast v28, Llyiahf/vczjk/rn9;

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v31, 0x0

    const v32, 0x1fffe

    const/4 v11, 0x0

    const-wide/16 v12, 0x0

    const-wide/16 v14, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const-wide/16 v18, 0x0

    const/16 v20, 0x0

    const-wide/16 v21, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v30, 0x0

    move-object/from16 v29, v8

    invoke-static/range {v10 .. v32}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->module_component_manager_click_header_to_select_all:I

    invoke-static {v2, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v10

    sget-object v2, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/n6a;

    iget-object v11, v2, Llyiahf/vczjk/n6a;->OooOO0o:Llyiahf/vczjk/rn9;

    const-wide/high16 v2, 0x4027000000000000L    # 11.5

    invoke-static {v2, v3}, Llyiahf/vczjk/eo6;->OooOO0O(D)J

    move-result-wide v14

    const/16 v24, 0x0

    const v25, 0xfffffd

    const-wide/16 v12, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const-wide/16 v19, 0x0

    const-wide/16 v21, 0x0

    const/16 v23, 0x0

    invoke-static/range {v11 .. v25}, Llyiahf/vczjk/rn9;->OooO00o(Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/ba3;JJLlyiahf/vczjk/vx6;Llyiahf/vczjk/jz4;I)Llyiahf/vczjk/rn9;

    move-result-object v28

    const/16 v31, 0x0

    const v32, 0x1fffe

    const/4 v11, 0x0

    const-wide/16 v14, 0x0

    const-wide/16 v18, 0x0

    const/16 v20, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v30, 0x0

    move-object/from16 v29, v8

    invoke-static/range {v10 .. v32}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto/16 :goto_4

    :cond_9
    check-cast v8, Llyiahf/vczjk/zf1;

    const v3, 0x4b2abc5e    # 1.1189342E7f

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v3, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v7, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v10, 0x30

    invoke-static {v7, v3, v8, v10}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    iget v7, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v8, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v11

    sget-object v12, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v12, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v13, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v13, :cond_a

    invoke-virtual {v8, v12}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_a
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v12, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v8, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v10, v8, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v10, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v10, :cond_b

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    invoke-static {v10, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_c

    :cond_b
    invoke-static {v7, v8, v7, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_c
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v11, v8, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v3, 0x20

    int-to-float v3, v3

    invoke-static {v5, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    const/4 v5, 0x6

    check-cast v2, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v3, v2, v8, v5}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    invoke-static {v4, v8}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v2

    const-string v3, "getAppLabel(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v3, Llyiahf/vczjk/gm9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    move-object/from16 v27, v3

    check-cast v27, Llyiahf/vczjk/rn9;

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v30, 0x0

    const v31, 0x1fffe

    const/4 v10, 0x0

    const-wide/16 v11, 0x0

    const-wide/16 v13, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const-wide/16 v17, 0x0

    const/16 v19, 0x0

    const-wide/16 v20, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v29, 0x0

    move-object v9, v2

    move-object/from16 v28, v8

    invoke-static/range {v9 .. v31}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_4
    return-object v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
