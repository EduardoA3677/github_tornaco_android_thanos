.class public final Llyiahf/vczjk/y71;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/hb8;

.field public final synthetic OooOOO0:Llyiahf/vczjk/t81;

.field public final synthetic OooOOOO:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/t81;Llyiahf/vczjk/hb8;Llyiahf/vczjk/qs5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/y71;->OooOOO0:Llyiahf/vczjk/t81;

    iput-object p2, p0, Llyiahf/vczjk/y71;->OooOOO:Llyiahf/vczjk/hb8;

    iput-object p3, p0, Llyiahf/vczjk/y71;->OooOOOO:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    move-object/from16 v0, p0

    const/4 v1, 0x1

    const/4 v2, 0x0

    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/kj;

    move-object/from16 v4, p2

    check-cast v4, Ljava/lang/Boolean;

    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    move-object/from16 v5, p3

    check-cast v5, Llyiahf/vczjk/rf1;

    move-object/from16 v6, p4

    check-cast v6, Ljava/lang/Number;

    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    const-string v6, "$this$AnimatedContent"

    invoke-static {v3, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/op3;->OooOo0o:Llyiahf/vczjk/tb0;

    sget-object v6, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    iget-object v7, v0, Llyiahf/vczjk/y71;->OooOOO0:Llyiahf/vczjk/t81;

    sget-object v8, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const v9, 0x4c5de2

    if-eqz v4, :cond_7

    check-cast v5, Llyiahf/vczjk/zf1;

    const v4, 0x87e4a22

    invoke-virtual {v5, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v4, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    invoke-static {v4, v3, v5, v2}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    iget v4, v5, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v5, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v11, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v5, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_0

    invoke-virtual {v5, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_0

    :cond_0
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_0
    sget-object v11, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v5, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v10, v5, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v10, v5, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v10, :cond_1

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v10, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_2

    :cond_1
    invoke-static {v4, v5, v4, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_2
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v8, v5, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v5, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v5, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_3

    if-ne v4, v6, :cond_4

    :cond_3
    new-instance v4, Llyiahf/vczjk/v71;

    invoke-direct {v4, v7, v2}, Llyiahf/vczjk/v71;-><init>(Llyiahf/vczjk/t81;I)V

    invoke-virtual {v5, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    move-object v10, v4

    check-cast v10, Llyiahf/vczjk/le3;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v16, Llyiahf/vczjk/y91;->OooO00o:Llyiahf/vczjk/a91;

    const/high16 v18, 0x30000000

    const/16 v19, 0x1fe

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    move-object/from16 v17, v5

    invoke-static/range {v10 .. v19}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v5, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v5, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_5

    if-ne v4, v6, :cond_6

    :cond_5
    new-instance v4, Llyiahf/vczjk/v71;

    invoke-direct {v4, v7, v1}, Llyiahf/vczjk/v71;-><init>(Llyiahf/vczjk/t81;I)V

    invoke-virtual {v5, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    move-object v10, v4

    check-cast v10, Llyiahf/vczjk/le3;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v16, Llyiahf/vczjk/y91;->OooO0O0:Llyiahf/vczjk/a91;

    const/high16 v18, 0x30000000

    const/16 v19, 0x1fe

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    move-object/from16 v17, v5

    invoke-static/range {v10 .. v19}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v5, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto/16 :goto_4

    :cond_7
    move-object v12, v5

    check-cast v12, Llyiahf/vczjk/zf1;

    const v4, 0x8885380

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v4, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    invoke-static {v4, v3, v12, v2}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    iget v4, v12, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v12, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v10

    sget-object v11, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v13, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v13, :cond_8

    invoke-virtual {v12, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_8
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v13, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v12, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v12, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v14, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v14, :cond_9

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v15

    invoke-static {v14, v15}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-nez v14, :cond_a

    :cond_9
    invoke-static {v4, v12, v4, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_a
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v10, v12, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v19, Llyiahf/vczjk/jw7;->OooO00o:Llyiahf/vczjk/jw7;

    invoke-virtual {v12, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v10, :cond_b

    if-ne v14, v6, :cond_c

    :cond_b
    new-instance v14, Llyiahf/vczjk/v71;

    const/4 v10, 0x2

    invoke-direct {v14, v7, v10}, Llyiahf/vczjk/v71;-><init>(Llyiahf/vczjk/t81;I)V

    invoke-virtual {v12, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    move-object v10, v14

    check-cast v10, Llyiahf/vczjk/le3;

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v15, Llyiahf/vczjk/y91;->OooO0OO:Llyiahf/vczjk/a91;

    const/high16 v17, 0x180000

    const/16 v18, 0x3e

    move-object v14, v11

    const/4 v11, 0x0

    move-object/from16 v16, v12

    const/4 v12, 0x0

    move-object/from16 v20, v13

    const/4 v13, 0x0

    move-object/from16 v21, v14

    const/4 v14, 0x0

    move-object/from16 v9, v20

    move-object/from16 v1, v21

    invoke-static/range {v10 .. v18}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    move-object/from16 v12, v16

    sget v10, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OoooO0O:I

    iget-object v10, v0, Llyiahf/vczjk/y71;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v10}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/yia;

    sget-object v11, Llyiahf/vczjk/yia;->OooOOO0:Llyiahf/vczjk/yia;

    if-ne v10, v11, :cond_d

    const/4 v11, 0x1

    goto :goto_2

    :cond_d
    move v11, v2

    :goto_2
    new-instance v10, Llyiahf/vczjk/x71;

    invoke-direct {v10, v7, v2}, Llyiahf/vczjk/x71;-><init>(Llyiahf/vczjk/t81;I)V

    const v13, -0x4e76803d

    invoke-static {v13, v10, v12}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v16

    const v18, 0x180006

    move-object/from16 v10, v19

    const/16 v19, 0x1e

    move-object v14, v12

    const/4 v12, 0x0

    const/4 v13, 0x0

    move-object/from16 v17, v14

    const/4 v14, 0x0

    const/4 v15, 0x0

    invoke-static/range {v10 .. v19}, Landroidx/compose/animation/OooO0O0;->OooO0OO(Llyiahf/vczjk/iw7;ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    move-object/from16 v12, v17

    invoke-static {v12}, Llyiahf/vczjk/jp8;->Oooo0oO(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/oj2;

    move-result-object v10

    sget-object v11, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v11, v2}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v11

    iget v13, v12, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v12, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_e

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_e
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    invoke-static {v11, v12, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v14, v12, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v1, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v1, :cond_f

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_10

    :cond_f
    invoke-static {v13, v12, v13, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_10
    invoke-static {v8, v12, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v1, 0x4c5de2

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v1, :cond_11

    if-ne v3, v6, :cond_12

    :cond_11
    new-instance v3, Llyiahf/vczjk/w71;

    invoke-direct {v3, v10, v2}, Llyiahf/vczjk/w71;-><init>(Llyiahf/vczjk/oj2;I)V

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_12
    check-cast v3, Llyiahf/vczjk/le3;

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v15, Llyiahf/vczjk/y91;->OooO0o0:Llyiahf/vczjk/a91;

    const/high16 v17, 0x180000

    const/16 v18, 0x3e

    const/4 v11, 0x0

    move-object/from16 v16, v12

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    move-object v1, v10

    move-object v10, v3

    invoke-static/range {v10 .. v18}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    move-object/from16 v12, v16

    sget-object v3, Llyiahf/vczjk/y03;->OooOOO0:Llyiahf/vczjk/y03;

    sget v4, Lgithub/tornaco/android/thanos/res/R$string;->all:I

    invoke-static {v4, v12}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v4

    new-instance v5, Llyiahf/vczjk/gj2;

    invoke-direct {v5, v4, v3}, Llyiahf/vczjk/gj2;-><init>(Ljava/util/List;Ljava/lang/Enum;)V

    sget-object v3, Llyiahf/vczjk/y03;->OooOOO:Llyiahf/vczjk/y03;

    sget v4, Lgithub/tornaco/android/thanos/res/R$string;->enabled:I

    invoke-static {v4, v12}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v4

    new-instance v8, Llyiahf/vczjk/gj2;

    invoke-direct {v8, v4, v3}, Llyiahf/vczjk/gj2;-><init>(Ljava/util/List;Ljava/lang/Enum;)V

    sget-object v3, Llyiahf/vczjk/y03;->OooOOOO:Llyiahf/vczjk/y03;

    sget v4, Lgithub/tornaco/android/thanos/res/R$string;->disabled:I

    invoke-static {v4, v12}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v4

    new-instance v9, Llyiahf/vczjk/gj2;

    invoke-direct {v9, v4, v3}, Llyiahf/vczjk/gj2;-><init>(Ljava/util/List;Ljava/lang/Enum;)V

    filled-new-array {v5, v8, v9}, [Llyiahf/vczjk/gj2;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    const v4, 0x4c5de2

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v4, :cond_13

    if-ne v5, v6, :cond_14

    :cond_13
    new-instance v5, Llyiahf/vczjk/o000OO;

    const/16 v4, 0x10

    invoke-direct {v5, v7, v4}, Llyiahf/vczjk/o000OO;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_14
    move-object v13, v5

    check-cast v13, Llyiahf/vczjk/oe3;

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v10, 0x0

    const/16 v15, 0x200

    move-object v11, v1

    move-object v14, v12

    move-object v12, v3

    invoke-static/range {v10 .. v15}, Llyiahf/vczjk/jp8;->OooO0OO(FLlyiahf/vczjk/oj2;Ljava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    move-object v12, v14

    const/4 v1, 0x1

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v1, 0x4c5de2

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v1, v0, Llyiahf/vczjk/y71;->OooOOO:Llyiahf/vczjk/hb8;

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_15

    if-ne v4, v6, :cond_16

    :cond_15
    new-instance v4, Llyiahf/vczjk/n20;

    const/4 v3, 0x6

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/n20;-><init>(Llyiahf/vczjk/hb8;I)V

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_16
    move-object v6, v4

    check-cast v6, Llyiahf/vczjk/le3;

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v11, Llyiahf/vczjk/y91;->OooO0o:Llyiahf/vczjk/a91;

    const/high16 v13, 0x180000

    const/16 v14, 0x3e

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    invoke-static/range {v6 .. v14}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    const/4 v1, 0x1

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_4
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
