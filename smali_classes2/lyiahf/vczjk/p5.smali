.class public final Llyiahf/vczjk/p5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/qs5;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/p5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/p5;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/p5;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/vk;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    const-string v3, "$this$AnimatedVisibility"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->apps_count:I

    iget-object v3, v0, Llyiahf/vczjk/p5;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/j28;

    iget-object v3, v3, Llyiahf/vczjk/j28;->OooO0Oo:Ljava/util/Set;

    invoke-interface {v3}, Ljava/util/Set;->size()I

    move-result v3

    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v3

    filled-new-array {v3}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {v1, v3, v2}, Llyiahf/vczjk/vt6;->Oooo0O0(I[Ljava/lang/Object;Llyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v1

    const/16 v23, 0x0

    const v24, 0x3fffe

    const/4 v3, 0x0

    const-wide/16 v4, 0x0

    const-wide/16 v6, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const-wide/16 v10, 0x0

    const/4 v12, 0x0

    const-wide/16 v13, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v22, 0x0

    move-object/from16 v21, v2

    move-object v2, v1

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/iw7;

    move-object/from16 v21, p2

    check-cast v21, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "$this$OutlinedToggleButton"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v2, 0x11

    const/16 v2, 0x10

    if-ne v1, v2, :cond_1

    move-object/from16 v1, v21

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    iget-object v1, v0, Llyiahf/vczjk/p5;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lgithub/tornaco/android/thanos/core/pm/PackageSet;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/PackageSet;->getLabel()Ljava/lang/String;

    move-result-object v2

    const-string v1, "getLabel(...)"

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 v23, 0x0

    const v24, 0x3fffe

    const/4 v3, 0x0

    const-wide/16 v4, 0x0

    const-wide/16 v6, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const-wide/16 v10, 0x0

    const/4 v12, 0x0

    const-wide/16 v13, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v22, 0x0

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_1
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_1
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/iw7;

    move-object/from16 v8, p2

    check-cast v8, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "$this$ThanoxMediumAppBarScaffold"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v2, 0x11

    const/16 v2, 0x10

    if-ne v1, v2, :cond_3

    move-object v1, v8

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_4

    :cond_3
    :goto_2
    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v2, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v3, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v4, 0x30

    invoke-static {v3, v2, v8, v4}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    move-object v11, v8

    check-cast v11, Llyiahf/vczjk/zf1;

    iget v3, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v8, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v5, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_4

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_4
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v8, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v4, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_5

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_6

    :cond_5
    invoke-static {v3, v11, v3, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_6
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v1, 0x4c5de2

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v1, v2, :cond_7

    new-instance v1, Llyiahf/vczjk/l5;

    iget-object v2, v0, Llyiahf/vczjk/p5;->OooOOO:Llyiahf/vczjk/qs5;

    const/16 v3, 0x18

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/l5;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/le3;

    const/4 v1, 0x0

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/za1;->OooO00o:Llyiahf/vczjk/a91;

    const v9, 0x180006

    const/16 v10, 0x3e

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v2 .. v10}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    const/4 v1, 0x1

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_4
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_2
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/gh0;

    move-object/from16 v8, p2

    check-cast v8, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "$this$BadgedBox"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v2, 0x11

    const/16 v2, 0x10

    if-ne v1, v2, :cond_9

    move-object v1, v8

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_8

    goto :goto_5

    :cond_8
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_8

    :cond_9
    :goto_5
    iget-object v1, v0, Llyiahf/vczjk/p5;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/w18;

    iget v1, v1, Llyiahf/vczjk/w18;->OooO0OO:I

    if-lez v1, :cond_a

    const/4 v1, 0x1

    :goto_6
    move v2, v1

    goto :goto_7

    :cond_a
    const/4 v1, 0x0

    goto :goto_6

    :goto_7
    sget-object v7, Llyiahf/vczjk/va1;->OooO0O0:Llyiahf/vczjk/a91;

    const/high16 v9, 0x30000

    const/16 v10, 0x1e

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v2 .. v10}, Landroidx/compose/animation/OooO0O0;->OooO0Oo(ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_8
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_3
    move-object/from16 v1, p1

    check-cast v1, Landroidx/compose/foundation/lazy/OooO00o;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    const-string v4, "$this$item"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v3, 0x11

    const/16 v3, 0x10

    if-ne v1, v3, :cond_c

    move-object v1, v2

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_b

    goto :goto_9

    :cond_b
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_b

    :cond_c
    :goto_9
    sget-object v1, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    int-to-float v3, v3

    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    const/4 v4, 0x0

    invoke-static {v3, v4}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v3

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/zf1;

    iget v5, v4, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v2, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v7, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v8, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_d

    invoke-virtual {v4, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_a

    :cond_d
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_a
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v2, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v6, v2, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v6, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_e

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_f

    :cond_e
    invoke-static {v5, v4, v5, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_f
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, v2, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v1, v0, Llyiahf/vczjk/p5;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/r7a;

    const-string v3, "null cannot be cast to non-null type github.tornaco.android.thanos.module.compose.common.infra.UiState.Error"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, Llyiahf/vczjk/o7a;

    iget-object v1, v1, Llyiahf/vczjk/o7a;->OooO00o:Ljava/lang/Throwable;

    invoke-static {v1}, Llyiahf/vczjk/cp7;->Oooo0o(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v1

    const/16 v23, 0x0

    const v24, 0x3fffe

    const/4 v3, 0x0

    move-object v6, v4

    const-wide/16 v4, 0x0

    move-object v8, v6

    const-wide/16 v6, 0x0

    move-object v9, v8

    const/4 v8, 0x0

    move-object v10, v9

    const/4 v9, 0x0

    move-object v12, v10

    const-wide/16 v10, 0x0

    move-object v13, v12

    const/4 v12, 0x0

    move-object v15, v13

    const-wide/16 v13, 0x0

    move-object/from16 v16, v15

    const/4 v15, 0x0

    move-object/from16 v17, v16

    const/16 v16, 0x0

    move-object/from16 v18, v17

    const/16 v17, 0x0

    move-object/from16 v19, v18

    const/16 v18, 0x0

    move-object/from16 v20, v19

    const/16 v19, 0x0

    move-object/from16 v21, v20

    const/16 v20, 0x0

    const/16 v22, 0x0

    move-object/from16 v25, v2

    move-object v2, v1

    move-object/from16 v1, v21

    move-object/from16 v21, v25

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    const/4 v2, 0x1

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_b
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_4
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/bi6;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    const-string v4, "paddingValues"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v4, v3, 0x6

    if-nez v4, :cond_11

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_10

    const/4 v4, 0x4

    goto :goto_c

    :cond_10
    const/4 v4, 0x2

    :goto_c
    or-int/2addr v3, v4

    :cond_11
    and-int/lit8 v3, v3, 0x13

    sget-object v4, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/16 v5, 0x12

    if-ne v3, v5, :cond_13

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_12

    goto :goto_d

    :cond_12
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_f

    :cond_13
    :goto_d
    check-cast v2, Llyiahf/vczjk/zf1;

    const v3, 0x4c5de2

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v5, v0, Llyiahf/vczjk/p5;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v6, :cond_14

    if-ne v7, v8, :cond_15

    :cond_14
    new-instance v7, Llyiahf/vczjk/xd;

    const/4 v6, 0x1

    invoke-direct {v7, v5, v6}, Llyiahf/vczjk/xd;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_15
    move-object v13, v7

    check-cast v13, Llyiahf/vczjk/ze3;

    const/4 v6, 0x0

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const-string v7, "onMove"

    invoke-static {v13, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const v7, -0x30c243d4

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const/4 v7, 0x3

    invoke-static {v6, v7, v2}, Llyiahf/vczjk/fw4;->OooO00o(IILlyiahf/vczjk/rf1;)Llyiahf/vczjk/dw4;

    move-result-object v10

    const/16 v7, 0x14

    int-to-float v7, v7

    new-instance v14, Llyiahf/vczjk/tz8;

    invoke-direct {v14}, Llyiahf/vczjk/tz8;-><init>()V

    sget-object v9, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/f62;

    invoke-interface {v9, v7}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v12

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-ne v7, v8, :cond_16

    invoke-static {v2}, Llyiahf/vczjk/c6a;->Oooo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/xr1;

    move-result-object v7

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_16
    move-object v11, v7

    check-cast v11, Llyiahf/vczjk/xr1;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v7, :cond_17

    if-ne v9, v8, :cond_18

    :cond_17
    new-instance v9, Llyiahf/vczjk/yp7;

    invoke-direct/range {v9 .. v14}, Llyiahf/vczjk/yp7;-><init>(Llyiahf/vczjk/dw4;Llyiahf/vczjk/xr1;FLlyiahf/vczjk/ze3;Llyiahf/vczjk/tz8;)V

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_18
    check-cast v9, Llyiahf/vczjk/yp7;

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/ch1;->OooOOO:Llyiahf/vczjk/l39;

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v7

    sget-object v11, Llyiahf/vczjk/yn4;->OooOOO:Llyiahf/vczjk/yn4;

    if-ne v7, v11, :cond_19

    const/4 v7, 0x1

    goto :goto_e

    :cond_19
    move v7, v6

    :goto_e
    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    const/4 v12, 0x0

    if-nez v3, :cond_1a

    if-ne v11, v8, :cond_1b

    :cond_1a
    new-instance v11, Llyiahf/vczjk/zp7;

    invoke-direct {v11, v9, v12}, Llyiahf/vczjk/zp7;-><init>(Llyiahf/vczjk/yp7;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v2, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1b
    check-cast v11, Llyiahf/vczjk/ze3;

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v9, v2, v11}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v3, -0x6815fd56

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v11

    or-int/2addr v3, v11

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v3, v11

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v3, :cond_1c

    if-ne v11, v8, :cond_1d

    :cond_1c
    new-instance v11, Llyiahf/vczjk/aq7;

    invoke-direct {v11, v10, v7, v9, v12}, Llyiahf/vczjk/aq7;-><init>(Llyiahf/vczjk/dw4;ZLlyiahf/vczjk/yp7;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v2, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1d
    check-cast v11, Llyiahf/vczjk/ze3;

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v9, v2, v11}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    iget-object v7, v9, Llyiahf/vczjk/yp7;->OooOOO0:Llyiahf/vczjk/dw4;

    sget-object v3, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v10, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v10, v1}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v11

    const/16 v1, 0x40

    int-to-float v15, v1

    const/4 v12, 0x0

    const/16 v16, 0x7

    const/4 v13, 0x0

    const/4 v14, 0x0

    invoke-static/range {v11 .. v16}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v1

    const-string v10, "<this>"

    invoke-static {v1, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v11, Llyiahf/vczjk/h92;

    const/4 v12, 0x1

    invoke-direct {v11, v9, v12}, Llyiahf/vczjk/h92;-><init>(Llyiahf/vczjk/yp7;I)V

    invoke-static {v3, v4, v11}, Llyiahf/vczjk/gb9;->OooO00o(Llyiahf/vczjk/kl5;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Llyiahf/vczjk/kl5;

    move-result-object v11

    invoke-interface {v1, v11}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v1, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v10, Llyiahf/vczjk/h92;

    const/4 v11, 0x0

    invoke-direct {v10, v9, v11}, Llyiahf/vczjk/h92;-><init>(Llyiahf/vczjk/yp7;I)V

    invoke-static {v3, v4, v10}, Llyiahf/vczjk/gb9;->OooO00o(Llyiahf/vczjk/kl5;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-interface {v1, v3}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    const v3, -0x615d173a

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    or-int/2addr v3, v10

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v3, :cond_1e

    if-ne v10, v8, :cond_1f

    :cond_1e
    new-instance v10, Llyiahf/vczjk/o0OO000o;

    const/16 v3, 0x9

    invoke-direct {v10, v3, v5, v9}, Llyiahf/vczjk/o0OO000o;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1f
    move-object v15, v10

    check-cast v15, Llyiahf/vczjk/oe3;

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v17, 0x0

    const/16 v18, 0x1fc

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    move-object v6, v1

    move-object/from16 v16, v2

    invoke-static/range {v6 .. v18}, Llyiahf/vczjk/mc4;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    :goto_f
    return-object v4

    :pswitch_5
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/iw7;

    move-object/from16 v8, p2

    check-cast v8, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "$this$LargeTopAppBar"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v2, 0x11

    const/16 v2, 0x10

    if-ne v1, v2, :cond_21

    move-object v1, v8

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_20

    goto :goto_10

    :cond_20
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_12

    :cond_21
    :goto_10
    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v2, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v3, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v4, 0x30

    invoke-static {v3, v2, v8, v4}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    move-object v11, v8

    check-cast v11, Llyiahf/vczjk/zf1;

    iget v3, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v8, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v5, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_22

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_11

    :cond_22
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_11
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v8, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v4, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_23

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_24

    :cond_23
    invoke-static {v3, v11, v3, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_24
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v1, 0x4c5de2

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v1, v2, :cond_25

    new-instance v1, Llyiahf/vczjk/l5;

    iget-object v2, v0, Llyiahf/vczjk/p5;->OooOOO:Llyiahf/vczjk/qs5;

    const/4 v3, 0x2

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/l5;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_25
    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/le3;

    const/4 v1, 0x0

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/e91;->OooO00o:Llyiahf/vczjk/a91;

    const v9, 0x180006

    const/16 v10, 0x3e

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v2 .. v10}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    const/4 v1, 0x1

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_12
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
