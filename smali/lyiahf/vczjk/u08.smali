.class public final Llyiahf/vczjk/u08;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/xr1;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/h48;

.field public final synthetic OooOOOo:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOo:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOo0:Landroid/content/Context;

.field public final synthetic OooOOoo:Llyiahf/vczjk/qs5;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/h48;Llyiahf/vczjk/qs5;Landroid/content/Context;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;I)V
    .locals 0

    iput p7, p0, Llyiahf/vczjk/u08;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/u08;->OooOOO:Llyiahf/vczjk/xr1;

    iput-object p2, p0, Llyiahf/vczjk/u08;->OooOOOO:Llyiahf/vczjk/h48;

    iput-object p3, p0, Llyiahf/vczjk/u08;->OooOOOo:Llyiahf/vczjk/qs5;

    iput-object p4, p0, Llyiahf/vczjk/u08;->OooOOo0:Landroid/content/Context;

    iput-object p5, p0, Llyiahf/vczjk/u08;->OooOOo:Llyiahf/vczjk/qs5;

    iput-object p6, p0, Llyiahf/vczjk/u08;->OooOOoo:Llyiahf/vczjk/qs5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/u08;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/vk;

    move-object/from16 v9, p2

    check-cast v9, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    const-string v2, "$this$AnimatedVisibility"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    const/16 v2, 0x10

    int-to-float v2, v2

    invoke-static {v1, v2, v2}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v2

    new-instance v10, Llyiahf/vczjk/u08;

    iget-object v12, v0, Llyiahf/vczjk/u08;->OooOOOO:Llyiahf/vczjk/h48;

    iget-object v15, v0, Llyiahf/vczjk/u08;->OooOOo:Llyiahf/vczjk/qs5;

    iget-object v1, v0, Llyiahf/vczjk/u08;->OooOOoo:Llyiahf/vczjk/qs5;

    iget-object v11, v0, Llyiahf/vczjk/u08;->OooOOO:Llyiahf/vczjk/xr1;

    iget-object v13, v0, Llyiahf/vczjk/u08;->OooOOOo:Llyiahf/vczjk/qs5;

    iget-object v14, v0, Llyiahf/vczjk/u08;->OooOOo0:Landroid/content/Context;

    const/16 v17, 0x0

    move-object/from16 v16, v1

    invoke-direct/range {v10 .. v17}, Llyiahf/vczjk/u08;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/h48;Llyiahf/vczjk/qs5;Landroid/content/Context;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;I)V

    const v1, 0x65cf4950

    invoke-static {v1, v10, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    const v10, 0x180006

    const/16 v11, 0x3e

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    invoke-static/range {v2 .. v11}, Llyiahf/vczjk/os9;->OooO0oO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/nx;Llyiahf/vczjk/px;Llyiahf/vczjk/n4;IILlyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/w73;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    const-string v4, "$this$FlowRow"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v3, 0x11

    const/16 v3, 0x10

    if-ne v1, v3, :cond_1

    move-object v1, v2

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_7

    :cond_1
    :goto_0
    move-object v13, v2

    check-cast v13, Llyiahf/vczjk/zf1;

    const v1, 0x2f223b41

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v5, v0, Llyiahf/vczjk/u08;->OooOOOo:Llyiahf/vczjk/qs5;

    invoke-interface {v5}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/i28;

    iget-object v1, v1, Llyiahf/vczjk/i28;->OooO0O0:Ljava/util/Set;

    invoke-interface {v1}, Ljava/util/Set;->size()I

    move-result v1

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    iget-object v4, v0, Llyiahf/vczjk/u08;->OooOOOO:Llyiahf/vczjk/h48;

    const/4 v9, 0x1

    const/4 v10, 0x0

    if-ne v1, v9, :cond_4

    const v1, -0x48fade91

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v3, v0, Llyiahf/vczjk/u08;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    iget-object v6, v0, Llyiahf/vczjk/u08;->OooOOo0:Landroid/content/Context;

    invoke-virtual {v13, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_3

    if-ne v2, v8, :cond_2

    goto :goto_1

    :cond_2
    move-object v1, v4

    goto :goto_2

    :cond_3
    :goto_1
    new-instance v2, Llyiahf/vczjk/c02;

    const/4 v7, 0x3

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/c02;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    move-object v1, v4

    invoke-virtual {v13, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_2
    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/le3;

    invoke-virtual {v13, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v12, Llyiahf/vczjk/xb1;->OooO0o:Llyiahf/vczjk/a91;

    const/high16 v14, 0x30000000

    const/16 v15, 0x1fe

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    move-object v2, v8

    const/4 v8, 0x0

    move v3, v9

    const/4 v9, 0x0

    move v11, v10

    const/4 v10, 0x0

    move/from16 v16, v11

    const/4 v11, 0x0

    move/from16 v3, v16

    invoke-static/range {v4 .. v15}, Llyiahf/vczjk/bua;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/se0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    invoke-static {v3, v13}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    goto :goto_3

    :cond_4
    move-object v1, v4

    move-object v2, v8

    move v3, v10

    :goto_3
    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v4, 0x4c5de2

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_5

    if-ne v6, v2, :cond_6

    :cond_5
    new-instance v6, Llyiahf/vczjk/l08;

    const/4 v5, 0x2

    invoke-direct {v6, v1, v5}, Llyiahf/vczjk/l08;-><init>(Llyiahf/vczjk/h48;I)V

    invoke-virtual {v13, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v6, Llyiahf/vczjk/le3;

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v12, Llyiahf/vczjk/xb1;->OooO0oO:Llyiahf/vczjk/a91;

    const/high16 v14, 0x30000000

    const/16 v15, 0x1fe

    const/4 v5, 0x0

    move v7, v4

    move-object v4, v6

    const/4 v6, 0x0

    move v8, v7

    const/4 v7, 0x0

    move v9, v8

    const/4 v8, 0x0

    move v10, v9

    const/4 v9, 0x0

    move v11, v10

    const/4 v10, 0x0

    move/from16 v17, v11

    const/4 v11, 0x0

    invoke-static/range {v4 .. v15}, Llyiahf/vczjk/bua;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/se0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    const v4, 0x2f22b653

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v4, v0, Llyiahf/vczjk/u08;->OooOOo:Llyiahf/vczjk/qs5;

    invoke-interface {v4}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    sget-object v5, Llyiahf/vczjk/v18;->OooO00o:Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;

    invoke-virtual {v5}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;->getId()Ljava/lang/String;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_9

    invoke-static {v3, v13}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    const v4, 0x4c5de2

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_7

    if-ne v6, v2, :cond_8

    :cond_7
    new-instance v6, Llyiahf/vczjk/l08;

    const/4 v5, 0x3

    invoke-direct {v6, v1, v5}, Llyiahf/vczjk/l08;-><init>(Llyiahf/vczjk/h48;I)V

    invoke-virtual {v13, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v6, Llyiahf/vczjk/le3;

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v12, Llyiahf/vczjk/xb1;->OooO0oo:Llyiahf/vczjk/a91;

    const/high16 v14, 0x30000000

    const/16 v15, 0x1fe

    const/4 v5, 0x0

    move/from16 v17, v4

    move-object v4, v6

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    invoke-static/range {v4 .. v15}, Llyiahf/vczjk/bua;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/se0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :cond_9
    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v3, v13}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    sget-object v4, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v5, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v5, v3}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v5

    iget v6, v13, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v13, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v13, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_a

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_a
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v13, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, v13, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v7, v13, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_b

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_c

    :cond_b
    invoke-static {v6, v13, v6, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_c
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v4, v13, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v4, 0x6e3c21fe

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v2, :cond_d

    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v4}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v4

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    check-cast v4, Llyiahf/vczjk/qs5;

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    iget-object v5, v0, Llyiahf/vczjk/u08;->OooOOoo:Llyiahf/vczjk/qs5;

    invoke-interface {v5}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/util/List;

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :cond_e
    :goto_5
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_f

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    move-object v8, v7

    check-cast v8, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;

    invoke-static {v8}, Llyiahf/vczjk/v18;->OooO00o(Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;)Z

    move-result v8

    if-nez v8, :cond_e

    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_5

    :cond_f
    new-instance v5, Ljava/util/ArrayList;

    const/16 v7, 0xa

    invoke-static {v6, v7}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v7

    invoke-direct {v5, v7}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :goto_6
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_10

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;

    new-instance v8, Llyiahf/vczjk/ah5;

    invoke-virtual {v7}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;->getId()Ljava/lang/String;

    move-result-object v9

    const-string v10, "getId(...)"

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v7}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;->getLabel()Ljava/lang/String;

    move-result-object v7

    const-string v10, "getLabel(...)"

    invoke-static {v7, v10}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget v10, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_folder_line:I

    invoke-direct {v8, v9, v7, v10}, Llyiahf/vczjk/ah5;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_6

    :cond_10
    const v7, 0x4c5de2

    invoke-virtual {v13, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v6, :cond_11

    if-ne v8, v2, :cond_12

    :cond_11
    new-instance v8, Llyiahf/vczjk/pz7;

    const/4 v6, 0x3

    invoke-direct {v8, v1, v6}, Llyiahf/vczjk/pz7;-><init>(Llyiahf/vczjk/h48;I)V

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_12
    check-cast v8, Llyiahf/vczjk/oe3;

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v6, 0x6

    invoke-static {v4, v5, v8, v13, v6}, Llyiahf/vczjk/so8;->OooO0o0(Llyiahf/vczjk/qs5;Ljava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v13, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v2, :cond_13

    new-instance v5, Llyiahf/vczjk/a67;

    const/16 v6, 0x9

    invoke-direct {v5, v4, v6}, Llyiahf/vczjk/a67;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    move-object v4, v5

    check-cast v4, Llyiahf/vczjk/le3;

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v12, Llyiahf/vczjk/xb1;->OooO:Llyiahf/vczjk/a91;

    const v14, 0x30000006

    const/16 v15, 0x1fe

    const/4 v5, 0x0

    const/4 v6, 0x0

    move/from16 v17, v7

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    invoke-static/range {v4 .. v15}, Llyiahf/vczjk/bua;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/se0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    const/4 v4, 0x1

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v3, v13}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    const v4, 0x4c5de2

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_14

    if-ne v6, v2, :cond_15

    :cond_14
    new-instance v6, Llyiahf/vczjk/l08;

    const/4 v5, 0x4

    invoke-direct {v6, v1, v5}, Llyiahf/vczjk/l08;-><init>(Llyiahf/vczjk/h48;I)V

    invoke-virtual {v13, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_15
    check-cast v6, Llyiahf/vczjk/le3;

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v12, Llyiahf/vczjk/xb1;->OooOO0:Llyiahf/vczjk/a91;

    const/high16 v14, 0x30000000

    const/16 v15, 0x1fe

    const/4 v5, 0x0

    move/from16 v17, v4

    move-object v4, v6

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    move/from16 v0, v17

    invoke-static/range {v4 .. v15}, Llyiahf/vczjk/bua;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/se0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    invoke-static {v3, v13}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    invoke-virtual {v13, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v0, :cond_16

    if-ne v4, v2, :cond_17

    :cond_16
    new-instance v4, Llyiahf/vczjk/l08;

    const/4 v0, 0x5

    invoke-direct {v4, v1, v0}, Llyiahf/vczjk/l08;-><init>(Llyiahf/vczjk/h48;I)V

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_17
    check-cast v4, Llyiahf/vczjk/le3;

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v12, Llyiahf/vczjk/xb1;->OooOO0O:Llyiahf/vczjk/a91;

    const/high16 v14, 0x30000000

    const/16 v15, 0x1fe

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    invoke-static/range {v4 .. v15}, Llyiahf/vczjk/bua;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/se0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_7
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
