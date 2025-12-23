.class public final Llyiahf/vczjk/o60;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/e60;Landroid/content/Context;Llyiahf/vczjk/g70;Llyiahf/vczjk/qs5;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/o60;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/o60;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/o60;->OooOOOo:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/o60;->OooOOo0:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/o60;->OooOOO:Llyiahf/vczjk/qs5;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/h48;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/o60;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/o60;->OooOOO:Llyiahf/vczjk/qs5;

    iput-object p2, p0, Llyiahf/vczjk/o60;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/o60;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/o60;->OooOOo0:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/o60;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/ql6;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    move-object/from16 v3, p3

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v4, p4

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    const-string v4, "$this$HorizontalPager"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, v0, Llyiahf/vczjk/o60;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/qs5;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Map;

    iget-object v4, v0, Llyiahf/vczjk/o60;->OooOOo0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/qs5;

    invoke-interface {v4}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/util/List;

    invoke-interface {v4, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    invoke-interface {v1, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/List;

    if-nez v1, :cond_0

    sget-object v1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :cond_0
    new-instance v4, Llyiahf/vczjk/yj3;

    const/16 v2, 0x50

    int-to-float v2, v2

    invoke-direct {v4, v2}, Llyiahf/vczjk/yj3;-><init>(F)V

    sget-object v5, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    const/16 v2, 0x20

    int-to-float v2, v2

    const/4 v6, 0x7

    const/4 v7, 0x0

    invoke-static {v7, v7, v7, v2, v6}, Landroidx/compose/foundation/layout/OooO00o;->OooO0OO(FFFFI)Llyiahf/vczjk/di6;

    move-result-object v7

    move-object v15, v3

    check-cast v15, Llyiahf/vczjk/zf1;

    const v2, -0x6815fd56

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    iget-object v3, v0, Llyiahf/vczjk/o60;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v2, v6

    iget-object v6, v0, Llyiahf/vczjk/o60;->OooOOOO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/h48;

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v2, v8

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v2, :cond_1

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v8, v2, :cond_2

    :cond_1
    new-instance v8, Llyiahf/vczjk/oo0ooO;

    const/16 v2, 0x13

    invoke-direct {v8, v1, v3, v2, v6}, Llyiahf/vczjk/oo0ooO;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2
    move-object v14, v8

    check-cast v14, Llyiahf/vczjk/oe3;

    const/4 v1, 0x0

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v17, 0x0

    const/16 v18, 0x3f4

    const/4 v6, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/16 v16, 0xc30

    invoke-static/range {v4 .. v18}, Llyiahf/vczjk/yi4;->OooOOO0(Llyiahf/vczjk/ak3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/er4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/nx;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;III)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/eq4;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-object/from16 v8, p3

    check-cast v8, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p4

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "$this$stickyHeader"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit16 v1, v2, 0x81

    const/16 v2, 0x80

    if-ne v1, v2, :cond_4

    move-object v1, v8

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_3

    goto :goto_0

    :cond_3
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_a

    :cond_4
    :goto_0
    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    move-object v11, v8

    check-cast v11, Llyiahf/vczjk/zf1;

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/x21;

    iget-wide v4, v4, Llyiahf/vczjk/x21;->OooOOO:J

    sget-object v6, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v3, v4, v5, v6}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v5, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v12, 0x0

    invoke-static {v4, v5, v8, v12}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v4

    iget v5, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v8, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v7, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_5

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_5
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v14, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v4, v8, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v15, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v6, v8, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v6, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_6

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_7

    :cond_6
    invoke-static {v5, v11, v5, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_7
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v8, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v3, v0, Llyiahf/vczjk/o60;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/e60;

    iget-object v6, v3, Llyiahf/vczjk/e60;->OooO0o:Llyiahf/vczjk/lc9;

    const v7, 0x3fa88743

    invoke-virtual {v11, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v7, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const v10, 0x4c5de2

    if-nez v6, :cond_8

    move-object/from16 v20, v3

    move-object/from16 v19, v5

    move-object/from16 v21, v7

    move v2, v12

    move-object v12, v4

    goto/16 :goto_2

    :cond_8
    invoke-static {v12, v8}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    invoke-virtual {v11, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v16

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v16, :cond_9

    if-ne v10, v7, :cond_a

    :cond_9
    iget-boolean v10, v6, Llyiahf/vczjk/lc9;->OooO0O0:Z

    invoke-static {v10}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v10

    invoke-static {v10}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v10

    invoke-virtual {v11, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    check-cast v10, Llyiahf/vczjk/qs5;

    invoke-virtual {v11, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-interface {v10}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v16

    move-object/from16 v2, v16

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    iget-object v12, v6, Llyiahf/vczjk/lc9;->OooO00o:Llyiahf/vczjk/ze3;

    iget-object v9, v0, Llyiahf/vczjk/o60;->OooOOOo:Ljava/lang/Object;

    check-cast v9, Landroid/content/Context;

    invoke-interface {v12, v9, v2}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    sget-object v9, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v9

    iget-object v12, v3, Llyiahf/vczjk/e60;->OooO0Oo:Llyiahf/vczjk/oe3;

    invoke-interface {v12, v9}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/String;

    invoke-interface {v10}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Ljava/lang/Boolean;

    invoke-virtual {v12}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v12

    move-object/from16 v16, v2

    move-object/from16 p4, v3

    const/16 v2, 0x10

    int-to-float v3, v2

    const/4 v2, 0x0

    move-object/from16 v18, v4

    const/4 v4, 0x2

    invoke-static {v1, v3, v2, v4}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v3

    const v2, -0x615d173a

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v11, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v2, v4

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v2, :cond_b

    if-ne v4, v7, :cond_c

    :cond_b
    new-instance v4, Llyiahf/vczjk/o0OO000o;

    const/4 v2, 0x5

    invoke-direct {v4, v2, v6, v10}, Llyiahf/vczjk/o0OO000o;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    check-cast v4, Llyiahf/vczjk/oe3;

    const/4 v2, 0x0

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v6, v9

    const/4 v9, 0x6

    const/4 v10, 0x0

    move-object/from16 v20, p4

    move-object/from16 v19, v5

    move-object/from16 v21, v7

    move-object/from16 v5, v16

    move-object v7, v4

    move v4, v12

    move-object/from16 v12, v18

    invoke-static/range {v3 .. v10}, Llyiahf/vczjk/er8;->OooOO0(Llyiahf/vczjk/kl5;ZLjava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    :goto_2
    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/16 v3, 0x10

    int-to-float v3, v3

    const/16 v4, 0x8

    int-to-float v4, v4

    invoke-static {v2, v3, v4}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v5, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    sget-object v6, Llyiahf/vczjk/op3;->OooOo0o:Llyiahf/vczjk/tb0;

    const/4 v7, 0x0

    invoke-static {v5, v6, v8, v7}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v5

    iget v6, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v8, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_d

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_d
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    invoke-static {v5, v8, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v7, v8, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v5, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_f

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_e

    goto :goto_5

    :cond_e
    :goto_4
    move-object/from16 v5, v19

    goto :goto_6

    :cond_f
    :goto_5
    invoke-static {v6, v11, v6, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    goto :goto_4

    :goto_6
    invoke-static {v2, v8, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object/from16 v2, v20

    iget-object v2, v2, Llyiahf/vczjk/e60;->OooO0OO:Llyiahf/vczjk/du;

    iget-object v2, v2, Llyiahf/vczjk/du;->OooO00o:Llyiahf/vczjk/cu;

    instance-of v2, v2, Llyiahf/vczjk/au;

    iget-object v12, v0, Llyiahf/vczjk/o60;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/yu;

    const v13, 0x4c5de2

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v6, v0, Llyiahf/vczjk/o60;->OooOOo0:Ljava/lang/Object;

    move-object v14, v6

    check-cast v14, Llyiahf/vczjk/g70;

    invoke-virtual {v11, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    move-object/from16 v15, v21

    if-nez v6, :cond_10

    if-ne v7, v15, :cond_11

    :cond_10
    new-instance v7, Llyiahf/vczjk/n60;

    const/4 v6, 0x0

    invoke-direct {v7, v14, v6}, Llyiahf/vczjk/n60;-><init>(Llyiahf/vczjk/g70;I)V

    invoke-virtual {v11, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_11
    check-cast v7, Llyiahf/vczjk/oe3;

    const/4 v6, 0x0

    invoke-virtual {v11, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v5, v7, v2, v8, v6}, Llyiahf/vczjk/qqa;->OooO00o(Llyiahf/vczjk/yu;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;I)V

    if-eqz v2, :cond_12

    move v5, v4

    goto :goto_7

    :cond_12
    move v5, v3

    :goto_7
    invoke-static {v1, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-static {v8, v5}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/yu;

    iget-object v5, v5, Llyiahf/vczjk/yu;->OooO0oO:Llyiahf/vczjk/vw;

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/yu;

    iget-object v6, v6, Llyiahf/vczjk/yu;->OooO:Ljava/util/List;

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/yu;

    iget-boolean v7, v7, Llyiahf/vczjk/yu;->OooO0oo:Z

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v9, :cond_13

    if-ne v10, v15, :cond_14

    :cond_13
    new-instance v10, Llyiahf/vczjk/n60;

    const/4 v9, 0x1

    invoke-direct {v10, v14, v9}, Llyiahf/vczjk/n60;-><init>(Llyiahf/vczjk/g70;I)V

    invoke-virtual {v11, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_14
    check-cast v10, Llyiahf/vczjk/oe3;

    const/4 v9, 0x0

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v9, :cond_15

    if-ne v13, v15, :cond_16

    :cond_15
    new-instance v13, Llyiahf/vczjk/n60;

    const/4 v9, 0x2

    invoke-direct {v13, v14, v9}, Llyiahf/vczjk/n60;-><init>(Llyiahf/vczjk/g70;I)V

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_16
    check-cast v13, Llyiahf/vczjk/oe3;

    const/4 v9, 0x0

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move v9, v4

    move-object v4, v6

    move-object v6, v10

    const/4 v10, 0x0

    move-object/from16 v22, v8

    move v8, v2

    move v2, v3

    move-object v3, v5

    move v5, v7

    move-object v7, v13

    move v13, v9

    move-object/from16 v9, v22

    invoke-static/range {v3 .. v10}, Llyiahf/vczjk/vt6;->OooOOO(Llyiahf/vczjk/vw;Ljava/util/List;ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;I)V

    move v3, v8

    move-object v8, v9

    if-eqz v3, :cond_17

    goto :goto_8

    :cond_17
    move v13, v2

    :goto_8
    invoke-static {v1, v13}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v8, v1}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const v1, -0x2a4f6d6e

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/yu;

    iget-object v1, v1, Llyiahf/vczjk/yu;->OooO0o0:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_1a

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/yu;

    const v13, 0x4c5de2

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v2, :cond_18

    if-ne v4, v15, :cond_19

    :cond_18
    new-instance v4, Llyiahf/vczjk/n60;

    const/4 v2, 0x3

    invoke-direct {v4, v14, v2}, Llyiahf/vczjk/n60;-><init>(Llyiahf/vczjk/g70;I)V

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_19
    check-cast v4, Llyiahf/vczjk/oe3;

    const/4 v9, 0x0

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v1, v4, v3, v8, v9}, Llyiahf/vczjk/qqa;->OooO0o(Llyiahf/vczjk/yu;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;I)V

    goto :goto_9

    :cond_1a
    const/4 v9, 0x0

    :goto_9
    const/4 v1, 0x1

    invoke-static {v11, v9, v1, v1}, Llyiahf/vczjk/ii5;->OooOo0O(Llyiahf/vczjk/zf1;ZZZ)V

    :goto_a
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
