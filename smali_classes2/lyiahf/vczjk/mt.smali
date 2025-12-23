.class public final Llyiahf/vczjk/mt;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/mt;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/mt;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/hv3;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Llyiahf/vczjk/mt;->OooOOO0:I

    sget-object v0, Llyiahf/vczjk/bi3;->OooOOO0:Llyiahf/vczjk/bi3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/mt;->OooOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/mt;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Landroidx/compose/foundation/lazy/OooO00o;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-object/from16 v2, p3

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p4

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    const-string v4, "$this$stickyHeader"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit16 v1, v3, 0x81

    const/16 v3, 0x80

    if-ne v1, v3, :cond_1

    move-object v1, v2

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    iget-object v1, v0, Llyiahf/vczjk/mt;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s67;

    iget-object v1, v1, Llyiahf/vczjk/s67;->OooO0Oo:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    const/4 v3, 0x0

    invoke-static {v1, v3, v2}, Llyiahf/vczjk/vt6;->OooO0o(IILlyiahf/vczjk/rf1;)V

    :goto_1
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/pl6;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-object/from16 v2, p3

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p4

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    const-string v4, "$this$HorizontalPager"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit16 v1, v3, 0x81

    const/16 v3, 0x80

    if-ne v1, v3, :cond_3

    move-object v1, v2

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3

    :cond_3
    :goto_2
    sget-object v1, Llyiahf/vczjk/mb6;->OooO00o:Ljava/util/List;

    iget-object v3, v0, Llyiahf/vczjk/mt;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/km6;

    invoke-virtual {v3}, Llyiahf/vczjk/km6;->OooO0oo()I

    move-result v3

    invoke-interface {v1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ib6;

    const/4 v3, 0x0

    invoke-static {v1, v2, v3}, Llyiahf/vczjk/r02;->OooO0o0(Llyiahf/vczjk/ib6;Llyiahf/vczjk/rf1;I)V

    :goto_3
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_1
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/kh0;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/dv3;

    move-object/from16 v3, p3

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v4, p4

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    move-result v4

    const-string v5, "$this$ImageRequest"

    invoke-static {v1, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "imageState"

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v4, 0x30

    if-nez v1, :cond_5

    move-object v1, v3

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_4

    const/16 v1, 0x20

    goto :goto_4

    :cond_4
    const/16 v1, 0x10

    :goto_4
    or-int/2addr v4, v1

    :cond_5
    and-int/lit16 v1, v4, 0x91

    const/16 v4, 0x90

    if-ne v1, v4, :cond_7

    move-object v1, v3

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_6

    goto :goto_5

    :cond_6
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_6

    :cond_7
    :goto_5
    sget-object v1, Llyiahf/vczjk/bi3;->OooOOO0:Llyiahf/vczjk/bi3;

    invoke-static {v2, v1}, Llyiahf/vczjk/jp8;->Ooooo00(Llyiahf/vczjk/dv3;Llyiahf/vczjk/bi3;)Llyiahf/vczjk/ph3;

    move-result-object v1

    instance-of v2, v1, Llyiahf/vczjk/oh3;

    if-eqz v2, :cond_8

    check-cast v1, Llyiahf/vczjk/oh3;

    iget-object v1, v1, Llyiahf/vczjk/oh3;->OooO00o:Ljava/lang/Object;

    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    check-cast v1, Landroid/graphics/drawable/Drawable;

    sget-object v4, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    const/16 v5, 0x30

    invoke-static {v1, v4, v3, v5}, Llyiahf/vczjk/ls6;->OooOOo0(Landroid/graphics/drawable/Drawable;Ljava/util/List;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/un6;

    move-result-object v1

    iget-object v4, v0, Llyiahf/vczjk/mt;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/hv3;

    invoke-static {v4, v2, v1, v3, v5}, Llyiahf/vczjk/zsa;->OooOO0(Llyiahf/vczjk/hv3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/un6;Llyiahf/vczjk/rf1;I)V

    :cond_8
    :goto_6
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_2
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/gh0;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v2

    move-object/from16 v6, p3

    check-cast v6, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p4

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    const-string v4, "$this$ReorderableItem"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v3, 0x30

    if-nez v1, :cond_a

    move-object v1, v6

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v1

    if-eqz v1, :cond_9

    const/16 v1, 0x20

    goto :goto_7

    :cond_9
    const/16 v1, 0x10

    :goto_7
    or-int/2addr v3, v1

    :cond_a
    and-int/lit16 v1, v3, 0x91

    const/16 v3, 0x90

    if-ne v1, v3, :cond_c

    move-object v1, v6

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_b

    goto :goto_8

    :cond_b
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_c

    :cond_c
    :goto_8
    const/high16 v1, 0x3f800000    # 1.0f

    if-eqz v2, :cond_d

    const v2, 0x3f87ae14    # 1.06f

    move v3, v2

    goto :goto_9

    :cond_d
    move v3, v1

    :goto_9
    const/16 v7, 0xc00

    const/16 v8, 0x16

    const/4 v4, 0x0

    const-string v5, "ScaleAnim"

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/ti;->OooO0O0(FLlyiahf/vczjk/p13;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/p29;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    move-result v8

    sget-object v7, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    cmpg-float v1, v8, v1

    if-nez v1, :cond_e

    if-nez v1, :cond_e

    :goto_a
    move-object v3, v7

    goto :goto_b

    :cond_e
    const/4 v12, 0x0

    const v15, 0x1fffc

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    move v9, v8

    invoke-static/range {v7 .. v15}, Landroidx/compose/ui/graphics/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;FFFFFLlyiahf/vczjk/qj8;ZI)Llyiahf/vczjk/kl5;

    move-result-object v7

    goto :goto_a

    :goto_b
    iget-object v1, v0, Llyiahf/vczjk/mt;->OooOOO:Ljava/lang/Object;

    check-cast v1, Lgithub/tornaco/android/thanos/module/compose/common/widget/SortItem;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/module/compose/common/widget/SortItem;->OooO0O0()Ljava/lang/String;

    move-result-object v4

    const/4 v8, 0x0

    const/16 v9, 0x1c

    const/4 v5, 0x0

    move-object v7, v6

    const/4 v6, 0x0

    invoke-static/range {v3 .. v9}, Llyiahf/vczjk/e16;->OooO0oo(Llyiahf/vczjk/kl5;Ljava/lang/String;Llyiahf/vczjk/ze3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    :goto_c
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_3
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/q31;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/String;

    move-object/from16 v3, p3

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v4, p4

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    move-result v4

    const-string v5, "$this$ThanoxBottomSheet"

    invoke-static {v1, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "it"

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit16 v1, v4, 0x81

    const/16 v2, 0x80

    if-ne v1, v2, :cond_10

    move-object v1, v3

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_f

    goto :goto_d

    :cond_f
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_e

    :cond_10
    :goto_d
    check-cast v3, Llyiahf/vczjk/zf1;

    const v1, 0x4c5de2

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v1, v0, Llyiahf/vczjk/mt;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/yo9;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v2, :cond_11

    if-ne v4, v5, :cond_12

    :cond_11
    new-instance v4, Llyiahf/vczjk/lt;

    const/4 v2, 0x0

    invoke-direct {v4, v1, v2}, Llyiahf/vczjk/lt;-><init>(Llyiahf/vczjk/yo9;I)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_12
    check-cast v4, Llyiahf/vczjk/le3;

    const/4 v1, 0x0

    const v2, 0x6e3c21fe

    invoke-static {v3, v1, v2}, Llyiahf/vczjk/ix8;->OooO0o0(Llyiahf/vczjk/zf1;ZI)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v5, :cond_13

    new-instance v2, Llyiahf/vczjk/oOOO0OO0;

    const/16 v5, 0x16

    invoke-direct {v2, v5}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    check-cast v2, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v5, 0x30

    invoke-static {v4, v2, v3, v5, v1}, Llyiahf/vczjk/rs;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    invoke-static {v1, v3}, Llyiahf/vczjk/dn8;->OooOooo(ILlyiahf/vczjk/rf1;)V

    :goto_e
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
