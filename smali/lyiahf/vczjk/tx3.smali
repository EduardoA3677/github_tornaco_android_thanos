.class public final Llyiahf/vczjk/tx3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/tx3;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/tx3;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/tx3;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p2

    const/4 v2, 0x3

    const/4 v3, 0x2

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x1

    sget-object v7, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v8, v0, Llyiahf/vczjk/tx3;->OooOOOO:Ljava/lang/Object;

    iget-object v9, v0, Llyiahf/vczjk/tx3;->OooOOO:Ljava/lang/Object;

    iget v10, v0, Llyiahf/vczjk/tx3;->OooOOO0:I

    packed-switch v10, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/al1;

    check-cast v9, Llyiahf/vczjk/pa6;

    check-cast v8, Llyiahf/vczjk/ara;

    invoke-interface {v9, v8, v1}, Llyiahf/vczjk/pa6;->OooO00o(Llyiahf/vczjk/ara;Llyiahf/vczjk/al1;)V

    return-object v7

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/j24;

    instance-of v2, v1, Llyiahf/vczjk/q37;

    check-cast v9, Llyiahf/vczjk/fl7;

    if-eqz v2, :cond_0

    iget v1, v9, Llyiahf/vczjk/fl7;->element:I

    add-int/2addr v1, v6

    iput v1, v9, Llyiahf/vczjk/fl7;->element:I

    goto :goto_0

    :cond_0
    instance-of v2, v1, Llyiahf/vczjk/r37;

    if-eqz v2, :cond_1

    iget v1, v9, Llyiahf/vczjk/fl7;->element:I

    add-int/lit8 v1, v1, -0x1

    iput v1, v9, Llyiahf/vczjk/fl7;->element:I

    goto :goto_0

    :cond_1
    instance-of v1, v1, Llyiahf/vczjk/p37;

    if-eqz v1, :cond_2

    iget v1, v9, Llyiahf/vczjk/fl7;->element:I

    add-int/lit8 v1, v1, -0x1

    iput v1, v9, Llyiahf/vczjk/fl7;->element:I

    :cond_2
    :goto_0
    iget v1, v9, Llyiahf/vczjk/fl7;->element:I

    if-lez v1, :cond_3

    move v5, v6

    :cond_3
    check-cast v8, Llyiahf/vczjk/sr9;

    iget-boolean v1, v8, Llyiahf/vczjk/sr9;->OooOooO:Z

    if-eq v1, v5, :cond_4

    iput-boolean v5, v8, Llyiahf/vczjk/sr9;->OooOooO:Z

    invoke-static {v8}, Llyiahf/vczjk/t51;->Oooo00o(Llyiahf/vczjk/go4;)V

    :cond_4
    return-object v7

    :pswitch_1
    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/p86;

    iget-wide v5, v3, Llyiahf/vczjk/p86;->OooO00o:J

    check-cast v9, Llyiahf/vczjk/gi;

    invoke-virtual {v9}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/p86;

    iget-wide v10, v3, Llyiahf/vczjk/p86;->OooO00o:J

    const-wide v12, 0x7fffffff7fffffffL

    and-long/2addr v10, v12

    const-wide v14, 0x7fc000007fc00000L    # 2.247117487993712E307

    cmp-long v3, v10, v14

    if-eqz v3, :cond_6

    and-long v10, v5, v12

    cmp-long v3, v10, v14

    if-eqz v3, :cond_6

    invoke-virtual {v9}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/p86;

    iget-wide v10, v3, Llyiahf/vczjk/p86;->OooO00o:J

    const-wide v12, 0xffffffffL

    and-long/2addr v10, v12

    long-to-int v3, v10

    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v3

    and-long v10, v5, v12

    long-to-int v10, v10

    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v10

    cmpg-float v3, v3, v10

    if-nez v3, :cond_5

    goto :goto_1

    :cond_5
    new-instance v1, Llyiahf/vczjk/ee8;

    invoke-direct {v1, v9, v5, v6, v4}, Llyiahf/vczjk/ee8;-><init>(Llyiahf/vczjk/gi;JLlyiahf/vczjk/yo1;)V

    check-cast v8, Llyiahf/vczjk/xr1;

    invoke-static {v8, v4, v4, v1, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_2

    :cond_6
    :goto_1
    new-instance v2, Llyiahf/vczjk/p86;

    invoke-direct {v2, v5, v6}, Llyiahf/vczjk/p86;-><init>(J)V

    invoke-virtual {v9, v2, v1}, Llyiahf/vczjk/gi;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne v1, v2, :cond_7

    move-object v7, v1

    :cond_7
    :goto_2
    return-object v7

    :pswitch_2
    move-object/from16 v1, p1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    check-cast v8, Llyiahf/vczjk/p29;

    invoke-interface {v8}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/List;

    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    move-result v2

    if-nez v2, :cond_8

    if-ltz v1, :cond_8

    invoke-interface {v8}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/List;

    invoke-interface {v2}, Ljava/util/Collection;->size()I

    move-result v2

    if-ge v1, v2, :cond_8

    invoke-interface {v8}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/List;

    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;

    check-cast v9, Llyiahf/vczjk/h48;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v2, "set"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v3, v9, Llyiahf/vczjk/h48;->OooO0o0:Llyiahf/vczjk/x58;

    invoke-virtual {v1}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;->getId()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v3, v2, v1}, Llyiahf/vczjk/x58;->OooO0OO(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v9}, Llyiahf/vczjk/h48;->OooO0oo()V

    :cond_8
    return-object v7

    :pswitch_3
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/j24;

    instance-of v5, v1, Llyiahf/vczjk/s37;

    check-cast v9, Llyiahf/vczjk/cu7;

    if-eqz v5, :cond_a

    iget-boolean v2, v9, Llyiahf/vczjk/cu7;->Oooo0:Z

    if-eqz v2, :cond_9

    check-cast v1, Llyiahf/vczjk/s37;

    invoke-virtual {v9, v1}, Llyiahf/vczjk/cu7;->o00000OO(Llyiahf/vczjk/s37;)V

    goto/16 :goto_8

    :cond_9
    iget-object v2, v9, Llyiahf/vczjk/cu7;->Oooo0O0:Llyiahf/vczjk/as5;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/as5;->OooO0oO(Ljava/lang/Object;)V

    goto/16 :goto_8

    :cond_a
    iget-object v5, v9, Llyiahf/vczjk/cu7;->Oooo000:Llyiahf/vczjk/w29;

    if-nez v5, :cond_b

    new-instance v5, Llyiahf/vczjk/w29;

    iget-object v6, v9, Llyiahf/vczjk/cu7;->OooOooo:Llyiahf/vczjk/le3;

    iget-boolean v10, v9, Llyiahf/vczjk/cu7;->OooOoo0:Z

    invoke-direct {v5, v6, v10}, Llyiahf/vczjk/w29;-><init>(Llyiahf/vczjk/le3;Z)V

    invoke-static {v9}, Llyiahf/vczjk/ye5;->OooOoO0(Llyiahf/vczjk/fg2;)V

    iput-object v5, v9, Llyiahf/vczjk/cu7;->Oooo000:Llyiahf/vczjk/w29;

    :cond_b
    instance-of v6, v1, Llyiahf/vczjk/wo3;

    iget-object v9, v5, Llyiahf/vczjk/w29;->OooO0Oo:Ljava/util/ArrayList;

    if-eqz v6, :cond_c

    invoke-virtual {v9, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_c
    instance-of v10, v1, Llyiahf/vczjk/xo3;

    if-eqz v10, :cond_d

    move-object v10, v1

    check-cast v10, Llyiahf/vczjk/xo3;

    iget-object v10, v10, Llyiahf/vczjk/xo3;->OooO00o:Llyiahf/vczjk/wo3;

    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_d
    instance-of v10, v1, Llyiahf/vczjk/g83;

    if-eqz v10, :cond_e

    invoke-virtual {v9, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_e
    instance-of v10, v1, Llyiahf/vczjk/h83;

    if-eqz v10, :cond_f

    move-object v10, v1

    check-cast v10, Llyiahf/vczjk/h83;

    iget-object v10, v10, Llyiahf/vczjk/h83;->OooO00o:Llyiahf/vczjk/g83;

    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_f
    instance-of v10, v1, Llyiahf/vczjk/mf2;

    if-eqz v10, :cond_10

    invoke-virtual {v9, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_10
    instance-of v10, v1, Llyiahf/vczjk/nf2;

    if-eqz v10, :cond_11

    move-object v10, v1

    check-cast v10, Llyiahf/vczjk/nf2;

    iget-object v10, v10, Llyiahf/vczjk/nf2;->OooO00o:Llyiahf/vczjk/mf2;

    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_11
    instance-of v10, v1, Llyiahf/vczjk/lf2;

    if-eqz v10, :cond_1c

    move-object v10, v1

    check-cast v10, Llyiahf/vczjk/lf2;

    iget-object v10, v10, Llyiahf/vczjk/lf2;->OooO00o:Llyiahf/vczjk/mf2;

    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    :goto_3
    invoke-static {v9}, Llyiahf/vczjk/d21;->o0OO00O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/j24;

    iget-object v10, v5, Llyiahf/vczjk/w29;->OooO0o0:Llyiahf/vczjk/j24;

    invoke-static {v10, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_1c

    check-cast v8, Llyiahf/vczjk/xr1;

    if-eqz v9, :cond_18

    iget-object v10, v5, Llyiahf/vczjk/w29;->OooO0O0:Llyiahf/vczjk/le3;

    invoke-interface {v10}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/st7;

    if-eqz v6, :cond_12

    iget v1, v10, Llyiahf/vczjk/st7;->OooO0OO:F

    goto :goto_4

    :cond_12
    instance-of v6, v1, Llyiahf/vczjk/g83;

    if-eqz v6, :cond_13

    iget v1, v10, Llyiahf/vczjk/st7;->OooO0O0:F

    goto :goto_4

    :cond_13
    instance-of v1, v1, Llyiahf/vczjk/mf2;

    if-eqz v1, :cond_14

    iget v1, v10, Llyiahf/vczjk/st7;->OooO00o:F

    goto :goto_4

    :cond_14
    const/4 v1, 0x0

    :goto_4
    sget-object v6, Llyiahf/vczjk/yt7;->OooO00o:Llyiahf/vczjk/h1a;

    instance-of v6, v9, Llyiahf/vczjk/wo3;

    sget-object v10, Llyiahf/vczjk/yt7;->OooO00o:Llyiahf/vczjk/h1a;

    if-eqz v6, :cond_15

    goto :goto_5

    :cond_15
    instance-of v6, v9, Llyiahf/vczjk/g83;

    const/16 v11, 0x2d

    if-eqz v6, :cond_16

    new-instance v10, Llyiahf/vczjk/h1a;

    sget-object v6, Llyiahf/vczjk/jk2;->OooO0Oo:Llyiahf/vczjk/oOO0O00O;

    invoke-direct {v10, v11, v6, v3}, Llyiahf/vczjk/h1a;-><init>(ILlyiahf/vczjk/ik2;I)V

    goto :goto_5

    :cond_16
    instance-of v6, v9, Llyiahf/vczjk/mf2;

    if-eqz v6, :cond_17

    new-instance v10, Llyiahf/vczjk/h1a;

    sget-object v6, Llyiahf/vczjk/jk2;->OooO0Oo:Llyiahf/vczjk/oOO0O00O;

    invoke-direct {v10, v11, v6, v3}, Llyiahf/vczjk/h1a;-><init>(ILlyiahf/vczjk/ik2;I)V

    :cond_17
    :goto_5
    new-instance v3, Llyiahf/vczjk/u29;

    invoke-direct {v3, v5, v1, v10, v4}, Llyiahf/vczjk/u29;-><init>(Llyiahf/vczjk/w29;FLlyiahf/vczjk/wl;Llyiahf/vczjk/yo1;)V

    invoke-static {v8, v4, v4, v3, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_7

    :cond_18
    iget-object v1, v5, Llyiahf/vczjk/w29;->OooO0o0:Llyiahf/vczjk/j24;

    sget-object v6, Llyiahf/vczjk/yt7;->OooO00o:Llyiahf/vczjk/h1a;

    instance-of v6, v1, Llyiahf/vczjk/wo3;

    sget-object v10, Llyiahf/vczjk/yt7;->OooO00o:Llyiahf/vczjk/h1a;

    if-eqz v6, :cond_19

    goto :goto_6

    :cond_19
    instance-of v6, v1, Llyiahf/vczjk/g83;

    if-eqz v6, :cond_1a

    goto :goto_6

    :cond_1a
    instance-of v1, v1, Llyiahf/vczjk/mf2;

    if-eqz v1, :cond_1b

    new-instance v10, Llyiahf/vczjk/h1a;

    sget-object v1, Llyiahf/vczjk/jk2;->OooO0Oo:Llyiahf/vczjk/oOO0O00O;

    const/16 v6, 0x96

    invoke-direct {v10, v6, v1, v3}, Llyiahf/vczjk/h1a;-><init>(ILlyiahf/vczjk/ik2;I)V

    :cond_1b
    :goto_6
    new-instance v1, Llyiahf/vczjk/v29;

    invoke-direct {v1, v5, v10, v4}, Llyiahf/vczjk/v29;-><init>(Llyiahf/vczjk/w29;Llyiahf/vczjk/wl;Llyiahf/vczjk/yo1;)V

    invoke-static {v8, v4, v4, v1, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :goto_7
    iput-object v9, v5, Llyiahf/vczjk/w29;->OooO0o0:Llyiahf/vczjk/j24;

    :cond_1c
    :goto_8
    return-object v7

    :pswitch_4
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/mu6;

    sget-object v2, Llyiahf/vczjk/ku6;->OooO00o:Llyiahf/vczjk/ku6;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    check-cast v9, Landroid/content/Context;

    if-eqz v2, :cond_1d

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->module_locker_title_verify_custom_pin_settings_complete:I

    invoke-static {v9, v1, v5}, Landroid/widget/Toast;->makeText(Landroid/content/Context;II)Landroid/widget/Toast;

    move-result-object v1

    invoke-virtual {v1}, Landroid/widget/Toast;->show()V

    check-cast v8, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PinSettingsActivity;

    invoke-virtual {v8}, Landroid/app/Activity;->finish()V

    goto :goto_9

    :cond_1d
    sget-object v2, Llyiahf/vczjk/lu6;->OooO00o:Llyiahf/vczjk/lu6;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1e

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->module_locker_title_verify_custom_pin_settings_mismatch:I

    invoke-static {v9, v1, v5}, Landroid/widget/Toast;->makeText(Landroid/content/Context;II)Landroid/widget/Toast;

    move-result-object v1

    invoke-virtual {v1}, Landroid/widget/Toast;->show()V

    :goto_9
    return-object v7

    :cond_1e
    new-instance v1, Llyiahf/vczjk/k61;

    invoke-direct {v1}, Ljava/lang/RuntimeException;-><init>()V

    throw v1

    :pswitch_5
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/sr6;

    sget-object v2, Llyiahf/vczjk/qr6;->OooO00o:Llyiahf/vczjk/qr6;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    check-cast v9, Landroid/content/Context;

    if-eqz v2, :cond_1f

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->module_locker_title_verify_custom_pattern_settings_draw_set_complete:I

    invoke-static {v9, v1, v5}, Landroid/widget/Toast;->makeText(Landroid/content/Context;II)Landroid/widget/Toast;

    move-result-object v1

    invoke-virtual {v1}, Landroid/widget/Toast;->show()V

    check-cast v8, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PatternSettingsActivity;

    invoke-virtual {v8}, Landroid/app/Activity;->finish()V

    goto :goto_a

    :cond_1f
    sget-object v2, Llyiahf/vczjk/rr6;->OooO00o:Llyiahf/vczjk/rr6;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_20

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->module_locker_title_verify_custom_pattern_settings_draw_mismatch:I

    invoke-static {v9, v1, v5}, Landroid/widget/Toast;->makeText(Landroid/content/Context;II)Landroid/widget/Toast;

    move-result-object v1

    invoke-virtual {v1}, Landroid/widget/Toast;->show()V

    :goto_a
    return-object v7

    :cond_20
    new-instance v1, Llyiahf/vczjk/k61;

    invoke-direct {v1}, Ljava/lang/RuntimeException;-><init>()V

    throw v1

    :pswitch_6
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/li6;

    sget-object v10, Landroid/os/Build;->ID:Ljava/lang/String;

    const-string v11, "Paging"

    if-eqz v10, :cond_21

    invoke-static {v11, v3}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result v3

    if-eqz v3, :cond_21

    move v5, v6

    :cond_21
    if-eqz v5, :cond_22

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v5, "Collected "

    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    const-string v5, "message"

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v11, v3, v4}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_22
    check-cast v9, Llyiahf/vczjk/kn6;

    iget-object v3, v9, Llyiahf/vczjk/kn6;->OooO00o:Llyiahf/vczjk/or1;

    new-instance v5, Llyiahf/vczjk/hn6;

    check-cast v8, Llyiahf/vczjk/xm6;

    invoke-direct {v5, v2, v9, v8, v4}, Llyiahf/vczjk/hn6;-><init>(Llyiahf/vczjk/li6;Llyiahf/vczjk/kn6;Llyiahf/vczjk/xm6;Llyiahf/vczjk/yo1;)V

    invoke-static {v3, v5, v1}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne v1, v2, :cond_23

    move-object v7, v1

    :cond_23
    return-object v7

    :pswitch_7
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/xg3;

    check-cast v9, Llyiahf/vczjk/pj6;

    check-cast v8, Llyiahf/vczjk/s25;

    invoke-static {v9, v8, v2, v1}, Llyiahf/vczjk/pj6;->OooO0O0(Llyiahf/vczjk/pj6;Llyiahf/vczjk/s25;Llyiahf/vczjk/xg3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne v1, v2, :cond_24

    move-object v7, v1

    :cond_24
    return-object v7

    :pswitch_8
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/j24;

    instance-of v2, v1, Llyiahf/vczjk/wo3;

    if-eqz v2, :cond_25

    move v2, v6

    goto :goto_b

    :cond_25
    instance-of v2, v1, Llyiahf/vczjk/g83;

    :goto_b
    if-eqz v2, :cond_26

    move v2, v6

    goto :goto_c

    :cond_26
    instance-of v2, v1, Llyiahf/vczjk/q37;

    :goto_c
    check-cast v9, Llyiahf/vczjk/as5;

    if-eqz v2, :cond_27

    invoke-virtual {v9, v1}, Llyiahf/vczjk/as5;->OooO0oO(Ljava/lang/Object;)V

    goto :goto_d

    :cond_27
    instance-of v2, v1, Llyiahf/vczjk/xo3;

    if-eqz v2, :cond_28

    check-cast v1, Llyiahf/vczjk/xo3;

    iget-object v1, v1, Llyiahf/vczjk/xo3;->OooO00o:Llyiahf/vczjk/wo3;

    invoke-virtual {v9, v1}, Llyiahf/vczjk/as5;->OooOO0(Ljava/lang/Object;)Z

    goto :goto_d

    :cond_28
    instance-of v2, v1, Llyiahf/vczjk/h83;

    if-eqz v2, :cond_29

    check-cast v1, Llyiahf/vczjk/h83;

    iget-object v1, v1, Llyiahf/vczjk/h83;->OooO00o:Llyiahf/vczjk/g83;

    invoke-virtual {v9, v1}, Llyiahf/vczjk/as5;->OooOO0(Ljava/lang/Object;)Z

    goto :goto_d

    :cond_29
    instance-of v2, v1, Llyiahf/vczjk/r37;

    if-eqz v2, :cond_2a

    check-cast v1, Llyiahf/vczjk/r37;

    iget-object v1, v1, Llyiahf/vczjk/r37;->OooO00o:Llyiahf/vczjk/q37;

    invoke-virtual {v9, v1}, Llyiahf/vczjk/as5;->OooOO0(Ljava/lang/Object;)Z

    goto :goto_d

    :cond_2a
    instance-of v2, v1, Llyiahf/vczjk/p37;

    if-eqz v2, :cond_2b

    check-cast v1, Llyiahf/vczjk/p37;

    iget-object v1, v1, Llyiahf/vczjk/p37;->OooO00o:Llyiahf/vczjk/q37;

    invoke-virtual {v9, v1}, Llyiahf/vczjk/as5;->OooOO0(Ljava/lang/Object;)Z

    :cond_2b
    :goto_d
    iget-object v1, v9, Llyiahf/vczjk/c76;->OooO00o:[Ljava/lang/Object;

    iget v2, v9, Llyiahf/vczjk/c76;->OooO0O0:I

    move v4, v5

    :goto_e
    move-object v9, v8

    check-cast v9, Llyiahf/vczjk/i05;

    if-ge v5, v2, :cond_2f

    aget-object v10, v1, v5

    check-cast v10, Llyiahf/vczjk/j24;

    instance-of v11, v10, Llyiahf/vczjk/wo3;

    if-eqz v11, :cond_2c

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    or-int/2addr v4, v3

    goto :goto_f

    :cond_2c
    instance-of v11, v10, Llyiahf/vczjk/g83;

    if-eqz v11, :cond_2d

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    or-int/2addr v4, v6

    goto :goto_f

    :cond_2d
    instance-of v10, v10, Llyiahf/vczjk/q37;

    if-eqz v10, :cond_2e

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    or-int/lit8 v4, v4, 0x4

    :cond_2e
    :goto_f
    add-int/2addr v5, v6

    goto :goto_e

    :cond_2f
    iget-object v1, v9, Llyiahf/vczjk/i05;->OooO0O0:Llyiahf/vczjk/qr5;

    check-cast v1, Llyiahf/vczjk/bw8;

    invoke-virtual {v1, v4}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    return-object v7

    :pswitch_9
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/j24;

    instance-of v2, v1, Llyiahf/vczjk/g83;

    check-cast v9, Ljava/util/ArrayList;

    if-eqz v2, :cond_30

    invoke-virtual {v9, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_10

    :cond_30
    instance-of v2, v1, Llyiahf/vczjk/h83;

    if-eqz v2, :cond_31

    check-cast v1, Llyiahf/vczjk/h83;

    iget-object v1, v1, Llyiahf/vczjk/h83;->OooO00o:Llyiahf/vczjk/g83;

    invoke-virtual {v9, v1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    :cond_31
    :goto_10
    invoke-virtual {v9}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v1

    xor-int/2addr v1, v6

    check-cast v8, Llyiahf/vczjk/vx3;

    iget-boolean v2, v8, Llyiahf/vczjk/vx3;->Oooo00O:Z

    if-eq v1, v2, :cond_32

    iput-boolean v1, v8, Llyiahf/vczjk/vx3;->Oooo00O:Z

    invoke-virtual {v8}, Llyiahf/vczjk/vx3;->o00000oO()V

    :cond_32
    return-object v7

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
