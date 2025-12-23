.class public final Llyiahf/vczjk/iv5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/iv5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

    const-string v0, "$this$AnimatedVisibility"

    const/4 v1, 0x0

    const/16 v2, 0x10

    const-string v3, "$this$BadgedBox"

    sget-object v4, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    move-object/from16 v5, p0

    iget v6, v5, Llyiahf/vczjk/iv5;->OooOOO0:I

    packed-switch v6, :pswitch_data_0

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/gh0;

    move-object/from16 v11, p2

    check-cast v11, Llyiahf/vczjk/rf1;

    move-object/from16 v6, p3

    check-cast v6, Ljava/lang/Number;

    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    move-result v6

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v0, v6, 0x11

    if-ne v0, v2, :cond_1

    move-object v0, v11

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_3

    :cond_1
    :goto_0
    const/16 v0, 0x18

    int-to-float v0, v0

    const/4 v2, 0x0

    const/4 v3, 0x6

    const/16 v6, 0x12c

    invoke-static {v6, v1, v2, v3}, Llyiahf/vczjk/ng0;->OooooO0(IILlyiahf/vczjk/ik2;I)Llyiahf/vczjk/h1a;

    move-result-object v1

    const/16 v2, 0x1b0

    const/16 v3, 0x8

    invoke-static {v0, v1, v11, v2, v3}, Llyiahf/vczjk/ti;->OooO00o(FLlyiahf/vczjk/p13;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/p29;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/ng0;->OooOO0O:Llyiahf/vczjk/qv3;

    if-eqz v1, :cond_2

    :goto_1
    move-object v6, v1

    goto :goto_2

    :cond_2
    new-instance v12, Llyiahf/vczjk/pv3;

    const/16 v20, 0x0

    const/16 v21, 0x0

    const-string v13, "Outlined.Menu"

    const/high16 v14, 0x41c00000    # 24.0f

    const/high16 v15, 0x41c00000    # 24.0f

    const/high16 v16, 0x41c00000    # 24.0f

    const/high16 v17, 0x41c00000    # 24.0f

    const-wide/16 v18, 0x0

    const/16 v22, 0x60

    invoke-direct/range {v12 .. v22}, Llyiahf/vczjk/pv3;-><init>(Ljava/lang/String;FFFFJIZI)V

    sget v1, Llyiahf/vczjk/tda;->OooO00o:I

    new-instance v1, Llyiahf/vczjk/gx8;

    sget-wide v2, Llyiahf/vczjk/n21;->OooO0O0:J

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/gx8;-><init>(J)V

    new-instance v2, Llyiahf/vczjk/jq;

    const/4 v3, 0x1

    invoke-direct {v2, v3}, Llyiahf/vczjk/jq;-><init>(I)V

    const/high16 v3, 0x40400000    # 3.0f

    const/high16 v6, 0x41900000    # 18.0f

    invoke-virtual {v2, v3, v6}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v2, v6}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v7, -0x40000000    # -2.0f

    invoke-virtual {v2, v7}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    const/high16 v8, 0x41800000    # 16.0f

    invoke-virtual {v2, v3, v8}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    const/high16 v8, 0x40000000    # 2.0f

    invoke-virtual {v2, v8}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v2}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v9, 0x41500000    # 13.0f

    invoke-virtual {v2, v3, v9}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v2, v6}, Llyiahf/vczjk/jq;->OooO0o(F)V

    invoke-virtual {v2, v7}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    const/high16 v7, 0x41300000    # 11.0f

    invoke-virtual {v2, v3, v7}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v2, v8}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v2}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v7, 0x40c00000    # 6.0f

    invoke-virtual {v2, v3, v7}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    invoke-virtual {v2, v8}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v2, v6}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v6, 0x41a80000    # 21.0f

    invoke-virtual {v2, v6, v7}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v2, v3, v7}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v2}, Llyiahf/vczjk/jq;->OooO0O0()V

    iget-object v2, v2, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    invoke-static {v12, v2, v1}, Llyiahf/vczjk/pv3;->OooO00o(Llyiahf/vczjk/pv3;Ljava/util/ArrayList;Llyiahf/vczjk/gx8;)V

    invoke-virtual {v12}, Llyiahf/vczjk/pv3;->OooO0O0()Llyiahf/vczjk/qv3;

    move-result-object v1

    sput-object v1, Llyiahf/vczjk/ng0;->OooOO0O:Llyiahf/vczjk/qv3;

    goto :goto_1

    :goto_2
    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/wd2;

    iget v0, v0, Llyiahf/vczjk/wd2;->OooOOO0:F

    invoke-static {v1, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v8

    const/16 v12, 0x30

    const/16 v13, 0x8

    const/4 v7, 0x0

    const-wide/16 v9, 0x0

    invoke-static/range {v6 .. v13}, Llyiahf/vczjk/yt3;->OooO00o(Llyiahf/vczjk/qv3;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    :goto_3
    return-object v4

    :pswitch_0
    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/gh0;

    move-object/from16 v1, p2

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v6, p3

    check-cast v6, Ljava/lang/Number;

    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    move-result v6

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v0, v6, 0x11

    if-ne v0, v2, :cond_4

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_4

    :cond_3
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :cond_4
    :goto_4
    return-object v4

    :pswitch_1
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/vk;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v4

    :pswitch_2
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/vk;

    move-object/from16 v3, p2

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v6, p3

    check-cast v6, Ljava/lang/Number;

    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/ya1;->OooO00o:Llyiahf/vczjk/a91;

    invoke-virtual {v1, v3, v0}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object v4

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
