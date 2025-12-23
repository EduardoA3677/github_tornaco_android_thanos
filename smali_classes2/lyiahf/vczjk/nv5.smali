.class public final Llyiahf/vczjk/nv5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/x39;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/x39;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/nv5;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/nv5;->OooOOO:Llyiahf/vczjk/x39;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/nv5;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

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

    goto :goto_4

    :cond_1
    :goto_0
    iget-object v1, v0, Llyiahf/vczjk/nv5;->OooOOO:Llyiahf/vczjk/x39;

    iget-object v3, v1, Llyiahf/vczjk/x39;->OooO0O0:Ljava/lang/Object;

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_3

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    sget-object v5, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/4 v6, 0x2

    int-to-float v6, v6

    invoke-static {v5, v6}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    iget-object v6, v1, Llyiahf/vczjk/x39;->OooO0O0:Ljava/lang/Object;

    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v6

    const/4 v7, 0x6

    if-le v6, v7, :cond_2

    const/16 v6, 0xe

    :goto_2
    int-to-float v6, v6

    goto :goto_3

    :cond_2
    const/16 v6, 0x12

    goto :goto_2

    :goto_3
    invoke-static {v5, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    const/4 v6, 0x0

    invoke-static {v5, v4, v2, v6}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    goto :goto_1

    :cond_3
    :goto_4
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/iw7;

    move-object/from16 v8, p2

    check-cast v8, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "$this$FilledTonalButton"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v2, 0x11

    const/16 v2, 0x10

    if-ne v1, v2, :cond_5

    move-object v1, v8

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_4

    goto :goto_5

    :cond_4
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v1, v0

    goto/16 :goto_6

    :cond_5
    :goto_5
    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->boost_status_running_apps:I

    invoke-static {v1, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v2

    sget-object v1, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    move-object v3, v8

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/n6a;

    iget-object v9, v1, Llyiahf/vczjk/n6a;->OooO0oo:Llyiahf/vczjk/rn9;

    const-wide v4, 0x4030800000000000L    # 16.5

    invoke-static {v4, v5}, Llyiahf/vczjk/eo6;->OooOO0O(D)J

    move-result-wide v12

    const/16 v22, 0x0

    const v23, 0xfffffd

    const-wide/16 v10, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const-wide/16 v17, 0x0

    const-wide/16 v19, 0x0

    const/16 v21, 0x0

    invoke-static/range {v9 .. v23}, Llyiahf/vczjk/rn9;->OooO00o(Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/ba3;JJLlyiahf/vczjk/vx6;Llyiahf/vczjk/jz4;I)Llyiahf/vczjk/rn9;

    move-result-object v20

    sget-object v1, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/x21;

    iget-wide v4, v4, Llyiahf/vczjk/x21;->OooOOo0:J

    const/16 v23, 0x0

    const v24, 0x1fffa

    move-object v6, v3

    const/4 v3, 0x0

    move-object v9, v6

    const-wide/16 v6, 0x0

    move-object/from16 v21, v8

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

    move-object/from16 v22, v19

    const/16 v19, 0x0

    move-object/from16 v25, v22

    const/16 v22, 0x0

    move-object/from16 v0, v25

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v8, v21

    const/4 v2, 0x0

    invoke-static {v2, v8}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/x21;

    iget-wide v3, v0, Llyiahf/vczjk/x21;->OooO00o:J

    new-instance v0, Llyiahf/vczjk/nv5;

    move-object/from16 v1, p0

    iget-object v2, v1, Llyiahf/vczjk/nv5;->OooOOO:Llyiahf/vczjk/x39;

    const/4 v5, 0x0

    invoke-direct {v0, v2, v5}, Llyiahf/vczjk/nv5;-><init>(Llyiahf/vczjk/x39;I)V

    const v2, 0x64fa9cae

    invoke-static {v2, v0, v8}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v7

    const/16 v9, 0xc00

    const/4 v10, 0x5

    const/4 v2, 0x0

    const-wide/16 v5, 0x0

    invoke-static/range {v2 .. v10}, Llyiahf/vczjk/l50;->OooO00o(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_6
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_1
    move-object v1, v0

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/iw7;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    const-string v4, "$this$Badge"

    invoke-static {v0, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v0, v3, 0x11

    const/16 v3, 0x10

    if-ne v0, v3, :cond_7

    move-object v0, v2

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_6

    goto :goto_7

    :cond_6
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_8

    :cond_7
    :goto_7
    iget-object v0, v1, Llyiahf/vczjk/nv5;->OooOOO:Llyiahf/vczjk/x39;

    iget v0, v0, Llyiahf/vczjk/x39;->OooO00o:I

    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v3

    move-object v10, v2

    check-cast v10, Llyiahf/vczjk/zf1;

    const v0, 0x20afa4f1

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const v0, 0x6e3c21fe

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, v2, :cond_8

    sget-object v0, Llyiahf/vczjk/g13;->Oooo000:Llyiahf/vczjk/g13;

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    move-object v5, v0

    check-cast v5, Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v2, Llyiahf/vczjk/k91;

    const/16 v4, 0xa

    invoke-direct {v2, v4}, Llyiahf/vczjk/k91;-><init>(I)V

    const v4, 0x72008807

    invoke-static {v4, v2, v10}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v9

    const v11, 0x180180

    const/16 v12, 0x3a

    const/4 v4, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    invoke-static/range {v3 .. v12}, Landroidx/compose/animation/OooO00o;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o4;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_8
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
