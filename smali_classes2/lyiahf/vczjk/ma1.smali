.class public final Llyiahf/vczjk/ma1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field final synthetic $context$inlined:Landroid/content/Context;

.field final synthetic $items:Ljava/util/List;


# direct methods
.method public constructor <init>(Ljava/util/ArrayList;Landroid/content/Context;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ma1;->$items:Ljava/util/List;

    iput-object p2, p0, Llyiahf/vczjk/ma1;->$context$inlined:Landroid/content/Context;

    const/4 p1, 0x4

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Landroidx/compose/foundation/lazy/OooO00o;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    move-object/from16 v3, p3

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v4, p4

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    move-result v4

    and-int/lit8 v5, v4, 0x6

    if-nez v5, :cond_1

    move-object v5, v3

    check-cast v5, Llyiahf/vczjk/zf1;

    invoke-virtual {v5, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v1, 0x4

    goto :goto_0

    :cond_0
    const/4 v1, 0x2

    :goto_0
    or-int/2addr v1, v4

    goto :goto_1

    :cond_1
    move v1, v4

    :goto_1
    and-int/lit8 v4, v4, 0x30

    if-nez v4, :cond_3

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4, v2}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v4

    if-eqz v4, :cond_2

    const/16 v4, 0x20

    goto :goto_2

    :cond_2
    const/16 v4, 0x10

    :goto_2
    or-int/2addr v1, v4

    :cond_3
    and-int/lit16 v4, v1, 0x93

    const/16 v5, 0x92

    const/4 v6, 0x1

    const/4 v7, 0x0

    if-eq v4, v5, :cond_4

    move v4, v6

    goto :goto_3

    :cond_4
    move v4, v7

    :goto_3
    and-int/2addr v1, v6

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v1, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_9

    iget-object v1, v0, Llyiahf/vczjk/ma1;->$items:Ljava/util/List;

    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ww2;

    const v2, -0x553e1a52

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const v2, 0x6e3c21fe

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v4, v5, :cond_5

    iget-object v4, v0, Llyiahf/vczjk/ma1;->$context$inlined:Landroid/content/Context;

    iget v6, v1, Llyiahf/vczjk/ww2;->OooO00o:I

    invoke-static {v4, v6}, Llyiahf/vczjk/hw;->OooO00o(Landroid/content/Context;I)Z

    move-result v4

    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v4

    invoke-static {v4}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v4

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v4, Llyiahf/vczjk/qs5;

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    iget v6, v1, Llyiahf/vczjk/ww2;->OooO0O0:I

    invoke-static {v6, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v8

    invoke-interface {v4}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/Boolean;

    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v13

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v5, :cond_6

    sget-object v2, Llyiahf/vczjk/dk0;->OooOOOO:Llyiahf/vczjk/dk0;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    move-object v14, v2

    check-cast v14, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v2, -0x6815fd56

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v2, v0, Llyiahf/vczjk/ma1;->$context$inlined:Landroid/content/Context;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v2, v6

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v2, :cond_7

    if-ne v6, v5, :cond_8

    :cond_7
    new-instance v6, Llyiahf/vczjk/r60;

    iget-object v2, v0, Llyiahf/vczjk/ma1;->$context$inlined:Landroid/content/Context;

    const/4 v5, 0x1

    invoke-direct {v6, v5, v2, v1, v4}, Llyiahf/vczjk/r60;-><init>(ILjava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/qs5;)V

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    move-object v15, v6

    check-cast v15, Llyiahf/vczjk/oe3;

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/high16 v17, 0x180000

    const/16 v18, 0x1e

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    move-object/from16 v16, v3

    invoke-static/range {v8 .. v18}, Llyiahf/vczjk/e16;->OooO0O0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;ZLlyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_4

    :cond_9
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_4
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
