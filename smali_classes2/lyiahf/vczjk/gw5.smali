.class public final Llyiahf/vczjk/gw5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field final synthetic $activity$inlined:Landroidx/appcompat/app/AppCompatActivity;

.field final synthetic $createShortcut$inlined:Llyiahf/vczjk/oe3;

.field final synthetic $items:Ljava/util/List;

.field final synthetic $onItemClick$inlined:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(Ljava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Landroidx/appcompat/app/AppCompatActivity;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gw5;->$items:Ljava/util/List;

    iput-object p2, p0, Llyiahf/vczjk/gw5;->$onItemClick$inlined:Llyiahf/vczjk/oe3;

    iput-object p3, p0, Llyiahf/vczjk/gw5;->$createShortcut$inlined:Llyiahf/vczjk/oe3;

    iput-object p4, p0, Llyiahf/vczjk/gw5;->$activity$inlined:Landroidx/appcompat/app/AppCompatActivity;

    const/4 p1, 0x4

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/eq4;

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

    move-object v12, v3

    check-cast v12, Llyiahf/vczjk/zf1;

    invoke-virtual {v12, v1, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_e

    iget-object v1, v0, Llyiahf/vczjk/gw5;->$items:Ljava/util/List;

    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ww2;

    const v2, -0x376cb36f

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/16 v3, 0x8

    int-to-float v3, v3

    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v3, v7}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v3

    iget v4, v12, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v12, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_5

    invoke-virtual {v12, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_5
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v12, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v12, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_6

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v5, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_7

    :cond_6
    invoke-static {v4, v12, v4, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_7
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v12, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v2, 0x4c5de2

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v3, :cond_8

    if-ne v4, v5, :cond_9

    :cond_8
    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v3}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v4

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    move-object v14, v4

    check-cast v14, Llyiahf/vczjk/qs5;

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_a

    if-ne v3, v5, :cond_b

    :cond_a
    iget-object v3, v1, Llyiahf/vczjk/ww2;->OooO0oO:Ljava/util/List;

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    move-object v15, v3

    check-cast v15, Ljava/util/List;

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    iget-object v2, v0, Llyiahf/vczjk/gw5;->$onItemClick$inlined:Llyiahf/vczjk/oe3;

    const v3, -0x615d173a

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v3, v0, Llyiahf/vczjk/gw5;->$createShortcut$inlined:Llyiahf/vczjk/oe3;

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v12, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v3, v4

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_c

    if-ne v4, v5, :cond_d

    :cond_c
    new-instance v4, Llyiahf/vczjk/o0oOO;

    iget-object v3, v0, Llyiahf/vczjk/gw5;->$createShortcut$inlined:Llyiahf/vczjk/oe3;

    const/16 v5, 0xa

    invoke-direct {v4, v5, v3, v14}, Llyiahf/vczjk/o0oOO;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    check-cast v4, Llyiahf/vczjk/oe3;

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v1, v2, v4, v12, v7}, Llyiahf/vczjk/yi4;->OooO(Llyiahf/vczjk/ww2;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object v2, Llyiahf/vczjk/cl8;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/al8;

    const/16 v3, 0x12

    int-to-float v3, v3

    invoke-static {v3}, Llyiahf/vczjk/uv7;->OooO00o(F)Llyiahf/vczjk/tv7;

    move-result-object v3

    invoke-static {v2, v3}, Llyiahf/vczjk/al8;->OooO00o(Llyiahf/vczjk/al8;Llyiahf/vczjk/tv7;)Llyiahf/vczjk/al8;

    move-result-object v9

    new-instance v13, Llyiahf/vczjk/ha2;

    iget-object v2, v0, Llyiahf/vczjk/gw5;->$createShortcut$inlined:Llyiahf/vczjk/oe3;

    iget-object v3, v0, Llyiahf/vczjk/gw5;->$activity$inlined:Landroidx/appcompat/app/AppCompatActivity;

    const/16 v19, 0x2

    move-object/from16 v17, v1

    move-object/from16 v16, v2

    move-object/from16 v18, v3

    invoke-direct/range {v13 .. v19}, Llyiahf/vczjk/ha2;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    const v1, 0xd9b83a6

    invoke-static {v1, v13, v12}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v11

    const/4 v10, 0x0

    const/16 v13, 0xc00

    const/4 v8, 0x0

    invoke-static/range {v8 .. v13}, Llyiahf/vczjk/we5;->OooO0OO(Llyiahf/vczjk/x21;Llyiahf/vczjk/al8;Llyiahf/vczjk/n6a;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_5

    :cond_e
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_5
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
