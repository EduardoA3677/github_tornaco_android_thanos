.class public final Llyiahf/vczjk/er8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/gr8;


# static fields
.field public static final synthetic OooO0O0:I


# instance fields
.field public final synthetic OooO00o:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/er8;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static final OooO(Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 12

    const-string v0, "onBackPressed"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onItemSelected"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onCenterSelected"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v9, p3

    check-cast v9, Llyiahf/vczjk/zf1;

    const v0, -0x8f543d8

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v9, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int v0, p4, v0

    invoke-virtual {v9, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1

    const/16 v4, 0x20

    goto :goto_1

    :cond_1
    const/16 v4, 0x10

    :goto_1
    or-int/2addr v0, v4

    invoke-virtual {v9, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_2

    const/16 v4, 0x100

    goto :goto_2

    :cond_2
    const/16 v4, 0x80

    :goto_2
    or-int/2addr v0, v4

    and-int/lit16 v4, v0, 0x93

    const/16 v5, 0x92

    if-ne v4, v5, :cond_4

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_5

    :cond_4
    :goto_3
    const v4, 0x70b323c8

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-static {v9}, Llyiahf/vczjk/c45;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lha;

    move-result-object v4

    if-eqz v4, :cond_9

    invoke-static {v4, v9}, Llyiahf/vczjk/mc4;->OooOo0O(Llyiahf/vczjk/lha;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/sn3;

    move-result-object v5

    const v6, 0x671a9c9b

    invoke-virtual {v9, v6}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    instance-of v6, v4, Llyiahf/vczjk/om3;

    if-eqz v6, :cond_5

    move-object v6, v4

    check-cast v6, Llyiahf/vczjk/om3;

    invoke-interface {v6}, Llyiahf/vczjk/om3;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v6

    goto :goto_4

    :cond_5
    sget-object v6, Llyiahf/vczjk/ms1;->OooO0O0:Llyiahf/vczjk/ms1;

    :goto_4
    const-class v7, Llyiahf/vczjk/n19;

    invoke-static {v7, v4, v5, v6, v9}, Llyiahf/vczjk/eo6;->OooOooO(Ljava/lang/Class;Llyiahf/vczjk/lha;Llyiahf/vczjk/sn3;Llyiahf/vczjk/os1;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/dha;

    move-result-object v4

    const/4 v5, 0x0

    invoke-virtual {v9, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v9, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    check-cast v4, Llyiahf/vczjk/n19;

    iget-object v6, v4, Llyiahf/vczjk/n19;->OooO0Oo:Llyiahf/vczjk/gh7;

    invoke-static {v6, v9}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v6

    const v7, 0x4c5de2

    invoke-virtual {v9, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v7, :cond_6

    sget-object v7, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v8, v7, :cond_7

    :cond_6
    new-instance v8, Llyiahf/vczjk/i19;

    const/4 v7, 0x0

    invoke-direct {v8, v4, v7}, Llyiahf/vczjk/i19;-><init>(Llyiahf/vczjk/n19;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v9, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v8, Llyiahf/vczjk/ze3;

    invoke-virtual {v9, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v4, v9, v8}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/bd1;->OooO00o:Llyiahf/vczjk/a91;

    new-instance v5, Llyiahf/vczjk/u20;

    const/16 v7, 0x19

    invoke-direct {v5, v4, v7}, Llyiahf/vczjk/u20;-><init>(Ljava/lang/Object;I)V

    const v7, -0x53790b56

    invoke-static {v7, v5, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    new-instance v2, Llyiahf/vczjk/a6;

    const/16 v7, 0xf

    move-object v5, v4

    move-object v3, v6

    move-object v4, p1

    move-object v6, p2

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/a6;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    const v3, -0x30b9f997

    invoke-static {v3, v2, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    shl-int/lit8 v0, v0, 0xc

    const v3, 0xe000

    and-int/2addr v0, v3

    const v3, 0x60001b0

    or-int v10, v0, v3

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v0, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    const/16 v11, 0xe9

    move-object v4, v8

    move-object v8, v2

    move-object v2, v4

    move-object v4, p0

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/xr6;->OooO0Oo(Llyiahf/vczjk/hl5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/hb8;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_5
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_8

    new-instance v0, Llyiahf/vczjk/h19;

    const/4 v5, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move/from16 v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/h19;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_8
    return-void

    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static final OooO0OO(Llyiahf/vczjk/ur0;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 17

    move-object/from16 v0, p1

    move/from16 v1, p3

    const-string v2, "onCategorySelected"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v10, p2

    check-cast v10, Llyiahf/vczjk/zf1;

    const v2, 0x15faf65

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v2, v1, 0x6

    const/4 v3, 0x2

    if-nez v2, :cond_1

    invoke-virtual/range {p0 .. p0}, Ljava/lang/Enum;->ordinal()I

    move-result v2

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v2

    if-eqz v2, :cond_0

    const/4 v2, 0x4

    goto :goto_0

    :cond_0
    move v2, v3

    :goto_0
    or-int/2addr v2, v1

    goto :goto_1

    :cond_1
    move v2, v1

    :goto_1
    and-int/lit8 v4, v1, 0x30

    const/16 v5, 0x10

    if-nez v4, :cond_3

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_2

    const/16 v4, 0x20

    goto :goto_2

    :cond_2
    move v4, v5

    :goto_2
    or-int/2addr v2, v4

    :cond_3
    and-int/lit8 v2, v2, 0x13

    const/16 v4, 0x12

    if-ne v2, v4, :cond_5

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_4

    goto :goto_3

    :cond_4
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_5

    :cond_5
    :goto_3
    const v2, 0x6e3c21fe

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    sget-object v13, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, v13, :cond_6

    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v2}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v2

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v2, Llyiahf/vczjk/qs5;

    const/4 v14, 0x0

    invoke-virtual {v10, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v15, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    int-to-float v4, v5

    invoke-static {v15, v4}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v4, v5, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooOo00(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ub0;I)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-static {v5, v14}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v4

    iget v5, v10, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v10, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v7, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v8, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_7

    invoke-virtual {v10, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_7
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v4, v10, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v6, v10, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v6, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_8

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_9

    :cond_8
    invoke-static {v5, v10, v5, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_9
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v10, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual/range {p0 .. p0}, Llyiahf/vczjk/ur0;->OooO00o()I

    move-result v3

    invoke-static {v3, v10}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v3

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Boolean;

    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    const v5, 0x4c5de2

    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-ne v6, v13, :cond_a

    new-instance v6, Llyiahf/vczjk/a67;

    const/16 v7, 0xc

    invoke-direct {v6, v2, v7}, Llyiahf/vczjk/a67;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v10, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    check-cast v6, Llyiahf/vczjk/le3;

    invoke-virtual {v10, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v8, 0x0

    const/4 v9, 0x0

    move v7, v5

    move-object v5, v6

    const/4 v6, 0x0

    move v11, v7

    const/4 v7, 0x0

    move v12, v11

    const/16 v11, 0x180

    move/from16 v16, v12

    const/16 v12, 0x78

    move/from16 v14, v16

    invoke-static/range {v3 .. v12}, Llyiahf/vczjk/zsa;->OooO0o0(Ljava/lang/String;ZLlyiahf/vczjk/le3;Llyiahf/vczjk/hl5;Llyiahf/vczjk/qv3;Llyiahf/vczjk/qv3;ZLlyiahf/vczjk/rf1;II)V

    sget-object v3, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/x21;

    iget-wide v3, v3, Llyiahf/vczjk/x21;->OooOOOo:J

    sget-object v5, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v15, v3, v4, v5}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Boolean;

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    invoke-virtual {v10, v14}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v13, :cond_b

    new-instance v4, Llyiahf/vczjk/a67;

    const/16 v6, 0xd

    invoke-direct {v4, v2, v6}, Llyiahf/vczjk/a67;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v10, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    check-cast v4, Llyiahf/vczjk/le3;

    const/4 v6, 0x0

    invoke-virtual {v10, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v6, Llyiahf/vczjk/r6;

    const/16 v7, 0x16

    invoke-direct {v6, v7, v0, v2}, Llyiahf/vczjk/r6;-><init>(ILjava/lang/Object;Llyiahf/vczjk/qs5;)V

    const v2, -0x6eb5e7e2

    invoke-static {v2, v6, v10}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    const/4 v8, 0x0

    const/4 v9, 0x0

    const-wide/16 v6, 0x0

    const v12, 0x180030

    const/16 v13, 0x38

    move-object v11, v10

    move-object v10, v2

    invoke-static/range {v3 .. v13}, Llyiahf/vczjk/ge;->OooO00o(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/z98;Llyiahf/vczjk/d07;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    move-object v10, v11

    const/4 v2, 0x1

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_5
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v2

    if-eqz v2, :cond_c

    new-instance v3, Llyiahf/vczjk/rt;

    const/4 v4, 0x5

    move-object/from16 v5, p0

    invoke-direct {v3, v5, v0, v1, v4}, Llyiahf/vczjk/rt;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v3, v2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_c
    return-void
.end method

.method public static final OooO0Oo(IFLlyiahf/vczjk/jr1;Ljava/util/List;)Llyiahf/vczjk/aw7;
    .locals 8

    const-string v0, "rounding"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    mul-int/lit8 v0, p0, 0x2

    new-array v0, v0, [F

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    const/4 v3, 0x0

    if-ge v1, p0, :cond_0

    sget v4, Llyiahf/vczjk/tba;->OooO0O0:F

    int-to-float v5, p0

    div-float/2addr v4, v5

    const/4 v5, 0x2

    int-to-float v6, v5

    mul-float/2addr v4, v6

    int-to-float v6, v1

    mul-float/2addr v4, v6

    invoke-static {p1, v4}, Llyiahf/vczjk/tba;->OooO0o0(FF)J

    move-result-wide v6

    invoke-static {v3, v3}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide v3

    invoke-static {v6, v7, v3, v4}, Llyiahf/vczjk/rl6;->OooOo0O(JJ)J

    move-result-wide v3

    add-int/lit8 v6, v2, 0x1

    invoke-static {v3, v4}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v7

    aput v7, v0, v2

    add-int/2addr v2, v5

    invoke-static {v3, v4}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result v3

    aput v3, v0, v6

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    invoke-static {v0, p2, p3, v3, v3}, Llyiahf/vczjk/er8;->OooO0o0([FLlyiahf/vczjk/jr1;Ljava/util/List;FF)Llyiahf/vczjk/aw7;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/gp3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V
    .locals 17

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    const-string v0, "currentColor"

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onSaturationValueChanged"

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v0, p3

    check-cast v0, Llyiahf/vczjk/zf1;

    const v4, -0x2a5b025c

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 v4, 0x4

    goto :goto_0

    :cond_0
    const/4 v4, 0x2

    :goto_0
    or-int v4, p4, v4

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1

    const/16 v5, 0x20

    goto :goto_1

    :cond_1
    const/16 v5, 0x10

    :goto_1
    or-int/2addr v4, v5

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    const/16 v7, 0x100

    if-eqz v5, :cond_2

    move v5, v7

    goto :goto_2

    :cond_2
    const/16 v5, 0x80

    :goto_2
    or-int/2addr v4, v5

    and-int/lit16 v5, v4, 0x93

    const/16 v8, 0x92

    if-ne v5, v8, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_6

    :cond_4
    :goto_3
    const v5, 0x6e3c21fe

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const-wide v9, 0xffffffffL

    if-ne v5, v8, :cond_5

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooO0o0(J)J

    move-result-wide v11

    new-instance v5, Llyiahf/vczjk/n21;

    invoke-direct {v5, v11, v12}, Llyiahf/vczjk/n21;-><init>(J)V

    const-wide v11, 0xff000000L

    invoke-static {v11, v12}, Llyiahf/vczjk/v34;->OooO0o0(J)J

    move-result-wide v11

    new-instance v13, Llyiahf/vczjk/n21;

    invoke-direct {v13, v11, v12}, Llyiahf/vczjk/n21;-><init>(J)V

    filled-new-array {v5, v13}, [Llyiahf/vczjk/n21;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v5

    const/16 v11, 0xe

    const/4 v12, 0x0

    invoke-static {v5, v12, v12, v11}, Llyiahf/vczjk/vp3;->OooOOOo(Ljava/util/List;FFI)Llyiahf/vczjk/rz4;

    move-result-object v5

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v5, Llyiahf/vczjk/ri0;

    const/4 v11, 0x0

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v12, 0x4c5de2

    invoke-virtual {v0, v12}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget v13, v2, Llyiahf/vczjk/gp3;->OooO00o:F

    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v14

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v15

    if-nez v14, :cond_6

    if-ne v15, v8, :cond_8

    :cond_6
    new-instance v14, Llyiahf/vczjk/yk3;

    const/high16 v15, 0x3f800000    # 1.0f

    invoke-direct {v14, v13, v15, v15, v15}, Llyiahf/vczjk/yk3;-><init>(FFFF)V

    invoke-virtual {v14}, Llyiahf/vczjk/yk3;->OooO0O0()Llyiahf/vczjk/zf7;

    move-result-object v13

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooO0o0(J)J

    move-result-wide v9

    new-instance v14, Llyiahf/vczjk/n21;

    invoke-direct {v14, v9, v10}, Llyiahf/vczjk/n21;-><init>(J)V

    const/16 v9, 0xff

    int-to-float v9, v9

    iget v10, v13, Llyiahf/vczjk/zf7;->OooO00o:F

    mul-float/2addr v10, v9

    invoke-static {v10}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v10

    iget v15, v13, Llyiahf/vczjk/zf7;->OooO0O0:F

    mul-float/2addr v15, v9

    invoke-static {v15}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v15

    iget v6, v13, Llyiahf/vczjk/zf7;->OooO0OO:F

    mul-float/2addr v6, v9

    invoke-static {v6}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v6

    iget v13, v13, Llyiahf/vczjk/zf7;->OooO0Oo:F

    invoke-static {v13}, Ljava/lang/Float;->isNaN(F)Z

    move-result v16

    if-eqz v16, :cond_7

    const/high16 v13, 0x3f800000    # 1.0f

    :cond_7
    mul-float/2addr v13, v9

    invoke-static {v13}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v9

    invoke-static {v10, v15, v6, v9}, Llyiahf/vczjk/v34;->OooO0Oo(IIII)J

    move-result-wide v9

    new-instance v6, Llyiahf/vczjk/n21;

    invoke-direct {v6, v9, v10}, Llyiahf/vczjk/n21;-><init>(J)V

    filled-new-array {v14, v6}, [Llyiahf/vczjk/n21;

    move-result-object v6

    invoke-static {v6}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v6

    invoke-static {v6}, Llyiahf/vczjk/vp3;->OooOOO0(Ljava/util/List;)Llyiahf/vczjk/rz4;

    move-result-object v15

    invoke-virtual {v0, v15}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v15, Llyiahf/vczjk/ri0;

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v6, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-interface {v1, v6}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v9, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, v12}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit16 v10, v4, 0x380

    const/4 v12, 0x1

    if-ne v10, v7, :cond_9

    move v7, v12

    goto :goto_4

    :cond_9
    move v7, v11

    :goto_4
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v7, :cond_a

    if-ne v10, v8, :cond_b

    :cond_a
    new-instance v10, Llyiahf/vczjk/o0000O0;

    const/4 v7, 0x5

    invoke-direct {v10, v3, v7}, Llyiahf/vczjk/o0000O0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    check-cast v10, Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v6, v9, v10}, Llyiahf/vczjk/gb9;->OooO00o(Llyiahf/vczjk/kl5;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Llyiahf/vczjk/kl5;

    move-result-object v6

    const v7, -0x6815fd56

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v0, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    and-int/lit8 v4, v4, 0x70

    const/16 v9, 0x20

    if-ne v4, v9, :cond_c

    goto :goto_5

    :cond_c
    move v12, v11

    :goto_5
    or-int v4, v7, v12

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v4, :cond_d

    if-ne v7, v8, :cond_e

    :cond_d
    new-instance v7, Llyiahf/vczjk/oo0ooO;

    const/16 v4, 0x14

    invoke-direct {v7, v5, v15, v4, v2}, Llyiahf/vczjk/oo0ooO;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    check-cast v7, Llyiahf/vczjk/oe3;

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v6, v7, v0, v11}, Llyiahf/vczjk/vc6;->OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    :goto_6
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_f

    new-instance v0, Llyiahf/vczjk/o0OO00OO;

    const/16 v5, 0x11

    move/from16 v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/o0OO00OO;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_f
    return-void
.end method

.method public static final OooO0o0([FLlyiahf/vczjk/jr1;Ljava/util/List;FF)Llyiahf/vczjk/aw7;
    .locals 35

    move-object/from16 v0, p0

    move-object/from16 v1, p2

    const/4 v2, 0x2

    const/4 v3, 0x1

    const-string v4, "rounding"

    move-object/from16 v5, p1

    invoke-static {v5, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    array-length v4, v0

    const/4 v6, 0x6

    if-lt v4, v6, :cond_18

    array-length v4, v0

    rem-int/2addr v4, v2

    if-eq v4, v3, :cond_17

    if-eqz v1, :cond_1

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v4

    mul-int/2addr v4, v2

    array-length v6, v0

    if-ne v4, v6, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "perVertexRounding list should be either null or the same size as the number of vertices (vertices.size / 2)"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    :goto_0
    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    array-length v6, v0

    div-int/2addr v6, v2

    new-instance v7, Ljava/util/ArrayList;

    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    const/4 v8, 0x0

    move v9, v8

    :goto_1
    if-ge v9, v6, :cond_4

    if-eqz v1, :cond_3

    invoke-interface {v1, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/jr1;

    if-nez v10, :cond_2

    goto :goto_2

    :cond_2
    move-object/from16 v18, v10

    goto :goto_3

    :cond_3
    :goto_2
    move-object/from16 v18, v5

    :goto_3
    add-int v10, v9, v6

    sub-int/2addr v10, v3

    rem-int/2addr v10, v6

    mul-int/2addr v10, v2

    add-int/lit8 v19, v9, 0x1

    rem-int v11, v19, v6

    mul-int/2addr v11, v2

    move v12, v11

    new-instance v11, Llyiahf/vczjk/sv7;

    aget v13, v0, v10

    add-int/2addr v10, v3

    aget v10, v0, v10

    invoke-static {v13, v10}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide v13

    mul-int/2addr v9, v2

    aget v10, v0, v9

    add-int/2addr v9, v3

    aget v9, v0, v9

    invoke-static {v10, v9}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide v9

    aget v15, v0, v12

    add-int/2addr v12, v3

    aget v12, v0, v12

    invoke-static {v15, v12}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide v16

    move-wide v12, v13

    move-wide v14, v9

    invoke-direct/range {v11 .. v18}, Llyiahf/vczjk/sv7;-><init>(JJJLlyiahf/vczjk/jr1;)V

    invoke-virtual {v7, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move/from16 v9, v19

    goto :goto_1

    :cond_4
    invoke-static {v8, v6}, Llyiahf/vczjk/vt6;->Oooo0oO(II)Llyiahf/vczjk/x14;

    move-result-object v1

    new-instance v5, Ljava/util/ArrayList;

    const/16 v9, 0xa

    invoke-static {v1, v9}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v9

    invoke-direct {v5, v9}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v1}, Llyiahf/vczjk/v14;->OooO00o()Llyiahf/vczjk/w14;

    move-result-object v1

    :goto_4
    iget-boolean v9, v1, Llyiahf/vczjk/w14;->OooOOOO:Z

    const/high16 v10, 0x3f800000    # 1.0f

    const/4 v11, 0x0

    if-eqz v9, :cond_7

    invoke-virtual {v1}, Llyiahf/vczjk/n14;->OooO00o()I

    move-result v9

    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/sv7;

    iget v12, v12, Llyiahf/vczjk/sv7;->OooO0oo:F

    add-int/lit8 v13, v9, 0x1

    rem-int/2addr v13, v6

    invoke-virtual {v7, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/sv7;

    iget v14, v14, Llyiahf/vczjk/sv7;->OooO0oo:F

    add-float/2addr v12, v14

    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/sv7;

    invoke-virtual {v14}, Llyiahf/vczjk/sv7;->OooO0OO()F

    move-result v14

    invoke-virtual {v7, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Llyiahf/vczjk/sv7;

    invoke-virtual {v15}, Llyiahf/vczjk/sv7;->OooO0OO()F

    move-result v15

    add-float/2addr v15, v14

    mul-int/2addr v9, v2

    aget v14, v0, v9

    add-int/2addr v9, v3

    aget v9, v0, v9

    mul-int/2addr v13, v2

    aget v16, v0, v13

    add-int/2addr v13, v3

    aget v13, v0, v13

    sub-float v14, v14, v16

    sub-float/2addr v9, v13

    sget v13, Llyiahf/vczjk/tba;->OooO0O0:F

    mul-float/2addr v14, v14

    mul-float/2addr v9, v9

    add-float/2addr v9, v14

    float-to-double v13, v9

    invoke-static {v13, v14}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v13

    double-to-float v9, v13

    cmpl-float v13, v12, v9

    if-lez v13, :cond_5

    div-float/2addr v9, v12

    invoke-static {v9}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v9

    invoke-static {v11}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v10

    new-instance v11, Llyiahf/vczjk/xn6;

    invoke-direct {v11, v9, v10}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_5

    :cond_5
    cmpl-float v11, v15, v9

    if-lez v11, :cond_6

    invoke-static {v10}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v10

    sub-float/2addr v9, v12

    sub-float/2addr v15, v12

    div-float/2addr v9, v15

    invoke-static {v9}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v9

    new-instance v11, Llyiahf/vczjk/xn6;

    invoke-direct {v11, v10, v9}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_5

    :cond_6
    invoke-static {v10}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v9

    invoke-static {v10}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v10

    new-instance v11, Llyiahf/vczjk/xn6;

    invoke-direct {v11, v9, v10}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    :goto_5
    invoke-virtual {v5, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto/16 :goto_4

    :cond_7
    move v1, v8

    :goto_6
    if-ge v1, v6, :cond_11

    new-array v13, v2, [F

    move v14, v8

    move v15, v14

    :goto_7
    const/16 v16, 0x3

    if-ge v14, v2, :cond_9

    add-int v17, v1, v6

    add-int/lit8 v17, v17, -0x1

    add-int v17, v17, v14

    move/from16 v18, v8

    rem-int v8, v17, v6

    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/xn6;

    invoke-virtual {v8}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v17

    check-cast v17, Ljava/lang/Number;

    invoke-virtual/range {v17 .. v17}, Ljava/lang/Number;->floatValue()F

    move-result v17

    invoke-virtual {v8}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/lang/Number;

    invoke-virtual {v8}, Ljava/lang/Number;->floatValue()F

    move-result v8

    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v19

    move-object/from16 v10, v19

    check-cast v10, Llyiahf/vczjk/sv7;

    iget v10, v10, Llyiahf/vczjk/sv7;->OooO0oo:F

    mul-float v10, v10, v17

    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v17

    check-cast v17, Llyiahf/vczjk/sv7;

    move/from16 p2, v11

    invoke-virtual/range {v17 .. v17}, Llyiahf/vczjk/sv7;->OooO0OO()F

    move-result v11

    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v17

    move/from16 v19, v2

    move-object/from16 v2, v17

    check-cast v2, Llyiahf/vczjk/sv7;

    iget v2, v2, Llyiahf/vczjk/sv7;->OooO0oo:F

    invoke-static {v11, v2, v8, v10}, Llyiahf/vczjk/u81;->OooO0O0(FFFF)F

    move-result v2

    add-int/lit8 v8, v15, 0x1

    array-length v10, v13

    if-ge v10, v8, :cond_8

    array-length v10, v13

    mul-int/lit8 v10, v10, 0x3

    div-int/lit8 v10, v10, 0x2

    invoke-static {v8, v10}, Ljava/lang/Math;->max(II)I

    move-result v10

    invoke-static {v13, v10}, Ljava/util/Arrays;->copyOf([FI)[F

    move-result-object v10

    const-string v11, "copyOf(...)"

    invoke-static {v10, v11}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v13, v10

    :cond_8
    aput v2, v13, v15

    add-int/2addr v14, v3

    move/from16 v11, p2

    move v15, v8

    move/from16 v8, v18

    move/from16 v2, v19

    const/high16 v10, 0x3f800000    # 1.0f

    goto :goto_7

    :cond_9
    move/from16 v19, v2

    move/from16 v18, v8

    move/from16 p2, v11

    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/sv7;

    const/4 v8, 0x0

    const-string v10, "Index must be between 0 and size"

    if-lez v15, :cond_10

    aget v11, v13, v18

    if-ge v3, v15, :cond_f

    aget v8, v13, v3

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v11, v8}, Ljava/lang/Math;->min(FF)F

    move-result v10

    iget v13, v2, Llyiahf/vczjk/sv7;->OooO0oo:F

    const v14, 0x38d1b717    # 1.0E-4f

    cmpg-float v15, v13, v14

    move/from16 v17, v14

    move/from16 v20, v15

    iget-wide v14, v2, Llyiahf/vczjk/sv7;->OooO0O0:J

    if-ltz v20, :cond_a

    cmpg-float v20, v10, v17

    if-ltz v20, :cond_a

    move/from16 v20, v3

    iget v3, v2, Llyiahf/vczjk/sv7;->OooO0o:F

    cmpg-float v17, v3, v17

    if-gez v17, :cond_b

    :cond_a
    move/from16 v34, v1

    move-object/from16 v17, v4

    move-object/from16 v16, v5

    goto/16 :goto_c

    :cond_b
    invoke-static {v10, v13}, Ljava/lang/Math;->min(FF)F

    move-result v10

    invoke-virtual {v2, v11}, Llyiahf/vczjk/sv7;->OooO00o(F)F

    move-result v22

    invoke-virtual {v2, v8}, Llyiahf/vczjk/sv7;->OooO00o(F)F

    move-result v8

    mul-float/2addr v3, v10

    div-float v33, v3, v13

    sget v3, Llyiahf/vczjk/tba;->OooO0O0:F

    mul-float v3, v33, v33

    mul-float v11, v10, v10

    add-float/2addr v11, v3

    float-to-double v12, v11

    invoke-static {v12, v13}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v11

    double-to-float v11, v11

    iget-wide v12, v2, Llyiahf/vczjk/sv7;->OooO0Oo:J

    move-object/from16 v17, v4

    iget-wide v3, v2, Llyiahf/vczjk/sv7;->OooO0o0:J

    move/from16 v21, v10

    invoke-static {v12, v13, v3, v4}, Llyiahf/vczjk/rl6;->OooOo0O(JJ)J

    move-result-wide v9

    move/from16 v34, v1

    const/high16 v1, 0x40000000    # 2.0f

    invoke-static {v1, v9, v10}, Llyiahf/vczjk/rl6;->OooOO0O(FJ)J

    move-result-wide v9

    invoke-static {v9, v10}, Llyiahf/vczjk/rl6;->OooOOOO(J)J

    move-result-wide v9

    invoke-static {v11, v9, v10}, Llyiahf/vczjk/rl6;->OooOoo(FJ)J

    move-result-wide v9

    invoke-static {v14, v15, v9, v10}, Llyiahf/vczjk/rl6;->OooOo0O(JJ)J

    move-result-wide v9

    iput-wide v9, v2, Llyiahf/vczjk/sv7;->OooO:J

    move/from16 v1, v21

    invoke-static {v1, v12, v13}, Llyiahf/vczjk/rl6;->OooOoo(FJ)J

    move-result-wide v9

    invoke-static {v14, v15, v9, v10}, Llyiahf/vczjk/rl6;->OooOo0O(JJ)J

    move-result-wide v27

    invoke-static {v1, v3, v4}, Llyiahf/vczjk/rl6;->OooOoo(FJ)J

    move-result-wide v3

    invoke-static {v14, v15, v3, v4}, Llyiahf/vczjk/rl6;->OooOo0O(JJ)J

    move-result-wide v29

    iget-wide v3, v2, Llyiahf/vczjk/sv7;->OooO:J

    iget-wide v9, v2, Llyiahf/vczjk/sv7;->OooO0O0:J

    iget-wide v11, v2, Llyiahf/vczjk/sv7;->OooO00o:J

    move-wide/from16 v31, v3

    move-wide/from16 v23, v9

    move-wide/from16 v25, v11

    invoke-static/range {v21 .. v33}, Llyiahf/vczjk/sv7;->OooO0O0(FFJJJJJF)Llyiahf/vczjk/bu1;

    move-result-object v1

    iget-wide v3, v2, Llyiahf/vczjk/sv7;->OooO:J

    iget-wide v9, v2, Llyiahf/vczjk/sv7;->OooO0O0:J

    iget-wide v11, v2, Llyiahf/vczjk/sv7;->OooO0OO:J

    move-wide/from16 v22, v29

    move-wide/from16 v29, v27

    move-wide/from16 v27, v22

    move-wide/from16 v31, v3

    move/from16 v22, v8

    move-wide/from16 v23, v9

    move-wide/from16 v25, v11

    invoke-static/range {v21 .. v33}, Llyiahf/vczjk/sv7;->OooO0O0(FFJJJJJF)Llyiahf/vczjk/bu1;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/bu1;->OooO00o()F

    move-result v8

    invoke-virtual {v3}, Llyiahf/vczjk/bu1;->OooO0O0()F

    move-result v9

    iget-object v3, v3, Llyiahf/vczjk/bu1;->OooO00o:[F

    const/4 v4, 0x4

    aget v10, v3, v4

    const/4 v4, 0x5

    aget v11, v3, v4

    aget v12, v3, v19

    aget v13, v3, v16

    aget v14, v3, v18

    aget v15, v3, v20

    invoke-static/range {v8 .. v15}, Llyiahf/vczjk/e16;->OooO0OO(FFFFFFFF)Llyiahf/vczjk/bu1;

    move-result-object v3

    iget-wide v8, v2, Llyiahf/vczjk/sv7;->OooO:J

    invoke-static {v8, v9}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v4

    iget-wide v8, v2, Llyiahf/vczjk/sv7;->OooO:J

    invoke-static {v8, v9}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result v2

    invoke-virtual {v1}, Llyiahf/vczjk/bu1;->OooO00o()F

    move-result v8

    invoke-virtual {v1}, Llyiahf/vczjk/bu1;->OooO0O0()F

    move-result v9

    iget-object v10, v3, Llyiahf/vczjk/bu1;->OooO00o:[F

    aget v14, v10, v18

    aget v15, v10, v20

    sub-float v10, v8, v4

    sub-float v11, v9, v2

    invoke-static {v10, v11}, Llyiahf/vczjk/tba;->OooO0O0(FF)J

    move-result-wide v12

    sub-float v4, v14, v4

    sub-float v2, v15, v2

    move/from16 v16, v10

    move/from16 v21, v11

    invoke-static {v4, v2}, Llyiahf/vczjk/tba;->OooO0O0(FF)J

    move-result-wide v10

    move/from16 v22, v2

    invoke-static {v12, v13}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result v2

    neg-float v2, v2

    move/from16 v23, v4

    invoke-static {v12, v13}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v4

    invoke-static {v2, v4}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide v24

    invoke-static {v10, v11}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result v2

    neg-float v2, v2

    invoke-static {v10, v11}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v4

    invoke-static {v2, v4}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide v26

    invoke-static/range {v24 .. v25}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v2

    mul-float v2, v2, v23

    invoke-static/range {v24 .. v25}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result v4

    mul-float v4, v4, v22

    add-float/2addr v4, v2

    cmpl-float v2, v4, p2

    if-ltz v2, :cond_c

    move/from16 v2, v20

    goto :goto_8

    :cond_c
    move/from16 v2, v18

    :goto_8
    invoke-static {v12, v13, v10, v11}, Llyiahf/vczjk/rl6;->OooOO0o(JJ)F

    move-result v4

    const v10, 0x3f7fbe77    # 0.999f

    cmpl-float v10, v4, v10

    if-lez v10, :cond_d

    const v10, 0x3eaaaaab

    invoke-static {v8, v14, v10}, Llyiahf/vczjk/tba;->OooO0OO(FFF)F

    move-result v2

    invoke-static {v9, v15, v10}, Llyiahf/vczjk/tba;->OooO0OO(FFF)F

    move-result v11

    const v4, 0x3f2aaaab

    invoke-static {v8, v14, v4}, Llyiahf/vczjk/tba;->OooO0OO(FFF)F

    move-result v12

    invoke-static {v9, v15, v4}, Llyiahf/vczjk/tba;->OooO0OO(FFF)F

    move-result v13

    move v10, v2

    invoke-static/range {v8 .. v15}, Llyiahf/vczjk/e16;->OooO0OO(FFFFFFFF)Llyiahf/vczjk/bu1;

    move-result-object v2

    move-object/from16 v16, v5

    goto :goto_a

    :cond_d
    mul-float v10, v16, v16

    mul-float v11, v21, v21

    add-float/2addr v11, v10

    float-to-double v10, v11

    invoke-static {v10, v11}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v10

    double-to-float v10, v10

    const/high16 v11, 0x40800000    # 4.0f

    mul-float/2addr v10, v11

    const/high16 v11, 0x40400000    # 3.0f

    div-float/2addr v10, v11

    move/from16 v11, v19

    int-to-float v12, v11

    move/from16 v11, v20

    int-to-float v13, v11

    sub-float v11, v13, v4

    mul-float/2addr v12, v11

    move/from16 v21, v4

    move-object/from16 v16, v5

    float-to-double v4, v12

    invoke-static {v4, v5}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v4

    double-to-float v4, v4

    mul-float v5, v21, v21

    sub-float/2addr v13, v5

    float-to-double v12, v13

    invoke-static {v12, v13}, Ljava/lang/Math;->sqrt(D)D

    move-result-wide v12

    double-to-float v5, v12

    sub-float/2addr v4, v5

    mul-float/2addr v4, v10

    div-float/2addr v4, v11

    if-eqz v2, :cond_e

    const/high16 v2, 0x3f800000    # 1.0f

    goto :goto_9

    :cond_e
    const/high16 v2, -0x40800000    # -1.0f

    :goto_9
    mul-float/2addr v4, v2

    invoke-static/range {v24 .. v25}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v2

    mul-float/2addr v2, v4

    add-float v10, v2, v8

    invoke-static/range {v24 .. v25}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result v2

    mul-float/2addr v2, v4

    add-float v11, v2, v9

    invoke-static/range {v26 .. v27}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v2

    mul-float/2addr v2, v4

    sub-float v12, v14, v2

    invoke-static/range {v26 .. v27}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result v2

    mul-float/2addr v2, v4

    sub-float v13, v15, v2

    invoke-static/range {v8 .. v15}, Llyiahf/vczjk/e16;->OooO0OO(FFFFFFFF)Llyiahf/vczjk/bu1;

    move-result-object v2

    :goto_a
    filled-new-array {v1, v2, v3}, [Llyiahf/vczjk/bu1;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    :goto_b
    move-object/from16 v2, v17

    goto :goto_d

    :goto_c
    iput-wide v14, v2, Llyiahf/vczjk/sv7;->OooO:J

    invoke-static {v14, v15}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v8

    invoke-static {v14, v15}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result v9

    move-wide v1, v14

    invoke-static {v1, v2}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v14

    invoke-static {v1, v2}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result v15

    const v10, 0x3eaaaaab

    invoke-static {v8, v14, v10}, Llyiahf/vczjk/tba;->OooO0OO(FFF)F

    move-result v1

    invoke-static {v9, v15, v10}, Llyiahf/vczjk/tba;->OooO0OO(FFF)F

    move-result v11

    const v3, 0x3f2aaaab

    invoke-static {v8, v14, v3}, Llyiahf/vczjk/tba;->OooO0OO(FFF)F

    move-result v12

    invoke-static {v9, v15, v3}, Llyiahf/vczjk/tba;->OooO0OO(FFF)F

    move-result v13

    move v10, v1

    invoke-static/range {v8 .. v15}, Llyiahf/vczjk/e16;->OooO0OO(FFFFFFFF)Llyiahf/vczjk/bu1;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    goto :goto_b

    :goto_d
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    const/16 v20, 0x1

    add-int/lit8 v1, v34, 0x1

    move/from16 v11, p2

    move-object v4, v2

    move-object/from16 v5, v16

    move/from16 v8, v18

    move/from16 v3, v20

    const/4 v2, 0x2

    const/high16 v10, 0x3f800000    # 1.0f

    goto/16 :goto_6

    :cond_f
    invoke-static {v10}, Llyiahf/vczjk/vt6;->Oooo0o0(Ljava/lang/String;)V

    throw v8

    :cond_10
    invoke-static {v10}, Llyiahf/vczjk/vt6;->Oooo0o0(Ljava/lang/String;)V

    throw v8

    :cond_11
    move/from16 v20, v3

    move-object v2, v4

    move/from16 v18, v8

    move/from16 p2, v11

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    move/from16 v4, v18

    :goto_e
    if-ge v4, v6, :cond_13

    add-int v5, v4, v6

    add-int/lit8 v5, v5, -0x1

    rem-int/2addr v5, v6

    add-int/lit8 v8, v4, 0x1

    rem-int v9, v8, v6

    const/16 v19, 0x2

    mul-int/lit8 v10, v4, 0x2

    aget v11, v0, v10

    add-int/lit8 v10, v10, 0x1

    aget v10, v0, v10

    invoke-static {v11, v10}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide v10

    mul-int/lit8 v5, v5, 0x2

    aget v12, v0, v5

    add-int/lit8 v5, v5, 0x1

    aget v5, v0, v5

    invoke-static {v12, v5}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide v12

    mul-int/lit8 v5, v9, 0x2

    aget v14, v0, v5

    add-int/lit8 v5, v5, 0x1

    aget v5, v0, v5

    invoke-static {v14, v5}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide v14

    invoke-static {v10, v11, v12, v13}, Llyiahf/vczjk/rl6;->OooOo0(JJ)J

    move-result-wide v12

    invoke-static {v14, v15, v10, v11}, Llyiahf/vczjk/rl6;->OooOo0(JJ)J

    move-result-wide v14

    invoke-static {v12, v13}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v5

    invoke-static {v14, v15}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result v16

    mul-float v16, v16, v5

    invoke-static {v12, v13}, Llyiahf/vczjk/rl6;->OooOOoo(J)F

    move-result v5

    invoke-static {v14, v15}, Llyiahf/vczjk/rl6;->OooOOo(J)F

    move-result v12

    mul-float/2addr v12, v5

    sub-float v16, v16, v12

    cmpl-float v5, v16, p2

    if-lez v5, :cond_12

    const/16 v27, 0x1

    goto :goto_f

    :cond_12
    move/from16 v27, v18

    :goto_f
    new-instance v21, Llyiahf/vczjk/hw2;

    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v5

    move-object/from16 v22, v5

    check-cast v22, Ljava/util/List;

    invoke-virtual {v7, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/sv7;

    iget-wide v12, v5, Llyiahf/vczjk/sv7;->OooO:J

    move-wide/from16 v23, v10

    move-wide/from16 v25, v12

    invoke-direct/range {v21 .. v27}, Llyiahf/vczjk/hw2;-><init>(Ljava/util/List;JJZ)V

    move-object/from16 v5, v21

    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v5, Llyiahf/vczjk/iw2;

    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ljava/util/List;

    invoke-static {v10}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/bu1;

    invoke-virtual {v10}, Llyiahf/vczjk/bu1;->OooO00o()F

    move-result v10

    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/util/List;

    invoke-static {v4}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/bu1;

    invoke-virtual {v4}, Llyiahf/vczjk/bu1;->OooO0O0()F

    move-result v4

    invoke-virtual {v2, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Ljava/util/List;

    invoke-static {v11}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/bu1;

    iget-object v11, v11, Llyiahf/vczjk/bu1;->OooO00o:[F

    aget v11, v11, v18

    invoke-virtual {v2, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/util/List;

    invoke-static {v9}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/bu1;

    iget-object v9, v9, Llyiahf/vczjk/bu1;->OooO00o:[F

    const/16 v20, 0x1

    aget v9, v9, v20

    const v12, 0x3eaaaaab

    invoke-static {v10, v11, v12}, Llyiahf/vczjk/tba;->OooO0OO(FFF)F

    move-result v23

    invoke-static {v4, v9, v12}, Llyiahf/vczjk/tba;->OooO0OO(FFF)F

    move-result v24

    const v3, 0x3f2aaaab

    invoke-static {v10, v11, v3}, Llyiahf/vczjk/tba;->OooO0OO(FFF)F

    move-result v25

    invoke-static {v4, v9, v3}, Llyiahf/vczjk/tba;->OooO0OO(FFF)F

    move-result v26

    move/from16 v22, v4

    move/from16 v28, v9

    move/from16 v21, v10

    move/from16 v27, v11

    invoke-static/range {v21 .. v28}, Llyiahf/vczjk/e16;->OooO0OO(FFFFFFFF)Llyiahf/vczjk/bu1;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v4

    invoke-direct {v5, v4}, Llyiahf/vczjk/jw2;-><init>(Ljava/util/List;)V

    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move v4, v8

    const/16 v20, 0x1

    goto/16 :goto_e

    :cond_13
    const/4 v2, 0x1

    cmpg-float v3, p3, v2

    if-nez v3, :cond_14

    goto :goto_10

    :cond_14
    cmpg-float v2, p4, v2

    if-nez v2, :cond_16

    :goto_10
    move/from16 v2, p2

    move v11, v2

    move/from16 v8, v18

    :goto_11
    array-length v3, v0

    if-ge v8, v3, :cond_15

    const/16 v20, 0x1

    add-int/lit8 v3, v8, 0x1

    aget v4, v0, v8

    add-float/2addr v11, v4

    const/4 v4, 0x2

    add-int/2addr v8, v4

    aget v3, v0, v3

    add-float/2addr v2, v3

    goto :goto_11

    :cond_15
    const/4 v4, 0x2

    array-length v3, v0

    int-to-float v3, v3

    div-float/2addr v11, v3

    int-to-float v3, v4

    div-float/2addr v11, v3

    array-length v0, v0

    int-to-float v0, v0

    div-float/2addr v2, v0

    div-float/2addr v2, v3

    invoke-static {v11, v2}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide v2

    goto :goto_12

    :cond_16
    invoke-static/range {p3 .. p4}, Llyiahf/vczjk/v23;->OooO00o(FF)J

    move-result-wide v2

    :goto_12
    const/16 v0, 0x20

    shr-long v4, v2, v0

    long-to-int v0, v4

    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    const-wide v4, 0xffffffffL

    and-long/2addr v2, v4

    long-to-int v2, v2

    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    new-instance v3, Llyiahf/vczjk/aw7;

    invoke-direct {v3, v1, v0, v2}, Llyiahf/vczjk/aw7;-><init>(Ljava/util/AbstractList;FF)V

    return-object v3

    :cond_17
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "The vertices array should have even size"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_18
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Polygons must have at least 3 vertices"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static final OooO0oO(Llyiahf/vczjk/j19;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 21

    move-object/from16 v1, p0

    move/from16 v4, p4

    move-object/from16 v11, p3

    check-cast v11, Llyiahf/vczjk/zf1;

    const v0, 0x5ede1799

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, v4, 0x6

    if-nez v0, :cond_1

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, v4

    goto :goto_1

    :cond_1
    move v0, v4

    :goto_1
    and-int/lit8 v2, v4, 0x30

    const/16 v3, 0x10

    if-nez v2, :cond_3

    move-object/from16 v2, p1

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2

    const/16 v5, 0x20

    goto :goto_2

    :cond_2
    move v5, v3

    :goto_2
    or-int/2addr v0, v5

    goto :goto_3

    :cond_3
    move-object/from16 v2, p1

    :goto_3
    and-int/lit16 v5, v4, 0x180

    move-object/from16 v10, p2

    if-nez v5, :cond_5

    invoke-virtual {v11, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_4

    const/16 v5, 0x100

    goto :goto_4

    :cond_4
    const/16 v5, 0x80

    :goto_4
    or-int/2addr v0, v5

    :cond_5
    and-int/lit16 v5, v0, 0x93

    const/16 v6, 0x92

    if-ne v5, v6, :cond_7

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_6

    goto :goto_5

    :cond_6
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_7

    :cond_7
    :goto_5
    sget-object v14, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v15, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    const/16 v5, 0x40

    int-to-float v5, v5

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v16, 0x0

    const/16 v20, 0xd

    move/from16 v17, v5

    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v5

    int-to-float v3, v3

    invoke-static {v5, v3}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v5, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    sget-object v6, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    const/16 v7, 0x30

    invoke-static {v6, v5, v11, v7}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v5

    iget v6, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v11, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_8

    invoke-virtual {v11, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_8
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v11, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, v11, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v7, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_9

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_a

    :cond_9
    invoke-static {v6, v11, v6, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_a
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v11, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v3, 0x3f19999a    # 0.6f

    invoke-static {v14, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    const/4 v5, 0x0

    invoke-static {v3, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;Z)Llyiahf/vczjk/kl5;

    move-result-object v5

    const/16 v3, 0x26

    int-to-float v7, v3

    iget-object v8, v1, Llyiahf/vczjk/j19;->OooO0Oo:Ljava/util/List;

    new-instance v6, Llyiahf/vczjk/wr0;

    move-object v3, v14

    iget-wide v13, v1, Llyiahf/vczjk/j19;->OooO0O0:J

    invoke-static {v13, v14}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    move-result-object v9

    sget-object v12, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v11, v12}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/x21;

    iget-wide v12, v12, Llyiahf/vczjk/x21;->OooOOo0:J

    const/16 v14, 0x18

    int-to-float v14, v14

    invoke-direct {v6, v12, v13, v9, v14}, Llyiahf/vczjk/wr0;-><init>(JLjava/lang/String;F)V

    shl-int/lit8 v0, v0, 0x9

    const v9, 0xe000

    and-int/2addr v9, v0

    const/16 v12, 0x186

    or-int/2addr v9, v12

    const/high16 v12, 0x70000

    and-int/2addr v0, v12

    or-int v12, v9, v0

    move-object v9, v2

    invoke-static/range {v5 .. v12}, Llyiahf/vczjk/vt6;->OooO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/wr0;FLjava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    const/16 v0, 0x20

    int-to-float v0, v0

    invoke-static {v3, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v11, v2}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const v2, 0x3f4ccccd    # 0.8f

    invoke-static {v3, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    iget-object v9, v1, Llyiahf/vczjk/j19;->OooO0Oo:Ljava/util/List;

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    move-object v10, v11

    const/16 v11, 0x186

    invoke-static/range {v5 .. v11}, Llyiahf/vczjk/r02;->OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/di6;FLlyiahf/vczjk/tv7;Ljava/util/List;Llyiahf/vczjk/rf1;I)V

    move-object v11, v10

    const/4 v0, 0x1

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_7
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_b

    new-instance v0, Llyiahf/vczjk/z4;

    const/16 v5, 0x8

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/z4;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_b
    return-void
.end method

.method public static final OooO0oo(Llyiahf/vczjk/bi6;Llyiahf/vczjk/j19;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 22

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    move-object/from16 v5, p4

    move/from16 v6, p6

    const-string v0, "paddings"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "startChartState"

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onItemSelected"

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onCategorySelected"

    invoke-static {v4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onCenterSelected"

    invoke-static {v5, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v0, p5

    check-cast v0, Llyiahf/vczjk/zf1;

    const v7, -0x7b5aa28e

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v7, v6, 0x6

    if-nez v7, :cond_1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_0

    const/4 v7, 0x4

    goto :goto_0

    :cond_0
    const/4 v7, 0x2

    :goto_0
    or-int/2addr v7, v6

    goto :goto_1

    :cond_1
    move v7, v6

    :goto_1
    and-int/lit8 v8, v6, 0x30

    if-nez v8, :cond_3

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_2

    const/16 v8, 0x20

    goto :goto_2

    :cond_2
    const/16 v8, 0x10

    :goto_2
    or-int/2addr v7, v8

    :cond_3
    and-int/lit16 v8, v6, 0x180

    if-nez v8, :cond_5

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_4

    const/16 v8, 0x100

    goto :goto_3

    :cond_4
    const/16 v8, 0x80

    :goto_3
    or-int/2addr v7, v8

    :cond_5
    and-int/lit16 v8, v6, 0xc00

    if-nez v8, :cond_7

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_6

    const/16 v8, 0x800

    goto :goto_4

    :cond_6
    const/16 v8, 0x400

    :goto_4
    or-int/2addr v7, v8

    :cond_7
    and-int/lit16 v8, v6, 0x6000

    if-nez v8, :cond_9

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_8

    const/16 v8, 0x4000

    goto :goto_5

    :cond_8
    const/16 v8, 0x2000

    :goto_5
    or-int/2addr v7, v8

    :cond_9
    and-int/lit16 v8, v7, 0x2493

    const/16 v9, 0x2492

    if-ne v8, v9, :cond_b

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v8

    if-nez v8, :cond_a

    goto :goto_6

    :cond_a
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v8, v0

    goto/16 :goto_9

    :cond_b
    :goto_6
    sget-object v8, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v9, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v9, v1}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v9

    sget-object v10, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    const/4 v11, 0x0

    invoke-static {v10, v11}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v10

    iget v12, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v13

    invoke-static {v0, v9}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v9

    sget-object v14, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v14, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_c

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_c
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    sget-object v14, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v10, v0, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v13, v0, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v13, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v13, :cond_d

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v13

    if-nez v13, :cond_e

    :cond_d
    invoke-static {v12, v0, v12, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_e
    sget-object v10, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v9, v0, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v9, v2, Llyiahf/vczjk/j19;->OooO00o:Z

    if-eqz v9, :cond_f

    const v7, -0x293df59d

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v7, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/x21;

    iget-wide v9, v7, Llyiahf/vczjk/x21;->OooO00o:J

    const/high16 v7, 0x3f800000    # 1.0f

    invoke-static {v8, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v7

    const/4 v8, 0x6

    int-to-float v8, v8

    invoke-static {v7, v8}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0o0(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v7

    const/16 v16, 0x0

    const/16 v17, 0x0

    move-wide v12, v9

    move v8, v11

    const-wide/16 v10, 0x0

    move-wide/from16 v20, v12

    move v13, v8

    move-wide/from16 v8, v20

    const/4 v12, 0x0

    move v14, v13

    const/4 v13, 0x0

    move v15, v14

    const/4 v14, 0x0

    move/from16 v18, v15

    const/4 v15, 0x0

    const/16 v19, 0x6

    move/from16 v20, v18

    move-object/from16 v18, v0

    move/from16 v0, v20

    invoke-static/range {v7 .. v19}, Llyiahf/vczjk/kla;->OooO0O0(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFFFLlyiahf/vczjk/rf1;I)V

    move-object/from16 v8, v18

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_8

    :cond_f
    move-object v8, v0

    move v0, v11

    const v9, -0x293a6814

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    shr-int/lit8 v9, v7, 0x6

    and-int/lit8 v10, v9, 0x70

    iget-object v11, v2, Llyiahf/vczjk/j19;->OooO0OO:Llyiahf/vczjk/ur0;

    invoke-static {v11, v4, v8, v10}, Llyiahf/vczjk/er8;->OooO0OO(Llyiahf/vczjk/ur0;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    shr-int/lit8 v7, v7, 0x3

    and-int/lit8 v7, v7, 0x7e

    and-int/lit16 v9, v9, 0x380

    or-int/2addr v7, v9

    invoke-static {v2, v3, v5, v8, v7}, Llyiahf/vczjk/er8;->OooO0oO(Llyiahf/vczjk/j19;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_8
    const/4 v0, 0x1

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_9
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_10

    new-instance v0, Llyiahf/vczjk/ve5;

    const/4 v7, 0x2

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/ve5;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/cf3;II)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_10
    return-void
.end method

.method public static final OooOO0(Llyiahf/vczjk/kl5;ZLjava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V
    .locals 38

    move/from16 v0, p1

    move-object/from16 v8, p2

    move-object/from16 v9, p4

    move/from16 v10, p6

    const-string v1, "onCheckChange"

    invoke-static {v9, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v5, p5

    check-cast v5, Llyiahf/vczjk/zf1;

    const v1, -0x1a000a1c

    invoke-virtual {v5, v1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v5, v0}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v1

    const/16 v3, 0x20

    if-eqz v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    const/16 v1, 0x10

    :goto_0
    or-int/2addr v1, v10

    and-int/lit16 v4, v10, 0x180

    if-nez v4, :cond_2

    invoke-virtual {v5, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1

    const/16 v4, 0x100

    goto :goto_1

    :cond_1
    const/16 v4, 0x80

    :goto_1
    or-int/2addr v1, v4

    :cond_2
    and-int/lit8 v4, p7, 0x8

    if-eqz v4, :cond_3

    or-int/lit16 v1, v1, 0xc00

    move-object/from16 v6, p3

    goto :goto_3

    :cond_3
    move-object/from16 v6, p3

    invoke-virtual {v5, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_4

    const/16 v7, 0x800

    goto :goto_2

    :cond_4
    const/16 v7, 0x400

    :goto_2
    or-int/2addr v1, v7

    :goto_3
    invoke-virtual {v5, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    const/16 v11, 0x4000

    if-eqz v7, :cond_5

    move v7, v11

    goto :goto_4

    :cond_5
    const/16 v7, 0x2000

    :goto_4
    or-int/2addr v1, v7

    and-int/lit16 v7, v1, 0x2493

    const/16 v12, 0x2492

    if-ne v7, v12, :cond_7

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v7

    if-nez v7, :cond_6

    goto :goto_5

    :cond_6
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v4, v6

    goto/16 :goto_13

    :cond_7
    :goto_5
    if-eqz v4, :cond_8

    const/16 v34, 0x0

    goto :goto_6

    :cond_8
    move-object/from16 v34, v6

    :goto_6
    const/high16 v4, 0x3f800000    # 1.0f

    move-object/from16 v6, p0

    invoke-static {v6, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    const/16 v12, 0x40

    int-to-float v12, v12

    const/4 v13, 0x0

    const/4 v14, 0x2

    invoke-static {v4, v12, v13, v14}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v4

    int-to-float v12, v3

    invoke-static {v12}, Llyiahf/vczjk/uv7;->OooO00o(F)Llyiahf/vczjk/tv7;

    move-result-object v12

    invoke-static {v4, v12}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v4

    const v12, -0x615d173a

    invoke-virtual {v5, v12}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const v12, 0xe000

    and-int/2addr v12, v1

    const/4 v14, 0x0

    if-ne v12, v11, :cond_9

    const/4 v15, 0x1

    goto :goto_7

    :cond_9
    move v15, v14

    :goto_7
    and-int/lit8 v7, v1, 0x70

    if-ne v7, v3, :cond_a

    const/4 v3, 0x1

    goto :goto_8

    :cond_a
    move v3, v14

    :goto_8
    or-int/2addr v3, v15

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    sget-object v15, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v3, :cond_b

    if-ne v7, v15, :cond_c

    :cond_b
    new-instance v7, Llyiahf/vczjk/ev0;

    const/4 v3, 0x7

    invoke-direct {v7, v9, v0, v3}, Llyiahf/vczjk/ev0;-><init>(Llyiahf/vczjk/oe3;ZI)V

    invoke-virtual {v5, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    check-cast v7, Llyiahf/vczjk/le3;

    invoke-virtual {v5, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v4, v7}, Llyiahf/vczjk/yi4;->Oooo0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v3

    const/4 v4, 0x4

    int-to-float v4, v4

    move/from16 p3, v12

    invoke-static {v4, v5, v14}, Llyiahf/vczjk/u34;->OooO0o(FLlyiahf/vczjk/rf1;I)J

    move-result-wide v11

    sget-object v4, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v3, v11, v12, v4}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v3

    const/16 v4, 0xc

    int-to-float v4, v4

    invoke-static {v3, v4, v4}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v4, v14}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v4

    iget v11, v5, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    invoke-static {v5, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v16, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v13, v5, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v13, :cond_d

    invoke-virtual {v5, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_9

    :cond_d
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_9
    sget-object v13, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v4, v5, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v12, v5, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v12, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v2, v5, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_e

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    invoke-static {v2, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_f

    :cond_e
    invoke-static {v11, v5, v11, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_f
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v5, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o:Landroidx/compose/foundation/layout/OooO0O0;

    const-string v11, ""

    if-nez v8, :cond_10

    move-object v14, v11

    goto :goto_a

    :cond_10
    move-object v14, v8

    :goto_a
    if-nez v34, :cond_11

    goto :goto_b

    :cond_11
    move-object/from16 v11, v34

    :goto_b
    invoke-static {v14, v11, v5}, Llyiahf/vczjk/zsa;->o00Ooo(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/ps9;

    move-result-object v11

    const v14, 0x5bb4b9bb

    invoke-virtual {v5, v14}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-nez v34, :cond_12

    const/4 v14, 0x0

    goto :goto_c

    :cond_12
    const/4 v14, 0x0

    invoke-static {v11, v5, v14}, Llyiahf/vczjk/zsa;->OooOo0(Llyiahf/vczjk/ps9;Llyiahf/vczjk/rf1;I)V

    :goto_c
    invoke-virtual {v5, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v20, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/16 v14, 0x10

    int-to-float v14, v14

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v22, 0x0

    const/16 v25, 0xe

    move/from16 v21, v14

    invoke-static/range {v20 .. v25}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v14

    move-object/from16 v35, v20

    move/from16 v36, v21

    sget-object v0, Llyiahf/vczjk/op3;->OooOOo0:Llyiahf/vczjk/ub0;

    invoke-virtual {v3, v14, v0}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v14, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    move/from16 v37, v1

    sget-object v1, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v6, 0x30

    invoke-static {v1, v14, v5, v6}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v1

    iget v6, v5, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v5, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v8, v5, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_13

    invoke-virtual {v5, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_d

    :cond_13
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_d
    invoke-static {v1, v5, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v14, v5, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v1, v5, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v1, :cond_14

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_15

    :cond_14
    invoke-static {v6, v5, v6, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_15
    invoke-static {v0, v5, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v0, -0x64e73433

    invoke-virtual {v5, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-nez p2, :cond_16

    const/4 v7, 0x0

    :goto_e
    const/4 v14, 0x0

    goto :goto_f

    :cond_16
    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->common_switchbar_title_format:I

    filled-new-array/range {p2 .. p2}, [Ljava/lang/Object;

    move-result-object v1

    invoke-static {v0, v1, v5}, Llyiahf/vczjk/vt6;->Oooo0O0(I[Ljava/lang/Object;Llyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v7

    goto :goto_e

    :goto_f
    invoke-virtual {v5, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v0, -0x64e7341e

    invoke-virtual {v5, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-nez v7, :cond_18

    if-eqz p1, :cond_17

    const v0, -0x37fbe3a2

    invoke-virtual {v5, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->on:I

    invoke-static {v0, v5}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v5, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_10

    :cond_17
    const v0, -0x37fa3183

    invoke-virtual {v5, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->off:I

    invoke-static {v0, v5}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v5, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :cond_18
    :goto_10
    invoke-virtual {v5, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v0, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v5, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/n6a;

    iget-object v0, v0, Llyiahf/vczjk/n6a;->OooO0oo:Llyiahf/vczjk/rn9;

    sget-object v23, Llyiahf/vczjk/ib3;->OooOOOO:Llyiahf/vczjk/ib3;

    const/16 v1, 0x12

    invoke-static {v1}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v21

    const/16 v30, 0x0

    const/16 v31, 0x0

    const-wide/16 v19, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const-wide/16 v26, 0x0

    const-wide/16 v28, 0x0

    const v32, 0xfffff9

    move-object/from16 v18, v0

    invoke-static/range {v18 .. v32}, Llyiahf/vczjk/rn9;->OooO00o(Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/ba3;JJLlyiahf/vczjk/vx6;Llyiahf/vczjk/jz4;I)Llyiahf/vczjk/rn9;

    move-result-object v29

    const/16 v28, 0x0

    const/16 v31, 0x0

    const/4 v12, 0x0

    move/from16 v19, v14

    const-wide/16 v13, 0x0

    move-object v1, v15

    const/16 v0, 0x4000

    const-wide/16 v15, 0x0

    const/4 v2, 0x1

    const/16 v17, 0x0

    const/16 v18, 0x0

    move/from16 v4, v19

    const-wide/16 v19, 0x0

    const/16 v21, 0x0

    const-wide/16 v22, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v32, 0x0

    const v33, 0x1fffe

    move v8, v2

    move-object/from16 v30, v5

    move-object v5, v11

    move-object v2, v1

    move-object v11, v7

    move/from16 v1, p3

    invoke-static/range {v11 .. v33}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v6, v30

    const v7, -0x64e6e1d0

    invoke-virtual {v6, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const v7, 0x4c5de2

    if-nez v34, :cond_19

    move-object v5, v6

    goto :goto_11

    :cond_19
    invoke-virtual {v6, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v6, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    if-nez v11, :cond_1a

    if-ne v12, v2, :cond_1b

    :cond_1a
    new-instance v12, Llyiahf/vczjk/qa2;

    const/4 v11, 0x3

    invoke-direct {v12, v5, v11}, Llyiahf/vczjk/qa2;-><init>(Llyiahf/vczjk/ps9;I)V

    invoke-virtual {v6, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1b
    move-object v11, v12

    check-cast v11, Llyiahf/vczjk/le3;

    invoke-virtual {v6, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v16, Llyiahf/vczjk/hd1;->OooO00o:Llyiahf/vczjk/a91;

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/high16 v18, 0x180000

    const/16 v19, 0x3e

    move-object/from16 v17, v6

    invoke-static/range {v11 .. v19}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    move-object/from16 v5, v17

    :goto_11
    invoke-virtual {v5, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v5, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v21, 0x0

    const/16 v23, 0x0

    const/16 v20, 0x0

    const/16 v24, 0xb

    move-object/from16 v19, v35

    move/from16 v22, v36

    invoke-static/range {v19 .. v24}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v11, Llyiahf/vczjk/op3;->OooOOoo:Llyiahf/vczjk/ub0;

    invoke-virtual {v3, v6, v11}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v5, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-ne v1, v0, :cond_1c

    move v13, v8

    goto :goto_12

    :cond_1c
    move v13, v4

    :goto_12
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez v13, :cond_1d

    if-ne v0, v2, :cond_1e

    :cond_1d
    new-instance v0, Llyiahf/vczjk/fi2;

    const/4 v1, 0x4

    invoke-direct {v0, v9, v1}, Llyiahf/vczjk/fi2;-><init>(Llyiahf/vczjk/oe3;I)V

    invoke-virtual {v5, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1e
    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/oe3;

    invoke-virtual {v5, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    shr-int/lit8 v0, v37, 0x3

    and-int/lit8 v6, v0, 0xe

    move-object v2, v3

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/16 v7, 0x78

    move/from16 v0, p1

    invoke-static/range {v0 .. v7}, Landroidx/compose/material3/OooO0O0;->OooO00o(ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/nc9;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v5, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v4, v34

    :goto_13
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_1f

    new-instance v0, Llyiahf/vczjk/mc9;

    move-object/from16 v1, p0

    move/from16 v2, p1

    move-object/from16 v3, p2

    move/from16 v7, p7

    move-object v5, v9

    move v6, v10

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/mc9;-><init>(Llyiahf/vczjk/kl5;ZLjava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;II)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_1f
    return-void
.end method

.method public static final OooOO0O(JJ)Llyiahf/vczjk/xn6;
    .locals 6

    invoke-static {p2, p3}, Llyiahf/vczjk/e16;->Oooo0oO(J)J

    move-result-wide p2

    const/16 v0, 0x20

    shr-long v1, p2, v0

    long-to-int v1, v1

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    const-wide v2, 0xffffffffL

    and-long/2addr p2, v2

    long-to-int p2, p2

    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p3

    shr-long v4, p0, v0

    long-to-int v0, v4

    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    const/4 v4, 0x0

    invoke-static {v0, v4, v1}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result v0

    and-long/2addr p0, v2

    long-to-int p0, p0

    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p0

    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p1

    invoke-static {p0, v4, p1}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result p0

    const/high16 p1, 0x3f800000    # 1.0f

    div-float p2, p1, v1

    mul-float/2addr p2, v0

    div-float p3, p1, p3

    mul-float/2addr p3, p0

    sub-float p0, p1, p3

    invoke-static {p2, v4, p1}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result p2

    invoke-static {p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p2

    invoke-static {p0, v4, p1}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result p0

    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p0

    new-instance p1, Llyiahf/vczjk/xn6;

    invoke-direct {p1, p2, p0}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {p1}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Number;

    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    move-result p0

    invoke-virtual {p1}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p0

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/xn6;

    invoke-direct {p2, p0, p1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    return-object p2
.end method

.method public static final OooOO0o(Llyiahf/vczjk/vd7;)Llyiahf/vczjk/q72;
    .locals 1

    if-nez p0, :cond_0

    const/4 p0, -0x1

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/ae7;->OooO0O0:[I

    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    move-result p0

    aget p0, v0, p0

    :goto_0
    const-string v0, "PRIVATE"

    packed-switch p0, :pswitch_data_0

    sget-object p0, Llyiahf/vczjk/r72;->OooO00o:Llyiahf/vczjk/q72;

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0

    :pswitch_0
    sget-object p0, Llyiahf/vczjk/r72;->OooO0o:Llyiahf/vczjk/q72;

    const-string v0, "LOCAL"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0

    :pswitch_1
    sget-object p0, Llyiahf/vczjk/r72;->OooO0o0:Llyiahf/vczjk/q72;

    const-string v0, "PUBLIC"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0

    :pswitch_2
    sget-object p0, Llyiahf/vczjk/r72;->OooO0OO:Llyiahf/vczjk/q72;

    const-string v0, "PROTECTED"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0

    :pswitch_3
    sget-object p0, Llyiahf/vczjk/r72;->OooO0O0:Llyiahf/vczjk/q72;

    const-string v0, "PRIVATE_TO_THIS"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0

    :pswitch_4
    sget-object p0, Llyiahf/vczjk/r72;->OooO00o:Llyiahf/vczjk/q72;

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0

    :pswitch_5
    sget-object p0, Llyiahf/vczjk/r72;->OooO0Oo:Llyiahf/vczjk/q72;

    const-string v0, "INTERNAL"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static final OooOOO(Llyiahf/vczjk/th4;)Ljava/lang/reflect/Field;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/mba;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/ai4;

    move-result-object p0

    if-eqz p0, :cond_0

    iget-object p0, p0, Llyiahf/vczjk/ai4;->OooOOoo:Ljava/lang/Object;

    invoke-interface {p0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/reflect/Field;

    return-object p0

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public static final OooOOO0(Llyiahf/vczjk/c0a;)Llyiahf/vczjk/c0a;
    .locals 10

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/jl5;

    iget-object v1, v0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v1, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v1, :cond_0

    const-string v1, "visitAncestors called on an unattached node"

    invoke-static {v1}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v1

    :goto_0
    const/4 v2, 0x0

    if-eqz v1, :cond_b

    iget-object v3, v1, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v3, v3, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/jl5;

    iget v3, v3, Llyiahf/vczjk/jl5;->OooOOOo:I

    const/high16 v4, 0x40000

    and-int/2addr v3, v4

    if-eqz v3, :cond_9

    :goto_1
    if-eqz v0, :cond_9

    iget v3, v0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v3, v4

    if-eqz v3, :cond_8

    move-object v3, v0

    move-object v5, v2

    :goto_2
    if-eqz v3, :cond_8

    instance-of v6, v3, Llyiahf/vczjk/c0a;

    if-eqz v6, :cond_1

    check-cast v3, Llyiahf/vczjk/c0a;

    invoke-interface {p0}, Llyiahf/vczjk/c0a;->OooOO0O()Ljava/lang/Object;

    move-result-object v6

    invoke-interface {v3}, Llyiahf/vczjk/c0a;->OooOO0O()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_7

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v6

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v7

    if-ne v6, v7, :cond_7

    return-object v3

    :cond_1
    iget v6, v3, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v6, v4

    if-eqz v6, :cond_7

    instance-of v6, v3, Llyiahf/vczjk/m52;

    if-eqz v6, :cond_7

    move-object v6, v3

    check-cast v6, Llyiahf/vczjk/m52;

    iget-object v6, v6, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    const/4 v7, 0x0

    :goto_3
    const/4 v8, 0x1

    if-eqz v6, :cond_6

    iget v9, v6, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v9, v4

    if-eqz v9, :cond_5

    add-int/lit8 v7, v7, 0x1

    if-ne v7, v8, :cond_2

    move-object v3, v6

    goto :goto_4

    :cond_2
    if-nez v5, :cond_3

    new-instance v5, Llyiahf/vczjk/ws5;

    const/16 v8, 0x10

    new-array v8, v8, [Llyiahf/vczjk/jl5;

    invoke-direct {v5, v8}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_3
    if-eqz v3, :cond_4

    invoke-virtual {v5, v3}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v3, v2

    :cond_4
    invoke-virtual {v5, v6}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_5
    :goto_4
    iget-object v6, v6, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_3

    :cond_6
    if-ne v7, v8, :cond_7

    goto :goto_2

    :cond_7
    invoke-static {v5}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v3

    goto :goto_2

    :cond_8
    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto :goto_1

    :cond_9
    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v1

    if-eqz v1, :cond_a

    iget-object v0, v1, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    if-eqz v0, :cond_a

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cf9;

    goto/16 :goto_0

    :cond_a
    move-object v0, v2

    goto/16 :goto_0

    :cond_b
    return-object v2
.end method

.method public static final OooOOOO(Llyiahf/vczjk/zf4;)Ljava/lang/reflect/Method;
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/mba;->OooO00o(Llyiahf/vczjk/bf4;)Llyiahf/vczjk/ff4;

    move-result-object p0

    const/4 v0, 0x0

    if-eqz p0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/ff4;->OooOO0O()Llyiahf/vczjk/so0;

    move-result-object p0

    if-eqz p0, :cond_0

    invoke-interface {p0}, Llyiahf/vczjk/so0;->OooO00o()Ljava/lang/reflect/Member;

    move-result-object p0

    goto :goto_0

    :cond_0
    move-object p0, v0

    :goto_0
    instance-of v1, p0, Ljava/lang/reflect/Method;

    if-eqz v1, :cond_1

    check-cast p0, Ljava/lang/reflect/Method;

    return-object p0

    :cond_1
    return-object v0
.end method

.method public static OooOOOo(I)Z
    .locals 1

    invoke-static {p0}, Ljava/lang/Character;->getType(I)I

    move-result p0

    const/16 v0, 0x17

    if-eq p0, v0, :cond_1

    const/16 v0, 0x14

    if-eq p0, v0, :cond_1

    const/16 v0, 0x16

    if-eq p0, v0, :cond_1

    const/16 v0, 0x1e

    if-eq p0, v0, :cond_1

    const/16 v0, 0x1d

    if-eq p0, v0, :cond_1

    const/16 v0, 0x18

    if-eq p0, v0, :cond_1

    const/16 v0, 0x15

    if-ne p0, v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    return p0

    :cond_1
    :goto_0
    const/4 p0, 0x1

    return p0
.end method

.method public static final OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;
    .locals 54

    move/from16 v0, p0

    const/4 v1, 0x1

    sget-object v2, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/content/Context;

    sget-object v4, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v4

    sget-object v5, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0Oo:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/wr7;

    monitor-enter v5

    :try_start_0
    iget-object v6, v5, Llyiahf/vczjk/wr7;->OooO00o:Llyiahf/vczjk/or5;

    invoke-virtual {v6, v0}, Llyiahf/vczjk/s14;->OooO0O0(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Landroid/util/TypedValue;

    if-nez v6, :cond_0

    new-instance v6, Landroid/util/TypedValue;

    invoke-direct {v6}, Landroid/util/TypedValue;-><init>()V

    invoke-virtual {v4, v0, v6, v1}, Landroid/content/res/Resources;->getValue(ILandroid/util/TypedValue;Z)V

    iget-object v7, v5, Llyiahf/vczjk/wr7;->OooO00o:Llyiahf/vczjk/or5;

    invoke-virtual {v7, v0}, Llyiahf/vczjk/or5;->OooO0Oo(I)I

    move-result v8

    iget-object v9, v7, Llyiahf/vczjk/s14;->OooO0OO:[Ljava/lang/Object;

    aget-object v10, v9, v8

    iget-object v7, v7, Llyiahf/vczjk/s14;->OooO0O0:[I

    aput v0, v7, v8

    aput-object v6, v9, v8
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    goto/16 :goto_25

    :cond_0
    :goto_0
    monitor-exit v5

    iget-object v5, v6, Landroid/util/TypedValue;->string:Ljava/lang/CharSequence;

    const/4 v8, 0x0

    if-eqz v5, :cond_32

    const-string v9, ".xml"

    invoke-static {v5, v9}, Llyiahf/vczjk/z69;->Oooo0o(Ljava/lang/CharSequence;Ljava/lang/String;)Z

    move-result v9

    if-ne v9, v1, :cond_32

    const v5, -0x2fdd7805

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v2

    iget v5, v6, Landroid/util/TypedValue;->changingConfigurations:I

    sget-object v6, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0OO:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/tv3;

    new-instance v9, Llyiahf/vczjk/sv3;

    invoke-direct {v9, v2, v0}, Llyiahf/vczjk/sv3;-><init>(Landroid/content/res/Resources$Theme;I)V

    iget-object v10, v6, Llyiahf/vczjk/tv3;->OooO00o:Ljava/util/HashMap;

    invoke-virtual {v10, v9}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ljava/lang/ref/WeakReference;

    if-eqz v10, :cond_1

    invoke-virtual {v10}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/rv3;

    goto :goto_1

    :cond_1
    const/4 v10, 0x0

    :goto_1
    if-nez v10, :cond_31

    invoke-virtual {v4, v0}, Landroid/content/res/Resources;->getXml(I)Landroid/content/res/XmlResourceParser;

    move-result-object v0

    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    move-result v10

    :goto_2
    const/4 v11, 0x2

    if-eq v10, v11, :cond_2

    if-eq v10, v1, :cond_2

    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    move-result v10

    goto :goto_2

    :cond_2
    if-ne v10, v11, :cond_30

    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    move-result-object v10

    const-string v12, "vector"

    invoke-static {v10, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_2f

    invoke-static {v0}, Landroid/util/Xml;->asAttributeSet(Lorg/xmlpull/v1/XmlPullParser;)Landroid/util/AttributeSet;

    move-result-object v10

    new-instance v12, Llyiahf/vczjk/yg;

    invoke-direct {v12, v0}, Llyiahf/vczjk/yg;-><init>(Landroid/content/res/XmlResourceParser;)V

    sget-object v13, Llyiahf/vczjk/u34;->OooOOO0:[I

    invoke-static {v4, v2, v10, v13}, Llyiahf/vczjk/ru6;->OooOoO(Landroid/content/res/Resources;Landroid/content/res/Resources$Theme;Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object v13

    invoke-virtual {v13}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v14

    invoke-virtual {v12, v14}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    const-string v14, "autoMirrored"

    invoke-static {v0, v14}, Llyiahf/vczjk/ru6;->OooOo0o(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    move-result v14

    const/4 v15, 0x5

    if-nez v14, :cond_3

    move/from16 v25, v8

    goto :goto_3

    :cond_3
    invoke-virtual {v13, v15, v8}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    move-result v14

    move/from16 v25, v14

    :goto_3
    invoke-virtual {v13}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v14

    invoke-virtual {v12, v14}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    const-string v14, "viewportWidth"

    const/4 v7, 0x7

    const/4 v8, 0x0

    invoke-virtual {v12, v13, v14, v7, v8}, Llyiahf/vczjk/yg;->OooO00o(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    move-result v20

    const-string v14, "viewportHeight"

    const/16 v7, 0x8

    invoke-virtual {v12, v13, v14, v7, v8}, Llyiahf/vczjk/yg;->OooO00o(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    move-result v21

    cmpg-float v14, v20, v8

    if-lez v14, :cond_2e

    cmpg-float v14, v21, v8

    if-lez v14, :cond_2d

    const/4 v14, 0x3

    invoke-virtual {v13, v14, v8}, Landroid/content/res/TypedArray;->getDimension(IF)F

    move-result v16

    invoke-virtual {v13}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v7

    invoke-virtual {v12, v7}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    invoke-virtual {v13, v11, v8}, Landroid/content/res/TypedArray;->getDimension(IF)F

    move-result v7

    invoke-virtual {v13}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v8

    invoke-virtual {v12, v8}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    invoke-virtual {v13, v1}, Landroid/content/res/TypedArray;->hasValue(I)Z

    move-result v8

    if-eqz v8, :cond_6

    new-instance v8, Landroid/util/TypedValue;

    invoke-direct {v8}, Landroid/util/TypedValue;-><init>()V

    invoke-virtual {v13, v1, v8}, Landroid/content/res/TypedArray;->getValue(ILandroid/util/TypedValue;)Z

    iget v8, v8, Landroid/util/TypedValue;->type:I

    if-ne v8, v11, :cond_4

    sget-wide v17, Llyiahf/vczjk/n21;->OooOO0:J

    :goto_4
    move-wide/from16 v22, v17

    goto :goto_5

    :cond_4
    invoke-static {v13, v0, v2}, Llyiahf/vczjk/ru6;->OooOOo0(Landroid/content/res/TypedArray;Lorg/xmlpull/v1/XmlPullParser;Landroid/content/res/Resources$Theme;)Landroid/content/res/ColorStateList;

    move-result-object v8

    invoke-virtual {v13}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v11

    invoke-virtual {v12, v11}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    if-eqz v8, :cond_5

    invoke-virtual {v8}, Landroid/content/res/ColorStateList;->getDefaultColor()I

    move-result v8

    invoke-static {v8}, Llyiahf/vczjk/v34;->OooO0OO(I)J

    move-result-wide v17

    goto :goto_4

    :cond_5
    sget-wide v17, Llyiahf/vczjk/n21;->OooOO0:J

    goto :goto_4

    :cond_6
    sget-wide v17, Llyiahf/vczjk/n21;->OooOO0:J

    goto :goto_4

    :goto_5
    const/4 v8, 0x6

    const/4 v11, -0x1

    invoke-virtual {v13, v8, v11}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result v1

    invoke-virtual {v13}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v8

    invoke-virtual {v12, v8}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    const/16 v8, 0x9

    if-eq v1, v11, :cond_7

    if-eq v1, v14, :cond_9

    if-eq v1, v15, :cond_7

    if-eq v1, v8, :cond_8

    packed-switch v1, :pswitch_data_0

    :cond_7
    move/from16 v24, v15

    goto :goto_6

    :pswitch_0
    const/16 v24, 0xc

    goto :goto_6

    :pswitch_1
    const/16 v1, 0xe

    move/from16 v24, v1

    goto :goto_6

    :pswitch_2
    const/16 v24, 0xd

    goto :goto_6

    :cond_8
    move/from16 v24, v8

    goto :goto_6

    :cond_9
    move/from16 v24, v14

    :goto_6
    invoke-virtual {v4}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v1

    iget v1, v1, Landroid/util/DisplayMetrics;->density:F

    div-float v18, v16, v1

    invoke-virtual {v4}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v1

    iget v1, v1, Landroid/util/DisplayMetrics;->density:F

    div-float v19, v7, v1

    invoke-virtual {v13}, Landroid/content/res/TypedArray;->recycle()V

    new-instance v16, Llyiahf/vczjk/pv3;

    const/16 v26, 0x1

    const/16 v17, 0x0

    invoke-direct/range {v16 .. v26}, Llyiahf/vczjk/pv3;-><init>(Ljava/lang/String;FFFFJIZI)V

    move-object/from16 v1, v16

    const/4 v7, 0x0

    :goto_7
    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->getEventType()I

    move-result v13

    const/4 v8, 0x1

    if-eq v13, v8, :cond_a

    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->getDepth()I

    move-result v13

    if-ge v13, v8, :cond_b

    invoke-interface {v0}, Lorg/xmlpull/v1/XmlPullParser;->getEventType()I

    move-result v8

    if-ne v8, v14, :cond_b

    :cond_a
    move-object/from16 v22, v3

    goto/16 :goto_23

    :cond_b
    iget-object v8, v12, Llyiahf/vczjk/yg;->OooO00o:Landroid/content/res/XmlResourceParser;

    invoke-interface {v8}, Lorg/xmlpull/v1/XmlPullParser;->getEventType()I

    move-result v13

    const-string v11, "group"

    const/4 v15, 0x2

    if-eq v13, v15, :cond_11

    if-eq v13, v14, :cond_e

    :cond_c
    move-object/from16 v20, v0

    :cond_d
    move-object/from16 v22, v3

    move/from16 v21, v7

    :goto_8
    const/16 v3, 0xd

    const/16 v27, 0x8

    :goto_9
    const/16 v28, 0x1

    goto/16 :goto_21

    :cond_e
    invoke-interface {v8}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v11, v8}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_c

    const/16 v28, 0x1

    add-int/lit8 v7, v7, 0x1

    const/4 v8, 0x0

    :goto_a
    if-ge v8, v7, :cond_10

    iget-boolean v11, v1, Llyiahf/vczjk/pv3;->OooOO0O:Z

    if-eqz v11, :cond_f

    const-string v11, "ImageVector.Builder is single use, create a new instance to create a new ImageVector"

    invoke-static {v11}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_f
    iget-object v11, v1, Llyiahf/vczjk/pv3;->OooO:Ljava/util/ArrayList;

    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    move-result v13

    const/4 v15, 0x1

    sub-int/2addr v13, v15

    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/ov3;

    invoke-static {v15, v11}, Llyiahf/vczjk/ix8;->OooO0Oo(ILjava/util/ArrayList;)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/ov3;

    iget-object v11, v11, Llyiahf/vczjk/ov3;->OooOO0:Ljava/util/ArrayList;

    new-instance v29, Llyiahf/vczjk/sda;

    iget-object v15, v13, Llyiahf/vczjk/ov3;->OooO00o:Ljava/lang/String;

    iget v14, v13, Llyiahf/vczjk/ov3;->OooO0O0:F

    move-object/from16 v20, v0

    iget v0, v13, Llyiahf/vczjk/ov3;->OooO0OO:F

    move/from16 v32, v0

    iget v0, v13, Llyiahf/vczjk/ov3;->OooO0Oo:F

    move/from16 v33, v0

    iget v0, v13, Llyiahf/vczjk/ov3;->OooO0o0:F

    move/from16 v34, v0

    iget v0, v13, Llyiahf/vczjk/ov3;->OooO0o:F

    move/from16 v35, v0

    iget v0, v13, Llyiahf/vczjk/ov3;->OooO0oO:F

    move/from16 v36, v0

    iget v0, v13, Llyiahf/vczjk/ov3;->OooO0oo:F

    move/from16 v37, v0

    iget-object v0, v13, Llyiahf/vczjk/ov3;->OooO:Ljava/util/List;

    iget-object v13, v13, Llyiahf/vczjk/ov3;->OooOO0:Ljava/util/ArrayList;

    move-object/from16 v38, v0

    move-object/from16 v39, v13

    move/from16 v31, v14

    move-object/from16 v30, v15

    invoke-direct/range {v29 .. v39}, Llyiahf/vczjk/sda;-><init>(Ljava/lang/String;FFFFFFFLjava/util/List;Ljava/util/ArrayList;)V

    move-object/from16 v0, v29

    invoke-virtual {v11, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    const/16 v28, 0x1

    add-int/lit8 v8, v8, 0x1

    move-object/from16 v0, v20

    const/4 v14, 0x3

    goto :goto_a

    :cond_10
    move-object/from16 v20, v0

    move-object/from16 v22, v3

    const/16 v3, 0xd

    const/4 v7, 0x0

    :goto_b
    const/16 v27, 0x8

    :goto_c
    const/16 v28, 0x1

    goto/16 :goto_22

    :cond_11
    move-object/from16 v20, v0

    invoke-interface {v8}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_d

    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    move-result v13

    sget-object v38, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    const-string v14, ""

    iget-object v15, v12, Llyiahf/vczjk/yg;->OooO0OO:Llyiahf/vczjk/cr6;

    move/from16 v21, v7

    const v7, -0x624e8b7e

    if-eq v13, v7, :cond_28

    const v7, 0x346425

    move-object/from16 v23, v14

    const/high16 v14, 0x3f800000    # 1.0f

    if-eq v13, v7, :cond_16

    const v7, 0x5e0f67f

    if-eq v13, v7, :cond_12

    :goto_d
    move-object/from16 v22, v3

    goto/16 :goto_8

    :cond_12
    invoke-virtual {v0, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_13

    :goto_e
    goto :goto_d

    :cond_13
    sget-object v0, Llyiahf/vczjk/u34;->OooOOO:[I

    invoke-static {v4, v2, v10, v0}, Llyiahf/vczjk/ru6;->OooOoO(Landroid/content/res/Resources;Landroid/content/res/Resources$Theme;Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v7

    invoke-virtual {v12, v7}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    const-string v7, "rotation"

    const/4 v8, 0x5

    const/4 v11, 0x0

    invoke-virtual {v12, v0, v7, v8, v11}, Llyiahf/vczjk/yg;->OooO00o(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    move-result v31

    const/4 v15, 0x1

    invoke-virtual {v0, v15, v11}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v32

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v7

    invoke-virtual {v12, v7}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    const/4 v15, 0x2

    invoke-virtual {v0, v15, v11}, Landroid/content/res/TypedArray;->getFloat(IF)F

    move-result v33

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v7

    invoke-virtual {v12, v7}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    const-string v7, "scaleX"

    const/4 v8, 0x3

    invoke-virtual {v12, v0, v7, v8, v14}, Llyiahf/vczjk/yg;->OooO00o(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    move-result v34

    const-string v7, "scaleY"

    const/4 v8, 0x4

    invoke-virtual {v12, v0, v7, v8, v14}, Llyiahf/vczjk/yg;->OooO00o(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    move-result v35

    const-string v7, "translateX"

    const/4 v8, 0x6

    invoke-virtual {v12, v0, v7, v8, v11}, Llyiahf/vczjk/yg;->OooO00o(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    move-result v36

    const-string v7, "translateY"

    const/4 v8, 0x7

    invoke-virtual {v12, v0, v7, v8, v11}, Llyiahf/vczjk/yg;->OooO00o(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    move-result v37

    const/4 v7, 0x0

    invoke-virtual {v0, v7}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v7

    invoke-virtual {v12, v7}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    if-nez v8, :cond_14

    move-object/from16 v30, v23

    goto :goto_f

    :cond_14
    move-object/from16 v30, v8

    :goto_f
    invoke-virtual {v0}, Landroid/content/res/TypedArray;->recycle()V

    sget v0, Llyiahf/vczjk/tda;->OooO00o:I

    iget-boolean v0, v1, Llyiahf/vczjk/pv3;->OooOO0O:Z

    if-eqz v0, :cond_15

    const-string v0, "ImageVector.Builder is single use, create a new instance to create a new ImageVector"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_15
    new-instance v29, Llyiahf/vczjk/ov3;

    const/16 v39, 0x200

    invoke-direct/range {v29 .. v39}, Llyiahf/vczjk/ov3;-><init>(Ljava/lang/String;FFFFFFFLjava/util/List;I)V

    move-object/from16 v0, v29

    iget-object v7, v1, Llyiahf/vczjk/pv3;->OooO:Ljava/util/ArrayList;

    invoke-virtual {v7, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object/from16 v22, v3

    move/from16 v7, v21

    const/16 v3, 0xd

    goto/16 :goto_b

    :cond_16
    const-string v7, "path"

    invoke-virtual {v0, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_17

    goto/16 :goto_e

    :cond_17
    sget-object v0, Llyiahf/vczjk/u34;->OooOOOO:[I

    invoke-static {v4, v2, v10, v0}, Llyiahf/vczjk/ru6;->OooOoO(Landroid/content/res/Resources;Landroid/content/res/Resources$Theme;Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v7

    invoke-virtual {v12, v7}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    const-string v7, "pathData"

    const-string v11, "http://schemas.android.com/apk/res/android"

    invoke-interface {v8, v11, v7}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    if-eqz v7, :cond_27

    const/4 v7, 0x0

    invoke-virtual {v0, v7}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v7

    invoke-virtual {v12, v7}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    if-nez v8, :cond_18

    move-object/from16 v40, v23

    :goto_10
    const/4 v7, 0x2

    goto :goto_11

    :cond_18
    move-object/from16 v40, v8

    goto :goto_10

    :goto_11
    invoke-virtual {v0, v7}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v7

    invoke-virtual {v12, v7}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    if-nez v8, :cond_19

    sget v7, Llyiahf/vczjk/tda;->OooO00o:I

    :goto_12
    move-object/from16 v41, v38

    goto :goto_13

    :cond_19
    invoke-static {v15, v8}, Llyiahf/vczjk/cr6;->OooO0O0(Llyiahf/vczjk/cr6;Ljava/lang/String;)Ljava/util/ArrayList;

    move-result-object v38

    goto :goto_12

    :goto_13
    const-string v7, "fillColor"

    iget-object v8, v12, Llyiahf/vczjk/yg;->OooO00o:Landroid/content/res/XmlResourceParser;

    const/4 v15, 0x1

    invoke-static {v0, v8, v2, v7, v15}, Llyiahf/vczjk/ru6;->OooOOo(Landroid/content/res/TypedArray;Lorg/xmlpull/v1/XmlPullParser;Landroid/content/res/Resources$Theme;Ljava/lang/String;I)Llyiahf/vczjk/yw;

    move-result-object v7

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v8

    invoke-virtual {v12, v8}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    const-string v8, "fillAlpha"

    const/16 v11, 0xc

    invoke-virtual {v12, v0, v8, v11, v14}, Llyiahf/vczjk/yg;->OooO00o(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    move-result v44

    const-string v8, "strokeLineCap"

    iget-object v13, v12, Llyiahf/vczjk/yg;->OooO00o:Landroid/content/res/XmlResourceParser;

    const/4 v11, -0x1

    const/16 v15, 0x8

    invoke-static {v0, v13, v8, v15, v11}, Llyiahf/vczjk/ru6;->OooOOoo(Landroid/content/res/TypedArray;Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;II)I

    move-result v8

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v11

    invoke-virtual {v12, v11}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    if-eqz v8, :cond_1c

    const/4 v11, 0x1

    if-eq v8, v11, :cond_1b

    const/4 v11, 0x2

    if-eq v8, v11, :cond_1a

    :goto_14
    const/16 v48, 0x0

    goto :goto_15

    :cond_1a
    move/from16 v48, v11

    goto :goto_15

    :cond_1b
    const/4 v11, 0x2

    const/16 v48, 0x1

    goto :goto_15

    :cond_1c
    const/4 v11, 0x2

    goto :goto_14

    :goto_15
    const-string v8, "strokeLineJoin"

    iget-object v13, v12, Llyiahf/vczjk/yg;->OooO00o:Landroid/content/res/XmlResourceParser;

    const/4 v11, -0x1

    const/16 v14, 0x9

    invoke-static {v0, v13, v8, v14, v11}, Llyiahf/vczjk/ru6;->OooOOoo(Landroid/content/res/TypedArray;Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;II)I

    move-result v8

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v13

    invoke-virtual {v12, v13}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    if-eqz v8, :cond_1e

    const/4 v13, 0x1

    if-eq v8, v13, :cond_1d

    const/16 v49, 0x2

    goto :goto_16

    :cond_1d
    const/16 v49, 0x1

    goto :goto_16

    :cond_1e
    const/16 v49, 0x0

    :goto_16
    const-string v8, "strokeMiterLimit"

    const/16 v13, 0xa

    const/high16 v11, 0x3f800000    # 1.0f

    invoke-virtual {v12, v0, v8, v13, v11}, Llyiahf/vczjk/yg;->OooO00o(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    move-result v50

    const-string v8, "strokeColor"

    iget-object v13, v12, Llyiahf/vczjk/yg;->OooO00o:Landroid/content/res/XmlResourceParser;

    const/4 v14, 0x3

    invoke-static {v0, v13, v2, v8, v14}, Llyiahf/vczjk/ru6;->OooOOo(Landroid/content/res/TypedArray;Lorg/xmlpull/v1/XmlPullParser;Landroid/content/res/Resources$Theme;Ljava/lang/String;I)Llyiahf/vczjk/yw;

    move-result-object v8

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v13

    invoke-virtual {v12, v13}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    const-string v13, "strokeAlpha"

    const/16 v14, 0xb

    invoke-virtual {v12, v0, v13, v14, v11}, Llyiahf/vczjk/yg;->OooO00o(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    move-result v46

    const-string v13, "strokeWidth"

    const/4 v14, 0x4

    invoke-virtual {v12, v0, v13, v14, v11}, Llyiahf/vczjk/yg;->OooO00o(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    move-result v47

    const-string v13, "trimPathEnd"

    const/4 v14, 0x6

    invoke-virtual {v12, v0, v13, v14, v11}, Llyiahf/vczjk/yg;->OooO00o(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    move-result v52

    const-string v11, "trimPathOffset"

    const/4 v13, 0x7

    const/4 v14, 0x0

    invoke-virtual {v12, v0, v11, v13, v14}, Llyiahf/vczjk/yg;->OooO00o(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    move-result v53

    const-string v11, "trimPathStart"

    const/4 v13, 0x5

    invoke-virtual {v12, v0, v11, v13, v14}, Llyiahf/vczjk/yg;->OooO00o(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    move-result v51

    const-string v11, "fillType"

    iget-object v13, v12, Llyiahf/vczjk/yg;->OooO00o:Landroid/content/res/XmlResourceParser;

    move-object/from16 v22, v3

    const/16 v3, 0xd

    const/4 v14, 0x0

    invoke-static {v0, v13, v11, v3, v14}, Llyiahf/vczjk/ru6;->OooOOoo(Landroid/content/res/TypedArray;Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;II)I

    move-result v11

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v13

    invoke-virtual {v12, v13}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->recycle()V

    iget-object v0, v7, Llyiahf/vczjk/yw;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Landroid/graphics/Shader;

    if-eqz v0, :cond_1f

    goto :goto_17

    :cond_1f
    iget v13, v7, Llyiahf/vczjk/yw;->OooO0O0:I

    if-eqz v13, :cond_21

    :goto_17
    if-eqz v0, :cond_20

    new-instance v7, Llyiahf/vczjk/si0;

    invoke-direct {v7, v0}, Llyiahf/vczjk/si0;-><init>(Landroid/graphics/Shader;)V

    move-object/from16 v43, v7

    goto :goto_18

    :cond_20
    new-instance v0, Llyiahf/vczjk/gx8;

    iget v7, v7, Llyiahf/vczjk/yw;->OooO0O0:I

    invoke-static {v7}, Llyiahf/vczjk/v34;->OooO0OO(I)J

    move-result-wide v13

    invoke-direct {v0, v13, v14}, Llyiahf/vczjk/gx8;-><init>(J)V

    move-object/from16 v43, v0

    goto :goto_18

    :cond_21
    const/16 v43, 0x0

    :goto_18
    iget-object v0, v8, Llyiahf/vczjk/yw;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Landroid/graphics/Shader;

    if-eqz v0, :cond_22

    goto :goto_19

    :cond_22
    iget v7, v8, Llyiahf/vczjk/yw;->OooO0O0:I

    if-eqz v7, :cond_24

    :goto_19
    if-eqz v0, :cond_23

    new-instance v7, Llyiahf/vczjk/si0;

    invoke-direct {v7, v0}, Llyiahf/vczjk/si0;-><init>(Landroid/graphics/Shader;)V

    :goto_1a
    move-object/from16 v45, v7

    goto :goto_1b

    :cond_23
    new-instance v7, Llyiahf/vczjk/gx8;

    iget v0, v8, Llyiahf/vczjk/yw;->OooO0O0:I

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooO0OO(I)J

    move-result-wide v13

    invoke-direct {v7, v13, v14}, Llyiahf/vczjk/gx8;-><init>(J)V

    goto :goto_1a

    :cond_24
    const/16 v45, 0x0

    :goto_1b
    if-nez v11, :cond_25

    const/16 v42, 0x0

    goto :goto_1c

    :cond_25
    const/16 v42, 0x1

    :goto_1c
    iget-boolean v0, v1, Llyiahf/vczjk/pv3;->OooOO0O:Z

    if-eqz v0, :cond_26

    const-string v0, "ImageVector.Builder is single use, create a new instance to create a new ImageVector"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_26
    iget-object v0, v1, Llyiahf/vczjk/pv3;->OooO:Ljava/util/ArrayList;

    const/4 v8, 0x1

    invoke-static {v8, v0}, Llyiahf/vczjk/ix8;->OooO0Oo(ILjava/util/ArrayList;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ov3;

    iget-object v0, v0, Llyiahf/vczjk/ov3;->OooOO0:Ljava/util/ArrayList;

    new-instance v39, Llyiahf/vczjk/xda;

    invoke-direct/range {v39 .. v53}, Llyiahf/vczjk/xda;-><init>(Ljava/lang/String;Ljava/util/List;ILlyiahf/vczjk/ri0;FLlyiahf/vczjk/ri0;FFIIFFFF)V

    move-object/from16 v7, v39

    invoke-virtual {v0, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move/from16 v27, v15

    move/from16 v7, v21

    goto/16 :goto_c

    :cond_27
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "No path data available"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_28
    move-object/from16 v22, v3

    move-object/from16 v23, v14

    const/16 v3, 0xd

    const/16 v27, 0x8

    const-string v7, "clip-path"

    invoke-virtual {v0, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_29

    goto/16 :goto_9

    :cond_29
    sget-object v0, Llyiahf/vczjk/u34;->OooOOOo:[I

    invoke-static {v4, v2, v10, v0}, Llyiahf/vczjk/ru6;->OooOoO(Landroid/content/res/Resources;Landroid/content/res/Resources$Theme;Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v7

    invoke-virtual {v12, v7}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    const/4 v7, 0x0

    invoke-virtual {v0, v7}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v7

    invoke-virtual {v12, v7}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    if-nez v8, :cond_2a

    move-object/from16 v40, v23

    :goto_1d
    const/4 v8, 0x1

    goto :goto_1e

    :cond_2a
    move-object/from16 v40, v8

    goto :goto_1d

    :goto_1e
    invoke-virtual {v0, v8}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v0}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    move-result v8

    invoke-virtual {v12, v8}, Llyiahf/vczjk/yg;->OooO0O0(I)V

    if-nez v7, :cond_2b

    sget v7, Llyiahf/vczjk/tda;->OooO00o:I

    :goto_1f
    move-object/from16 v48, v38

    goto :goto_20

    :cond_2b
    invoke-static {v15, v7}, Llyiahf/vczjk/cr6;->OooO0O0(Llyiahf/vczjk/cr6;Ljava/lang/String;)Ljava/util/ArrayList;

    move-result-object v38

    goto :goto_1f

    :goto_20
    invoke-virtual {v0}, Landroid/content/res/TypedArray;->recycle()V

    iget-boolean v0, v1, Llyiahf/vczjk/pv3;->OooOO0O:Z

    if-eqz v0, :cond_2c

    const-string v0, "ImageVector.Builder is single use, create a new instance to create a new ImageVector"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_2c
    new-instance v39, Llyiahf/vczjk/ov3;

    const/16 v49, 0x200

    const/16 v41, 0x0

    const/16 v42, 0x0

    const/16 v43, 0x0

    const/high16 v44, 0x3f800000    # 1.0f

    const/high16 v45, 0x3f800000    # 1.0f

    const/16 v46, 0x0

    const/16 v47, 0x0

    invoke-direct/range {v39 .. v49}, Llyiahf/vczjk/ov3;-><init>(Ljava/lang/String;FFFFFFFLjava/util/List;I)V

    move-object/from16 v0, v39

    iget-object v7, v1, Llyiahf/vczjk/pv3;->OooO:Ljava/util/ArrayList;

    invoke-virtual {v7, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    const/16 v28, 0x1

    add-int/lit8 v7, v21, 0x1

    goto :goto_22

    :goto_21
    move/from16 v7, v21

    :goto_22
    invoke-interface/range {v20 .. v20}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    move-object/from16 v0, v20

    move-object/from16 v3, v22

    const/16 v8, 0x9

    const/4 v11, -0x1

    const/4 v14, 0x3

    const/4 v15, 0x5

    goto/16 :goto_7

    :goto_23
    new-instance v10, Llyiahf/vczjk/rv3;

    invoke-virtual {v1}, Llyiahf/vczjk/pv3;->OooO0O0()Llyiahf/vczjk/qv3;

    move-result-object v0

    invoke-direct {v10, v0, v5}, Llyiahf/vczjk/rv3;-><init>(Llyiahf/vczjk/qv3;I)V

    iget-object v0, v6, Llyiahf/vczjk/tv3;->OooO00o:Ljava/util/HashMap;

    new-instance v1, Ljava/lang/ref/WeakReference;

    invoke-direct {v1, v10}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    invoke-virtual {v0, v9, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_24

    :cond_2d
    new-instance v0, Lorg/xmlpull/v1/XmlPullParserException;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v13}, Landroid/content/res/TypedArray;->getPositionDescription()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "<VectorGraphic> tag requires viewportHeight > 0"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_2e
    new-instance v0, Lorg/xmlpull/v1/XmlPullParserException;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v13}, Landroid/content/res/TypedArray;->getPositionDescription()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "<VectorGraphic> tag requires viewportWidth > 0"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_2f
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Only VectorDrawables and rasterized asset types are supported ex. PNG, JPG, WEBP"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_30
    new-instance v0, Lorg/xmlpull/v1/XmlPullParserException;

    const-string v1, "No start tag found"

    invoke-direct {v0, v1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_31
    move-object/from16 v22, v3

    :goto_24
    iget-object v0, v10, Llyiahf/vczjk/rv3;->OooO00o:Llyiahf/vczjk/qv3;

    move-object/from16 v1, v22

    invoke-static {v0, v1}, Llyiahf/vczjk/ru6;->OooOoOO(Llyiahf/vczjk/qv3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/wda;

    move-result-object v0

    const/4 v7, 0x0

    invoke-virtual {v1, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v0

    :cond_32
    move-object v1, v3

    const v3, -0x2fdb18db

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v2

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v6

    or-int/2addr v3, v6

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v2, v3

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_33

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v3, v2, :cond_34

    :cond_33
    const/4 v2, 0x0

    :try_start_1
    invoke-virtual {v4, v0, v2}, Landroid/content/res/Resources;->getDrawable(ILandroid/content/res/Resources$Theme;)Landroid/graphics/drawable/Drawable;

    move-result-object v0

    const-string v2, "null cannot be cast to non-null type android.graphics.drawable.BitmapDrawable"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Landroid/graphics/drawable/BitmapDrawable;

    invoke-virtual {v0}, Landroid/graphics/drawable/BitmapDrawable;->getBitmap()Landroid/graphics/Bitmap;

    move-result-object v0

    new-instance v3, Llyiahf/vczjk/kd;

    invoke-direct {v3, v0}, Llyiahf/vczjk/kd;-><init>(Landroid/graphics/Bitmap;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_34
    check-cast v3, Llyiahf/vczjk/lu3;

    new-instance v0, Llyiahf/vczjk/cd0;

    invoke-direct {v0, v3}, Llyiahf/vczjk/cd0;-><init>(Llyiahf/vczjk/lu3;)V

    const/4 v7, 0x0

    invoke-virtual {v1, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v0

    :catch_0
    move-exception v0

    new-instance v1, Llyiahf/vczjk/k61;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Error attempting to load resource: "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v1

    :goto_25
    monitor-exit v5

    throw v0

    :pswitch_data_0
    .packed-switch 0xe
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static final OooOOo0(Llyiahf/vczjk/qc7;)I
    .locals 2

    if-nez p0, :cond_0

    const/4 p0, -0x1

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/ae7;->OooO00o:[I

    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    move-result p0

    aget p0, v0, p0

    :goto_0
    const/4 v0, 0x1

    if-eq p0, v0, :cond_2

    const/4 v1, 0x2

    if-eq p0, v1, :cond_1

    const/4 v1, 0x3

    if-eq p0, v1, :cond_1

    const/4 v1, 0x4

    if-eq p0, v1, :cond_1

    goto :goto_1

    :cond_1
    return v1

    :cond_2
    :goto_1
    return v0
.end method

.method public static final OooOOoo(Llyiahf/vczjk/rn9;Llyiahf/vczjk/yn4;)Llyiahf/vczjk/rn9;
    .locals 30

    move-object/from16 v0, p0

    new-instance v1, Llyiahf/vczjk/rn9;

    iget-object v2, v0, Llyiahf/vczjk/rn9;->OooO00o:Llyiahf/vczjk/dy8;

    sget-object v3, Llyiahf/vczjk/ey8;->OooO0Oo:Llyiahf/vczjk/kl9;

    iget-object v3, v2, Llyiahf/vczjk/dy8;->OooO00o:Llyiahf/vczjk/kl9;

    sget-object v4, Llyiahf/vczjk/hl9;->OooO00o:Llyiahf/vczjk/hl9;

    invoke-virtual {v3, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_0

    :goto_0
    move-object v5, v3

    goto :goto_1

    :cond_0
    sget-object v3, Llyiahf/vczjk/ey8;->OooO0Oo:Llyiahf/vczjk/kl9;

    goto :goto_0

    :goto_1
    sget-object v3, Llyiahf/vczjk/un9;->OooO0O0:[Llyiahf/vczjk/vn9;

    iget-wide v3, v2, Llyiahf/vczjk/dy8;->OooO0O0:J

    const-wide v24, 0xff00000000L

    and-long v6, v3, v24

    const-wide/16 v26, 0x0

    cmp-long v6, v6, v26

    if-nez v6, :cond_1

    sget-wide v3, Llyiahf/vczjk/ey8;->OooO00o:J

    :cond_1
    move-wide v6, v3

    iget-object v3, v2, Llyiahf/vczjk/dy8;->OooO0OO:Llyiahf/vczjk/ib3;

    if-nez v3, :cond_2

    sget-object v3, Llyiahf/vczjk/ib3;->OooOOoo:Llyiahf/vczjk/ib3;

    :cond_2
    move-object v8, v3

    iget-object v3, v2, Llyiahf/vczjk/dy8;->OooO0Oo:Llyiahf/vczjk/cb3;

    if-eqz v3, :cond_3

    iget v3, v3, Llyiahf/vczjk/cb3;->OooO00o:I

    goto :goto_2

    :cond_3
    const/4 v3, 0x0

    :goto_2
    new-instance v9, Llyiahf/vczjk/cb3;

    invoke-direct {v9, v3}, Llyiahf/vczjk/cb3;-><init>(I)V

    iget-object v3, v2, Llyiahf/vczjk/dy8;->OooO0o0:Llyiahf/vczjk/db3;

    if-eqz v3, :cond_4

    iget v3, v3, Llyiahf/vczjk/db3;->OooO00o:I

    goto :goto_3

    :cond_4
    const v3, 0xffff

    :goto_3
    new-instance v10, Llyiahf/vczjk/db3;

    invoke-direct {v10, v3}, Llyiahf/vczjk/db3;-><init>(I)V

    iget-object v3, v2, Llyiahf/vczjk/dy8;->OooO0o:Llyiahf/vczjk/ba3;

    if-nez v3, :cond_5

    sget-object v3, Llyiahf/vczjk/ba3;->OooOOO0:Llyiahf/vczjk/g22;

    :cond_5
    move-object v11, v3

    iget-object v3, v2, Llyiahf/vczjk/dy8;->OooO0oO:Ljava/lang/String;

    if-nez v3, :cond_6

    const-string v3, ""

    :cond_6
    move-object v12, v3

    iget-wide v3, v2, Llyiahf/vczjk/dy8;->OooO0oo:J

    and-long v13, v3, v24

    cmp-long v13, v13, v26

    if-nez v13, :cond_7

    sget-wide v3, Llyiahf/vczjk/ey8;->OooO0O0:J

    :cond_7
    move-wide v13, v3

    iget-object v3, v2, Llyiahf/vczjk/dy8;->OooO:Llyiahf/vczjk/f90;

    if-eqz v3, :cond_8

    iget v3, v3, Llyiahf/vczjk/f90;->OooO00o:F

    goto :goto_4

    :cond_8
    const/4 v3, 0x0

    :goto_4
    new-instance v15, Llyiahf/vczjk/f90;

    invoke-direct {v15, v3}, Llyiahf/vczjk/f90;-><init>(F)V

    iget-object v3, v2, Llyiahf/vczjk/dy8;->OooOO0:Llyiahf/vczjk/ll9;

    if-nez v3, :cond_9

    sget-object v3, Llyiahf/vczjk/ll9;->OooO0OO:Llyiahf/vczjk/ll9;

    :cond_9
    move-object/from16 v16, v3

    iget-object v3, v2, Llyiahf/vczjk/dy8;->OooOO0O:Llyiahf/vczjk/e45;

    if-nez v3, :cond_a

    sget-object v3, Llyiahf/vczjk/e45;->OooOOOO:Llyiahf/vczjk/e45;

    sget-object v3, Llyiahf/vczjk/gx6;->OooO00o:Llyiahf/vczjk/uqa;

    invoke-virtual {v3}, Llyiahf/vczjk/uqa;->OooOOo0()Llyiahf/vczjk/e45;

    move-result-object v3

    :cond_a
    move-object/from16 v17, v3

    const-wide/16 v18, 0x10

    iget-wide v3, v2, Llyiahf/vczjk/dy8;->OooOO0o:J

    cmp-long v18, v3, v18

    if-eqz v18, :cond_b

    :goto_5
    move-wide/from16 v18, v3

    goto :goto_6

    :cond_b
    sget-wide v3, Llyiahf/vczjk/ey8;->OooO0OO:J

    goto :goto_5

    :goto_6
    iget-object v3, v2, Llyiahf/vczjk/dy8;->OooOOO0:Llyiahf/vczjk/vh9;

    if-nez v3, :cond_c

    sget-object v3, Llyiahf/vczjk/vh9;->OooO0O0:Llyiahf/vczjk/vh9;

    :cond_c
    move-object/from16 v20, v3

    iget-object v3, v2, Llyiahf/vczjk/dy8;->OooOOO:Llyiahf/vczjk/ij8;

    if-nez v3, :cond_d

    sget-object v3, Llyiahf/vczjk/ij8;->OooO0Oo:Llyiahf/vczjk/ij8;

    :cond_d
    move-object/from16 v21, v3

    iget-object v3, v2, Llyiahf/vczjk/dy8;->OooOOOo:Llyiahf/vczjk/ig2;

    if-nez v3, :cond_e

    sget-object v3, Llyiahf/vczjk/i03;->OooO00o:Llyiahf/vczjk/i03;

    :cond_e
    move-object/from16 v23, v3

    new-instance v4, Llyiahf/vczjk/dy8;

    iget-object v2, v2, Llyiahf/vczjk/dy8;->OooOOOO:Llyiahf/vczjk/ox6;

    move-object/from16 v22, v2

    invoke-direct/range {v4 .. v23}, Llyiahf/vczjk/dy8;-><init>(Llyiahf/vczjk/kl9;JLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/db3;Llyiahf/vczjk/ba3;Ljava/lang/String;JLlyiahf/vczjk/f90;Llyiahf/vczjk/ll9;Llyiahf/vczjk/e45;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ij8;Llyiahf/vczjk/ox6;Llyiahf/vczjk/ig2;)V

    sget v2, Llyiahf/vczjk/io6;->OooO0O0:I

    new-instance v5, Llyiahf/vczjk/ho6;

    iget-object v2, v0, Llyiahf/vczjk/rn9;->OooO0O0:Llyiahf/vczjk/ho6;

    iget v3, v2, Llyiahf/vczjk/ho6;->OooO00o:I

    const/4 v6, 0x5

    const/high16 v7, -0x80000000

    if-ne v3, v7, :cond_f

    move v3, v6

    :cond_f
    const/4 v8, 0x3

    const/4 v9, 0x1

    iget v10, v2, Llyiahf/vczjk/ho6;->OooO0O0:I

    if-ne v10, v8, :cond_12

    invoke-virtual/range {p1 .. p1}, Ljava/lang/Enum;->ordinal()I

    move-result v8

    if-eqz v8, :cond_11

    if-ne v8, v9, :cond_10

    goto :goto_7

    :cond_10
    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :cond_11
    const/4 v6, 0x4

    goto :goto_7

    :cond_12
    if-ne v10, v7, :cond_15

    invoke-virtual/range {p1 .. p1}, Ljava/lang/Enum;->ordinal()I

    move-result v6

    if-eqz v6, :cond_14

    if-ne v6, v9, :cond_13

    const/4 v6, 0x2

    goto :goto_7

    :cond_13
    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :cond_14
    move v6, v9

    goto :goto_7

    :cond_15
    move v6, v10

    :goto_7
    iget-wide v10, v2, Llyiahf/vczjk/ho6;->OooO0OO:J

    and-long v12, v10, v24

    cmp-long v8, v12, v26

    if-nez v8, :cond_16

    sget-wide v10, Llyiahf/vczjk/io6;->OooO00o:J

    :cond_16
    iget-object v8, v2, Llyiahf/vczjk/ho6;->OooO0Oo:Llyiahf/vczjk/ol9;

    if-nez v8, :cond_17

    sget-object v8, Llyiahf/vczjk/ol9;->OooO0OO:Llyiahf/vczjk/ol9;

    :cond_17
    iget v12, v2, Llyiahf/vczjk/ho6;->OooO0oO:I

    if-nez v12, :cond_18

    sget v12, Llyiahf/vczjk/cz4;->OooO0O0:I

    :cond_18
    move v13, v12

    iget v12, v2, Llyiahf/vczjk/ho6;->OooO0oo:I

    if-ne v12, v7, :cond_19

    move v14, v9

    goto :goto_8

    :cond_19
    move v14, v12

    :goto_8
    iget-object v7, v2, Llyiahf/vczjk/ho6;->OooO:Llyiahf/vczjk/dn9;

    if-nez v7, :cond_1a

    sget-object v7, Llyiahf/vczjk/dn9;->OooO0OO:Llyiahf/vczjk/dn9;

    :cond_1a
    move-wide/from16 v28, v10

    move-object v10, v8

    move-wide/from16 v8, v28

    move-object v15, v7

    iget-object v11, v2, Llyiahf/vczjk/ho6;->OooO0o0:Llyiahf/vczjk/lx6;

    iget-object v12, v2, Llyiahf/vczjk/ho6;->OooO0o:Llyiahf/vczjk/jz4;

    move v7, v6

    move v6, v3

    invoke-direct/range {v5 .. v15}, Llyiahf/vczjk/ho6;-><init>(IIJLlyiahf/vczjk/ol9;Llyiahf/vczjk/lx6;Llyiahf/vczjk/jz4;IILlyiahf/vczjk/dn9;)V

    iget-object v0, v0, Llyiahf/vczjk/rn9;->OooO0OO:Llyiahf/vczjk/vx6;

    invoke-direct {v1, v4, v5, v0}, Llyiahf/vczjk/rn9;-><init>(Llyiahf/vczjk/dy8;Llyiahf/vczjk/ho6;Llyiahf/vczjk/vx6;)V

    return-object v1
.end method

.method public static final OooOo(Llyiahf/vczjk/c0a;Llyiahf/vczjk/oe3;)V
    .locals 12

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/jl5;

    iget-object v1, v0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v1, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v1, :cond_0

    const-string v1, "visitSubtreeIf called on an unattached node"

    invoke-static {v1}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    new-instance v1, Llyiahf/vczjk/ws5;

    const/16 v2, 0x10

    new-array v3, v2, [Llyiahf/vczjk/jl5;

    invoke-direct {v1, v3}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-object v3, v0, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    if-nez v3, :cond_1

    invoke-static {v1, v0}, Llyiahf/vczjk/yi4;->OooOOoo(Llyiahf/vczjk/ws5;Llyiahf/vczjk/jl5;)V

    goto :goto_0

    :cond_1
    invoke-virtual {v1, v3}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_2
    :goto_0
    iget v0, v1, Llyiahf/vczjk/ws5;->OooOOOO:I

    if-eqz v0, :cond_e

    add-int/lit8 v0, v0, -0x1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ws5;->OooOO0O(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/jl5;

    iget v3, v0, Llyiahf/vczjk/jl5;->OooOOOo:I

    const/high16 v4, 0x40000

    and-int/2addr v3, v4

    if-eqz v3, :cond_d

    move-object v3, v0

    :goto_1
    if-eqz v3, :cond_d

    iget v5, v3, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v5, v4

    if-eqz v5, :cond_c

    const/4 v5, 0x0

    move-object v6, v3

    move-object v7, v5

    :goto_2
    if-eqz v6, :cond_c

    instance-of v8, v6, Llyiahf/vczjk/c0a;

    if-eqz v8, :cond_5

    check-cast v6, Llyiahf/vczjk/c0a;

    invoke-interface {p0}, Llyiahf/vczjk/c0a;->OooOO0O()Ljava/lang/Object;

    move-result-object v8

    invoke-interface {v6}, Llyiahf/vczjk/c0a;->OooOO0O()Ljava/lang/Object;

    move-result-object v9

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_3

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v8

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v9

    if-ne v8, v9, :cond_3

    invoke-interface {p1, v6}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/b0a;

    goto :goto_3

    :cond_3
    sget-object v6, Llyiahf/vczjk/b0a;->OooOOO0:Llyiahf/vczjk/b0a;

    :goto_3
    sget-object v8, Llyiahf/vczjk/b0a;->OooOOOO:Llyiahf/vczjk/b0a;

    if-ne v6, v8, :cond_4

    goto :goto_7

    :cond_4
    sget-object v8, Llyiahf/vczjk/b0a;->OooOOO:Llyiahf/vczjk/b0a;

    if-eq v6, v8, :cond_2

    goto :goto_6

    :cond_5
    iget v8, v6, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v8, v4

    if-eqz v8, :cond_b

    instance-of v8, v6, Llyiahf/vczjk/m52;

    if-eqz v8, :cond_b

    move-object v8, v6

    check-cast v8, Llyiahf/vczjk/m52;

    iget-object v8, v8, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    const/4 v9, 0x0

    :goto_4
    const/4 v10, 0x1

    if-eqz v8, :cond_a

    iget v11, v8, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v11, v4

    if-eqz v11, :cond_9

    add-int/lit8 v9, v9, 0x1

    if-ne v9, v10, :cond_6

    move-object v6, v8

    goto :goto_5

    :cond_6
    if-nez v7, :cond_7

    new-instance v7, Llyiahf/vczjk/ws5;

    new-array v10, v2, [Llyiahf/vczjk/jl5;

    invoke-direct {v7, v10}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_7
    if-eqz v6, :cond_8

    invoke-virtual {v7, v6}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v6, v5

    :cond_8
    invoke-virtual {v7, v8}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_9
    :goto_5
    iget-object v8, v8, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_4

    :cond_a
    if-ne v9, v10, :cond_b

    goto :goto_2

    :cond_b
    :goto_6
    invoke-static {v7}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v6

    goto :goto_2

    :cond_c
    iget-object v3, v3, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_1

    :cond_d
    invoke-static {v1, v0}, Llyiahf/vczjk/yi4;->OooOOoo(Llyiahf/vczjk/ws5;Llyiahf/vczjk/jl5;)V

    goto/16 :goto_0

    :cond_e
    :goto_7
    return-void
.end method

.method public static final OooOo0(Llyiahf/vczjk/ey6;JLlyiahf/vczjk/oe3;Z)V
    .locals 4

    iget-object p0, p0, Llyiahf/vczjk/ey6;->OooO0O0:Llyiahf/vczjk/hl1;

    if-eqz p0, :cond_0

    iget-object p0, p0, Llyiahf/vczjk/hl1;->OooOOOo:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/n62;

    iget-object p0, p0, Llyiahf/vczjk/n62;->OooOOOO:Ljava/lang/Object;

    check-cast p0, Landroid/view/MotionEvent;

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    :goto_0
    if-eqz p0, :cond_2

    invoke-virtual {p0}, Landroid/view/MotionEvent;->getAction()I

    move-result v0

    if-eqz p4, :cond_1

    const/4 p4, 0x3

    invoke-virtual {p0, p4}, Landroid/view/MotionEvent;->setAction(I)V

    :cond_1
    const/16 p4, 0x20

    shr-long v1, p1, p4

    long-to-int p4, v1

    invoke-static {p4}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    neg-float v1, v1

    const-wide v2, 0xffffffffL

    and-long/2addr p1, v2

    long-to-int p1, p1

    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p2

    neg-float p2, p2

    invoke-virtual {p0, v1, p2}, Landroid/view/MotionEvent;->offsetLocation(FF)V

    invoke-interface {p3, p0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-static {p4}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p2

    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p1

    invoke-virtual {p0, p2, p1}, Landroid/view/MotionEvent;->offsetLocation(FF)V

    invoke-virtual {p0, v0}, Landroid/view/MotionEvent;->setAction(I)V

    return-void

    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "The PointerEvent receiver cannot have a null MotionEvent."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V
    .locals 1

    check-cast p1, Llyiahf/vczjk/zf1;

    iget-boolean v0, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0, p0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    return-void

    :cond_1
    :goto_0
    invoke-virtual {p1, p0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    invoke-virtual {p1, p0, p2}, Llyiahf/vczjk/zf1;->OooO0OO(Ljava/lang/Object;Llyiahf/vczjk/ze3;)V

    return-void
.end method

.method public static final OooOo0O(Llyiahf/vczjk/l52;Ljava/lang/Object;Llyiahf/vczjk/oe3;)V
    .locals 10

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/jl5;

    iget-object v1, v0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v1, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v1, :cond_0

    const-string v1, "visitAncestors called on an unattached node"

    invoke-static {v1}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object p0

    :goto_0
    if-eqz p0, :cond_e

    iget-object v1, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v1, v1, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/jl5;

    iget v1, v1, Llyiahf/vczjk/jl5;->OooOOOo:I

    const/high16 v2, 0x40000

    and-int/2addr v1, v2

    const/4 v3, 0x0

    if-eqz v1, :cond_c

    :goto_1
    if-eqz v0, :cond_c

    iget v1, v0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v1, v2

    if-eqz v1, :cond_b

    move-object v1, v0

    move-object v4, v3

    :goto_2
    if-eqz v1, :cond_b

    instance-of v5, v1, Llyiahf/vczjk/c0a;

    const/4 v6, 0x1

    if-eqz v5, :cond_2

    check-cast v1, Llyiahf/vczjk/c0a;

    invoke-interface {v1}, Llyiahf/vczjk/c0a;->OooOO0O()Ljava/lang/Object;

    move-result-object v5

    invoke-virtual {p1, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1

    invoke-interface {p2, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v6

    :cond_1
    if-nez v6, :cond_a

    goto/16 :goto_7

    :cond_2
    iget v5, v1, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v5, v2

    const/4 v7, 0x0

    if-eqz v5, :cond_3

    move v5, v6

    goto :goto_3

    :cond_3
    move v5, v7

    :goto_3
    if-eqz v5, :cond_a

    instance-of v5, v1, Llyiahf/vczjk/m52;

    if-eqz v5, :cond_a

    move-object v5, v1

    check-cast v5, Llyiahf/vczjk/m52;

    iget-object v5, v5, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    move v8, v7

    :goto_4
    if-eqz v5, :cond_9

    iget v9, v5, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v9, v2

    if-eqz v9, :cond_4

    move v9, v6

    goto :goto_5

    :cond_4
    move v9, v7

    :goto_5
    if-eqz v9, :cond_8

    add-int/lit8 v8, v8, 0x1

    if-ne v8, v6, :cond_5

    move-object v1, v5

    goto :goto_6

    :cond_5
    if-nez v4, :cond_6

    new-instance v4, Llyiahf/vczjk/ws5;

    const/16 v9, 0x10

    new-array v9, v9, [Llyiahf/vczjk/jl5;

    invoke-direct {v4, v9}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_6
    if-eqz v1, :cond_7

    invoke-virtual {v4, v1}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v1, v3

    :cond_7
    invoke-virtual {v4, v5}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_8
    :goto_6
    iget-object v5, v5, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_4

    :cond_9
    if-ne v8, v6, :cond_a

    goto :goto_2

    :cond_a
    invoke-static {v4}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v1

    goto :goto_2

    :cond_b
    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto :goto_1

    :cond_c
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object p0

    if-eqz p0, :cond_d

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    if-eqz v0, :cond_d

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cf9;

    goto/16 :goto_0

    :cond_d
    move-object v0, v3

    goto/16 :goto_0

    :cond_e
    :goto_7
    return-void
.end method

.method public static final OooOo0o(Llyiahf/vczjk/c0a;Llyiahf/vczjk/oe3;)V
    .locals 11

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/jl5;

    iget-object v1, v0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v1, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v1, :cond_0

    const-string v1, "visitAncestors called on an unattached node"

    invoke-static {v1}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v1

    :goto_0
    if-eqz v1, :cond_e

    iget-object v2, v1, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v2, v2, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jl5;

    iget v2, v2, Llyiahf/vczjk/jl5;->OooOOOo:I

    const/high16 v3, 0x40000

    and-int/2addr v2, v3

    const/4 v4, 0x0

    if-eqz v2, :cond_c

    :goto_1
    if-eqz v0, :cond_c

    iget v2, v0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v2, v3

    if-eqz v2, :cond_b

    move-object v2, v0

    move-object v5, v4

    :goto_2
    if-eqz v2, :cond_b

    instance-of v6, v2, Llyiahf/vczjk/c0a;

    const/4 v7, 0x1

    if-eqz v6, :cond_2

    check-cast v2, Llyiahf/vczjk/c0a;

    invoke-interface {p0}, Llyiahf/vczjk/c0a;->OooOO0O()Ljava/lang/Object;

    move-result-object v6

    invoke-interface {v2}, Llyiahf/vczjk/c0a;->OooOO0O()Ljava/lang/Object;

    move-result-object v8

    invoke-static {v6, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_1

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v6

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v8

    if-ne v6, v8, :cond_1

    invoke-interface {p1, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v7

    :cond_1
    if-nez v7, :cond_a

    goto/16 :goto_7

    :cond_2
    iget v6, v2, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v6, v3

    const/4 v8, 0x0

    if-eqz v6, :cond_3

    move v6, v7

    goto :goto_3

    :cond_3
    move v6, v8

    :goto_3
    if-eqz v6, :cond_a

    instance-of v6, v2, Llyiahf/vczjk/m52;

    if-eqz v6, :cond_a

    move-object v6, v2

    check-cast v6, Llyiahf/vczjk/m52;

    iget-object v6, v6, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    move v9, v8

    :goto_4
    if-eqz v6, :cond_9

    iget v10, v6, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v10, v3

    if-eqz v10, :cond_4

    move v10, v7

    goto :goto_5

    :cond_4
    move v10, v8

    :goto_5
    if-eqz v10, :cond_8

    add-int/lit8 v9, v9, 0x1

    if-ne v9, v7, :cond_5

    move-object v2, v6

    goto :goto_6

    :cond_5
    if-nez v5, :cond_6

    new-instance v5, Llyiahf/vczjk/ws5;

    const/16 v10, 0x10

    new-array v10, v10, [Llyiahf/vczjk/jl5;

    invoke-direct {v5, v10}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_6
    if-eqz v2, :cond_7

    invoke-virtual {v5, v2}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v2, v4

    :cond_7
    invoke-virtual {v5, v6}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_8
    :goto_6
    iget-object v6, v6, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_4

    :cond_9
    if-ne v9, v7, :cond_a

    goto :goto_2

    :cond_a
    invoke-static {v5}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v2

    goto :goto_2

    :cond_b
    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto/16 :goto_1

    :cond_c
    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v1

    if-eqz v1, :cond_d

    iget-object v0, v1, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    if-eqz v0, :cond_d

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cf9;

    goto/16 :goto_0

    :cond_d
    move-object v0, v4

    goto/16 :goto_0

    :cond_e
    :goto_7
    return-void
.end method

.method public static OooOoO0(Landroid/view/View;)V
    .locals 10

    const-class v0, Ljava/lang/String;

    const-class v1, Ljava/lang/Class;

    const/4 v2, 0x1

    :try_start_0
    sget-boolean v3, Llyiahf/vczjk/wga;->OooOooo:Z

    const/4 v4, 0x0

    if-nez v3, :cond_3

    sput-boolean v2, Llyiahf/vczjk/wga;->OooOooo:Z

    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/16 v5, 0x1c

    const-string v6, "mRecreateDisplayList"

    const-string v7, "updateDisplayListIfDirty"

    const-class v8, Landroid/view/View;

    if-ge v3, v5, :cond_0

    :try_start_1
    invoke-virtual {v8, v7, v4}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/wga;->OooOoo:Ljava/lang/reflect/Method;

    invoke-virtual {v8, v6}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/wga;->OooOooO:Ljava/lang/reflect/Field;

    goto :goto_0

    :cond_0
    const-string v3, "getDeclaredMethod"

    const/4 v5, 0x0

    new-array v9, v5, [Ljava/lang/Class;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v9

    filled-new-array {v0, v9}, [Ljava/lang/Class;

    move-result-object v9

    invoke-virtual {v1, v3, v9}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v3

    new-array v5, v5, [Ljava/lang/Class;

    filled-new-array {v7, v5}, [Ljava/lang/Object;

    move-result-object v5

    invoke-virtual {v3, v8, v5}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/reflect/Method;

    sput-object v3, Llyiahf/vczjk/wga;->OooOoo:Ljava/lang/reflect/Method;

    const-string v3, "getDeclaredField"

    filled-new-array {v0}, [Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v1, v3, v0}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    filled-new-array {v6}, [Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v8, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/reflect/Field;

    sput-object v0, Llyiahf/vczjk/wga;->OooOooO:Ljava/lang/reflect/Field;

    :goto_0
    sget-object v0, Llyiahf/vczjk/wga;->OooOoo:Ljava/lang/reflect/Method;

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v0, v2}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    :goto_1
    sget-object v0, Llyiahf/vczjk/wga;->OooOooO:Ljava/lang/reflect/Field;

    if-nez v0, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v0, v2}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    :cond_3
    :goto_2
    sget-object v0, Llyiahf/vczjk/wga;->OooOooO:Ljava/lang/reflect/Field;

    if-eqz v0, :cond_4

    invoke-virtual {v0, p0, v2}, Ljava/lang/reflect/Field;->setBoolean(Ljava/lang/Object;Z)V

    :cond_4
    sget-object v0, Llyiahf/vczjk/wga;->OooOoo:Ljava/lang/reflect/Method;

    if-eqz v0, :cond_5

    invoke-virtual {v0, p0, v4}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    return-void

    :catchall_0
    sput-boolean v2, Llyiahf/vczjk/wga;->Oooo000:Z

    :cond_5
    return-void
.end method


# virtual methods
.method public OooO00o(Landroid/view/ViewGroup;Landroid/view/View;)F
    .locals 0

    invoke-virtual {p2}, Landroid/view/View;->getTranslationY()F

    move-result p1

    return p1
.end method

.method public final OooO0O0(Landroid/view/ViewGroup;Landroid/view/View;)F
    .locals 2

    iget v0, p0, Llyiahf/vczjk/er8;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-virtual {p1}, Landroid/view/View;->getLayoutDirection()I

    move-result v0

    const/4 v1, 0x1

    if-ne v0, v1, :cond_0

    invoke-virtual {p2}, Landroid/view/View;->getTranslationX()F

    move-result p2

    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    move-result p1

    int-to-float p1, p1

    sub-float/2addr p2, p1

    goto :goto_0

    :cond_0
    invoke-virtual {p2}, Landroid/view/View;->getTranslationX()F

    move-result p2

    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    move-result p1

    int-to-float p1, p1

    add-float/2addr p2, p1

    :goto_0
    return p2

    :pswitch_0
    invoke-virtual {p2}, Landroid/view/View;->getTranslationX()F

    move-result p2

    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    move-result p1

    int-to-float p1, p1

    add-float/2addr p2, p1

    return p2

    :pswitch_1
    invoke-virtual {p1}, Landroid/view/View;->getLayoutDirection()I

    move-result v0

    const/4 v1, 0x1

    if-ne v0, v1, :cond_1

    invoke-virtual {p2}, Landroid/view/View;->getTranslationX()F

    move-result p2

    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    move-result p1

    int-to-float p1, p1

    add-float/2addr p2, p1

    goto :goto_1

    :cond_1
    invoke-virtual {p2}, Landroid/view/View;->getTranslationX()F

    move-result p2

    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    move-result p1

    int-to-float p1, p1

    sub-float/2addr p2, p1

    :goto_1
    return p2

    :pswitch_2
    invoke-virtual {p2}, Landroid/view/View;->getTranslationX()F

    move-result p2

    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    move-result p1

    int-to-float p1, p1

    sub-float/2addr p2, p1

    return p2

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
