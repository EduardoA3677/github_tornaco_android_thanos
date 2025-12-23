.class public final Landroidx/compose/material3/OooO00o;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOO:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOOo:Ljava/lang/String;

.field public final synthetic OooOOo:Z

.field public final synthetic OooOOo0:Ljava/lang/String;

.field public final synthetic OooOOoo:Llyiahf/vczjk/a91;

.field public final synthetic OooOo00:Llyiahf/vczjk/a91;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/qs5;Llyiahf/vczjk/oe3;Ljava/lang/String;Ljava/lang/String;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/a91;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/compose/material3/OooO00o;->OooOOO0:Llyiahf/vczjk/a91;

    iput-object p2, p0, Landroidx/compose/material3/OooO00o;->OooOOO:Llyiahf/vczjk/qs5;

    iput-object p3, p0, Landroidx/compose/material3/OooO00o;->OooOOOO:Llyiahf/vczjk/oe3;

    iput-object p4, p0, Landroidx/compose/material3/OooO00o;->OooOOOo:Ljava/lang/String;

    iput-object p5, p0, Landroidx/compose/material3/OooO00o;->OooOOo0:Ljava/lang/String;

    iput-boolean p6, p0, Landroidx/compose/material3/OooO00o;->OooOOo:Z

    iput-object p7, p0, Landroidx/compose/material3/OooO00o;->OooOOoo:Llyiahf/vczjk/a91;

    iput-object p8, p0, Landroidx/compose/material3/OooO00o;->OooOo00:Llyiahf/vczjk/a91;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v3, v2, 0x3

    const/4 v4, 0x2

    const/4 v5, 0x1

    const/4 v6, 0x0

    if-eq v3, v4, :cond_0

    move v3, v5

    goto :goto_0

    :cond_0
    move v3, v6

    :goto_0
    and-int/2addr v2, v5

    move-object v14, v1

    check-cast v14, Llyiahf/vczjk/zf1;

    invoke-virtual {v14, v2, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_a

    sget-object v1, Llyiahf/vczjk/op3;->OooOoo0:Llyiahf/vczjk/sb0;

    sget-object v2, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    sget-object v7, Llyiahf/vczjk/jw7;->OooO00o:Llyiahf/vczjk/jw7;

    iget-object v3, v0, Landroidx/compose/material3/OooO00o;->OooOOO:Llyiahf/vczjk/qs5;

    const/16 v4, 0xc

    iget-object v8, v0, Landroidx/compose/material3/OooO00o;->OooOOO0:Llyiahf/vczjk/a91;

    if-nez v8, :cond_1

    const v9, 0x184ab802

    invoke-virtual {v14, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v14, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v17, v8

    goto :goto_1

    :cond_1
    const v9, 0x184ab803

    invoke-virtual {v14, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Boolean;

    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v9

    sget v10, Llyiahf/vczjk/y33;->OooO00o:F

    sget-object v10, Llyiahf/vczjk/zo5;->OooOOO:Llyiahf/vczjk/zo5;

    invoke-static {v10, v14}, Llyiahf/vczjk/so8;->OoooO0O(Llyiahf/vczjk/zo5;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p13;

    move-result-object v11

    invoke-static {v11, v2, v4}, Llyiahf/vczjk/uo2;->OooO00o(Llyiahf/vczjk/p13;Llyiahf/vczjk/sb0;I)Llyiahf/vczjk/fp2;

    move-result-object v11

    invoke-static {v10, v14}, Llyiahf/vczjk/so8;->OoooO0O(Llyiahf/vczjk/zo5;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p13;

    move-result-object v10

    invoke-static {v10, v1, v4}, Llyiahf/vczjk/uo2;->OooO0o(Llyiahf/vczjk/p13;Llyiahf/vczjk/sb0;I)Llyiahf/vczjk/dt2;

    move-result-object v10

    new-instance v12, Llyiahf/vczjk/ra2;

    const/4 v13, 0x4

    invoke-direct {v12, v8, v13}, Llyiahf/vczjk/ra2;-><init>(Llyiahf/vczjk/a91;I)V

    const v13, -0x7212c99

    invoke-static {v13, v12, v14}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v13

    const/high16 v15, 0x180000

    const/16 v16, 0x12

    move-object v12, v8

    move v8, v9

    const/4 v9, 0x0

    move-object/from16 v17, v12

    const/4 v12, 0x0

    move-object/from16 v18, v11

    move-object v11, v10

    move-object/from16 v10, v18

    invoke-static/range {v7 .. v16}, Landroidx/compose/animation/OooO0O0;->OooO0OO(Llyiahf/vczjk/iw7;ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v14, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_1
    invoke-virtual {v14, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    iget-object v9, v0, Landroidx/compose/material3/OooO00o;->OooOOOO:Llyiahf/vczjk/oe3;

    invoke-virtual {v14, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v10

    or-int/2addr v8, v10

    iget-object v10, v0, Landroidx/compose/material3/OooO00o;->OooOOOo:Ljava/lang/String;

    invoke-virtual {v14, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v8, v11

    iget-object v11, v0, Landroidx/compose/material3/OooO00o;->OooOOo0:Ljava/lang/String;

    invoke-virtual {v14, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v12

    or-int/2addr v8, v12

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    if-nez v8, :cond_2

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v12, v8, :cond_3

    :cond_2
    new-instance v12, Llyiahf/vczjk/m60;

    invoke-direct {v12, v10, v11, v3, v9}, Llyiahf/vczjk/m60;-><init>(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/qs5;Llyiahf/vczjk/oe3;)V

    invoke-virtual {v14, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v12, Llyiahf/vczjk/oe3;

    new-instance v8, Landroidx/compose/material3/internal/ParentSemanticsNodeElement;

    invoke-direct {v8, v12}, Landroidx/compose/material3/internal/ParentSemanticsNodeElement;-><init>(Llyiahf/vczjk/oe3;)V

    iget-boolean v9, v0, Landroidx/compose/material3/OooO00o;->OooOOo:Z

    if-eqz v9, :cond_4

    if-eqz v17, :cond_4

    move v10, v5

    goto :goto_2

    :cond_4
    move v10, v6

    :goto_2
    iget-object v11, v0, Landroidx/compose/material3/OooO00o;->OooOOoo:Llyiahf/vczjk/a91;

    if-eqz v9, :cond_5

    if-eqz v11, :cond_5

    move v9, v5

    goto :goto_3

    :cond_5
    move v9, v6

    :goto_3
    sget-object v12, Llyiahf/vczjk/we5;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v14, v12}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/yo5;

    invoke-interface {v12}, Llyiahf/vczjk/yo5;->OooO0Oo()Llyiahf/vczjk/wz8;

    move-result-object v12

    new-instance v13, Landroidx/compose/material3/MinimumInteractiveBalancedPaddingElement;

    invoke-direct {v13, v10, v9, v12}, Landroidx/compose/material3/MinimumInteractiveBalancedPaddingElement;-><init>(ZZLlyiahf/vczjk/p13;)V

    invoke-interface {v8, v13}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    sget-object v10, Llyiahf/vczjk/op3;->OooOo0o:Llyiahf/vczjk/tb0;

    invoke-static {v9, v10, v14, v6}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v9

    iget v10, v14, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    invoke-static {v14, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v13, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v14, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_6

    invoke-virtual {v14, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_6
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v13, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v9, v14, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v12, v14, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v12, v14, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v12, :cond_7

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    invoke-static {v12, v13}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v12

    if-nez v12, :cond_8

    :cond_7
    invoke-static {v10, v14, v10, v9}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_8
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v8, v14, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/4 v8, 0x6

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    iget-object v9, v0, Landroidx/compose/material3/OooO00o;->OooOo00:Llyiahf/vczjk/a91;

    invoke-virtual {v9, v7, v14, v8}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v14, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    if-nez v11, :cond_9

    const v1, 0x186567a2

    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    :goto_5
    invoke-virtual {v14, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_6

    :cond_9
    const v5, 0x186567a3

    invoke-virtual {v14, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Boolean;

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v8

    sget v3, Llyiahf/vczjk/y33;->OooO00o:F

    sget-object v3, Llyiahf/vczjk/zo5;->OooOOO:Llyiahf/vczjk/zo5;

    invoke-static {v3, v14}, Llyiahf/vczjk/so8;->OoooO0O(Llyiahf/vczjk/zo5;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p13;

    move-result-object v5

    invoke-static {v5, v1, v4}, Llyiahf/vczjk/uo2;->OooO00o(Llyiahf/vczjk/p13;Llyiahf/vczjk/sb0;I)Llyiahf/vczjk/fp2;

    move-result-object v10

    invoke-static {v3, v14}, Llyiahf/vczjk/so8;->OoooO0O(Llyiahf/vczjk/zo5;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p13;

    move-result-object v1

    invoke-static {v1, v2, v4}, Llyiahf/vczjk/uo2;->OooO0o(Llyiahf/vczjk/p13;Llyiahf/vczjk/sb0;I)Llyiahf/vczjk/dt2;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/ra2;

    const/4 v3, 0x5

    invoke-direct {v2, v11, v3}, Llyiahf/vczjk/ra2;-><init>(Llyiahf/vczjk/a91;I)V

    const v3, -0x4808e2f0

    invoke-static {v3, v2, v14}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v13

    const/high16 v15, 0x180000

    const/16 v16, 0x12

    const/4 v9, 0x0

    const/4 v12, 0x0

    move-object v11, v1

    invoke-static/range {v7 .. v16}, Landroidx/compose/animation/OooO0O0;->OooO0OO(Llyiahf/vczjk/iw7;ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    goto :goto_5

    :cond_a
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_6
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
