.class public final Llyiahf/vczjk/ot8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $a11yPaneTitle:Ljava/lang/String;

.field final synthetic $current:Llyiahf/vczjk/ht8;

.field final synthetic $key:Llyiahf/vczjk/ht8;

.field final synthetic $keys:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/ht8;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic $state:Llyiahf/vczjk/mv2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/mv2;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/util/ArrayList;Llyiahf/vczjk/mv2;Ljava/lang/String;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ot8;->$keys:Ljava/util/List;

    iput-object p2, p0, Llyiahf/vczjk/ot8;->$state:Llyiahf/vczjk/mv2;

    iput-object p3, p0, Llyiahf/vczjk/ot8;->$a11yPaneTitle:Ljava/lang/String;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/ze3;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v4, v3, 0x6

    if-nez v4, :cond_1

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 v4, 0x4

    goto :goto_0

    :cond_0
    const/4 v4, 0x2

    :goto_0
    or-int/2addr v3, v4

    :cond_1
    and-int/lit8 v4, v3, 0x13

    const/16 v5, 0x12

    const/4 v6, 0x0

    const/4 v7, 0x1

    if-eq v4, v5, :cond_2

    move v4, v7

    goto :goto_1

    :cond_2
    move v4, v6

    :goto_1
    and-int/lit8 v5, v3, 0x1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v5, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v4

    if-eqz v4, :cond_11

    iget-object v4, v0, Llyiahf/vczjk/ot8;->$keys:Ljava/util/List;

    invoke-static {v4}, Llyiahf/vczjk/r15;->OooO00o(Ljava/util/List;)Ljava/util/ArrayList;

    move-result-object v4

    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    move-result v4

    if-eq v4, v7, :cond_3

    const/16 v4, 0x4b

    goto :goto_2

    :cond_3
    move v4, v6

    :goto_2
    sget-object v5, Llyiahf/vczjk/jk2;->OooO0Oo:Llyiahf/vczjk/oOO0O00O;

    new-instance v11, Llyiahf/vczjk/h1a;

    const/16 v14, 0x96

    invoke-direct {v11, v14, v4, v5}, Llyiahf/vczjk/h1a;-><init>(IILlyiahf/vczjk/ik2;)V

    const/4 v5, 0x0

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    iget-object v9, v0, Llyiahf/vczjk/ot8;->$state:Llyiahf/vczjk/mv2;

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v8, v9

    iget-object v9, v0, Llyiahf/vczjk/ot8;->$state:Llyiahf/vczjk/mv2;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    sget-object v15, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v8, :cond_4

    if-ne v10, v15, :cond_5

    :cond_4
    new-instance v10, Llyiahf/vczjk/nt8;

    invoke-direct {v10, v9}, Llyiahf/vczjk/nt8;-><init>(Llyiahf/vczjk/mv2;)V

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    move-object v12, v10

    check-cast v12, Llyiahf/vczjk/le3;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-ne v8, v15, :cond_6

    const/4 v8, 0x0

    invoke-static {v8}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object v8

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    move-object v9, v8

    check-cast v9, Llyiahf/vczjk/gi;

    sget-object v8, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    move v13, v10

    const/4 v10, 0x1

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v16

    or-int v13, v13, v16

    invoke-virtual {v2, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v16

    or-int v13, v13, v16

    invoke-virtual {v2, v12}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v16

    or-int v13, v13, v16

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v13, :cond_7

    if-ne v10, v15, :cond_8

    :cond_7
    move-object v10, v8

    goto :goto_3

    :cond_8
    move-object v7, v8

    move-object v8, v10

    const/4 v10, 0x1

    goto :goto_4

    :goto_3
    new-instance v8, Llyiahf/vczjk/wt8;

    const/4 v13, 0x0

    move-object v7, v10

    const/4 v10, 0x1

    invoke-direct/range {v8 .. v13}, Llyiahf/vczjk/wt8;-><init>(Llyiahf/vczjk/gi;ZLlyiahf/vczjk/wl;Llyiahf/vczjk/le3;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_4
    check-cast v8, Llyiahf/vczjk/ze3;

    invoke-static {v7, v2, v8}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v8, v9, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    sget-object v9, Llyiahf/vczjk/jk2;->OooO00o:Llyiahf/vczjk/cu1;

    new-instance v11, Llyiahf/vczjk/h1a;

    invoke-direct {v11, v14, v4, v9}, Llyiahf/vczjk/h1a;-><init>(IILlyiahf/vczjk/ik2;)V

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v15, :cond_9

    const v4, 0x3f4ccccd    # 0.8f

    invoke-static {v4}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object v4

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    check-cast v4, Llyiahf/vczjk/gi;

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v12

    or-int/2addr v9, v12

    invoke-virtual {v2, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v12

    or-int/2addr v9, v12

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    if-nez v9, :cond_a

    if-ne v12, v15, :cond_b

    :cond_a
    new-instance v12, Llyiahf/vczjk/yt8;

    invoke-direct {v12, v4, v10, v11, v5}, Llyiahf/vczjk/yt8;-><init>(Llyiahf/vczjk/gi;ZLlyiahf/vczjk/wl;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v2, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    check-cast v12, Llyiahf/vczjk/ze3;

    invoke-static {v7, v2, v12}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v4, v4, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    sget-object v16, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iget-object v7, v4, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v7, Llyiahf/vczjk/fw8;

    invoke-virtual {v7}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Ljava/lang/Number;

    invoke-virtual {v7}, Ljava/lang/Number;->floatValue()F

    move-result v17

    iget-object v4, v4, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v4, Llyiahf/vczjk/fw8;

    invoke-virtual {v4}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    move-result v18

    iget-object v4, v8, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v4, Llyiahf/vczjk/fw8;

    invoke-virtual {v4}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    move-result v19

    const/16 v23, 0x0

    const v24, 0x1fff8

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    invoke-static/range {v16 .. v24}, Landroidx/compose/ui/graphics/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;FFFFFLlyiahf/vczjk/qj8;ZI)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v7

    iget-object v8, v0, Llyiahf/vczjk/ot8;->$a11yPaneTitle:Ljava/lang/String;

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v7, v8

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v5, v7

    iget-object v7, v0, Llyiahf/vczjk/ot8;->$a11yPaneTitle:Ljava/lang/String;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v5, :cond_c

    if-ne v8, v15, :cond_d

    :cond_c
    new-instance v8, Llyiahf/vczjk/lt8;

    invoke-direct {v8, v7}, Llyiahf/vczjk/lt8;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    check-cast v8, Llyiahf/vczjk/oe3;

    invoke-static {v4, v6, v8}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v5, v6}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v5

    iget v6, v2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v2, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_e

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_5

    :cond_e
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_5
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v2, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, v2, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v7, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_f

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_10

    :cond_f
    invoke-static {v6, v2, v6, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_10
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v4, v2, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    and-int/lit8 v3, v3, 0xe

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-interface {v1, v2, v3}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v1, 0x1

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_6

    :cond_11
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_6
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
