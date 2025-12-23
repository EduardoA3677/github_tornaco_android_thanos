.class public final Lnow/fortuitous/thanos/settings/BuildPropActivity;
.super Landroidx/activity/ComponentActivity;
.source "SourceFile"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0007\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u00a8\u0006\u0004"
    }
    d2 = {
        "Lnow/fortuitous/thanos/settings/BuildPropActivity;",
        "Landroidx/activity/ComponentActivity;",
        "<init>",
        "()V",
        "app_prcRelease"
    }
    k = 0x1
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final synthetic Oooo00O:I


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/activity/ComponentActivity;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooOo0(ILlyiahf/vczjk/rf1;)V
    .locals 12

    move-object v9, p2

    check-cast v9, Llyiahf/vczjk/zf1;

    const p2, 0x535ef4c7

    invoke-virtual {v9, p2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v9, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    const/4 v0, 0x2

    if-eqz p2, :cond_0

    const/4 p2, 0x4

    goto :goto_0

    :cond_0
    move p2, v0

    :goto_0
    or-int/2addr p2, p1

    and-int/lit8 p2, p2, 0x3

    if-ne p2, v0, :cond_2

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p2

    if-nez p2, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_2

    :cond_2
    :goto_1
    sget-object v0, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    new-instance p2, Llyiahf/vczjk/sj0;

    const/4 v1, 0x1

    invoke-direct {p2, p0, v1}, Llyiahf/vczjk/sj0;-><init>(Lnow/fortuitous/thanos/settings/BuildPropActivity;I)V

    const v1, 0x158620b

    invoke-static {v1, p2, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v1, 0x0

    const-wide/16 v2, 0x0

    const-wide/16 v4, 0x0

    const v10, 0x180006

    const/16 v11, 0x3e

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/rd3;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJLlyiahf/vczjk/se0;FLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    :goto_2
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_3

    new-instance v0, Llyiahf/vczjk/rj0;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, v1}, Llyiahf/vczjk/rj0;-><init>(Lnow/fortuitous/thanos/settings/BuildPropActivity;II)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_3
    return-void
.end method

.method public final OooOo00(ILlyiahf/vczjk/rf1;)V
    .locals 11

    move-object v8, p2

    check-cast v8, Llyiahf/vczjk/zf1;

    const p2, -0x736469ea

    invoke-virtual {v8, p2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 p2, p1, 0x1

    if-nez p2, :cond_1

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p2

    if-nez p2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    sget-object p2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v0, 0x3f800000    # 1.0f

    invoke-static {p2, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v7, Llyiahf/vczjk/v91;->OooO00o:Llyiahf/vczjk/a91;

    const/4 v5, 0x0

    const/4 v6, 0x0

    const-wide/16 v1, 0x0

    const-wide/16 v3, 0x0

    const v9, 0x30006

    const/16 v10, 0x1e

    invoke-static/range {v0 .. v10}, Llyiahf/vczjk/vp;->OooO0O0(Llyiahf/vczjk/kl5;JJFLlyiahf/vczjk/bi6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_1
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_2

    new-instance v0, Llyiahf/vczjk/rj0;

    const/4 v1, 0x1

    invoke-direct {v0, p0, p1, v1}, Llyiahf/vczjk/rj0;-><init>(Lnow/fortuitous/thanos/settings/BuildPropActivity;II)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_2
    return-void
.end method

.method public final OooOo0O(Llyiahf/vczjk/xn6;Llyiahf/vczjk/rf1;I)V
    .locals 31

    move-object/from16 v0, p1

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/zf1;

    const v3, -0x9698354

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    const/4 v4, 0x2

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    move v3, v4

    :goto_0
    or-int v3, p3, v3

    and-int/lit8 v3, v3, 0x3

    if-ne v3, v4, :cond_2

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_3

    :cond_2
    :goto_1
    sget-object v3, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v4, 0x3f800000    # 1.0f

    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    const/16 v6, 0x10

    int-to-float v6, v6

    invoke-static {v5, v6}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v7, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/16 v8, 0x36

    invoke-static {v6, v7, v2, v8}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v6

    iget v7, v2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v2, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v9, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v10, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v10, :cond_3

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_3
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v6, v2, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v8, v2, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v8, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v8, :cond_4

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_5

    :cond_4
    invoke-static {v7, v2, v7, v6}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_5
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v5, v2, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v0}, Llyiahf/vczjk/xn6;->OooO0OO()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/String;

    sget-object v6, Llyiahf/vczjk/s6a;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/o6a;

    iget-object v7, v7, Llyiahf/vczjk/o6a;->OooO0oO:Llyiahf/vczjk/rn9;

    const/16 v21, 0x0

    const/16 v24, 0x0

    move-object v8, v3

    const/4 v3, 0x0

    move-object/from16 v23, v2

    move v9, v4

    move-object v2, v5

    const-wide/16 v4, 0x0

    move-object v10, v6

    move-object/from16 v22, v7

    const-wide/16 v6, 0x0

    move-object v11, v8

    const/4 v8, 0x0

    move v12, v9

    const/4 v9, 0x0

    move-object v13, v10

    const/4 v10, 0x0

    move-object v14, v11

    move v15, v12

    const-wide/16 v11, 0x0

    move-object/from16 v16, v13

    const/4 v13, 0x0

    move-object/from16 v17, v14

    const/4 v14, 0x0

    move/from16 v18, v15

    move-object/from16 v19, v16

    const-wide/16 v15, 0x0

    move-object/from16 v20, v17

    const/16 v17, 0x0

    move/from16 v25, v18

    const/16 v18, 0x0

    move-object/from16 v26, v19

    const/16 v19, 0x0

    move-object/from16 v27, v20

    const/16 v20, 0x0

    move/from16 v28, v25

    const/16 v25, 0x0

    move-object/from16 v29, v26

    const v26, 0xfffe

    move-object/from16 v0, v27

    move/from16 v1, v28

    move-object/from16 v30, v29

    invoke-static/range {v2 .. v26}, Llyiahf/vczjk/hm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/cb3;Llyiahf/vczjk/ib3;Llyiahf/vczjk/ba3;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v2, v23

    const/4 v3, 0x1

    int-to-float v4, v3

    invoke-static {v0, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0o0(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-static {v0, v1}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-static {v2, v0}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/xn6;->OooO0Oo()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    move-object/from16 v13, v30

    invoke-virtual {v2, v13}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/o6a;

    iget-object v1, v1, Llyiahf/vczjk/o6a;->OooOO0:Llyiahf/vczjk/rn9;

    const/16 v21, 0x0

    const/16 v24, 0x0

    move v4, v3

    const/4 v3, 0x0

    move v6, v4

    const-wide/16 v4, 0x0

    move v8, v6

    const-wide/16 v6, 0x0

    move v9, v8

    const/4 v8, 0x0

    move v10, v9

    const/4 v9, 0x0

    move v11, v10

    const/4 v10, 0x0

    move v13, v11

    const-wide/16 v11, 0x0

    move v14, v13

    const/4 v13, 0x0

    move v15, v14

    const/4 v14, 0x0

    move/from16 v17, v15

    const-wide/16 v15, 0x0

    move/from16 v18, v17

    const/16 v17, 0x0

    move/from16 v19, v18

    const/16 v18, 0x0

    move/from16 v20, v19

    const/16 v19, 0x0

    move/from16 v22, v20

    const/16 v20, 0x0

    const/16 v25, 0x0

    const v26, 0xfffe

    move-object/from16 v23, v2

    move-object v2, v0

    move/from16 v0, v22

    move-object/from16 v22, v1

    invoke-static/range {v2 .. v26}, Llyiahf/vczjk/hm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/cb3;Llyiahf/vczjk/ib3;Llyiahf/vczjk/ba3;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v2, v23

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_6

    new-instance v1, Llyiahf/vczjk/e2;

    const/4 v2, 0x4

    move-object/from16 v3, p0

    move-object/from16 v4, p1

    move/from16 v5, p3

    invoke-direct {v1, v3, v4, v5, v2}, Llyiahf/vczjk/e2;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v1, v0, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    return-void

    :cond_6
    move-object/from16 v3, p0

    return-void
.end method

.method public final onCreate(Landroid/os/Bundle;)V
    .locals 3

    invoke-super {p0, p1}, Landroidx/activity/ComponentActivity;->onCreate(Landroid/os/Bundle;)V

    new-instance p1, Llyiahf/vczjk/sj0;

    const/4 v0, 0x2

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/sj0;-><init>(Lnow/fortuitous/thanos/settings/BuildPropActivity;I)V

    new-instance v0, Llyiahf/vczjk/a91;

    const v1, 0x6f905cd4

    const/4 v2, 0x1

    invoke-direct {v0, v1, p1, v2}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-static {p0, v0}, Llyiahf/vczjk/x61;->OooO00o(Landroidx/activity/ComponentActivity;Llyiahf/vczjk/a91;)V

    return-void
.end method
