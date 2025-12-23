.class public final Llyiahf/vczjk/tu;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:I

.field public final synthetic OooOOO0:Llyiahf/vczjk/dv;

.field public final synthetic OooOOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOOo:Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dv;ILlyiahf/vczjk/qs5;Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/tu;->OooOOO0:Llyiahf/vczjk/dv;

    iput p2, p0, Llyiahf/vczjk/tu;->OooOOO:I

    iput-object p3, p0, Llyiahf/vczjk/tu;->OooOOOO:Llyiahf/vczjk/qs5;

    iput-object p4, p0, Llyiahf/vczjk/tu;->OooOOOo:Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    const/4 v1, 0x0

    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/bi6;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v4, p3

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    move-result v4

    const-string v5, "paddings"

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v5, v4, 0x6

    const/4 v6, 0x2

    if-nez v5, :cond_1

    move-object v5, v2

    check-cast v5, Llyiahf/vczjk/zf1;

    invoke-virtual {v5, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_0

    const/4 v5, 0x4

    goto :goto_0

    :cond_0
    move v5, v6

    :goto_0
    or-int/2addr v4, v5

    :cond_1
    move v8, v4

    and-int/lit8 v4, v8, 0x13

    const/16 v9, 0x12

    if-ne v4, v9, :cond_3

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_2

    :cond_3
    :goto_1
    move-object v12, v2

    check-cast v12, Llyiahf/vczjk/zf1;

    const v2, 0x4c5de2

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v4, v0, Llyiahf/vczjk/tu;->OooOOO0:Llyiahf/vczjk/dv;

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    sget-object v10, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v5, :cond_4

    if-ne v7, v10, :cond_5

    :cond_4
    new-instance v7, Llyiahf/vczjk/pu;

    invoke-direct {v7, v4, v1}, Llyiahf/vczjk/pu;-><init>(Llyiahf/vczjk/dv;I)V

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v7, Llyiahf/vczjk/le3;

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v5, 0x0

    invoke-static {v7, v5, v12, v1, v6}, Llyiahf/vczjk/rs;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    const v6, -0x615d173a

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v6, :cond_6

    if-ne v7, v10, :cond_7

    :cond_6
    new-instance v7, Llyiahf/vczjk/qu;

    iget v6, v0, Llyiahf/vczjk/tu;->OooOOO:I

    invoke-direct {v7, v4, v6, v5}, Llyiahf/vczjk/qu;-><init>(Llyiahf/vczjk/dv;ILlyiahf/vczjk/yo1;)V

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v7, Llyiahf/vczjk/ze3;

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v4, v12, v7}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v5, Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;->OoooO0O:I

    iget-object v5, v0, Llyiahf/vczjk/tu;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v5}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/xu;

    iget-boolean v6, v6, Llyiahf/vczjk/xu;->OooO00o:Z

    invoke-static {v6, v12}, Llyiahf/vczjk/tn6;->OooOOo0(ZLlyiahf/vczjk/rf1;)Llyiahf/vczjk/jc9;

    move-result-object v11

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v2, :cond_8

    if-ne v6, v10, :cond_9

    :cond_8
    new-instance v6, Llyiahf/vczjk/pu;

    const/4 v2, 0x1

    invoke-direct {v6, v4, v2}, Llyiahf/vczjk/pu;-><init>(Llyiahf/vczjk/dv;I)V

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    move-object v10, v6

    check-cast v10, Llyiahf/vczjk/le3;

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move v1, v9

    sget-object v9, Llyiahf/vczjk/m91;->OooO0O0:Llyiahf/vczjk/a91;

    new-instance v2, Llyiahf/vczjk/hq;

    move-object v6, v4

    iget-object v4, v0, Llyiahf/vczjk/tu;->OooOOOo:Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;

    const/4 v7, 0x1

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/hq;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    const v4, 0x56593cbe

    invoke-static {v4, v2, v12}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    const/high16 v4, 0x380000

    shl-int/lit8 v1, v8, 0x12

    and-int/2addr v1, v4

    const/high16 v4, 0x36c00000

    or-int v13, v1, v4

    const/4 v6, 0x0

    const/16 v14, 0x3c

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v7, 0x0

    move-object v8, v3

    move-object v3, v10

    const/4 v10, 0x0

    move-object v15, v11

    move-object v11, v2

    move-object v2, v15

    invoke-static/range {v2 .. v14}, Llyiahf/vczjk/tn6;->OooO0OO(Llyiahf/vczjk/jc9;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZFLlyiahf/vczjk/o4;Llyiahf/vczjk/bi6;Llyiahf/vczjk/df3;ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    :goto_2
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
