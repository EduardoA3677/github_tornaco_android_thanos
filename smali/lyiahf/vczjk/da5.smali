.class public final Llyiahf/vczjk/da5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOO0:Landroid/content/Context;

.field public final synthetic OooOOOO:Llyiahf/vczjk/ki2;

.field public final synthetic OooOOOo:Llyiahf/vczjk/ua5;

.field public final synthetic OooOOo:Llyiahf/vczjk/bf7;

.field public final synthetic OooOOo0:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOoo:Z

.field public final synthetic OooOo:Llyiahf/vczjk/qs5;

.field public final synthetic OooOo0:Llyiahf/vczjk/le3;

.field public final synthetic OooOo00:Llyiahf/vczjk/qs5;

.field public final synthetic OooOo0O:Llyiahf/vczjk/le3;

.field public final synthetic OooOo0o:Llyiahf/vczjk/le3;


# direct methods
.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/qs5;Llyiahf/vczjk/ki2;Llyiahf/vczjk/ua5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/bf7;ZLlyiahf/vczjk/qs5;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/qs5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/da5;->OooOOO0:Landroid/content/Context;

    iput-object p2, p0, Llyiahf/vczjk/da5;->OooOOO:Llyiahf/vczjk/qs5;

    iput-object p3, p0, Llyiahf/vczjk/da5;->OooOOOO:Llyiahf/vczjk/ki2;

    iput-object p4, p0, Llyiahf/vczjk/da5;->OooOOOo:Llyiahf/vczjk/ua5;

    iput-object p5, p0, Llyiahf/vczjk/da5;->OooOOo0:Llyiahf/vczjk/qs5;

    iput-object p6, p0, Llyiahf/vczjk/da5;->OooOOo:Llyiahf/vczjk/bf7;

    iput-boolean p7, p0, Llyiahf/vczjk/da5;->OooOOoo:Z

    iput-object p8, p0, Llyiahf/vczjk/da5;->OooOo00:Llyiahf/vczjk/qs5;

    iput-object p9, p0, Llyiahf/vczjk/da5;->OooOo0:Llyiahf/vczjk/le3;

    iput-object p10, p0, Llyiahf/vczjk/da5;->OooOo0O:Llyiahf/vczjk/le3;

    iput-object p11, p0, Llyiahf/vczjk/da5;->OooOo0o:Llyiahf/vczjk/le3;

    iput-object p12, p0, Llyiahf/vczjk/da5;->OooOo:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

    move-object/from16 v0, p0

    move-object/from16 v13, p1

    check-cast v13, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    and-int/lit8 v1, v1, 0x3

    const/4 v2, 0x2

    if-ne v1, v2, :cond_1

    move-object v1, v13

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_1

    :cond_1
    :goto_0
    sget v1, Llyiahf/vczjk/gx9;->OooO00o:F

    invoke-static {v13}, Llyiahf/vczjk/up;->OooO(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/kx9;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    move-object v3, v13

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v2, :cond_2

    new-instance v4, Llyiahf/vczjk/na9;

    const/4 v5, 0x5

    invoke-direct {v4, v5}, Llyiahf/vczjk/na9;-><init>(I)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2
    check-cast v4, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v5, v6

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_3

    if-ne v6, v2, :cond_4

    :cond_3
    new-instance v6, Llyiahf/vczjk/zu6;

    invoke-direct {v6, v1, v4}, Llyiahf/vczjk/zu6;-><init>(Llyiahf/vczjk/kx9;Llyiahf/vczjk/le3;)V

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    move-object v8, v6

    check-cast v8, Llyiahf/vczjk/zu6;

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iget-object v2, v8, Llyiahf/vczjk/zu6;->OooO0OO:Llyiahf/vczjk/yu6;

    const/4 v3, 0x0

    invoke-static {v1, v2, v3}, Landroidx/compose/ui/input/nestedscroll/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bz5;Llyiahf/vczjk/fz5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    new-instance v7, Llyiahf/vczjk/hq;

    iget-object v9, v0, Llyiahf/vczjk/da5;->OooOOO0:Landroid/content/Context;

    iget-object v10, v0, Llyiahf/vczjk/da5;->OooOOO:Llyiahf/vczjk/qs5;

    iget-object v11, v0, Llyiahf/vczjk/da5;->OooOOOO:Llyiahf/vczjk/ki2;

    const/16 v12, 0x8

    invoke-direct/range {v7 .. v12}, Llyiahf/vczjk/hq;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    const v2, -0x4bb0f5d9

    invoke-static {v2, v7, v13}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/b6;

    iget-object v4, v0, Llyiahf/vczjk/da5;->OooOOOo:Llyiahf/vczjk/ua5;

    iget-object v5, v0, Llyiahf/vczjk/da5;->OooOOo0:Llyiahf/vczjk/qs5;

    const/16 v6, 0x16

    invoke-direct {v3, v6, v4, v5}, Llyiahf/vczjk/b6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v4, 0x6a0ae304

    invoke-static {v4, v3, v13}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v5

    new-instance v14, Llyiahf/vczjk/ca5;

    iget-object v3, v0, Llyiahf/vczjk/da5;->OooOo00:Llyiahf/vczjk/qs5;

    iget-object v4, v0, Llyiahf/vczjk/da5;->OooOo0o:Llyiahf/vczjk/le3;

    iget-object v6, v0, Llyiahf/vczjk/da5;->OooOo:Llyiahf/vczjk/qs5;

    iget-object v15, v0, Llyiahf/vczjk/da5;->OooOOo:Llyiahf/vczjk/bf7;

    iget-boolean v7, v0, Llyiahf/vczjk/da5;->OooOOoo:Z

    iget-object v8, v0, Llyiahf/vczjk/da5;->OooOo0:Llyiahf/vczjk/le3;

    iget-object v9, v0, Llyiahf/vczjk/da5;->OooOo0O:Llyiahf/vczjk/le3;

    iget-object v10, v0, Llyiahf/vczjk/da5;->OooOOo0:Llyiahf/vczjk/qs5;

    move-object/from16 v17, v3

    move-object/from16 v21, v4

    move-object/from16 v22, v6

    move/from16 v16, v7

    move-object/from16 v18, v8

    move-object/from16 v19, v9

    move-object/from16 v20, v10

    invoke-direct/range {v14 .. v22}, Llyiahf/vczjk/ca5;-><init>(Llyiahf/vczjk/bf7;ZLlyiahf/vczjk/qs5;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/le3;Llyiahf/vczjk/qs5;)V

    const v3, -0x63afcc4

    invoke-static {v3, v14, v13}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v12

    const v14, 0x30006030

    const/16 v15, 0x1ec

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v6, 0x0

    const-wide/16 v7, 0x0

    const-wide/16 v9, 0x0

    const/4 v11, 0x0

    invoke-static/range {v1 .. v15}, Llyiahf/vczjk/j78;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;IJJLlyiahf/vczjk/x8a;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_1
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
