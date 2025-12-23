.class public final Llyiahf/vczjk/bma;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field public final synthetic OooOOO:F

.field public final synthetic OooOOO0:Ljava/util/List;

.field public final synthetic OooOOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOOo:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOo:Llyiahf/vczjk/n62;

.field public final synthetic OooOOo0:Llyiahf/vczjk/dw4;


# direct methods
.method public constructor <init>(Ljava/util/List;FLlyiahf/vczjk/qs5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/dw4;Llyiahf/vczjk/n62;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bma;->OooOOO0:Ljava/util/List;

    iput p2, p0, Llyiahf/vczjk/bma;->OooOOO:F

    iput-object p3, p0, Llyiahf/vczjk/bma;->OooOOOO:Llyiahf/vczjk/qs5;

    iput-object p4, p0, Llyiahf/vczjk/bma;->OooOOOo:Llyiahf/vczjk/oe3;

    iput-object p5, p0, Llyiahf/vczjk/bma;->OooOOo0:Llyiahf/vczjk/dw4;

    iput-object p6, p0, Llyiahf/vczjk/bma;->OooOOo:Llyiahf/vczjk/n62;

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 32

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

    const-string v5, "$this$items"

    invoke-static {v1, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v4, 0x30

    if-nez v1, :cond_1

    move-object v1, v3

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v1

    if-eqz v1, :cond_0

    const/16 v1, 0x20

    goto :goto_0

    :cond_0
    const/16 v1, 0x10

    :goto_0
    or-int/2addr v4, v1

    :cond_1
    and-int/lit16 v1, v4, 0x91

    const/16 v4, 0x90

    if-ne v1, v4, :cond_3

    move-object v1, v3

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_5

    :cond_3
    :goto_1
    iget-object v1, v0, Llyiahf/vczjk/bma;->OooOOO0:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v4

    rem-int v4, v2, v4

    sget-object v5, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    sget-object v6, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v7, 0x3f800000    # 1.0f

    invoke-static {v6, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v6

    iget v7, v0, Llyiahf/vczjk/bma;->OooOOO:F

    invoke-static {v6, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0o0(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v6

    check-cast v3, Llyiahf/vczjk/zf1;

    const v7, 0x4c5de2

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v7, v8, :cond_4

    new-instance v7, Llyiahf/vczjk/w5;

    iget-object v8, v0, Llyiahf/vczjk/bma;->OooOOOO:Llyiahf/vczjk/qs5;

    const/4 v9, 0x5

    invoke-direct {v7, v8, v9}, Llyiahf/vczjk/w5;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v7, Llyiahf/vczjk/oe3;

    const/4 v8, 0x0

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v6, v7}, Landroidx/compose/ui/layout/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v6

    invoke-static {v5, v8}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v5

    iget v7, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v3, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v9, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v10, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v10, :cond_5

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_5
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v8, v3, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v8, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v8, :cond_6

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_7

    :cond_6
    invoke-static {v7, v3, v7, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_7
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v6, v3, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    iget-object v4, v0, Llyiahf/vczjk/bma;->OooOOOo:Llyiahf/vczjk/oe3;

    invoke-interface {v4, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    move-object v7, v1

    check-cast v7, Ljava/lang/String;

    iget-object v1, v0, Llyiahf/vczjk/bma;->OooOOo0:Llyiahf/vczjk/dw4;

    iget-object v1, v1, Llyiahf/vczjk/dw4;->OooO0Oo:Llyiahf/vczjk/tq4;

    invoke-virtual {v1}, Llyiahf/vczjk/tq4;->OooO00o()I

    move-result v1

    iget-object v4, v0, Llyiahf/vczjk/bma;->OooOOo:Llyiahf/vczjk/n62;

    if-ne v2, v1, :cond_8

    iget-object v1, v4, Llyiahf/vczjk/n62;->OooOOOO:Ljava/lang/Object;

    :goto_3
    check-cast v1, Llyiahf/vczjk/rn9;

    move-object/from16 v27, v1

    goto :goto_4

    :cond_8
    iget-object v1, v4, Llyiahf/vczjk/n62;->OooOOO:Ljava/lang/Object;

    goto :goto_3

    :goto_4
    const/16 v30, 0x0

    const v31, 0xfffe

    const/4 v8, 0x0

    const-wide/16 v9, 0x0

    const-wide/16 v11, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const-wide/16 v16, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const-wide/16 v20, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v29, 0x0

    move-object/from16 v28, v3

    invoke-static/range {v7 .. v31}, Llyiahf/vczjk/hm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/cb3;Llyiahf/vczjk/ib3;Llyiahf/vczjk/ba3;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    const/4 v1, 0x1

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_5
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
