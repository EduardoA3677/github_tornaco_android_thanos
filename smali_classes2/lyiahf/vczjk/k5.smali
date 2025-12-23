.class public final Llyiahf/vczjk/k5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ki2;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/xr1;


# direct methods
.method public synthetic constructor <init>(ILlyiahf/vczjk/xr1;Llyiahf/vczjk/ki2;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/k5;->OooOOO0:I

    iput-object p3, p0, Llyiahf/vczjk/k5;->OooOOO:Llyiahf/vczjk/ki2;

    iput-object p2, p0, Llyiahf/vczjk/k5;->OooOOOO:Llyiahf/vczjk/xr1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    iget v0, p0, Llyiahf/vczjk/k5;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_1

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_3

    :cond_1
    :goto_0
    sget-object p2, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    sget-object v0, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    const/4 v1, 0x0

    invoke-static {v0, v1}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v0

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/zf1;

    iget v3, v2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {p1, p2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v5, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_2

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_2
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v0, p1, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v4, p1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_4

    :cond_3
    invoke-static {v3, v2, v3, v0}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_4
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p2, p1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v1, p1}, Llyiahf/vczjk/hi8;->OooO0O0(ILlyiahf/vczjk/rf1;)V

    iget-object p2, p0, Llyiahf/vczjk/k5;->OooOOO:Llyiahf/vczjk/ki2;

    iget-object v0, p2, Llyiahf/vczjk/ki2;->OooO0O0:Llyiahf/vczjk/c9;

    iget-object v0, v0, Llyiahf/vczjk/c9;->OooO0oO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/mi2;

    sget-object v3, Llyiahf/vczjk/mi2;->OooOOO:Llyiahf/vczjk/mi2;

    const/4 v4, 0x1

    if-ne v0, v3, :cond_5

    move v0, v4

    goto :goto_2

    :cond_5
    move v0, v1

    :goto_2
    const v3, -0x615d173a

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v3, p0, Llyiahf/vczjk/k5;->OooOOOO:Llyiahf/vczjk/xr1;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v2, p2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v5, v6

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_6

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v6, v5, :cond_7

    :cond_6
    new-instance v6, Llyiahf/vczjk/i5;

    const/4 v5, 0x2

    invoke-direct {v6, v5, v3, p2}, Llyiahf/vczjk/i5;-><init>(ILlyiahf/vczjk/xr1;Llyiahf/vczjk/ki2;)V

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v6, Llyiahf/vczjk/le3;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v0, v6, p1, v1, v1}, Llyiahf/vczjk/c6a;->OooO0O0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    move-object v9, p1

    check-cast v9, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p1

    and-int/lit8 p1, p1, 0x3

    const/4 p2, 0x2

    if-ne p1, p2, :cond_9

    move-object p1, v9

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p2

    if-nez p2, :cond_8

    goto :goto_4

    :cond_8
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_5

    :cond_9
    :goto_4
    const-wide/high16 p1, 0x3fe0000000000000L    # 0.5

    double-to-float v6, p1

    new-instance p1, Llyiahf/vczjk/r6;

    iget-object p2, p0, Llyiahf/vczjk/k5;->OooOOO:Llyiahf/vczjk/ki2;

    iget-object v0, p0, Llyiahf/vczjk/k5;->OooOOOO:Llyiahf/vczjk/xr1;

    const/16 v1, 0xa

    invoke-direct {p1, v1, p2, v0}, Llyiahf/vczjk/r6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const p2, 0x5ae2b3ba

    invoke-static {p2, p1, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    const-wide/16 v2, 0x0

    const v10, 0x186000

    const/4 v0, 0x0

    const/4 v1, 0x0

    const-wide/16 v4, 0x0

    const/4 v7, 0x0

    invoke-static/range {v0 .. v10}, Llyiahf/vczjk/yx5;->OooO00o(Llyiahf/vczjk/hl5;Llyiahf/vczjk/pp3;JJFLlyiahf/vczjk/zy4;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_b

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_a

    goto :goto_6

    :cond_a
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_9

    :cond_b
    :goto_6
    sget-object p2, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    sget-object v0, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    const/4 v1, 0x0

    invoke-static {v0, v1}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v0

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/zf1;

    iget v3, v2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {p1, p2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v5, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_c

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_c
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v0, p1, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v4, p1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_d

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_e

    :cond_d
    invoke-static {v3, v2, v3, v0}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_e
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p2, p1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v1, p1}, Llyiahf/vczjk/hi8;->OooO0O0(ILlyiahf/vczjk/rf1;)V

    iget-object p2, p0, Llyiahf/vczjk/k5;->OooOOO:Llyiahf/vczjk/ki2;

    iget-object v0, p2, Llyiahf/vczjk/ki2;->OooO0O0:Llyiahf/vczjk/c9;

    iget-object v0, v0, Llyiahf/vczjk/c9;->OooO0oO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/mi2;

    sget-object v3, Llyiahf/vczjk/mi2;->OooOOO:Llyiahf/vczjk/mi2;

    const/4 v4, 0x1

    if-ne v0, v3, :cond_f

    move v0, v4

    goto :goto_8

    :cond_f
    move v0, v1

    :goto_8
    const v3, -0x615d173a

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v3, p0, Llyiahf/vczjk/k5;->OooOOOO:Llyiahf/vczjk/xr1;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v2, p2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v5, v6

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_10

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v6, v5, :cond_11

    :cond_10
    new-instance v6, Llyiahf/vczjk/i5;

    const/4 v5, 0x0

    invoke-direct {v6, v5, v3, p2}, Llyiahf/vczjk/i5;-><init>(ILlyiahf/vczjk/xr1;Llyiahf/vczjk/ki2;)V

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_11
    check-cast v6, Llyiahf/vczjk/le3;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v0, v6, p1, v1, v1}, Llyiahf/vczjk/c6a;->OooO0O0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_9
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
