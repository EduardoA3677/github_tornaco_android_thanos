.class public final Llyiahf/vczjk/py7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/py7;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/py7;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/py7;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    iget v0, p0, Llyiahf/vczjk/py7;->OooOOO0:I

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

    goto :goto_1

    :cond_1
    :goto_0
    const/4 p2, 0x0

    iget-object v0, p0, Llyiahf/vczjk/py7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/uh6;

    iget-object v1, p0, Llyiahf/vczjk/py7;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ze3;

    invoke-static {v0, v1, p1, p2}, Llyiahf/vczjk/xt6;->OooOo00(Llyiahf/vczjk/uh6;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_3

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_4

    :cond_3
    :goto_2
    sget-object p2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v0, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/x21;

    iget-wide v2, v0, Llyiahf/vczjk/x21;->OooOOO:J

    sget-object v0, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {p2, v2, v3, v0}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v2, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v3, 0x0

    invoke-static {v0, v2, p1, v3}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v0

    iget v2, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {p1, p2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_4

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_4
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v0, p1, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, p1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v3, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_5

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_6

    :cond_5
    invoke-static {v2, v1, v2, v0}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_6
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p2, p1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p2, Llyiahf/vczjk/r31;->OooO00o:Llyiahf/vczjk/r31;

    iget-object v0, p0, Llyiahf/vczjk/py7;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yo9;

    iget-object v0, v0, Llyiahf/vczjk/yo9;->OooO0O0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    const/4 v2, 0x6

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    iget-object v3, p0, Llyiahf/vczjk/py7;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/a91;

    invoke-virtual {v3, p2, v0, p1, v2}, Llyiahf/vczjk/a91;->OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v1, :cond_7

    move v0, v2

    goto :goto_5

    :cond_7
    const/4 v0, 0x0

    :goto_5
    and-int/2addr p2, v2

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_8

    const/4 p2, 0x6

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/py7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/a91;

    iget-object v1, p0, Llyiahf/vczjk/py7;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ti9;

    invoke-virtual {v0, v1, p1, p2}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_6

    :cond_8
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_6
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_2
    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p1

    and-int/lit8 p1, p1, 0x3

    const/4 p2, 0x2

    if-ne p1, p2, :cond_a

    move-object p1, v8

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p2

    if-nez p2, :cond_9

    goto :goto_7

    :cond_9
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_9

    :cond_a
    :goto_7
    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const p2, 0x3f2e147b    # 0.68f

    invoke-static {p1, p2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object p2

    invoke-static {v8}, Llyiahf/vczjk/mt6;->OooOOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/z98;

    move-result-object v0

    const/4 v10, 0x1

    invoke-static {p2, v0, v10}, Llyiahf/vczjk/mt6;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/z98;Z)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v1, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v2, 0x0

    invoke-static {v0, v1, v8, v2}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v0

    move-object v11, v8

    check-cast v11, Llyiahf/vczjk/zf1;

    iget v1, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {v8, p2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_b

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_8

    :cond_b
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_8
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v0, v8, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, v8, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v3, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_c

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_d

    :cond_c
    invoke-static {v1, v11, v1, v0}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_d
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p2, v8, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 p2, 0x8

    int-to-float p2, p2

    invoke-static {p1, p2}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object p1

    const/high16 p2, 0x3f800000    # 1.0f

    invoke-static {p1, p2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object p1

    const/16 p2, 0x3e8

    int-to-float p2, p2

    const/4 v0, 0x0

    invoke-static {p1, v0, p2, v10}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v0

    move p1, v2

    sget-object v2, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    const p2, -0x615d173a

    invoke-virtual {v11, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p2, p0, Llyiahf/vczjk/py7;->OooOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/qs5;

    invoke-virtual {v11, p2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    iget-object v3, p0, Llyiahf/vczjk/py7;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/n07;

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v1, v4

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v1, :cond_e

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v4, v1, :cond_f

    :cond_e
    new-instance v4, Llyiahf/vczjk/gu6;

    const/16 v1, 0xe

    invoke-direct {v4, v1, v3, p2}, Llyiahf/vczjk/gu6;-><init>(ILjava/lang/Object;Llyiahf/vczjk/qs5;)V

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_f
    move-object v7, v4

    check-cast v7, Llyiahf/vczjk/oe3;

    invoke-virtual {v11, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v4, 0x0

    const/16 v9, 0x6c06

    const/4 v1, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object v3, v2

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/jp8;->OooO0o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/er4;Llyiahf/vczjk/px;Llyiahf/vczjk/nx;Llyiahf/vczjk/f22;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v11, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_9
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_3
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eq v0, v1, :cond_10

    move v0, v3

    goto :goto_a

    :cond_10
    move v0, v2

    :goto_a
    and-int/2addr p2, v3

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_14

    sget-object p2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v0, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v0, v2}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v0

    iget v1, p1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v2

    invoke-static {p1, p2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p2

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_11

    invoke-virtual {p1, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_b

    :cond_11
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_b
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v0, p1, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v2, p1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v2, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_12

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_13

    :cond_12
    invoke-static {v1, p1, v1, v0}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_13
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p2, p1, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/4 p2, 0x6

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/py7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/a91;

    iget-object v1, p0, Llyiahf/vczjk/py7;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/h78;

    invoke-virtual {v0, v1, p1, p2}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_c

    :cond_14
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_c
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_4
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_16

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_15

    goto :goto_d

    :cond_15
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_e

    :cond_16
    :goto_d
    iget-object p2, p0, Llyiahf/vczjk/py7;->OooOOO:Ljava/lang/Object;

    check-cast p2, Lnow/fortuitous/thanos/process/v2/RunningAppStateDetails;

    if-nez p2, :cond_17

    goto :goto_e

    :cond_17
    check-cast p1, Llyiahf/vczjk/zf1;

    const v0, 0x4c5de2

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v0, p0, Llyiahf/vczjk/py7;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Lnow/fortuitous/thanos/process/v2/RunningAppStateDetailsActivity;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_18

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, v1, :cond_19

    :cond_18
    new-instance v2, Llyiahf/vczjk/w45;

    const/16 v1, 0x12

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/w45;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_19
    check-cast v2, Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {p2, v2, p1, v0}, Llyiahf/vczjk/mt6;->OooO0Oo(Lnow/fortuitous/thanos/process/v2/RunningAppStateDetails;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    :goto_e
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
