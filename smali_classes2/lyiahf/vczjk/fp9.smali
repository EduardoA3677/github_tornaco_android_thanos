.class public final Llyiahf/vczjk/fp9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/hb8;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/hb8;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/fp9;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/fp9;->OooOOO:Llyiahf/vczjk/hb8;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    iget v0, p0, Llyiahf/vczjk/fp9;->OooOOO0:I

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
    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {v7, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/fp9;->OooOOO:Llyiahf/vczjk/hb8;

    invoke-virtual {v7, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p2, :cond_2

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p2, :cond_3

    :cond_2
    new-instance v0, Llyiahf/vczjk/n20;

    const/16 p2, 0x14

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/n20;-><init>(Llyiahf/vczjk/hb8;I)V

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-virtual {v7, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v6, Llyiahf/vczjk/kd1;->OooO0o:Llyiahf/vczjk/a91;

    const/high16 v8, 0x180000

    const/16 v9, 0x3e

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-static/range {v1 .. v9}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

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

    if-ne p2, v0, :cond_5

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_4

    goto :goto_2

    :cond_4
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_4

    :cond_5
    :goto_2
    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/zf1;

    const p1, 0x6e3c21fe

    invoke-virtual {v7, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne p1, p2, :cond_6

    new-instance p1, Llyiahf/vczjk/w83;

    invoke-direct {p1}, Llyiahf/vczjk/w83;-><init>()V

    invoke-virtual {v7, p1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast p1, Llyiahf/vczjk/w83;

    const/4 v0, 0x0

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    sget-object v3, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v4, 0x36

    invoke-static {v2, v3, v7, v4}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    iget v3, v7, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v7, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v5, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_7

    invoke-virtual {v7, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_7
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v7, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v4, v7, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_8

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_9

    :cond_8
    invoke-static {v3, v7, v3, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_9
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, v7, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v10, 0x4c5de2

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v11, p0, Llyiahf/vczjk/fp9;->OooOOO:Llyiahf/vczjk/hb8;

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_a

    if-ne v2, p2, :cond_b

    :cond_a
    new-instance v2, Llyiahf/vczjk/n20;

    const/16 v1, 0x13

    invoke-direct {v2, v11, v1}, Llyiahf/vczjk/n20;-><init>(Llyiahf/vczjk/hb8;I)V

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    move-object v1, v2

    check-cast v1, Llyiahf/vczjk/le3;

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v6, Llyiahf/vczjk/kd1;->OooO0o0:Llyiahf/vczjk/a91;

    const/high16 v8, 0x180000

    const/16 v9, 0x3e

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    invoke-static/range {v1 .. v9}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    const/16 v1, 0x30

    invoke-static {v11, p1, v7, v1}, Llyiahf/vczjk/xr6;->OooO0O0(Llyiahf/vczjk/hb8;Llyiahf/vczjk/w83;Llyiahf/vczjk/rf1;I)V

    const/4 v1, 0x1

    invoke-static {v7, v1, v10}, Llyiahf/vczjk/ix8;->OooO0o0(Llyiahf/vczjk/zf1;ZI)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, p2, :cond_c

    new-instance v1, Llyiahf/vczjk/ku7;

    const/16 p2, 0xe

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/ku7;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    check-cast v1, Llyiahf/vczjk/le3;

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v1, v7}, Llyiahf/vczjk/c6a;->OooOo00(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;)V

    :goto_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
