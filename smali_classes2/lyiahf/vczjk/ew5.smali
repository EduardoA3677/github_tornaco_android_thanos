.class public final Llyiahf/vczjk/ew5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/le3;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(ILlyiahf/vczjk/le3;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/ew5;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/ew5;->OooOOO:Llyiahf/vczjk/le3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    iget v0, p0, Llyiahf/vczjk/ew5;->OooOOO0:I

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
    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/ew5;->OooOOO:Llyiahf/vczjk/le3;

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p2, :cond_2

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p2, :cond_3

    :cond_2
    new-instance v0, Llyiahf/vczjk/ok5;

    const/16 p2, 0x11

    invoke-direct {v0, p2, p1}, Llyiahf/vczjk/ok5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/za1;->OooO0Oo:Llyiahf/vczjk/a91;

    const/high16 v9, 0x30000000

    const/16 v10, 0x1fe

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v1 .. v10}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

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

    goto :goto_3

    :cond_5
    :goto_2
    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/ew5;->OooOOO:Llyiahf/vczjk/le3;

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p2, :cond_6

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p2, :cond_7

    :cond_6
    new-instance v0, Llyiahf/vczjk/ok5;

    const/16 p2, 0x10

    invoke-direct {v0, p2, p1}, Llyiahf/vczjk/ok5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/za1;->OooO0OO:Llyiahf/vczjk/a91;

    const/high16 v9, 0x30000000

    const/16 v10, 0x1fe

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v1 .. v10}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_9

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_8

    goto :goto_4

    :cond_8
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_5

    :cond_9
    :goto_4
    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/ew5;->OooOOO:Llyiahf/vczjk/le3;

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p2, :cond_a

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p2, :cond_b

    :cond_a
    new-instance v0, Llyiahf/vczjk/ok5;

    const/16 p2, 0xf

    invoke-direct {v0, p2, p1}, Llyiahf/vczjk/ok5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/za1;->OooOOO0:Llyiahf/vczjk/a91;

    const/high16 v9, 0x30000000

    const/16 v10, 0x1fe

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v1 .. v10}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_d

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_c

    goto :goto_6

    :cond_c
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_7

    :cond_d
    :goto_6
    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/ew5;->OooOOO:Llyiahf/vczjk/le3;

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p2, :cond_e

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p2, :cond_f

    :cond_e
    new-instance v0, Llyiahf/vczjk/ok5;

    const/16 p2, 0xe

    invoke-direct {v0, p2, p1}, Llyiahf/vczjk/ok5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_f
    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/za1;->OooOOo:Llyiahf/vczjk/a91;

    const/high16 v9, 0x30000000

    const/16 v10, 0x1fe

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v1 .. v10}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_7
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_3
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_11

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_10

    goto :goto_8

    :cond_10
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_9

    :cond_11
    :goto_8
    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/ew5;->OooOOO:Llyiahf/vczjk/le3;

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p2, :cond_12

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p2, :cond_13

    :cond_12
    new-instance v0, Llyiahf/vczjk/ok5;

    const/16 p2, 0xd

    invoke-direct {v0, p2, p1}, Llyiahf/vczjk/ok5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/za1;->OooOO0:Llyiahf/vczjk/a91;

    const/high16 v9, 0x30000000

    const/16 v10, 0x1fe

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v1 .. v10}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_9
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_4
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_15

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_14

    goto :goto_a

    :cond_14
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_b

    :cond_15
    :goto_a
    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/ew5;->OooOOO:Llyiahf/vczjk/le3;

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p2, :cond_16

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p2, :cond_17

    :cond_16
    new-instance v0, Llyiahf/vczjk/ok5;

    const/16 p2, 0xc

    invoke-direct {v0, p2, p1}, Llyiahf/vczjk/ok5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_17
    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/za1;->OooOOOO:Llyiahf/vczjk/a91;

    const/high16 v9, 0x30000000

    const/16 v10, 0x1fe

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v1 .. v10}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_b
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_5
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_19

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_18

    goto :goto_c

    :cond_18
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_d

    :cond_19
    :goto_c
    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/ew5;->OooOOO:Llyiahf/vczjk/le3;

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p2, :cond_1a

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p2, :cond_1b

    :cond_1a
    new-instance v0, Llyiahf/vczjk/ok5;

    const/16 p2, 0xa

    invoke-direct {v0, p2, p1}, Llyiahf/vczjk/ok5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1b
    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/za1;->OooOo00:Llyiahf/vczjk/a91;

    const/high16 v9, 0x30000000

    const/16 v10, 0x1fe

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v1 .. v10}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_d
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_6
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_1d

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_1c

    goto :goto_e

    :cond_1c
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_f

    :cond_1d
    :goto_e
    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/ew5;->OooOOO:Llyiahf/vczjk/le3;

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p2, :cond_1e

    sget-object p2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, p2, :cond_1f

    :cond_1e
    new-instance v0, Llyiahf/vczjk/ok5;

    const/16 p2, 0x9

    invoke-direct {v0, p2, p1}, Llyiahf/vczjk/ok5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1f
    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/za1;->OooO0oO:Llyiahf/vczjk/a91;

    const/high16 v9, 0x30000000

    const/16 v10, 0x1fe

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v1 .. v10}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_f
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
