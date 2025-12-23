.class public final synthetic Llyiahf/vczjk/v81;
.super Llyiahf/vczjk/h1;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 0

    iput p7, p0, Llyiahf/vczjk/v81;->OooOOO0:I

    move-object p7, p4

    move-object p4, p3

    move p3, p6

    move-object p6, p7

    move-object p7, p5

    move-object p5, p2

    move p2, p1

    move-object p1, p0

    invoke-direct/range {p1 .. p7}, Llyiahf/vczjk/h1;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    iget v0, p0, Llyiahf/vczjk/v81;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/fea;

    iget-wide v0, p1, Llyiahf/vczjk/fea;->OooO00o:J

    check-cast p2, Llyiahf/vczjk/yo1;

    iget-object p1, p0, Llyiahf/vczjk/h1;->receiver:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/ra8;

    iget-object p2, p1, Llyiahf/vczjk/ra8;->Oooo0o:Llyiahf/vczjk/fz5;

    invoke-virtual {p2}, Llyiahf/vczjk/fz5;->OooO0OO()Llyiahf/vczjk/xr1;

    move-result-object p2

    new-instance v2, Llyiahf/vczjk/ma8;

    const/4 v3, 0x0

    invoke-direct {v2, p1, v0, v1, v3}, Llyiahf/vczjk/ma8;-><init>(Llyiahf/vczjk/ra8;JLlyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {p2, v3, v3, v2, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    check-cast p2, Llyiahf/vczjk/yo1;

    iget-object p2, p0, Llyiahf/vczjk/h1;->receiver:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/bf7;

    invoke-virtual {p2}, Llyiahf/vczjk/bf7;->OooO0OO()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    goto :goto_2

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/bf7;->OooO00o()F

    move-result v0

    invoke-virtual {p2}, Llyiahf/vczjk/bf7;->OooO0O0()F

    move-result v2

    cmpl-float v0, v0, v2

    if-lez v0, :cond_1

    iget-object v0, p2, Llyiahf/vczjk/bf7;->OooO0O0:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_1
    new-instance v0, Llyiahf/vczjk/af7;

    const/4 v2, 0x0

    invoke-direct {v0, p2, v1, v2}, Llyiahf/vczjk/af7;-><init>(Llyiahf/vczjk/bf7;FLlyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    iget-object v4, p2, Llyiahf/vczjk/bf7;->OooO00o:Llyiahf/vczjk/xr1;

    invoke-static {v4, v2, v2, v0, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    iget-object p2, p2, Llyiahf/vczjk/bf7;->OooO0o:Llyiahf/vczjk/lr5;

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v0

    cmpg-float v0, v0, v1

    if-nez v0, :cond_2

    :goto_0
    move p1, v1

    goto :goto_1

    :cond_2
    cmpg-float v0, p1, v1

    if-gez v0, :cond_3

    goto :goto_0

    :cond_3
    :goto_1
    check-cast p2, Llyiahf/vczjk/zv8;

    invoke-virtual {p2, v1}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    move v1, p1

    :goto_2
    new-instance p1, Ljava/lang/Float;

    invoke-direct {p1, v1}, Ljava/lang/Float;-><init>(F)V

    return-object p1

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/h1;->receiver:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/a91;

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/a91;->OooO0oO(ILlyiahf/vczjk/rf1;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
