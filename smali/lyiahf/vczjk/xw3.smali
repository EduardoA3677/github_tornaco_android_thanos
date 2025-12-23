.class public final synthetic Llyiahf/vczjk/xw3;
.super Llyiahf/vczjk/wf3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ef3;


# virtual methods
.method public final OooOO0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->floatValue()F

    check-cast p4, Llyiahf/vczjk/tq8;

    iget-wide p1, p4, Llyiahf/vczjk/tq8;->OooO00o:J

    check-cast p5, Llyiahf/vczjk/bq6;

    iget-object p1, p0, Llyiahf/vczjk/go0;->receiver:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/cx3;

    iget-object p1, p1, Llyiahf/vczjk/i70;->Oooo0O0:Llyiahf/vczjk/rx0;

    iget-object p1, p1, Llyiahf/vczjk/rx0;->OooO0OO:Llyiahf/vczjk/aw7;

    if-eqz p1, :cond_0

    const/4 p2, 0x0

    const/16 p3, 0xe

    invoke-static {p1, p5, p2, p3}, Llyiahf/vczjk/fu6;->OooOoo(Llyiahf/vczjk/aw7;Llyiahf/vczjk/bq6;ZI)V

    :cond_0
    return-object p5
.end method
