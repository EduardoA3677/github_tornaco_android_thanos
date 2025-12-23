.class public final synthetic Llyiahf/vczjk/xp0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/xp0;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/xp0;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    iget v0, p0, Llyiahf/vczjk/xp0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/nf5;

    check-cast p2, Llyiahf/vczjk/ef5;

    check-cast p3, Llyiahf/vczjk/rk1;

    iget-object v0, p0, Llyiahf/vczjk/xp0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/wd2;

    iget v0, v0, Llyiahf/vczjk/wd2;->OooOOO0:F

    iget-wide v1, p3, Llyiahf/vczjk/rk1;->OooO00o:J

    const/high16 v3, 0x7fc00000    # Float.NaN

    invoke-static {v0, v3}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v3

    if-nez v3, :cond_0

    invoke-interface {p1, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-static {v0, v1, v2}, Llyiahf/vczjk/uk1;->OooO0o(IJ)I

    move-result v7

    const/4 v6, 0x0

    const/4 v8, 0x0

    iget-wide v3, p3, Llyiahf/vczjk/rk1;->OooO00o:J

    const/4 v5, 0x0

    const/16 v9, 0xb

    invoke-static/range {v3 .. v9}, Llyiahf/vczjk/rk1;->OooO00o(JIIIII)J

    move-result-wide v0

    invoke-interface {p2, v0, v1}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v0, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    new-instance v1, Llyiahf/vczjk/j50;

    const/4 v2, 0x4

    invoke-direct {v1, p2, v2}, Llyiahf/vczjk/j50;-><init>(Llyiahf/vczjk/ow6;I)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, p3, v0, p2, v1}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/nf5;

    check-cast p2, Llyiahf/vczjk/ef5;

    check-cast p3, Llyiahf/vczjk/rk1;

    iget-wide v0, p3, Llyiahf/vczjk/rk1;->OooO00o:J

    invoke-interface {p2, v0, v1}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    const/high16 p3, 0x7fc00000    # Float.NaN

    invoke-static {p3, p3}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object p3, p0, Llyiahf/vczjk/xp0;->OooOOO:Ljava/lang/Object;

    check-cast p3, Llyiahf/vczjk/cs8;

    iget-object p3, p3, Llyiahf/vczjk/cs8;->OooOO0o:Llyiahf/vczjk/nf6;

    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    if-ne p3, v0, :cond_1

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    div-int/lit8 p3, p3, 0x2

    goto :goto_1

    :cond_1
    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    div-int/lit8 p3, p3, 0x2

    goto :goto_1

    :cond_2
    invoke-interface {p1, p3}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p3

    :goto_1
    iget v0, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v1, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    sget-object v2, Llyiahf/vczjk/as8;->OooO0o:Llyiahf/vczjk/dfa;

    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p3

    new-instance v3, Llyiahf/vczjk/xn6;

    invoke-direct {v3, v2, p3}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-static {v3}, Llyiahf/vczjk/lc5;->o00oO0O(Llyiahf/vczjk/xn6;)Ljava/util/Map;

    move-result-object p3

    new-instance v2, Llyiahf/vczjk/j50;

    const/4 v3, 0x3

    invoke-direct {v2, p2, v3}, Llyiahf/vczjk/j50;-><init>(Llyiahf/vczjk/ow6;I)V

    invoke-interface {p1, v0, v1, p3, v2}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1

    :pswitch_1
    check-cast p1, Ljava/lang/Throwable;

    check-cast p2, Llyiahf/vczjk/z8a;

    check-cast p3, Llyiahf/vczjk/or1;

    iget-object p1, p0, Llyiahf/vczjk/xp0;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/ef8;

    invoke-virtual {p1}, Llyiahf/vczjk/ef8;->OooO0OO()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_2
    check-cast p1, Ljava/lang/Throwable;

    check-cast p3, Llyiahf/vczjk/or1;

    iget-object p2, p0, Llyiahf/vczjk/xp0;->OooOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/o0OO000o;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/o0OO000o;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
