.class public final Llyiahf/vczjk/lj5;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/go4;


# instance fields
.field public OooOoOO:Z

.field public OooOoo:Llyiahf/vczjk/p13;

.field public OooOoo0:Z

.field public OooOooO:Llyiahf/vczjk/gi;


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 5

    invoke-interface {p2, p3, p4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget-boolean p3, p0, Llyiahf/vczjk/lj5;->OooOoOO:Z

    const/4 p4, 0x0

    if-eqz p3, :cond_1

    iget-boolean p3, p0, Llyiahf/vczjk/lj5;->OooOoo0:Z

    if-nez p3, :cond_0

    goto :goto_0

    :cond_0
    move v0, p4

    move v1, v0

    goto :goto_2

    :cond_1
    :goto_0
    iget-object p3, p0, Llyiahf/vczjk/lj5;->OooOooO:Llyiahf/vczjk/gi;

    invoke-virtual {p3}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->floatValue()F

    move-result p3

    sget-object v0, Llyiahf/vczjk/r24;->OooO00o:Llyiahf/vczjk/go3;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/ow6;->OooooOO(Llyiahf/vczjk/p4;)I

    move-result v0

    const/high16 v1, -0x80000000

    if-eq v0, v1, :cond_2

    int-to-float v0, v0

    mul-float/2addr v0, p3

    goto :goto_1

    :cond_2
    move v0, p4

    :goto_1
    sget-object v2, Llyiahf/vczjk/r24;->OooO0O0:Llyiahf/vczjk/dfa;

    invoke-virtual {p2, v2}, Llyiahf/vczjk/ow6;->OooooOO(Llyiahf/vczjk/p4;)I

    move-result v2

    if-eq v2, v1, :cond_3

    int-to-float v1, v2

    mul-float/2addr v1, p3

    goto :goto_2

    :cond_3
    move v1, p4

    :goto_2
    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    sub-float v2, v0, v1

    const/4 v3, 0x2

    int-to-float v3, v3

    mul-float/2addr v2, v3

    cmpg-float v4, v2, p4

    if-gez v4, :cond_4

    move v2, p4

    :cond_4
    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    move-result v2

    add-int/2addr v2, p3

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    sub-float/2addr v1, v0

    mul-float/2addr v1, v3

    cmpg-float v0, v1, p4

    if-gez v0, :cond_5

    goto :goto_3

    :cond_5
    move p4, v1

    :goto_3
    invoke-static {p4}, Ljava/lang/Math;->round(F)I

    move-result p4

    add-int/2addr p4, p3

    new-instance p3, Llyiahf/vczjk/jj5;

    invoke-direct {p3, p2, v2, p4}, Llyiahf/vczjk/jj5;-><init>(Llyiahf/vczjk/ow6;II)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, v2, p4, p2, p3}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method
