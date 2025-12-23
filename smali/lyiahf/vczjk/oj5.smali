.class public final Llyiahf/vczjk/oj5;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ug1;
.implements Llyiahf/vczjk/go4;


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v0, :cond_0

    sget-object v0, Llyiahf/vczjk/s24;->OooO00o:Llyiahf/vczjk/l39;

    invoke-static {p0, v0}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    sget-wide v1, Llyiahf/vczjk/s24;->OooO0O0:J

    invoke-interface {p2, p3, p4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    if-eqz v0, :cond_1

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    invoke-static {v1, v2}, Llyiahf/vczjk/ae2;->OooO0O0(J)F

    move-result p4

    invoke-interface {p1, p4}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p4

    invoke-static {p3, p4}, Ljava/lang/Math;->max(II)I

    move-result p3

    goto :goto_1

    :cond_1
    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    :goto_1
    if-eqz v0, :cond_2

    iget p4, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    invoke-static {v1, v2}, Llyiahf/vczjk/ae2;->OooO00o(J)F

    move-result v0

    invoke-interface {p1, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    invoke-static {p4, v0}, Ljava/lang/Math;->max(II)I

    move-result p4

    goto :goto_2

    :cond_2
    iget p4, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    :goto_2
    new-instance v0, Llyiahf/vczjk/mj5;

    invoke-direct {v0, p3, p2, p4}, Llyiahf/vczjk/mj5;-><init>(ILlyiahf/vczjk/ow6;I)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, p3, p4, p2, v0}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method
