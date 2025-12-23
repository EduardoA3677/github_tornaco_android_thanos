.class public final Llyiahf/vczjk/t34;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/go4;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/q34;

.field public OooOoo0:Z


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/t34;->OooOoOO:Llyiahf/vczjk/q34;

    sget-object v1, Llyiahf/vczjk/q34;->OooOOO0:Llyiahf/vczjk/q34;

    if-ne v0, v1, :cond_0

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v0

    invoke-interface {p2, v0}, Llyiahf/vczjk/ef5;->OooOo0(I)I

    move-result v0

    goto :goto_0

    :cond_0
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v0

    invoke-interface {p2, v0}, Llyiahf/vczjk/ef5;->OooOo0o(I)I

    move-result v0

    :goto_0
    const/4 v1, 0x0

    if-gez v0, :cond_1

    move v0, v1

    :cond_1
    if-ltz v0, :cond_2

    goto :goto_1

    :cond_2
    const-string v2, "width must be >= 0"

    invoke-static {v2}, Llyiahf/vczjk/rz3;->OooO00o(Ljava/lang/String;)V

    :goto_1
    const v2, 0x7fffffff

    invoke-static {v0, v0, v1, v2}, Llyiahf/vczjk/uk1;->OooO0oo(IIII)J

    move-result-wide v0

    iget-boolean v2, p0, Llyiahf/vczjk/t34;->OooOoo0:Z

    if-eqz v2, :cond_3

    invoke-static {p3, p4, v0, v1}, Llyiahf/vczjk/uk1;->OooO0o0(JJ)J

    move-result-wide v0

    :cond_3
    invoke-interface {p2, v0, v1}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget p4, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    new-instance v0, Llyiahf/vczjk/r34;

    invoke-direct {v0, p2}, Llyiahf/vczjk/r34;-><init>(Llyiahf/vczjk/ow6;)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, p3, p4, p2, v0}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method

.method public final OooOo00(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 0

    invoke-interface {p2, p3}, Llyiahf/vczjk/ef5;->OooooO0(I)I

    move-result p1

    return p1
.end method

.method public final OooOooO(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 0

    invoke-interface {p2, p3}, Llyiahf/vczjk/ef5;->OooO0OO(I)I

    move-result p1

    return p1
.end method

.method public final OoooOOo(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/t34;->OooOoOO:Llyiahf/vczjk/q34;

    sget-object v0, Llyiahf/vczjk/q34;->OooOOO0:Llyiahf/vczjk/q34;

    if-ne p1, v0, :cond_0

    invoke-interface {p2, p3}, Llyiahf/vczjk/ef5;->OooOo0(I)I

    move-result p1

    return p1

    :cond_0
    invoke-interface {p2, p3}, Llyiahf/vczjk/ef5;->OooOo0o(I)I

    move-result p1

    return p1
.end method

.method public final o0OoOo0(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/t34;->OooOoOO:Llyiahf/vczjk/q34;

    sget-object v0, Llyiahf/vczjk/q34;->OooOOO0:Llyiahf/vczjk/q34;

    if-ne p1, v0, :cond_0

    invoke-interface {p2, p3}, Llyiahf/vczjk/ef5;->OooOo0(I)I

    move-result p1

    return p1

    :cond_0
    invoke-interface {p2, p3}, Llyiahf/vczjk/ef5;->OooOo0o(I)I

    move-result p1

    return p1
.end method
