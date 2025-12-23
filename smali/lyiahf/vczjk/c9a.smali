.class public final Llyiahf/vczjk/c9a;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/b9a;
    .locals 5

    check-cast p0, Llyiahf/vczjk/wg3;

    iget-object v0, p0, Llyiahf/vczjk/wg3;->unknownFields:Llyiahf/vczjk/b9a;

    sget-object v1, Llyiahf/vczjk/b9a;->OooO0o:Llyiahf/vczjk/b9a;

    if-ne v0, v1, :cond_0

    new-instance v0, Llyiahf/vczjk/b9a;

    const/16 v1, 0x8

    new-array v2, v1, [I

    new-array v1, v1, [Ljava/lang/Object;

    const/4 v3, 0x1

    const/4 v4, 0x0

    invoke-direct {v0, v4, v2, v1, v3}, Llyiahf/vczjk/b9a;-><init>(I[I[Ljava/lang/Object;Z)V

    iput-object v0, p0, Llyiahf/vczjk/wg3;->unknownFields:Llyiahf/vczjk/b9a;

    :cond_0
    return-object v0
.end method

.method public static OooO0O0(ILjava/lang/Object;Llyiahf/vczjk/j11;)Z
    .locals 8

    iget v0, p2, Llyiahf/vczjk/j11;->OooO0O0:I

    ushr-int/lit8 v1, v0, 0x3

    and-int/lit8 v0, v0, 0x7

    const/4 v2, 0x1

    const/4 v3, 0x0

    const/4 v4, 0x3

    iget-object v5, p2, Llyiahf/vczjk/j11;->OooO0o0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/i11;

    if-eqz v0, :cond_a

    if-eq v0, v2, :cond_9

    const/4 v6, 0x2

    if-eq v0, v6, :cond_8

    if-eq v0, v4, :cond_2

    const/4 p0, 0x4

    if-eq v0, p0, :cond_1

    const/4 p0, 0x5

    if-ne v0, p0, :cond_0

    invoke-virtual {p2, p0}, Llyiahf/vczjk/j11;->OooOoo0(I)V

    invoke-virtual {v5}, Llyiahf/vczjk/i11;->OooOOO()I

    move-result p2

    check-cast p1, Llyiahf/vczjk/b9a;

    shl-int/lit8 v0, v1, 0x3

    or-int/2addr p0, v0

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    invoke-virtual {p1, p0, p2}, Llyiahf/vczjk/b9a;->OooO0OO(ILjava/lang/Object;)V

    return v2

    :cond_0
    invoke-static {}, Llyiahf/vczjk/j44;->OooO0OO()Llyiahf/vczjk/h44;

    move-result-object p0

    throw p0

    :cond_1
    return v3

    :cond_2
    new-instance v0, Llyiahf/vczjk/b9a;

    const/16 v5, 0x8

    new-array v6, v5, [I

    new-array v5, v5, [Ljava/lang/Object;

    invoke-direct {v0, v3, v6, v5, v2}, Llyiahf/vczjk/b9a;-><init>(I[I[Ljava/lang/Object;Z)V

    shl-int/2addr v1, v4

    or-int/lit8 v5, v1, 0x4

    add-int/2addr p0, v2

    const/16 v6, 0x64

    if-ge p0, v6, :cond_7

    :cond_3
    invoke-virtual {p2}, Llyiahf/vczjk/j11;->OooO0Oo()I

    move-result v6

    const v7, 0x7fffffff

    if-eq v6, v7, :cond_4

    invoke-static {p0, v0, p2}, Llyiahf/vczjk/c9a;->OooO0O0(ILjava/lang/Object;Llyiahf/vczjk/j11;)Z

    move-result v6

    if-nez v6, :cond_3

    :cond_4
    iget p0, p2, Llyiahf/vczjk/j11;->OooO0O0:I

    if-ne v5, p0, :cond_6

    iget-boolean p0, v0, Llyiahf/vczjk/b9a;->OooO0o0:Z

    if-eqz p0, :cond_5

    iput-boolean v3, v0, Llyiahf/vczjk/b9a;->OooO0o0:Z

    :cond_5
    check-cast p1, Llyiahf/vczjk/b9a;

    or-int/lit8 p0, v1, 0x3

    invoke-virtual {p1, p0, v0}, Llyiahf/vczjk/b9a;->OooO0OO(ILjava/lang/Object;)V

    return v2

    :cond_6
    new-instance p0, Llyiahf/vczjk/j44;

    const-string p1, "Protocol message end-group tag did not match expected tag."

    invoke-direct {p0, p1}, Llyiahf/vczjk/j44;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_7
    new-instance p0, Llyiahf/vczjk/j44;

    const-string p1, "Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit."

    invoke-direct {p0, p1}, Llyiahf/vczjk/j44;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_8
    invoke-virtual {p2}, Llyiahf/vczjk/j11;->OooOO0()Llyiahf/vczjk/km0;

    move-result-object p0

    check-cast p1, Llyiahf/vczjk/b9a;

    shl-int/lit8 p2, v1, 0x3

    or-int/2addr p2, v6

    invoke-virtual {p1, p2, p0}, Llyiahf/vczjk/b9a;->OooO0OO(ILjava/lang/Object;)V

    return v2

    :cond_9
    invoke-virtual {p2, v2}, Llyiahf/vczjk/j11;->OooOoo0(I)V

    invoke-virtual {v5}, Llyiahf/vczjk/i11;->OooOOOO()J

    move-result-wide v5

    check-cast p1, Llyiahf/vczjk/b9a;

    shl-int/lit8 p0, v1, 0x3

    or-int/2addr p0, v2

    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p2

    invoke-virtual {p1, p0, p2}, Llyiahf/vczjk/b9a;->OooO0OO(ILjava/lang/Object;)V

    return v2

    :cond_a
    invoke-virtual {p2, v3}, Llyiahf/vczjk/j11;->OooOoo0(I)V

    invoke-virtual {v5}, Llyiahf/vczjk/i11;->OooOOo()J

    move-result-wide v5

    check-cast p1, Llyiahf/vczjk/b9a;

    shl-int/lit8 p0, v1, 0x3

    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p2

    invoke-virtual {p1, p0, p2}, Llyiahf/vczjk/b9a;->OooO0OO(ILjava/lang/Object;)V

    return v2
.end method
