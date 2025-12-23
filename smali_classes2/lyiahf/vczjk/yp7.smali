.class public final Llyiahf/vczjk/yp7;
.super Llyiahf/vczjk/fq7;
.source "SourceFile"


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/dw4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dw4;Llyiahf/vczjk/xr1;FLlyiahf/vczjk/ze3;Llyiahf/vczjk/tz8;)V
    .locals 1

    const-string v0, "listState"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "scope"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p2, p3, p4, p5}, Llyiahf/vczjk/fq7;-><init>(Llyiahf/vczjk/xr1;FLlyiahf/vczjk/ze3;Llyiahf/vczjk/tz8;)V

    iput-object p1, p0, Llyiahf/vczjk/yp7;->OooOOO0:Llyiahf/vczjk/dw4;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Ljava/lang/Object;Ljava/util/ArrayList;II)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/gv4;

    const-string v0, "items"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/yp7;->OooOOOo()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-super {p0, p1, p2, v1, p4}, Llyiahf/vczjk/fq7;->OooO0O0(Ljava/lang/Object;Ljava/util/ArrayList;II)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gv4;

    return-object p1

    :cond_0
    invoke-super {p0, p1, p2, p3, v1}, Llyiahf/vczjk/fq7;->OooO0O0(Ljava/lang/Object;Ljava/util/ArrayList;II)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gv4;

    return-object p1
.end method

.method public final OooO0OO(IILjava/lang/Object;)Ljava/util/ArrayList;
    .locals 2

    check-cast p3, Llyiahf/vczjk/gv4;

    invoke-virtual {p0}, Llyiahf/vczjk/yp7;->OooOOOo()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-super {p0, v1, p2, p3}, Llyiahf/vczjk/fq7;->OooO0OO(IILjava/lang/Object;)Ljava/util/ArrayList;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-super {p0, p1, v1, p3}, Llyiahf/vczjk/fq7;->OooO0OO(IILjava/lang/Object;)Ljava/util/ArrayList;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo(Ljava/lang/Object;)I
    .locals 4

    check-cast p1, Llyiahf/vczjk/gv4;

    const-string v0, "<this>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/yp7;->OooOOOo()Z

    move-result v0

    if-nez v0, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/yp7;->OooOOO0:Llyiahf/vczjk/dw4;

    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v1

    iget-boolean v1, v1, Llyiahf/vczjk/sv4;->OooOOOO:Z

    if-eqz v1, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/sv4;->OooO0o0()J

    move-result-wide v0

    const-wide v2, 0xffffffffL

    and-long/2addr v0, v2

    long-to-int v0, v0

    check-cast p1, Llyiahf/vczjk/tv4;

    iget p1, p1, Llyiahf/vczjk/tv4;->OooOOOo:I

    sub-int/2addr v0, p1

    return v0

    :cond_1
    check-cast p1, Llyiahf/vczjk/tv4;

    iget v0, p1, Llyiahf/vczjk/tv4;->OooOOOo:I

    iget p1, p1, Llyiahf/vczjk/tv4;->OooOOo0:I

    add-int/2addr v0, p1

    return v0
.end method

.method public final OooOO0(Ljava/lang/Object;)I
    .locals 1

    check-cast p1, Llyiahf/vczjk/gv4;

    const-string v0, "<this>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/tv4;

    iget p1, p1, Llyiahf/vczjk/tv4;->OooO00o:I

    return p1
.end method

.method public final OooOO0O(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/gv4;

    const-string v0, "<this>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/tv4;

    iget-object p1, p1, Llyiahf/vczjk/tv4;->OooOO0o:Ljava/lang/Object;

    return-object p1
.end method

.method public final OooOO0o(Ljava/lang/Object;)I
    .locals 3

    check-cast p1, Llyiahf/vczjk/gv4;

    const-string v0, "<this>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/yp7;->OooOOOo()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/yp7;->OooOOO0:Llyiahf/vczjk/dw4;

    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v1

    iget-boolean v1, v1, Llyiahf/vczjk/sv4;->OooOOOO:Z

    if-eqz v1, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/sv4;->OooO0o0()J

    move-result-wide v0

    const/16 v2, 0x20

    shr-long/2addr v0, v2

    long-to-int v0, v0

    check-cast p1, Llyiahf/vczjk/tv4;

    iget v1, p1, Llyiahf/vczjk/tv4;->OooOOOo:I

    sub-int/2addr v0, v1

    iget p1, p1, Llyiahf/vczjk/tv4;->OooOOo0:I

    sub-int/2addr v0, p1

    return v0

    :cond_1
    check-cast p1, Llyiahf/vczjk/tv4;

    iget p1, p1, Llyiahf/vczjk/tv4;->OooOOOo:I

    return p1
.end method

.method public final OooOOO(Ljava/lang/Object;)I
    .locals 4

    check-cast p1, Llyiahf/vczjk/gv4;

    const-string v0, "<this>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/yp7;->OooOOOo()Z

    move-result v0

    if-nez v0, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/yp7;->OooOOO0:Llyiahf/vczjk/dw4;

    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v1

    iget-boolean v1, v1, Llyiahf/vczjk/sv4;->OooOOOO:Z

    if-eqz v1, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/sv4;->OooO0o0()J

    move-result-wide v0

    const-wide v2, 0xffffffffL

    and-long/2addr v0, v2

    long-to-int v0, v0

    check-cast p1, Llyiahf/vczjk/tv4;

    iget v1, p1, Llyiahf/vczjk/tv4;->OooOOOo:I

    sub-int/2addr v0, v1

    iget p1, p1, Llyiahf/vczjk/tv4;->OooOOo0:I

    sub-int/2addr v0, p1

    return v0

    :cond_1
    check-cast p1, Llyiahf/vczjk/tv4;

    iget p1, p1, Llyiahf/vczjk/tv4;->OooOOOo:I

    return p1
.end method

.method public final OooOOO0(Ljava/lang/Object;)I
    .locals 3

    check-cast p1, Llyiahf/vczjk/gv4;

    const-string v0, "<this>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/yp7;->OooOOOo()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/yp7;->OooOOO0:Llyiahf/vczjk/dw4;

    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v1

    iget-boolean v1, v1, Llyiahf/vczjk/sv4;->OooOOOO:Z

    if-eqz v1, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/sv4;->OooO0o0()J

    move-result-wide v0

    const/16 v2, 0x20

    shr-long/2addr v0, v2

    long-to-int v0, v0

    check-cast p1, Llyiahf/vczjk/tv4;

    iget p1, p1, Llyiahf/vczjk/tv4;->OooOOOo:I

    sub-int/2addr v0, p1

    return v0

    :cond_1
    check-cast p1, Llyiahf/vczjk/tv4;

    iget v0, p1, Llyiahf/vczjk/tv4;->OooOOOo:I

    iget p1, p1, Llyiahf/vczjk/tv4;->OooOOo0:I

    add-int/2addr v0, p1

    return v0
.end method

.method public final OooOOOO()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/yp7;->OooOOO0:Llyiahf/vczjk/dw4;

    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/sv4;->OooOO0O:Ljava/lang/Object;

    return-object v0
.end method

.method public final OooOOOo()Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/yp7;->OooOOO0:Llyiahf/vczjk/dw4;

    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/sv4;->OooOOOo:Llyiahf/vczjk/nf6;

    sget-object v1, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOoo(II)Z
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/yp7;->OooOOOo()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-super {p0, v1, p2}, Llyiahf/vczjk/fq7;->OooOOoo(II)Z

    move-result p1

    return p1

    :cond_0
    invoke-super {p0, p1, v1}, Llyiahf/vczjk/fq7;->OooOOoo(II)Z

    move-result p1

    return p1
.end method
