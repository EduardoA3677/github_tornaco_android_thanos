.class public final Llyiahf/vczjk/av4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/os4;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/dw4;

.field public final OooO0O0:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dw4;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/av4;->OooO00o:Llyiahf/vczjk/dw4;

    iput p2, p0, Llyiahf/vczjk/av4;->OooO0O0:I

    return-void
.end method


# virtual methods
.method public final OooO00o()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/av4;->OooO00o:Llyiahf/vczjk/dw4;

    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v0

    iget v0, v0, Llyiahf/vczjk/sv4;->OooOOO:I

    return v0
.end method

.method public final OooO0O0()I
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/av4;->OooO00o()I

    move-result v0

    add-int/lit8 v0, v0, -0x1

    iget-object v1, p0, Llyiahf/vczjk/av4;->OooO00o:Llyiahf/vczjk/dw4;

    invoke-virtual {v1}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/sv4;->OooOO0O:Ljava/lang/Object;

    invoke-static {v1}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/gv4;

    check-cast v1, Llyiahf/vczjk/tv4;

    iget v1, v1, Llyiahf/vczjk/tv4;->OooO00o:I

    iget v2, p0, Llyiahf/vczjk/av4;->OooO0O0:I

    add-int/2addr v1, v2

    invoke-static {v0, v1}, Ljava/lang/Math;->min(II)I

    move-result v0

    return v0
.end method

.method public final OooO0OO()I
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/av4;->OooO00o:Llyiahf/vczjk/dw4;

    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/sv4;->OooOO0O:Ljava/lang/Object;

    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    return v2

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v1

    iget-object v3, v1, Llyiahf/vczjk/sv4;->OooOOOo:Llyiahf/vczjk/nf6;

    sget-object v4, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    if-ne v3, v4, :cond_1

    invoke-virtual {v1}, Llyiahf/vczjk/sv4;->OooO0o0()J

    move-result-wide v3

    const-wide v5, 0xffffffffL

    and-long/2addr v3, v5

    :goto_0
    long-to-int v1, v3

    goto :goto_1

    :cond_1
    invoke-virtual {v1}, Llyiahf/vczjk/sv4;->OooO0o0()J

    move-result-wide v3

    const/16 v1, 0x20

    shr-long/2addr v3, v1

    goto :goto_0

    :goto_1
    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v0

    iget-object v3, v0, Llyiahf/vczjk/sv4;->OooOO0O:Ljava/lang/Object;

    invoke-interface {v3}, Ljava/util/Collection;->size()I

    move-result v4

    move v5, v2

    :goto_2
    if-ge v2, v4, :cond_2

    invoke-interface {v3, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/gv4;

    check-cast v6, Llyiahf/vczjk/tv4;

    iget v6, v6, Llyiahf/vczjk/tv4;->OooOOo0:I

    add-int/2addr v5, v6

    add-int/lit8 v2, v2, 0x1

    goto :goto_2

    :cond_2
    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v2

    div-int/2addr v5, v2

    iget v0, v0, Llyiahf/vczjk/sv4;->OooOOo:I

    add-int/2addr v5, v0

    const/4 v0, 0x1

    if-nez v5, :cond_3

    goto :goto_3

    :cond_3
    div-int/2addr v1, v5

    if-ge v1, v0, :cond_4

    :goto_3
    return v0

    :cond_4
    return v1
.end method

.method public final OooO0Oo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/av4;->OooO00o:Llyiahf/vczjk/dw4;

    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/sv4;->OooOO0O:Ljava/lang/Object;

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    xor-int/lit8 v0, v0, 0x1

    return v0
.end method

.method public final OooO0o0()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/av4;->OooO00o:Llyiahf/vczjk/dw4;

    iget-object v0, v0, Llyiahf/vczjk/dw4;->OooO0Oo:Llyiahf/vczjk/tq4;

    invoke-virtual {v0}, Llyiahf/vczjk/tq4;->OooO00o()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/av4;->OooO0O0:I

    sub-int/2addr v0, v1

    const/4 v1, 0x0

    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    move-result v0

    return v0
.end method
