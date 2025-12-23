.class public abstract Llyiahf/vczjk/sq4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Z

.field public final OooO0O0:Llyiahf/vczjk/n62;

.field public final OooO0OO:I

.field public final OooO0Oo:I

.field public final OooO0o:Llyiahf/vczjk/yq4;

.field public final OooO0o0:Llyiahf/vczjk/hq4;


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/n62;IILlyiahf/vczjk/hq4;Llyiahf/vczjk/yq4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/sq4;->OooO00o:Z

    iput-object p2, p0, Llyiahf/vczjk/sq4;->OooO0O0:Llyiahf/vczjk/n62;

    iput p3, p0, Llyiahf/vczjk/sq4;->OooO0OO:I

    iput p4, p0, Llyiahf/vczjk/sq4;->OooO0Oo:I

    iput-object p5, p0, Llyiahf/vczjk/sq4;->OooO0o0:Llyiahf/vczjk/hq4;

    iput-object p6, p0, Llyiahf/vczjk/sq4;->OooO0o:Llyiahf/vczjk/yq4;

    return-void
.end method


# virtual methods
.method public final OooO00o(II)J
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/sq4;->OooO0O0:Llyiahf/vczjk/n62;

    const/4 v1, 0x1

    if-ne p2, v1, :cond_0

    iget-object p2, v0, Llyiahf/vczjk/n62;->OooOOO:Ljava/lang/Object;

    check-cast p2, [I

    aget p1, p2, p1

    goto :goto_0

    :cond_0
    add-int/2addr p2, p1

    sub-int/2addr p2, v1

    iget-object v2, v0, Llyiahf/vczjk/n62;->OooOOOO:Ljava/lang/Object;

    check-cast v2, [I

    aget v3, v2, p2

    iget-object v0, v0, Llyiahf/vczjk/n62;->OooOOO:Ljava/lang/Object;

    check-cast v0, [I

    aget p2, v0, p2

    add-int/2addr v3, p2

    aget p1, v2, p1

    sub-int p1, v3, p1

    :goto_0
    const/4 p2, 0x0

    if-gez p1, :cond_1

    move p1, p2

    :cond_1
    iget-boolean v0, p0, Llyiahf/vczjk/sq4;->OooO00o:Z

    const v2, 0x7fffffff

    if-eqz v0, :cond_4

    if-ltz p1, :cond_2

    goto :goto_1

    :cond_2
    move v1, p2

    :goto_1
    if-nez v1, :cond_3

    const-string v0, "width must be >= 0"

    invoke-static {v0}, Llyiahf/vczjk/rz3;->OooO00o(Ljava/lang/String;)V

    :cond_3
    invoke-static {p1, p1, p2, v2}, Llyiahf/vczjk/uk1;->OooO0oo(IIII)J

    move-result-wide p1

    return-wide p1

    :cond_4
    if-ltz p1, :cond_5

    goto :goto_2

    :cond_5
    const-string v0, "height must be >= 0"

    invoke-static {v0}, Llyiahf/vczjk/rz3;->OooO00o(Ljava/lang/String;)V

    :goto_2
    invoke-static {p2, v2, p1, p1}, Llyiahf/vczjk/uk1;->OooO0oo(IIII)J

    move-result-wide p1

    return-wide p1
.end method

.method public final OooO0O0(I)Llyiahf/vczjk/rq4;
    .locals 13

    iget-object v0, p0, Llyiahf/vczjk/sq4;->OooO0o:Llyiahf/vczjk/yq4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yq4;->OooO0O0(I)Llyiahf/vczjk/w3;

    move-result-object v0

    iget-object v5, v0, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    invoke-interface {v5}, Ljava/util/List;->size()I

    move-result v1

    const/4 v2, 0x0

    iget v0, v0, Llyiahf/vczjk/w3;->OooOOO0:I

    if-eqz v1, :cond_1

    add-int v3, v0, v1

    iget v4, p0, Llyiahf/vczjk/sq4;->OooO0OO:I

    if-ne v3, v4, :cond_0

    goto :goto_0

    :cond_0
    iget v3, p0, Llyiahf/vczjk/sq4;->OooO0Oo:I

    move v7, v3

    goto :goto_1

    :cond_1
    :goto_0
    move v7, v2

    :goto_1
    new-array v3, v1, [Llyiahf/vczjk/pq4;

    move v10, v2

    :goto_2
    if-ge v2, v1, :cond_2

    invoke-interface {v5, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/bk3;

    iget-wide v8, v4, Llyiahf/vczjk/bk3;->OooO00o:J

    long-to-int v11, v8

    invoke-virtual {p0, v10, v11}, Llyiahf/vczjk/sq4;->OooO00o(II)J

    move-result-wide v8

    move v12, v7

    add-int v7, v0, v2

    iget-object v6, p0, Llyiahf/vczjk/sq4;->OooO0o0:Llyiahf/vczjk/hq4;

    invoke-virtual/range {v6 .. v12}, Llyiahf/vczjk/qq4;->OooO0O0(IJIII)Llyiahf/vczjk/pq4;

    move-result-object v4

    add-int/2addr v10, v11

    aput-object v4, v3, v2

    add-int/lit8 v2, v2, 0x1

    move v7, v12

    goto :goto_2

    :cond_2
    move v12, v7

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/iq4;

    new-instance v1, Llyiahf/vczjk/rq4;

    iget-object v4, v0, Llyiahf/vczjk/iq4;->OooO0oo:Llyiahf/vczjk/n62;

    iget-boolean v6, v0, Llyiahf/vczjk/iq4;->OooO0oO:Z

    move v2, p1

    move v7, v12

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/rq4;-><init>(I[Llyiahf/vczjk/pq4;Llyiahf/vczjk/n62;Ljava/util/List;ZI)V

    return-object v1
.end method
