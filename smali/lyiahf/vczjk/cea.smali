.class public final Llyiahf/vczjk/cea;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/yda;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/gq7;

.field public final OooOOO0:Llyiahf/vczjk/aea;

.field public final OooOOOO:J

.field public final OooOOOo:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/aea;Llyiahf/vczjk/gq7;J)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cea;->OooOOO0:Llyiahf/vczjk/aea;

    iput-object p2, p0, Llyiahf/vczjk/cea;->OooOOO:Llyiahf/vczjk/gq7;

    invoke-interface {p1}, Llyiahf/vczjk/aea;->OooOOOo()I

    move-result p2

    invoke-interface {p1}, Llyiahf/vczjk/aea;->OooOOo()I

    move-result p1

    add-int/2addr p1, p2

    int-to-long p1, p1

    const-wide/32 v0, 0xf4240

    mul-long/2addr p1, v0

    iput-wide p1, p0, Llyiahf/vczjk/cea;->OooOOOO:J

    mul-long/2addr p3, v0

    iput-wide p3, p0, Llyiahf/vczjk/cea;->OooOOOo:J

    return-void
.end method


# virtual methods
.method public final OooO00o()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooO0O0(J)J
    .locals 8

    iget-wide v0, p0, Llyiahf/vczjk/cea;->OooOOOo:J

    add-long v2, p1, v0

    const-wide/16 v4, 0x0

    cmp-long v2, v2, v4

    if-gtz v2, :cond_0

    return-wide v4

    :cond_0
    add-long/2addr p1, v0

    iget-wide v0, p0, Llyiahf/vczjk/cea;->OooOOOO:J

    div-long v2, p1, v0

    sget-object v6, Llyiahf/vczjk/gq7;->OooOOO0:Llyiahf/vczjk/gq7;

    iget-object v7, p0, Llyiahf/vczjk/cea;->OooOOO:Llyiahf/vczjk/gq7;

    if-eq v7, v6, :cond_2

    const/4 v6, 0x2

    int-to-long v6, v6

    rem-long v6, v2, v6

    cmp-long v4, v6, v4

    if-nez v4, :cond_1

    goto :goto_0

    :cond_1
    const-wide/16 v4, 0x1

    add-long/2addr v2, v4

    mul-long/2addr v2, v0

    sub-long/2addr v2, p1

    return-wide v2

    :cond_2
    :goto_0
    mul-long/2addr v2, v0

    sub-long/2addr p1, v2

    return-wide p1
.end method

.method public final OooO0OO(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;
    .locals 10

    iget-wide v0, p0, Llyiahf/vczjk/cea;->OooOOOo:J

    add-long/2addr p1, v0

    iget-wide v2, p0, Llyiahf/vczjk/cea;->OooOOOO:J

    cmp-long p1, p1, v2

    if-lez p1, :cond_0

    iget-object v4, p0, Llyiahf/vczjk/cea;->OooOOO0:Llyiahf/vczjk/aea;

    sub-long v5, v2, v0

    move-object v7, p3

    move-object v9, p4

    move-object v8, p5

    invoke-interface/range {v4 .. v9}, Llyiahf/vczjk/yda;->OooOO0o(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object p1

    return-object p1

    :cond_0
    move-object v9, p4

    return-object v9
.end method

.method public final OooO0o0(Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)J
    .locals 0

    const-wide p1, 0x7fffffffffffffffL

    return-wide p1
.end method

.method public final OooO0oo(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;
    .locals 9

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/cea;->OooO0O0(J)J

    move-result-wide v1

    move-object v3, p0

    move-wide v4, p1

    move-object v6, p3

    move-object v8, p4

    move-object v7, p5

    invoke-virtual/range {v3 .. v8}, Llyiahf/vczjk/cea;->OooO0OO(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object v5

    move-object p1, v3

    move-object v3, v6

    move-object v4, v8

    iget-object v0, p1, Llyiahf/vczjk/cea;->OooOOO0:Llyiahf/vczjk/aea;

    invoke-interface/range {v0 .. v5}, Llyiahf/vczjk/yda;->OooO0oo(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object p2

    return-object p2
.end method

.method public final OooOO0o(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;
    .locals 9

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/cea;->OooO0O0(J)J

    move-result-wide v1

    move-object v3, p0

    move-wide v4, p1

    move-object v6, p3

    move-object v8, p4

    move-object v7, p5

    invoke-virtual/range {v3 .. v8}, Llyiahf/vczjk/cea;->OooO0OO(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object v5

    move-object p1, v3

    move-object v3, v6

    move-object v4, v8

    iget-object v0, p1, Llyiahf/vczjk/cea;->OooOOO0:Llyiahf/vczjk/aea;

    invoke-interface/range {v0 .. v5}, Llyiahf/vczjk/yda;->OooOO0o(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object p2

    return-object p2
.end method
