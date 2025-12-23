.class public abstract Llyiahf/vczjk/ow6;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooOOO:I

.field public OooOOO0:I

.field public OooOOOO:J

.field public OooOOOo:J

.field public OooOOo0:J


# direct methods
.method public constructor <init>()V
    .locals 6

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    int-to-long v0, v0

    const/16 v2, 0x20

    shl-long v2, v0, v2

    const-wide v4, 0xffffffffL

    and-long/2addr v0, v4

    or-long/2addr v0, v2

    iput-wide v0, p0, Llyiahf/vczjk/ow6;->OooOOOO:J

    sget-wide v0, Llyiahf/vczjk/pw6;->OooO00o:J

    iput-wide v0, p0, Llyiahf/vczjk/ow6;->OooOOOo:J

    const-wide/16 v0, 0x0

    iput-wide v0, p0, Llyiahf/vczjk/ow6;->OooOOo0:J

    return-void
.end method


# virtual methods
.method public OooOoo()Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public abstract OooooOO(Llyiahf/vczjk/p4;)I
.end method

.method public OooooOo()I
    .locals 4

    iget-wide v0, p0, Llyiahf/vczjk/ow6;->OooOOOO:J

    const-wide v2, 0xffffffffL

    and-long/2addr v0, v2

    long-to-int v0, v0

    return v0
.end method

.method public Oooooo()I
    .locals 3

    iget-wide v0, p0, Llyiahf/vczjk/ow6;->OooOOOO:J

    const/16 v2, 0x20

    shr-long/2addr v0, v2

    long-to-int v0, v0

    return v0
.end method

.method public final Ooooooo()V
    .locals 9

    iget-wide v0, p0, Llyiahf/vczjk/ow6;->OooOOOO:J

    const/16 v2, 0x20

    shr-long/2addr v0, v2

    long-to-int v0, v0

    iget-wide v3, p0, Llyiahf/vczjk/ow6;->OooOOOo:J

    invoke-static {v3, v4}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v1

    iget-wide v3, p0, Llyiahf/vczjk/ow6;->OooOOOo:J

    invoke-static {v3, v4}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v3

    invoke-static {v0, v1, v3}, Llyiahf/vczjk/vt6;->OooOOo(III)I

    move-result v0

    iput v0, p0, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget-wide v0, p0, Llyiahf/vczjk/ow6;->OooOOOO:J

    const-wide v3, 0xffffffffL

    and-long/2addr v0, v3

    long-to-int v0, v0

    iget-wide v5, p0, Llyiahf/vczjk/ow6;->OooOOOo:J

    invoke-static {v5, v6}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v1

    iget-wide v5, p0, Llyiahf/vczjk/ow6;->OooOOOo:J

    invoke-static {v5, v6}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v5

    invoke-static {v0, v1, v5}, Llyiahf/vczjk/vt6;->OooOOo(III)I

    move-result v0

    iput v0, p0, Llyiahf/vczjk/ow6;->OooOOO:I

    iget v1, p0, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget-wide v5, p0, Llyiahf/vczjk/ow6;->OooOOOO:J

    shr-long v7, v5, v2

    long-to-int v7, v7

    sub-int/2addr v1, v7

    div-int/lit8 v1, v1, 0x2

    and-long/2addr v5, v3

    long-to-int v5, v5

    sub-int/2addr v0, v5

    div-int/lit8 v0, v0, 0x2

    int-to-long v5, v1

    shl-long v1, v5, v2

    int-to-long v5, v0

    and-long/2addr v3, v5

    or-long v0, v1, v3

    iput-wide v0, p0, Llyiahf/vczjk/ow6;->OooOOo0:J

    return-void
.end method

.method public final o00O0O(J)V
    .locals 2

    iget-wide v0, p0, Llyiahf/vczjk/ow6;->OooOOOO:J

    invoke-static {v0, v1, p1, p2}, Llyiahf/vczjk/b24;->OooO00o(JJ)Z

    move-result v0

    if-nez v0, :cond_0

    iput-wide p1, p0, Llyiahf/vczjk/ow6;->OooOOOO:J

    invoke-virtual {p0}, Llyiahf/vczjk/ow6;->Ooooooo()V

    :cond_0
    return-void
.end method

.method public abstract o0OoOo0(JFLlyiahf/vczjk/oe3;)V
.end method

.method public final oo000o(J)V
    .locals 2

    iget-wide v0, p0, Llyiahf/vczjk/ow6;->OooOOOo:J

    invoke-static {v0, v1, p1, p2}, Llyiahf/vczjk/rk1;->OooO0O0(JJ)Z

    move-result v0

    if-nez v0, :cond_0

    iput-wide p1, p0, Llyiahf/vczjk/ow6;->OooOOOo:J

    invoke-virtual {p0}, Llyiahf/vczjk/ow6;->Ooooooo()V

    :cond_0
    return-void
.end method

.method public ooOO(JFLlyiahf/vczjk/kj3;)V
    .locals 0

    const/4 p4, 0x0

    invoke-virtual {p0, p1, p2, p3, p4}, Llyiahf/vczjk/ow6;->o0OoOo0(JFLlyiahf/vczjk/oe3;)V

    return-void
.end method
