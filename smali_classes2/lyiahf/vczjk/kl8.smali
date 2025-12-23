.class public final Llyiahf/vczjk/kl8;
.super Llyiahf/vczjk/o00Oo00;
.source "SourceFile"


# instance fields
.field public OooO00o:J

.field public OooO0O0:Llyiahf/vczjk/yp0;


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/o00OOOOo;)Z
    .locals 4

    check-cast p1, Llyiahf/vczjk/jl8;

    iget-wide v0, p0, Llyiahf/vczjk/kl8;->OooO00o:J

    const-wide/16 v2, 0x0

    cmp-long v0, v0, v2

    if-ltz v0, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    iget-wide v0, p1, Llyiahf/vczjk/jl8;->OooOo0:J

    iget-wide v2, p1, Llyiahf/vczjk/jl8;->OooOo0O:J

    cmp-long v2, v0, v2

    if-gez v2, :cond_1

    iput-wide v0, p1, Llyiahf/vczjk/jl8;->OooOo0O:J

    :cond_1
    iput-wide v0, p0, Llyiahf/vczjk/kl8;->OooO00o:J

    const/4 p1, 0x1

    return p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/o00OOOOo;)[Llyiahf/vczjk/yo1;
    .locals 4

    check-cast p1, Llyiahf/vczjk/jl8;

    iget-wide v0, p0, Llyiahf/vczjk/kl8;->OooO00o:J

    const-wide/16 v2, -0x1

    iput-wide v2, p0, Llyiahf/vczjk/kl8;->OooO00o:J

    const/4 v2, 0x0

    iput-object v2, p0, Llyiahf/vczjk/kl8;->OooO0O0:Llyiahf/vczjk/yp0;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/jl8;->OooOoO(J)[Llyiahf/vczjk/yo1;

    move-result-object p1

    return-object p1
.end method
