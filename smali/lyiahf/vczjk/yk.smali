.class public interface abstract Llyiahf/vczjk/yk;
.super Ljava/lang/Object;
.source "SourceFile"


# virtual methods
.method public abstract OooO00o()Z
.end method

.method public abstract OooO0O0()J
.end method

.method public abstract OooO0OO()Llyiahf/vczjk/m1a;
.end method

.method public abstract OooO0Oo(J)Llyiahf/vczjk/dm;
.end method

.method public abstract OooO0o(J)Ljava/lang/Object;
.end method

.method public OooO0o0(J)Z
    .locals 2

    invoke-interface {p0}, Llyiahf/vczjk/yk;->OooO0O0()J

    move-result-wide v0

    cmp-long p1, p1, v0

    if-ltz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public abstract OooO0oO()Ljava/lang/Object;
.end method
