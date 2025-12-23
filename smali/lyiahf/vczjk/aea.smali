.class public interface abstract Llyiahf/vczjk/aea;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bea;


# virtual methods
.method public OooO0o0(Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)J
    .locals 2

    invoke-interface {p0}, Llyiahf/vczjk/aea;->OooOOOo()I

    move-result p1

    invoke-interface {p0}, Llyiahf/vczjk/aea;->OooOOo()I

    move-result p2

    add-int/2addr p2, p1

    int-to-long p1, p2

    const-wide/32 v0, 0xf4240

    mul-long/2addr p1, v0

    return-wide p1
.end method

.method public abstract OooOOOo()I
.end method

.method public abstract OooOOo()I
.end method
