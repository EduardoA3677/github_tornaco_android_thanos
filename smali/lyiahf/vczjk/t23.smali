.class public interface abstract Llyiahf/vczjk/t23;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wl;


# virtual methods
.method public OooO00o(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/yda;
    .locals 0

    new-instance p1, Llyiahf/vczjk/pb7;

    invoke-direct {p1, p0}, Llyiahf/vczjk/pb7;-><init>(Llyiahf/vczjk/t23;)V

    return-object p1
.end method

.method public abstract OooO0O0(JFFF)F
.end method

.method public abstract OooO0OO(FFF)J
.end method

.method public OooO0Oo(FFF)F
    .locals 6

    invoke-interface {p0, p1, p2, p3}, Llyiahf/vczjk/t23;->OooO0OO(FFF)J

    move-result-wide v1

    move-object v0, p0

    move v3, p1

    move v4, p2

    move v5, p3

    invoke-interface/range {v0 .. v5}, Llyiahf/vczjk/t23;->OooO0O0(JFFF)F

    move-result p1

    return p1
.end method

.method public abstract OooO0o0(JFFF)F
.end method
