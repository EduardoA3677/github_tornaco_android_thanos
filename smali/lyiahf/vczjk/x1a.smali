.class public Llyiahf/vczjk/x1a;
.super Llyiahf/vczjk/r1a;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/qb4;)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->o0000()I

    move-result v0

    const/16 v1, 0x9

    if-ne v0, v1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->o00000o0()V

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->o0OoOo0()D

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/zc4;Ljava/lang/Object;)V
    .locals 2

    check-cast p2, Ljava/lang/Number;

    if-nez p2, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/zc4;->OoooO00()Llyiahf/vczjk/zc4;

    return-void

    :cond_0
    invoke-virtual {p2}, Ljava/lang/Number;->doubleValue()D

    move-result-wide v0

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/zc4;->o00oO0o(D)V

    return-void
.end method
