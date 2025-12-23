.class public Llyiahf/vczjk/c2a;
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
    new-instance v0, Llyiahf/vczjk/jp4;

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->o00000oO()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Llyiahf/vczjk/jp4;-><init>(Ljava/lang/String;)V

    return-object v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/zc4;Ljava/lang/Object;)V
    .locals 0

    check-cast p2, Llyiahf/vczjk/jp4;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zc4;->o00000O(Ljava/lang/Number;)V

    return-void
.end method
