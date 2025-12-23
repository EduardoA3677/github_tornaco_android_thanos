.class public final Llyiahf/vczjk/r5a;
.super Llyiahf/vczjk/zb4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xo1;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/zb4;

.field public final OooOOO0:Llyiahf/vczjk/d5a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/r5a;->OooOOO0:Llyiahf/vczjk/d5a;

    iput-object p2, p0, Llyiahf/vczjk/r5a;->OooOOO:Llyiahf/vczjk/zb4;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/r5a;->OooOOO:Llyiahf/vczjk/zb4;

    instance-of v1, v0, Llyiahf/vczjk/xo1;

    if-eqz v1, :cond_0

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/tg8;->o00000O(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    goto :goto_0

    :cond_0
    move-object p1, v0

    :goto_0
    if-ne p1, v0, :cond_1

    return-object p0

    :cond_1
    new-instance p2, Llyiahf/vczjk/r5a;

    iget-object v0, p0, Llyiahf/vczjk/r5a;->OooOOO0:Llyiahf/vczjk/d5a;

    invoke-direct {p2, v0, p1}, Llyiahf/vczjk/r5a;-><init>(Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;)V

    return-object p2
.end method

.method public final OooO0OO()Ljava/lang/Class;
    .locals 1

    const-class v0, Ljava/lang/Object;

    return-object v0
.end method

.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/r5a;->OooOOO:Llyiahf/vczjk/zb4;

    iget-object v1, p0, Llyiahf/vczjk/r5a;->OooOOO0:Llyiahf/vczjk/d5a;

    invoke-virtual {v0, p1, p2, p3, v1}, Llyiahf/vczjk/zb4;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V

    return-void
.end method

.method public final OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/r5a;->OooOOO:Llyiahf/vczjk/zb4;

    invoke-virtual {v0, p1, p2, p3, p4}, Llyiahf/vczjk/zb4;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V

    return-void
.end method
