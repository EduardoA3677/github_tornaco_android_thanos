.class public final Llyiahf/vczjk/ky3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/pd1;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ly3;

.field public final OooO0O0:Llyiahf/vczjk/a47;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ly3;Llyiahf/vczjk/a47;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ky3;->OooO00o:Llyiahf/vczjk/ly3;

    iput-object p2, p0, Llyiahf/vczjk/ky3;->OooO0O0:Llyiahf/vczjk/a47;

    return-void
.end method

.method public static OooO0O0(Llyiahf/vczjk/dy3;)J
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/dy3;->OooOOo0:Llyiahf/vczjk/wl;

    const-string v1, "null cannot be cast to non-null type androidx.compose.animation.core.InfiniteRepeatableSpec<T of androidx.compose.ui.tooling.animation.clock.InfiniteTransitionClock.getIterationDuration>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/cy3;

    sget-object v1, Llyiahf/vczjk/gq7;->OooOOO:Llyiahf/vczjk/gq7;

    iget-object v2, v0, Llyiahf/vczjk/cy3;->OooO0O0:Llyiahf/vczjk/gq7;

    if-ne v2, v1, :cond_0

    const/4 v1, 0x2

    goto :goto_0

    :cond_0
    const/4 v1, 0x1

    :goto_0
    iget-object v0, v0, Llyiahf/vczjk/cy3;->OooO00o:Llyiahf/vczjk/xj2;

    iget-object p0, p0, Llyiahf/vczjk/dy3;->OooOOOO:Llyiahf/vczjk/n1a;

    invoke-interface {v0, p0}, Llyiahf/vczjk/xj2;->OooO00o(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/aea;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/aea;->OooOOOo()I

    move-result v0

    int-to-long v2, v0

    invoke-interface {p0}, Llyiahf/vczjk/aea;->OooOOo()I

    move-result p0

    mul-int/2addr p0, v1

    int-to-long v0, p0

    add-long/2addr v2, v0

    sget-object p0, Llyiahf/vczjk/vba;->OooO00o:Ljava/util/List;

    const-wide/32 v0, 0xf4240

    mul-long/2addr v2, v0

    return-wide v2
.end method


# virtual methods
.method public final OooO00o()J
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/ky3;->OooO0OO()J

    move-result-wide v0

    iget-object v2, p0, Llyiahf/vczjk/ky3;->OooO0O0:Llyiahf/vczjk/a47;

    invoke-virtual {v2}, Llyiahf/vczjk/a47;->OooO00o()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->longValue()J

    move-result-wide v2

    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->max(JJ)J

    move-result-wide v0

    return-wide v0
.end method

.method public final OooO0OO()J
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/ky3;->OooO00o:Llyiahf/vczjk/ly3;

    iget-object v0, v0, Llyiahf/vczjk/ly3;->OooO00o:Llyiahf/vczjk/jy3;

    iget-object v0, v0, Llyiahf/vczjk/jy3;->OooO00o:Llyiahf/vczjk/ws5;

    invoke-virtual {v0}, Llyiahf/vczjk/ws5;->OooO0o()Ljava/util/List;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ts5;

    invoke-virtual {v0}, Llyiahf/vczjk/ts5;->iterator()Ljava/util/Iterator;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-nez v1, :cond_0

    const/4 v0, 0x0

    goto :goto_1

    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/dy3;

    invoke-static {v1}, Llyiahf/vczjk/ky3;->OooO0O0(Llyiahf/vczjk/dy3;)J

    move-result-wide v1

    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    :cond_1
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/dy3;

    invoke-static {v2}, Llyiahf/vczjk/ky3;->OooO0O0(Llyiahf/vczjk/dy3;)J

    move-result-wide v2

    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/Long;->compareTo(Ljava/lang/Object;)I

    move-result v3

    if-gez v3, :cond_1

    move-object v1, v2

    goto :goto_0

    :cond_2
    move-object v0, v1

    :goto_1
    if-eqz v0, :cond_3

    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    move-result-wide v0

    goto :goto_2

    :cond_3
    const-wide/16 v0, 0x0

    :goto_2
    sget-object v2, Llyiahf/vczjk/vba;->OooO00o:Ljava/util/List;

    const v2, 0xf423f

    int-to-long v2, v2

    add-long/2addr v0, v2

    const v2, 0xf4240

    int-to-long v2, v2

    div-long/2addr v0, v2

    return-wide v0
.end method
