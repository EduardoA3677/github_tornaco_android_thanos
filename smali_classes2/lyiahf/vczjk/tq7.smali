.class public final Llyiahf/vczjk/tq7;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Landroid/content/Context;

.field public final OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/tq7;->OooO00o:Landroid/content/Context;

    new-instance p1, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v0, "Repo"

    invoke-direct {p1, v0}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/tq7;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/String;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 5

    instance-of v0, p2, Llyiahf/vczjk/qq7;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/qq7;

    iget v1, v0, Llyiahf/vczjk/qq7;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/qq7;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/qq7;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/qq7;-><init>(Llyiahf/vczjk/tq7;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/qq7;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/qq7;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/qq7;->L$0:Ljava/lang/Object;

    check-cast p1, Ljava/lang/String;

    :try_start_0
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception p1

    goto/16 :goto_6

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :goto_1
    :try_start_1
    sget-object p2, Llyiahf/vczjk/uq7;->OooO0O0:Lgithub/tornaco/android/thanos/support/subscribe/code/CodeRemaining;

    if-nez p2, :cond_8

    new-instance p2, Lgithub/tornaco/android/thanos/support/subscribe/code/CodeRemaining;

    const-wide/32 v0, 0xf423f

    const-wide v2, 0xd693a400L

    invoke-direct {p2, v0, v1, v2, v3}, Lgithub/tornaco/android/thanos/support/subscribe/code/CodeRemaining;-><init>(JJ)V

    sput-object p2, Llyiahf/vczjk/uq7;->OooO0O0:Lgithub/tornaco/android/thanos/support/subscribe/code/CodeRemaining;

    const-string v0, "VALID_PREMIUM_KEY"

    invoke-static {p1, v0}, Ltornaco/android/sec/net/S;->c(Ljava/lang/String;Ljava/lang/String;)V

    :cond_8
    :goto_5
    new-instance p1, Llyiahf/vczjk/us7;

    invoke-direct {p1, p2}, Llyiahf/vczjk/us7;-><init>(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_7

    :goto_6
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    :goto_7
    invoke-static {p1}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object p2

    if-nez p2, :cond_9

    goto :goto_8

    :cond_9
    iget-object p1, p0, Llyiahf/vczjk/tq7;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    const-string v0, "getCodeRemaining"

    invoke-virtual {p1, p2, v0}, Lgithub/tornaco/android/thanos/core/Logger;->e(Ljava/lang/Throwable;Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/ss7;

    invoke-direct {p1, p2}, Llyiahf/vczjk/ss7;-><init>(Ljava/lang/Throwable;)V

    :goto_8
    return-object p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 5

    instance-of v0, p1, Llyiahf/vczjk/rq7;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/rq7;

    iget v1, v0, Llyiahf/vczjk/rq7;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/rq7;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/rq7;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/rq7;-><init>(Llyiahf/vczjk/tq7;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/rq7;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/rq7;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_1
    sget-object p1, Llyiahf/vczjk/uq7;->OooO00o:Lgithub/tornaco/android/thanos/support/subscribe/code/SubscriptionConfig2;

    if-nez p1, :cond_4

    iget-object p1, p0, Llyiahf/vczjk/tq7;->OooO00o:Landroid/content/Context;

    const-string v2, "context"

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/pb7;

    const/4 v2, 0x1

    invoke-direct {p1, v2}, Llyiahf/vczjk/pb7;-><init>(I)V

    const-string v2, "http://thanox.emui.tech/api/"

    invoke-virtual {p1, v2}, Llyiahf/vczjk/pb7;->OooO(Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/pk3;->OooO0OO()Llyiahf/vczjk/pk3;

    move-result-object v2

    invoke-virtual {p1, v2}, Llyiahf/vczjk/pb7;->OooO0O0(Llyiahf/vczjk/pk3;)V

    new-instance v2, Llyiahf/vczjk/d96;

    invoke-direct {v2}, Llyiahf/vczjk/d96;-><init>()V

    new-instance v4, Llyiahf/vczjk/e96;

    invoke-direct {v4, v2}, Llyiahf/vczjk/e96;-><init>(Llyiahf/vczjk/d96;)V

    iput-object v4, p1, Llyiahf/vczjk/pb7;->OooOOO:Ljava/lang/Object;

    invoke-virtual {p1}, Llyiahf/vczjk/pb7;->OooOO0()Llyiahf/vczjk/mi;

    move-result-object p1

    const-class v2, Llyiahf/vczjk/v01;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/mi;->OooO0oO(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p1

    const-string v2, "create(...)"

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/v01;

    iput v3, v0, Llyiahf/vczjk/rq7;->label:I

    invoke-interface {p1, v0}, Llyiahf/vczjk/v01;->OooO0O0(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_3

    return-object v1

    :cond_3
    :goto_1
    check-cast p1, Lgithub/tornaco/android/thanos/support/subscribe/CommonApiResWrapper;

    sget-object v0, Llyiahf/vczjk/uq7;->OooO0OO:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nk3;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/support/subscribe/CommonApiResWrapper;->getMsg()Ljava/lang/String;

    move-result-object p1

    const-class v1, Lgithub/tornaco/android/thanos/support/subscribe/code/SubscriptionConfig2;

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/nk3;->OooO0O0(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    const-string v0, "fromJson(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Lgithub/tornaco/android/thanos/support/subscribe/code/SubscriptionConfig2;

    sput-object p1, Llyiahf/vczjk/uq7;->OooO00o:Lgithub/tornaco/android/thanos/support/subscribe/code/SubscriptionConfig2;

    :cond_4
    new-instance v0, Llyiahf/vczjk/us7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/us7;-><init>(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_3

    :goto_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    :goto_3
    invoke-static {v0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object p1

    if-nez p1, :cond_5

    goto :goto_4

    :cond_5
    iget-object v0, p0, Llyiahf/vczjk/tq7;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    const-string v1, "getSubscriptionConfig2"

    invoke-virtual {v0, p1, v1}, Lgithub/tornaco/android/thanos/core/Logger;->e(Ljava/lang/Throwable;Ljava/lang/Object;)V

    new-instance v0, Llyiahf/vczjk/ss7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/ss7;-><init>(Ljava/lang/Throwable;)V

    :goto_4
    return-object v0
.end method
