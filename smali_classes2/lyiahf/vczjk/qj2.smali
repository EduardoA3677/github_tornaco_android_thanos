.class public final Llyiahf/vczjk/qj2;
.super Llyiahf/vczjk/i88;
.source "SourceFile"


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/h88;
    .locals 1

    new-instance v0, Llyiahf/vczjk/pj2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    return-object v0
.end method

.method public final OooO0OO(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Llyiahf/vczjk/nc2;
    .locals 0

    new-instance p2, Ljava/lang/Throwable;

    invoke-direct {p2}, Ljava/lang/Throwable;-><init>()V

    const-string p3, "DroppingScheduler throws %s, is system started?"

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-static {p3, p1, p2}, Llyiahf/vczjk/zsa;->Oooo0o(Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    sget-object p1, Llyiahf/vczjk/v34;->OooO0OO:Llyiahf/vczjk/ul2;

    new-instance p2, Llyiahf/vczjk/fy7;

    invoke-direct {p2, p1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    return-object p2
.end method
