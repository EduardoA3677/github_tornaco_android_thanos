.class public final Llyiahf/vczjk/pj2;
.super Llyiahf/vczjk/h88;
.source "SourceFile"


# virtual methods
.method public final OooO00o()V
    .locals 0

    return-void
.end method

.method public final OooO0Oo(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Llyiahf/vczjk/nc2;
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
