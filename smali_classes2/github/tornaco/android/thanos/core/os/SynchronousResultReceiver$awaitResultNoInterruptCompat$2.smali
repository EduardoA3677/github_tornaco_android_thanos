.class final Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;->awaitResultNoInterruptCompat(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Llyiahf/vczjk/eb9;",
        "Llyiahf/vczjk/ze3;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\n\u00a2\u0006\u0004\u0008\u0002\u0010\u0003"
    }
    d2 = {
        "Llyiahf/vczjk/xr1;",
        "Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$Result;",
        "<anonymous>",
        "(Llyiahf/vczjk/xr1;)Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$Result;"
    }
    k = 0x3
    mv = {
        0x2,
        0x1,
        0x0
    }
.end annotation

.annotation runtime Llyiahf/vczjk/q02;
    c = "github.tornaco.android.thanos.core.os.SynchronousResultReceiver$awaitResultNoInterruptCompat$2"
    f = "SynchronousResultReceiverKt.kt"
    l = {
        0xc6
    }
    m = "invokeSuspend"
.end annotation


# instance fields
.field final synthetic $timeoutMillis:J

.field J$0:J

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;


# direct methods
.method public constructor <init>(JLgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;Llyiahf/vczjk/yo1;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(J",
            "Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;",
            "Llyiahf/vczjk/yo1<",
            "-",
            "Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;",
            ">;)V"
        }
    .end annotation

    iput-wide p1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->$timeoutMillis:J

    iput-object p3, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->this$0:Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Object;",
            "Llyiahf/vczjk/yo1<",
            "*>;)",
            "Llyiahf/vczjk/yo1<",
            "Llyiahf/vczjk/z8a;",
            ">;"
        }
    .end annotation

    new-instance v0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;

    iget-wide v1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->$timeoutMillis:J

    iget-object v3, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->this$0:Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;

    invoke-direct {v0, v1, v2, v3, p2}, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;-><init>(JLgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->invoke(Llyiahf/vczjk/xr1;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invoke(Llyiahf/vczjk/xr1;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/xr1;",
            "Llyiahf/vczjk/yo1<",
            "-",
            "Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$Result;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation

    invoke-virtual {p0, p1, p2}, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->label:I

    const-wide/16 v2, 0x0

    const/4 v4, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v4, :cond_0

    iget-wide v5, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->J$0:J

    iget-object v1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/xr1;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    iget-wide v5, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->$timeoutMillis:J

    cmp-long v1, v5, v2

    if-lez v1, :cond_5

    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    move-result-wide v5

    iget-wide v7, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->$timeoutMillis:J

    move-object v1, p1

    :goto_0
    cmp-long p1, v7, v2

    if-lez p1, :cond_4

    invoke-static {v1}, Llyiahf/vczjk/v34;->OoooOoO(Llyiahf/vczjk/xr1;)Z

    move-result p1

    if-eqz p1, :cond_4

    iget-object p1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->this$0:Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;->access$getMFuture$p(Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;)Ljava/util/concurrent/atomic/AtomicReference;

    move-result-object p1

    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$Result;

    if-eqz p1, :cond_2

    return-object p1

    :cond_2
    iput-object v1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->L$0:Ljava/lang/Object;

    iput-wide v5, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->J$0:J

    iput v4, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->label:I

    const-wide/16 v7, 0x64

    invoke-static {v7, v8, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_1
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    move-result-wide v7

    sub-long/2addr v7, v5

    iget-wide v9, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->$timeoutMillis:J

    sub-long v7, v9, v7

    goto :goto_0

    :cond_4
    new-instance p1, Ljava/util/concurrent/TimeoutException;

    iget-wide v0, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterruptCompat$2;->$timeoutMillis:J

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Timeout after "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string v0, " ms"

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/util/concurrent/TimeoutException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_5
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Timeout must be positive"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
