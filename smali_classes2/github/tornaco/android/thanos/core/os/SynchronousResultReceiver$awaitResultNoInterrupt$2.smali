.class final Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;->awaitResultNoInterrupt(Ljava/time/Duration;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
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
    c = "github.tornaco.android.thanos.core.os.SynchronousResultReceiver$awaitResultNoInterrupt$2"
    f = "SynchronousResultReceiverKt.kt"
    l = {
        0xae
    }
    m = "invokeSuspend"
.end annotation


# instance fields
.field final synthetic $timeout:Ljava/time/Duration;

.field J$0:J

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;


# direct methods
.method public constructor <init>(Ljava/time/Duration;Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;Llyiahf/vczjk/yo1;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/time/Duration;",
            "Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;",
            "Llyiahf/vczjk/yo1<",
            "-",
            "Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;",
            ">;)V"
        }
    .end annotation

    iput-object p1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->$timeout:Ljava/time/Duration;

    iput-object p2, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->this$0:Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3
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

    new-instance v0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;

    iget-object v1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->$timeout:Ljava/time/Duration;

    iget-object v2, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->this$0:Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;

    invoke-direct {v0, v1, v2, p2}, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;-><init>(Ljava/time/Duration;Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public bridge synthetic invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->invoke(Llyiahf/vczjk/xr1;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

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

    invoke-virtual {p0, p1, p2}, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    iget-wide v3, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->J$0:J

    iget-object v1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/xr1;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p1, v1

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    iget-object v1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->$timeout:Ljava/time/Duration;

    const-string v3, "Null timeout is not allowed"

    invoke-static {v1, v3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtimeNanos()J

    move-result-wide v3

    iget-object v1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->$timeout:Ljava/time/Duration;

    :goto_0
    invoke-static {v1}, Llyiahf/vczjk/xb8;->OooOoOO(Ljava/time/Duration;)Z

    move-result v1

    if-nez v1, :cond_4

    invoke-static {p1}, Llyiahf/vczjk/v34;->OoooOoO(Llyiahf/vczjk/xr1;)Z

    move-result v1

    if-eqz v1, :cond_4

    iget-object v1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->this$0:Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;

    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;->access$getMFuture$p(Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;)Ljava/util/concurrent/atomic/AtomicReference;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$Result;

    if-eqz v1, :cond_2

    return-object v1

    :cond_2
    iput-object p1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->L$0:Ljava/lang/Object;

    iput-wide v3, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->J$0:J

    iput v2, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->label:I

    const-wide/16 v5, 0x64

    invoke-static {v5, v6, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_1
    iget-object v1, p0, Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver$awaitResultNoInterrupt$2;->$timeout:Ljava/time/Duration;

    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtimeNanos()J

    move-result-wide v5

    sub-long/2addr v5, v3

    invoke-static {v5, v6}, Llyiahf/vczjk/xb8;->OooOOO0(J)Ljava/time/Duration;

    move-result-object v5

    invoke-static {v1, v5}, Llyiahf/vczjk/xb8;->OooOOO(Ljava/time/Duration;Ljava/time/Duration;)Ljava/time/Duration;

    move-result-object v1

    const-string v5, "minus(...)"

    invoke-static {v1, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_0

    :cond_4
    new-instance p1, Ljava/util/concurrent/TimeoutException;

    invoke-direct {p1}, Ljava/util/concurrent/TimeoutException;-><init>()V

    throw p1
.end method
