.class public final Llyiahf/vczjk/sra;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/wra;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wra;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sra;->this$0:Llyiahf/vczjk/wra;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/sra;

    iget-object v0, p0, Llyiahf/vczjk/sra;->this$0:Llyiahf/vczjk/wra;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/sra;-><init>(Llyiahf/vczjk/wra;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/sra;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/sra;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/sra;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/sra;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Llyiahf/vczjk/lra; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :catch_0
    move-exception p1

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_1
    iget-object p1, p0, Llyiahf/vczjk/sra;->this$0:Llyiahf/vczjk/wra;

    iget-object v1, p1, Llyiahf/vczjk/wra;->OooOOO0:Llyiahf/vczjk/x74;

    new-instance v3, Llyiahf/vczjk/rra;

    const/4 v4, 0x0

    invoke-direct {v3, p1, v4}, Llyiahf/vczjk/rra;-><init>(Llyiahf/vczjk/wra;Llyiahf/vczjk/yo1;)V

    iput v2, p0, Llyiahf/vczjk/sra;->label:I

    invoke-static {v1, v3, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    check-cast p1, Llyiahf/vczjk/qra;
    :try_end_1
    .catch Llyiahf/vczjk/lra; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_3

    :goto_1
    sget-object v0, Llyiahf/vczjk/yra;->OooO00o:Ljava/lang/String;

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v1

    const-string v2, "Unexpected error in WorkerWrapper"

    invoke-virtual {v1, v0, v2, p1}, Llyiahf/vczjk/o55;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    new-instance p1, Llyiahf/vczjk/nra;

    invoke-direct {p1}, Llyiahf/vczjk/nra;-><init>()V

    goto :goto_3

    :catch_1
    new-instance p1, Llyiahf/vczjk/nra;

    invoke-direct {p1}, Llyiahf/vczjk/nra;-><init>()V

    goto :goto_3

    :goto_2
    new-instance v0, Llyiahf/vczjk/pra;

    invoke-virtual {p1}, Llyiahf/vczjk/lra;->OooO00o()I

    move-result p1

    invoke-direct {v0, p1}, Llyiahf/vczjk/pra;-><init>(I)V

    move-object p1, v0

    :goto_3
    iget-object v0, p0, Llyiahf/vczjk/sra;->this$0:Llyiahf/vczjk/wra;

    iget-object v1, v0, Llyiahf/vczjk/wra;->OooO0oo:Landroidx/work/impl/WorkDatabase;

    new-instance v2, Llyiahf/vczjk/t75;

    const/4 v3, 0x1

    invoke-direct {v2, v3, p1, v0}, Llyiahf/vczjk/t75;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/ru7;->runInTransaction(Ljava/util/concurrent/Callable;)Ljava/lang/Object;

    move-result-object p1

    const-string v0, "workDatabase.runInTransa\u2026          }\n            )"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1
.end method
