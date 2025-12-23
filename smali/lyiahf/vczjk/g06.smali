.class public final Llyiahf/vczjk/g06;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $constraints:Llyiahf/vczjk/qk1;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/h06;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qk1;Llyiahf/vczjk/h06;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/g06;->$constraints:Llyiahf/vczjk/qk1;

    iput-object p2, p0, Llyiahf/vczjk/g06;->this$0:Llyiahf/vczjk/h06;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/g06;

    iget-object v1, p0, Llyiahf/vczjk/g06;->$constraints:Llyiahf/vczjk/qk1;

    iget-object v2, p0, Llyiahf/vczjk/g06;->this$0:Llyiahf/vczjk/h06;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/g06;-><init>(Llyiahf/vczjk/qk1;Llyiahf/vczjk/h06;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/g06;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/s77;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/g06;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/g06;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/g06;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/g06;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_4

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/g06;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s77;

    iget-object v1, p0, Llyiahf/vczjk/g06;->$constraints:Llyiahf/vczjk/qk1;

    iget-object v1, v1, Llyiahf/vczjk/qk1;->OooO0O0:Llyiahf/vczjk/c06;

    iget-object v1, v1, Llyiahf/vczjk/c06;->OooO00o:Landroid/net/NetworkRequest;

    const/4 v3, 0x0

    if-nez v1, :cond_2

    check-cast p1, Llyiahf/vczjk/r77;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/r77;->OooO0o(Ljava/lang/Throwable;)Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_2
    new-instance v4, Llyiahf/vczjk/f06;

    iget-object v5, p0, Llyiahf/vczjk/g06;->this$0:Llyiahf/vczjk/h06;

    invoke-direct {v4, v5, p1, v3}, Llyiahf/vczjk/f06;-><init>(Llyiahf/vczjk/h06;Llyiahf/vczjk/s77;Llyiahf/vczjk/yo1;)V

    const/4 v5, 0x3

    invoke-static {p1, v3, v3, v4, v5}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v3

    new-instance v4, Llyiahf/vczjk/e06;

    invoke-direct {v4, v3, p1}, Llyiahf/vczjk/e06;-><init>(Llyiahf/vczjk/r09;Llyiahf/vczjk/s77;)V

    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v5, 0x1e

    if-lt v3, v5, :cond_4

    sget-object v3, Llyiahf/vczjk/ml8;->OooO00o:Llyiahf/vczjk/ml8;

    iget-object v5, p0, Llyiahf/vczjk/g06;->this$0:Llyiahf/vczjk/h06;

    iget-object v5, v5, Llyiahf/vczjk/h06;->OooO00o:Landroid/net/ConnectivityManager;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/ml8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v6

    :try_start_0
    sget-object v7, Llyiahf/vczjk/ml8;->OooO0OO:Ljava/util/LinkedHashMap;

    invoke-interface {v7}, Ljava/util/Map;->isEmpty()Z

    move-result v8

    invoke-interface {v7, v1, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    if-eqz v8, :cond_3

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v4

    sget-object v7, Llyiahf/vczjk/cqa;->OooO00o:Ljava/lang/String;

    const-string v8, "NetworkRequestConstraintController register shared callback"

    invoke-virtual {v4, v7, v8}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v5, v3}, Landroid/net/ConnectivityManager;->registerDefaultNetworkCallback(Landroid/net/ConnectivityManager$NetworkCallback;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_3
    :goto_0
    monitor-exit v6

    new-instance v4, Llyiahf/vczjk/ll8;

    invoke-direct {v4, v1, v5, v3}, Llyiahf/vczjk/ll8;-><init>(Landroid/net/NetworkRequest;Landroid/net/ConnectivityManager;Llyiahf/vczjk/ml8;)V

    goto :goto_3

    :goto_1
    monitor-exit v6

    throw p1

    :cond_4
    sget v3, Llyiahf/vczjk/ay3;->OooO0O0:I

    iget-object v3, p0, Llyiahf/vczjk/g06;->this$0:Llyiahf/vczjk/h06;

    iget-object v3, v3, Llyiahf/vczjk/h06;->OooO00o:Landroid/net/ConnectivityManager;

    new-instance v5, Llyiahf/vczjk/ay3;

    invoke-direct {v5, v4}, Llyiahf/vczjk/ay3;-><init>(Llyiahf/vczjk/e06;)V

    new-instance v6, Llyiahf/vczjk/dl7;

    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    :try_start_1
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/cqa;->OooO00o:Ljava/lang/String;

    const-string v9, "NetworkRequestConstraintController register callback"

    invoke-virtual {v7, v8, v9}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v3, v1, v5}, Landroid/net/ConnectivityManager;->registerNetworkCallback(Landroid/net/NetworkRequest;Landroid/net/ConnectivityManager$NetworkCallback;)V

    iput-boolean v2, v6, Llyiahf/vczjk/dl7;->element:Z
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0

    goto :goto_2

    :catch_0
    move-exception v1

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v7

    invoke-virtual {v7}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v7

    const-string v8, "TooManyRequestsException"

    const/4 v9, 0x0

    invoke-static {v7, v8, v9}, Llyiahf/vczjk/g79;->OooOoOO(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v7

    if-eqz v7, :cond_6

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/cqa;->OooO00o:Ljava/lang/String;

    const-string v9, "NetworkRequestConstraintController couldn\'t register callback"

    invoke-virtual {v7, v8, v9, v1}, Llyiahf/vczjk/o55;->OooO0OO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    new-instance v1, Llyiahf/vczjk/zk1;

    const/4 v7, 0x7

    invoke-direct {v1, v7}, Llyiahf/vczjk/zk1;-><init>(I)V

    invoke-virtual {v4, v1}, Llyiahf/vczjk/e06;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :goto_2
    new-instance v4, Llyiahf/vczjk/zx3;

    invoke-direct {v4, v6, v3, v5}, Llyiahf/vczjk/zx3;-><init>(Llyiahf/vczjk/dl7;Landroid/net/ConnectivityManager;Llyiahf/vczjk/ay3;)V

    :goto_3
    new-instance v1, Llyiahf/vczjk/d06;

    invoke-direct {v1, v4}, Llyiahf/vczjk/d06;-><init>(Llyiahf/vczjk/le3;)V

    iput v2, p0, Llyiahf/vczjk/g06;->label:I

    invoke-static {p1, v1, p0}, Llyiahf/vczjk/v34;->OooOOo(Llyiahf/vczjk/s77;Llyiahf/vczjk/le3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    return-object v0

    :cond_5
    :goto_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_6
    throw v1
.end method
