.class public final Llyiahf/vczjk/ll8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $connManager:Landroid/net/ConnectivityManager;

.field final synthetic $networkRequest:Landroid/net/NetworkRequest;

.field final synthetic this$0:Llyiahf/vczjk/ml8;


# direct methods
.method public constructor <init>(Landroid/net/NetworkRequest;Landroid/net/ConnectivityManager;Llyiahf/vczjk/ml8;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ll8;->$networkRequest:Landroid/net/NetworkRequest;

    iput-object p2, p0, Llyiahf/vczjk/ll8;->$connManager:Landroid/net/ConnectivityManager;

    iput-object p3, p0, Llyiahf/vczjk/ll8;->this$0:Llyiahf/vczjk/ml8;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/ml8;->OooO0O0:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/ll8;->$networkRequest:Landroid/net/NetworkRequest;

    iget-object v2, p0, Llyiahf/vczjk/ll8;->$connManager:Landroid/net/ConnectivityManager;

    iget-object v3, p0, Llyiahf/vczjk/ll8;->this$0:Llyiahf/vczjk/ml8;

    monitor-enter v0

    :try_start_0
    sget-object v4, Llyiahf/vczjk/ml8;->OooO0OO:Ljava/util/LinkedHashMap;

    invoke-interface {v4, v1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-interface {v4}, Ljava/util/Map;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v1

    sget-object v4, Llyiahf/vczjk/cqa;->OooO00o:Ljava/lang/String;

    const-string v5, "NetworkRequestConstraintController unregister shared callback"

    invoke-virtual {v1, v4, v5}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v2, v3}, Landroid/net/ConnectivityManager;->unregisterNetworkCallback(Landroid/net/ConnectivityManager$NetworkCallback;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v1

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit v0

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :goto_1
    monitor-exit v0

    throw v1
.end method
