.class public final Llyiahf/vczjk/zx3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $callbackRegistered:Llyiahf/vczjk/dl7;

.field final synthetic $connManager:Landroid/net/ConnectivityManager;

.field final synthetic $networkCallback:Llyiahf/vczjk/ay3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dl7;Landroid/net/ConnectivityManager;Llyiahf/vczjk/ay3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zx3;->$callbackRegistered:Llyiahf/vczjk/dl7;

    iput-object p2, p0, Llyiahf/vczjk/zx3;->$connManager:Landroid/net/ConnectivityManager;

    iput-object p3, p0, Llyiahf/vczjk/zx3;->$networkCallback:Llyiahf/vczjk/ay3;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/zx3;->$callbackRegistered:Llyiahf/vczjk/dl7;

    iget-boolean v0, v0, Llyiahf/vczjk/dl7;->element:Z

    if-eqz v0, :cond_0

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/cqa;->OooO00o:Ljava/lang/String;

    const-string v2, "NetworkRequestConstraintController unregister callback"

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/zx3;->$connManager:Landroid/net/ConnectivityManager;

    iget-object v1, p0, Llyiahf/vczjk/zx3;->$networkCallback:Llyiahf/vczjk/ay3;

    invoke-virtual {v0, v1}, Landroid/net/ConnectivityManager;->unregisterNetworkCallback(Landroid/net/ConnectivityManager$NetworkCallback;)V

    :cond_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
