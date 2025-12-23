.class public final Llyiahf/vczjk/h06;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/pj1;


# instance fields
.field public final OooO00o:Landroid/net/ConnectivityManager;


# direct methods
.method public constructor <init>(Landroid/net/ConnectivityManager;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/h06;->OooO00o:Landroid/net/ConnectivityManager;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ara;)Z
    .locals 1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/h06;->OooO0O0(Llyiahf/vczjk/ara;)Z

    move-result p1

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "isCurrentlyConstrained() must never be called onNetworkRequestConstraintController. isCurrentlyConstrained() is called only on older platforms where NetworkRequest isn\'t supported"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/ara;)Z
    .locals 1

    const-string v0, "workSpec"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/ara;->OooOO0:Llyiahf/vczjk/qk1;

    iget-object p1, p1, Llyiahf/vczjk/qk1;->OooO0O0:Llyiahf/vczjk/c06;

    iget-object p1, p1, Llyiahf/vczjk/c06;->OooO00o:Landroid/net/NetworkRequest;

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/qk1;)Llyiahf/vczjk/lo0;
    .locals 2

    const-string v0, "constraints"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/g06;

    const/4 v1, 0x0

    invoke-direct {v0, p1, p0, v1}, Llyiahf/vczjk/g06;-><init>(Llyiahf/vczjk/qk1;Llyiahf/vczjk/h06;Llyiahf/vczjk/yo1;)V

    invoke-static {v0}, Llyiahf/vczjk/rs;->OooOO0O(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/lo0;

    move-result-object p1

    return-object p1
.end method
