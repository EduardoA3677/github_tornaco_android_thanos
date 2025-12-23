.class public final Llyiahf/vczjk/ay3;
.super Landroid/net/ConnectivityManager$NetworkCallback;
.source "SourceFile"


# static fields
.field public static final synthetic OooO0O0:I


# instance fields
.field public final OooO00o:Llyiahf/vczjk/e06;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/e06;)V
    .locals 0

    invoke-direct {p0}, Landroid/net/ConnectivityManager$NetworkCallback;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ay3;->OooO00o:Llyiahf/vczjk/e06;

    return-void
.end method


# virtual methods
.method public final onCapabilitiesChanged(Landroid/net/Network;Landroid/net/NetworkCapabilities;)V
    .locals 1

    const-string v0, "network"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "networkCapabilities"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/cqa;->OooO00o:Ljava/lang/String;

    const-string v0, "NetworkRequestConstraintController onCapabilitiesChanged callback"

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    sget-object p1, Llyiahf/vczjk/yk1;->OooO00o:Llyiahf/vczjk/yk1;

    iget-object p2, p0, Llyiahf/vczjk/ay3;->OooO00o:Llyiahf/vczjk/e06;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/e06;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public final onLost(Landroid/net/Network;)V
    .locals 2

    const-string v0, "network"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/cqa;->OooO00o:Ljava/lang/String;

    const-string v1, "NetworkRequestConstraintController onLost callback"

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/zk1;

    const/4 v0, 0x7

    invoke-direct {p1, v0}, Llyiahf/vczjk/zk1;-><init>(I)V

    iget-object v0, p0, Llyiahf/vczjk/ay3;->OooO00o:Llyiahf/vczjk/e06;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/e06;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method
