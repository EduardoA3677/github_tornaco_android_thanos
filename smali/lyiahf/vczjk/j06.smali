.class public final Llyiahf/vczjk/j06;
.super Landroid/net/ConnectivityManager$NetworkCallback;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/j06;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/j06;->OooO0O0:Ljava/lang/Object;

    invoke-direct {p0}, Landroid/net/ConnectivityManager$NetworkCallback;-><init>()V

    return-void
.end method


# virtual methods
.method public onAvailable(Landroid/net/Network;)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/j06;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0, p1}, Landroid/net/ConnectivityManager$NetworkCallback;->onAvailable(Landroid/net/Network;)V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/j06;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ed5;

    const/4 v1, 0x1

    invoke-static {v0, p1, v1}, Llyiahf/vczjk/ed5;->OooO00o(Llyiahf/vczjk/ed5;Landroid/net/Network;Z)V

    return-void

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public onCapabilitiesChanged(Landroid/net/Network;Landroid/net/NetworkCapabilities;)V
    .locals 4

    iget v0, p0, Llyiahf/vczjk/j06;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    :pswitch_0
    invoke-super {p0, p1, p2}, Landroid/net/ConnectivityManager$NetworkCallback;->onCapabilitiesChanged(Landroid/net/Network;Landroid/net/NetworkCapabilities;)V

    return-void

    :pswitch_1
    iget-object p1, p0, Llyiahf/vczjk/j06;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/qma;

    iget-object p1, p1, Llyiahf/vczjk/qma;->OooO:Llyiahf/vczjk/t87;

    invoke-virtual {p1}, Llyiahf/vczjk/t87;->run()V

    return-void

    :pswitch_2
    iget-object p1, p0, Llyiahf/vczjk/j06;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/pma;

    invoke-virtual {p1}, Llyiahf/vczjk/pma;->OooO0Oo()V

    iget-object p1, p1, Llyiahf/vczjk/pma;->OooOOO0:Llyiahf/vczjk/t87;

    invoke-virtual {p1}, Llyiahf/vczjk/t87;->run()V

    return-void

    :pswitch_3
    const-string v0, "network"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "capabilities"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/l06;->OooO00o:Ljava/lang/String;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Network capabilities changed: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v0, 0x1c

    iget-object v1, p0, Llyiahf/vczjk/j06;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/k06;

    if-lt p1, v0, :cond_0

    const/16 p1, 0xc

    invoke-virtual {p2, p1}, Landroid/net/NetworkCapabilities;->hasCapability(I)Z

    move-result p1

    const/16 v0, 0x10

    invoke-virtual {p2, v0}, Landroid/net/NetworkCapabilities;->hasCapability(I)Z

    move-result v0

    const/16 v2, 0xb

    invoke-virtual {p2, v2}, Landroid/net/NetworkCapabilities;->hasCapability(I)Z

    move-result v2

    xor-int/lit8 v2, v2, 0x1

    const/16 v3, 0x12

    invoke-virtual {p2, v3}, Landroid/net/NetworkCapabilities;->hasCapability(I)Z

    move-result p2

    new-instance v3, Llyiahf/vczjk/i06;

    invoke-direct {v3, p1, v0, v2, p2}, Llyiahf/vczjk/i06;-><init>(ZZZZ)V

    goto :goto_0

    :cond_0
    iget-object p1, v1, Llyiahf/vczjk/k06;->OooO0oO:Landroid/net/ConnectivityManager;

    invoke-static {p1}, Llyiahf/vczjk/l06;->OooO00o(Landroid/net/ConnectivityManager;)Llyiahf/vczjk/i06;

    move-result-object v3

    :goto_0
    invoke-virtual {v1, v3}, Llyiahf/vczjk/ak1;->OooO(Ljava/lang/Object;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_0
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public onLost(Landroid/net/Network;)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/j06;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0, p1}, Landroid/net/ConnectivityManager$NetworkCallback;->onLost(Landroid/net/Network;)V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/j06;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ed5;

    const/4 v1, 0x0

    invoke-static {v0, p1, v1}, Llyiahf/vczjk/ed5;->OooO00o(Llyiahf/vczjk/ed5;Landroid/net/Network;Z)V

    return-void

    :pswitch_1
    const-string v0, "network"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/l06;->OooO00o:Ljava/lang/String;

    const-string v1, "Network connection lost"

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/j06;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/k06;

    iget-object v0, p1, Llyiahf/vczjk/k06;->OooO0oO:Landroid/net/ConnectivityManager;

    invoke-static {v0}, Llyiahf/vczjk/l06;->OooO00o(Landroid/net/ConnectivityManager;)Llyiahf/vczjk/i06;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ak1;->OooO(Ljava/lang/Object;)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
