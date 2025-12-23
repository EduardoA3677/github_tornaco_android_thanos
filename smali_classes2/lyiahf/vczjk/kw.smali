.class public final Llyiahf/vczjk/kw;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/content/ServiceConnection;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/kw;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/kw;->OooO0O0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private final OooO00o(Landroid/content/ComponentName;)V
    .locals 0

    return-void
.end method


# virtual methods
.method public final onServiceConnected(Landroid/content/ComponentName;Landroid/os/IBinder;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/kw;->OooO0O0:Ljava/lang/Object;

    iget v1, p0, Llyiahf/vczjk/kw;->OooO00o:I

    packed-switch v1, :pswitch_data_0

    const-string v1, "name"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "service"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget p1, Llyiahf/vczjk/hq5;->OooO0o:I

    sget-object p1, Llyiahf/vczjk/cs3;->OooO0O0:Ljava/lang/String;

    invoke-interface {p2, p1}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    move-result-object p1

    if-eqz p1, :cond_0

    instance-of v1, p1, Llyiahf/vczjk/cs3;

    if-eqz v1, :cond_0

    check-cast p1, Llyiahf/vczjk/cs3;

    goto :goto_0

    :cond_0
    new-instance p1, Llyiahf/vczjk/bs3;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p2, p1, Llyiahf/vczjk/bs3;->OooO0o0:Landroid/os/IBinder;

    :goto_0
    check-cast v0, Llyiahf/vczjk/gq5;

    iput-object p1, v0, Llyiahf/vczjk/gq5;->OooO0oO:Llyiahf/vczjk/cs3;

    :try_start_0
    iget-object p2, v0, Llyiahf/vczjk/gq5;->OooOO0:Llyiahf/vczjk/fq5;

    iget-object v1, v0, Llyiahf/vczjk/gq5;->OooO00o:Ljava/lang/String;

    invoke-interface {p1, p2, v1}, Llyiahf/vczjk/cs3;->OooO00o(Llyiahf/vczjk/as3;Ljava/lang/String;)I

    move-result p1

    iput p1, v0, Llyiahf/vczjk/gq5;->OooO0o:I
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :catch_0
    move-exception p1

    const-string p2, "ROOM"

    const-string v0, "Cannot register multi-instance invalidation callback"

    invoke-static {p2, v0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :goto_1
    return-void

    :pswitch_0
    check-cast v0, Llyiahf/vczjk/lw;

    move-object p1, v0

    check-cast p1, Llyiahf/vczjk/q79;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p2}, Lgithub/tornaco/android/thanos/core/su/ISu$Stub;->asInterface(Landroid/os/IBinder;)Lgithub/tornaco/android/thanos/core/su/ISu;

    move-result-object p2

    iput-object p2, p1, Llyiahf/vczjk/q79;->OooO0o0:Lgithub/tornaco/android/thanos/core/su/ISu;

    iget-object p1, v0, Llyiahf/vczjk/lw;->OooO0OO:Llyiahf/vczjk/ed5;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Llyiahf/vczjk/oOO000o;

    const/4 p2, 0x7

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/oOO000o;-><init>(Ljava/lang/Object;I)V

    new-instance p2, Llyiahf/vczjk/y51;

    const/4 v0, 0x0

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/y51;-><init>(Ljava/lang/Object;I)V

    sget-object p1, Llyiahf/vczjk/s88;->OooO0OO:Llyiahf/vczjk/i88;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/t51;->OooooO0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/g61;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/t51;->OoooOoo()Llyiahf/vczjk/um2;

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onServiceDisconnected(Landroid/content/ComponentName;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/kw;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/kw;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/gq5;

    const/4 v0, 0x0

    iput-object v0, p1, Llyiahf/vczjk/gq5;->OooO0oO:Llyiahf/vczjk/cs3;

    :pswitch_0
    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
