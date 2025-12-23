.class public final Llyiahf/vczjk/lp8;
.super Llyiahf/vczjk/jp8;
.source "SourceFile"


# instance fields
.field public final synthetic OooOo0O:I

.field public final OooOo0o:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/lp8;->OooOo0O:I

    iput-object p1, p0, Llyiahf/vczjk/lp8;->OooOo0o:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OoooOOO(Llyiahf/vczjk/tp8;)V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/lp8;->OooOo0O:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/t76;

    invoke-direct {v0, p1}, Llyiahf/vczjk/t76;-><init>(Llyiahf/vczjk/tp8;)V

    iget-object p1, p0, Llyiahf/vczjk/lp8;->OooOo0o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/o76;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/o76;->OooO0Oo(Llyiahf/vczjk/j86;)V

    return-void

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/kp8;

    invoke-direct {v0, p1}, Llyiahf/vczjk/kp8;-><init>(Llyiahf/vczjk/tp8;)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/tp8;->OooO0O0(Llyiahf/vczjk/nc2;)V

    :try_start_0
    iget-object p1, p0, Llyiahf/vczjk/lp8;->OooOo0o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/up8;

    invoke-interface {p1, v0}, Llyiahf/vczjk/up8;->OooO00o(Llyiahf/vczjk/kp8;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/tc2;->OooOOO0:Llyiahf/vczjk/tc2;

    if-eq v1, v2, :cond_1

    invoke-virtual {v0, v2}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/nc2;

    if-eq v1, v2, :cond_1

    :try_start_1
    iget-object v0, v0, Llyiahf/vczjk/kp8;->downstream:Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0OO(Ljava/lang/Throwable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-eqz v1, :cond_2

    invoke-interface {v1}, Llyiahf/vczjk/nc2;->OooO00o()V

    goto :goto_0

    :catchall_1
    move-exception p1

    if-eqz v1, :cond_0

    invoke-interface {v1}, Llyiahf/vczjk/nc2;->OooO00o()V

    :cond_0
    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    :cond_2
    :goto_0
    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
