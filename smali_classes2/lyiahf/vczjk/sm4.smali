.class public final Llyiahf/vczjk/sm4;
.super Ljava/util/concurrent/atomic/AtomicReference;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/j86;
.implements Llyiahf/vczjk/nc2;


# static fields
.field private static final serialVersionUID:J = -0x64a12a8486b15cccL


# instance fields
.field final onComplete:Llyiahf/vczjk/o0oo0000;

.field final onError:Llyiahf/vczjk/nl1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/nl1;"
        }
    .end annotation
.end field

.field final onNext:Llyiahf/vczjk/nl1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/nl1;"
        }
    .end annotation
.end field

.field final onSubscribe:Llyiahf/vczjk/nl1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/nl1;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nl1;Llyiahf/vczjk/nl1;Llyiahf/vczjk/o0oo0000;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/v34;->OooO0o0:Llyiahf/vczjk/vp3;

    invoke-direct {p0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/sm4;->onNext:Llyiahf/vczjk/nl1;

    iput-object p2, p0, Llyiahf/vczjk/sm4;->onError:Llyiahf/vczjk/nl1;

    iput-object p3, p0, Llyiahf/vczjk/sm4;->onComplete:Llyiahf/vczjk/o0oo0000;

    iput-object v0, p0, Llyiahf/vczjk/sm4;->onSubscribe:Llyiahf/vczjk/nl1;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 0

    invoke-static {p0}, Llyiahf/vczjk/tc2;->OooO0O0(Ljava/util/concurrent/atomic/AtomicReference;)V

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/nc2;)V
    .locals 1

    invoke-static {p0, p1}, Llyiahf/vczjk/tc2;->OooO0Oo(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    move-result v0

    if-eqz v0, :cond_0

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/sm4;->onSubscribe:Llyiahf/vczjk/nl1;

    invoke-interface {v0, p0}, Llyiahf/vczjk/nl1;->accept(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    invoke-interface {p1}, Llyiahf/vczjk/nc2;->OooO00o()V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/sm4;->OooO0OO(Ljava/lang/Throwable;)V

    :cond_0
    return-void
.end method

.method public final OooO0OO(Ljava/lang/Throwable;)V
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/sm4;->OooO0o0()Z

    move-result v0

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/tc2;->OooOOO0:Llyiahf/vczjk/tc2;

    invoke-virtual {p0, v0}, Ljava/util/concurrent/atomic/AtomicReference;->lazySet(Ljava/lang/Object;)V

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/sm4;->onError:Llyiahf/vczjk/nl1;

    invoke-interface {v0, p1}, Llyiahf/vczjk/nl1;->accept(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    new-instance v1, Llyiahf/vczjk/fg1;

    filled-new-array {p1, v0}, [Ljava/lang/Throwable;

    move-result-object p1

    invoke-direct {v1, p1}, Llyiahf/vczjk/fg1;-><init>([Ljava/lang/Throwable;)V

    invoke-static {v1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    return-void

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    return-void
.end method

.method public final OooO0Oo()V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/sm4;->OooO0o0()Z

    move-result v0

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/tc2;->OooOOO0:Llyiahf/vczjk/tc2;

    invoke-virtual {p0, v0}, Ljava/util/concurrent/atomic/AtomicReference;->lazySet(Ljava/lang/Object;)V

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/sm4;->onComplete:Llyiahf/vczjk/o0oo0000;

    invoke-interface {v0}, Llyiahf/vczjk/o0oo0000;->run()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    invoke-static {v0}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    :cond_0
    return-void
.end method

.method public final OooO0o0()Z
    .locals 2

    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/tc2;->OooOOO0:Llyiahf/vczjk/tc2;

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOO0O(Ljava/lang/Object;)V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/sm4;->OooO0o0()Z

    move-result v0

    if-nez v0, :cond_0

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/sm4;->onNext:Llyiahf/vczjk/nl1;

    invoke-interface {v0, p1}, Llyiahf/vczjk/nl1;->accept(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nc2;

    invoke-interface {v0}, Llyiahf/vczjk/nc2;->OooO00o()V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/sm4;->OooO0OO(Ljava/lang/Throwable;)V

    :cond_0
    return-void
.end method
