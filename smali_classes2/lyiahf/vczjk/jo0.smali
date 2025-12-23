.class public final Llyiahf/vczjk/jo0;
.super Ljava/util/concurrent/atomic/AtomicReference;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/d61;
.implements Llyiahf/vczjk/nc2;
.implements Llyiahf/vczjk/nl1;


# static fields
.field private static final serialVersionUID:J = -0x3c8666afd0faa5aaL


# instance fields
.field final onComplete:Llyiahf/vczjk/o0oo0000;

.field final onError:Llyiahf/vczjk/nl1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/nl1;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/o0oo0000;)V
    .locals 0

    invoke-direct {p0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    iput-object p0, p0, Llyiahf/vczjk/jo0;->onError:Llyiahf/vczjk/nl1;

    iput-object p1, p0, Llyiahf/vczjk/jo0;->onComplete:Llyiahf/vczjk/o0oo0000;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 0

    invoke-static {p0}, Llyiahf/vczjk/tc2;->OooO0O0(Ljava/util/concurrent/atomic/AtomicReference;)V

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/nc2;)V
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tc2;->OooO0Oo(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-void
.end method

.method public final OooO0OO(Ljava/lang/Throwable;)V
    .locals 1

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/jo0;->onError:Llyiahf/vczjk/nl1;

    invoke-interface {v0, p1}, Llyiahf/vczjk/nl1;->accept(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    :goto_0
    sget-object p1, Llyiahf/vczjk/tc2;->OooOOO0:Llyiahf/vczjk/tc2;

    invoke-virtual {p0, p1}, Ljava/util/concurrent/atomic/AtomicReference;->lazySet(Ljava/lang/Object;)V

    return-void
.end method

.method public final OooO0Oo()V
    .locals 1

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/jo0;->onComplete:Llyiahf/vczjk/o0oo0000;

    invoke-interface {v0}, Llyiahf/vczjk/o0oo0000;->run()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    invoke-static {v0}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    :goto_0
    sget-object v0, Llyiahf/vczjk/tc2;->OooOOO0:Llyiahf/vczjk/tc2;

    invoke-virtual {p0, v0}, Ljava/util/concurrent/atomic/AtomicReference;->lazySet(Ljava/lang/Object;)V

    return-void
.end method

.method public final accept(Ljava/lang/Object;)V
    .locals 1

    check-cast p1, Ljava/lang/Throwable;

    new-instance v0, Llyiahf/vczjk/ta6;

    invoke-direct {v0, p1}, Llyiahf/vczjk/ta6;-><init>(Ljava/lang/Throwable;)V

    invoke-static {v0}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    return-void
.end method
