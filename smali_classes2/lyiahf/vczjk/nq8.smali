.class public final Llyiahf/vczjk/nq8;
.super Ljava/util/concurrent/atomic/AtomicReference;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/tp8;
.implements Ljava/lang/Runnable;
.implements Llyiahf/vczjk/nc2;


# static fields
.field private static final serialVersionUID:J = 0x85380018ff2a7eL


# instance fields
.field final downstream:Llyiahf/vczjk/tp8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/tp8;"
        }
    .end annotation
.end field

.field final fallback:Llyiahf/vczjk/mq8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/mq8;"
        }
    .end annotation
.end field

.field other:Llyiahf/vczjk/jq8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/jq8;"
        }
    .end annotation
.end field

.field final task:Ljava/util/concurrent/atomic/AtomicReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/atomic/AtomicReference<",
            "Llyiahf/vczjk/nc2;",
            ">;"
        }
    .end annotation
.end field

.field final timeout:J

.field final unit:Ljava/util/concurrent/TimeUnit;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tp8;Llyiahf/vczjk/oOO0O00O;J)V
    .locals 1

    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-direct {p0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/nq8;->downstream:Llyiahf/vczjk/tp8;

    iput-object p2, p0, Llyiahf/vczjk/nq8;->other:Llyiahf/vczjk/jq8;

    iput-wide p3, p0, Llyiahf/vczjk/nq8;->timeout:J

    iput-object v0, p0, Llyiahf/vczjk/nq8;->unit:Ljava/util/concurrent/TimeUnit;

    new-instance p3, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-direct {p3}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    iput-object p3, p0, Llyiahf/vczjk/nq8;->task:Ljava/util/concurrent/atomic/AtomicReference;

    if-eqz p2, :cond_0

    new-instance p2, Llyiahf/vczjk/mq8;

    invoke-direct {p2, p1}, Llyiahf/vczjk/mq8;-><init>(Llyiahf/vczjk/tp8;)V

    iput-object p2, p0, Llyiahf/vczjk/nq8;->fallback:Llyiahf/vczjk/mq8;

    return-void

    :cond_0
    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/nq8;->fallback:Llyiahf/vczjk/mq8;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    invoke-static {p0}, Llyiahf/vczjk/tc2;->OooO0O0(Ljava/util/concurrent/atomic/AtomicReference;)V

    iget-object v0, p0, Llyiahf/vczjk/nq8;->task:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-static {v0}, Llyiahf/vczjk/tc2;->OooO0O0(Ljava/util/concurrent/atomic/AtomicReference;)V

    iget-object v0, p0, Llyiahf/vczjk/nq8;->fallback:Llyiahf/vczjk/mq8;

    if-eqz v0, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/tc2;->OooO0O0(Ljava/util/concurrent/atomic/AtomicReference;)V

    :cond_0
    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/nc2;)V
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tc2;->OooO0Oo(Ljava/util/concurrent/atomic/AtomicReference;Llyiahf/vczjk/nc2;)Z

    return-void
.end method

.method public final OooO0OO(Ljava/lang/Throwable;)V
    .locals 2

    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nc2;

    sget-object v1, Llyiahf/vczjk/tc2;->OooOOO0:Llyiahf/vczjk/tc2;

    if-eq v0, v1, :cond_0

    invoke-virtual {p0, v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/nq8;->task:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-static {v0}, Llyiahf/vczjk/tc2;->OooO0O0(Ljava/util/concurrent/atomic/AtomicReference;)V

    iget-object v0, p0, Llyiahf/vczjk/nq8;->downstream:Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0OO(Ljava/lang/Throwable;)V

    return-void

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    return-void
.end method

.method public final OooO0o0(Ljava/lang/Object;)V
    .locals 2

    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nc2;

    sget-object v1, Llyiahf/vczjk/tc2;->OooOOO0:Llyiahf/vczjk/tc2;

    if-eq v0, v1, :cond_0

    invoke-virtual {p0, v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/nq8;->task:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-static {v0}, Llyiahf/vczjk/tc2;->OooO0O0(Ljava/util/concurrent/atomic/AtomicReference;)V

    iget-object v0, p0, Llyiahf/vczjk/nq8;->downstream:Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0o0(Ljava/lang/Object;)V

    :cond_0
    return-void
.end method

.method public final run()V
    .locals 7

    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nc2;

    sget-object v1, Llyiahf/vczjk/tc2;->OooOOO0:Llyiahf/vczjk/tc2;

    if-eq v0, v1, :cond_2

    invoke-virtual {p0, v0, v1}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/nc2;->OooO00o()V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/nq8;->other:Llyiahf/vczjk/jq8;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/nq8;->downstream:Llyiahf/vczjk/tp8;

    new-instance v1, Ljava/util/concurrent/TimeoutException;

    iget-wide v2, p0, Llyiahf/vczjk/nq8;->timeout:J

    iget-object v4, p0, Llyiahf/vczjk/nq8;->unit:Ljava/util/concurrent/TimeUnit;

    sget v5, Llyiahf/vczjk/ur2;->OooO00o:I

    new-instance v5, Ljava/lang/StringBuilder;

    const-string v6, "The source did not signal an event for "

    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string v2, " "

    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, " and has been terminated."

    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2}, Ljava/util/concurrent/TimeoutException;-><init>(Ljava/lang/String;)V

    invoke-interface {v0, v1}, Llyiahf/vczjk/tp8;->OooO0OO(Ljava/lang/Throwable;)V

    return-void

    :cond_1
    const/4 v1, 0x0

    iput-object v1, p0, Llyiahf/vczjk/nq8;->other:Llyiahf/vczjk/jq8;

    iget-object v1, p0, Llyiahf/vczjk/nq8;->fallback:Llyiahf/vczjk/mq8;

    invoke-interface {v0, v1}, Llyiahf/vczjk/jq8;->OooO0Oo(Llyiahf/vczjk/tp8;)V

    :cond_2
    return-void
.end method
