.class public final Llyiahf/vczjk/h84;
.super Llyiahf/vczjk/yp0;
.source "SourceFile"


# instance fields
.field public final OooOo0:Llyiahf/vczjk/k84;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/k84;)V
    .locals 1

    const/4 v0, 0x1

    invoke-direct {p0, v0, p1}, Llyiahf/vczjk/yp0;-><init>(ILlyiahf/vczjk/yo1;)V

    iput-object p2, p0, Llyiahf/vczjk/h84;->OooOo0:Llyiahf/vczjk/k84;

    return-void
.end method


# virtual methods
.method public final OooOOo0(Llyiahf/vczjk/k84;)Ljava/lang/Throwable;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/h84;->OooOo0:Llyiahf/vczjk/k84;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/k84;->OooOOO0:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/j84;

    if-eqz v1, :cond_0

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/j84;

    invoke-virtual {v1}, Llyiahf/vczjk/j84;->OooO0O0()Ljava/lang/Throwable;

    move-result-object v1

    if-eqz v1, :cond_0

    return-object v1

    :cond_0
    instance-of v1, v0, Llyiahf/vczjk/j61;

    if-eqz v1, :cond_1

    check-cast v0, Llyiahf/vczjk/j61;

    iget-object p1, v0, Llyiahf/vczjk/j61;->OooO00o:Ljava/lang/Throwable;

    return-object p1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/k84;->OooOoOO()Ljava/util/concurrent/CancellationException;

    move-result-object p1

    return-object p1
.end method

.method public final OooOoOO()Ljava/lang/String;
    .locals 1

    const-string v0, "AwaitContinuation"

    return-object v0
.end method
