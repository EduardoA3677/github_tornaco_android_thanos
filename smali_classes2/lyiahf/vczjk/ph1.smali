.class public abstract Llyiahf/vczjk/ph1;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooOOO:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

.field public static final synthetic OooOOO0:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;


# instance fields
.field private volatile synthetic _next$volatile:Ljava/lang/Object;

.field private volatile synthetic _prev$volatile:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    const-string v0, "_next$volatile"

    const-class v1, Llyiahf/vczjk/ph1;

    const-class v2, Ljava/lang/Object;

    invoke-static {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ph1;->OooOOO0:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    const-string v0, "_prev$volatile"

    invoke-static {v1, v2, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ph1;->OooOOO:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/zc8;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ph1;->_prev$volatile:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 2

    const/4 v0, 0x0

    sget-object v1, Llyiahf/vczjk/ph1;->OooOOO:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v1, p0, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    return-void
.end method

.method public final OooO0OO()Llyiahf/vczjk/ph1;
    .locals 2

    sget-object v0, Llyiahf/vczjk/ph1;->OooOOO0:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/sb;->OooO0O0:Llyiahf/vczjk/h87;

    if-ne v0, v1, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    check-cast v0, Llyiahf/vczjk/ph1;

    return-object v0
.end method

.method public abstract OooO0Oo()Z
.end method

.method public final OooO0o0()V
    .locals 6

    invoke-virtual {p0}, Llyiahf/vczjk/ph1;->OooO0OO()Llyiahf/vczjk/ph1;

    move-result-object v0

    if-nez v0, :cond_0

    return-void

    :cond_0
    sget-object v0, Llyiahf/vczjk/ph1;->OooOOO:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ph1;

    :goto_0
    if-eqz v1, :cond_1

    invoke-virtual {v1}, Llyiahf/vczjk/ph1;->OooO0Oo()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ph1;

    goto :goto_0

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/ph1;->OooO0OO()Llyiahf/vczjk/ph1;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    :goto_1
    invoke-virtual {v2}, Llyiahf/vczjk/ph1;->OooO0Oo()Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/ph1;->OooO0OO()Llyiahf/vczjk/ph1;

    move-result-object v3

    if-nez v3, :cond_2

    goto :goto_2

    :cond_2
    move-object v2, v3

    goto :goto_1

    :cond_3
    :goto_2
    invoke-virtual {v0, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/ph1;

    if-nez v4, :cond_4

    const/4 v4, 0x0

    goto :goto_3

    :cond_4
    move-object v4, v1

    :cond_5
    :goto_3
    invoke-virtual {v0, v2, v3, v4}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_9

    if-eqz v1, :cond_6

    sget-object v0, Llyiahf/vczjk/ph1;->OooOOO0:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    :cond_6
    invoke-virtual {v2}, Llyiahf/vczjk/ph1;->OooO0Oo()Z

    move-result v0

    if-eqz v0, :cond_7

    invoke-virtual {v2}, Llyiahf/vczjk/ph1;->OooO0OO()Llyiahf/vczjk/ph1;

    move-result-object v0

    if-nez v0, :cond_0

    :cond_7
    if-eqz v1, :cond_8

    invoke-virtual {v1}, Llyiahf/vczjk/ph1;->OooO0Oo()Z

    move-result v0

    if-nez v0, :cond_0

    :cond_8
    return-void

    :cond_9
    invoke-virtual {v0, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    if-eq v5, v3, :cond_5

    goto :goto_2
.end method
