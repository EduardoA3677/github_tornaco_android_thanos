.class public final Llyiahf/vczjk/u31;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $flows:[Llyiahf/vczjk/f43;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "[",
            "Llyiahf/vczjk/f43;"
        }
    .end annotation
.end field

.field final synthetic $i:I

.field final synthetic $nonClosed:Ljava/util/concurrent/atomic/AtomicInteger;

.field final synthetic $resultChannel:Llyiahf/vczjk/rs0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/rs0;"
        }
    .end annotation
.end field

.field label:I


# direct methods
.method public constructor <init>([Llyiahf/vczjk/f43;ILjava/util/concurrent/atomic/AtomicInteger;Llyiahf/vczjk/rs0;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/u31;->$flows:[Llyiahf/vczjk/f43;

    iput p2, p0, Llyiahf/vczjk/u31;->$i:I

    iput-object p3, p0, Llyiahf/vczjk/u31;->$nonClosed:Ljava/util/concurrent/atomic/AtomicInteger;

    iput-object p4, p0, Llyiahf/vczjk/u31;->$resultChannel:Llyiahf/vczjk/rs0;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/u31;

    iget-object v1, p0, Llyiahf/vczjk/u31;->$flows:[Llyiahf/vczjk/f43;

    iget v2, p0, Llyiahf/vczjk/u31;->$i:I

    iget-object v3, p0, Llyiahf/vczjk/u31;->$nonClosed:Ljava/util/concurrent/atomic/AtomicInteger;

    iget-object v4, p0, Llyiahf/vczjk/u31;->$resultChannel:Llyiahf/vczjk/rs0;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/u31;-><init>([Llyiahf/vczjk/f43;ILjava/util/concurrent/atomic/AtomicInteger;Llyiahf/vczjk/rs0;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/u31;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/u31;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/u31;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/u31;->label:I

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_1
    iget-object p1, p0, Llyiahf/vczjk/u31;->$flows:[Llyiahf/vczjk/f43;

    iget v1, p0, Llyiahf/vczjk/u31;->$i:I

    aget-object p1, p1, v1

    new-instance v4, Llyiahf/vczjk/t31;

    iget-object v5, p0, Llyiahf/vczjk/u31;->$resultChannel:Llyiahf/vczjk/rs0;

    invoke-direct {v4, v5, v1}, Llyiahf/vczjk/t31;-><init>(Llyiahf/vczjk/rs0;I)V

    iput v3, p0, Llyiahf/vczjk/u31;->label:I

    invoke-interface {p1, v4, p0}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/u31;->$nonClosed:Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    move-result p1

    if-nez p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/u31;->$resultChannel:Llyiahf/vczjk/rs0;

    invoke-interface {p1, v2}, Llyiahf/vczjk/if8;->OooO0o(Ljava/lang/Throwable;)Z

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/u31;->$nonClosed:Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->decrementAndGet()I

    move-result v0

    if-nez v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/u31;->$resultChannel:Llyiahf/vczjk/rs0;

    invoke-interface {v0, v2}, Llyiahf/vczjk/if8;->OooO0o(Ljava/lang/Throwable;)Z

    :cond_4
    throw p1
.end method
