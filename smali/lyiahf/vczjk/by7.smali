.class public final Llyiahf/vczjk/by7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $block:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/by7;->$block:Llyiahf/vczjk/ze3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/by7;

    iget-object v1, p0, Llyiahf/vczjk/by7;->$block:Llyiahf/vczjk/ze3;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/by7;-><init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/by7;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/by7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/by7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/by7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/by7;->label:I

    if-nez v0, :cond_3

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/by7;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    invoke-interface {p1}, Llyiahf/vczjk/xr1;->OoooOO0()Llyiahf/vczjk/or1;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/vp3;->OooOOOO:Llyiahf/vczjk/vp3;

    invoke-interface {p1, v0}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast p1, Llyiahf/vczjk/ap1;

    invoke-static {}, Llyiahf/vczjk/l4a;->OooO0O0()Llyiahf/vczjk/v51;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/ii3;->OooOOO0:Llyiahf/vczjk/ii3;

    sget-object v2, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v3, Llyiahf/vczjk/zx7;

    iget-object v4, p0, Llyiahf/vczjk/by7;->$block:Llyiahf/vczjk/ze3;

    const/4 v5, 0x0

    invoke-direct {v3, v0, v4, v5}, Llyiahf/vczjk/zx7;-><init>(Llyiahf/vczjk/u51;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, p1, v2, v3}, Llyiahf/vczjk/os9;->Oooo0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    :catch_0
    invoke-virtual {v0}, Llyiahf/vczjk/k84;->Oooo0o0()Z

    move-result v1

    if-nez v1, :cond_0

    :try_start_0
    new-instance v1, Llyiahf/vczjk/ay7;

    invoke-direct {v1, v0, v5}, Llyiahf/vczjk/ay7;-><init>(Llyiahf/vczjk/u51;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v1}, Llyiahf/vczjk/os9;->Oooo(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/k84;->OooOOO0:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {p1, v0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    instance-of v0, p1, Llyiahf/vczjk/ow3;

    if-nez v0, :cond_2

    instance-of v0, p1, Llyiahf/vczjk/j61;

    if-nez v0, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/cp7;->OoooO0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_1
    check-cast p1, Llyiahf/vczjk/j61;

    iget-object p1, p1, Llyiahf/vczjk/j61;->OooO00o:Ljava/lang/Throwable;

    throw p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "This job has not completed yet"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
