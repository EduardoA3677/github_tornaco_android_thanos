.class public final Llyiahf/vczjk/wh7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ai7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ai7;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ai7;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wh7;->this$0:Llyiahf/vczjk/ai7;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/wh7;

    iget-object v1, p0, Llyiahf/vczjk/wh7;->this$0:Llyiahf/vczjk/ai7;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/wh7;-><init>(Llyiahf/vczjk/ai7;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/wh7;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/wh7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wh7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/wh7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/wh7;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/wh7;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ej0;

    iget-object v3, p0, Llyiahf/vczjk/wh7;->L$0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/xr1;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/wh7;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    iget-object v1, p0, Llyiahf/vczjk/wh7;->this$0:Llyiahf/vczjk/ai7;

    iget-object v1, v1, Llyiahf/vczjk/ai7;->OooO0Oo:Llyiahf/vczjk/jj0;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v3, Llyiahf/vczjk/ej0;

    invoke-direct {v3, v1}, Llyiahf/vczjk/ej0;-><init>(Llyiahf/vczjk/jj0;)V

    move-object v1, v3

    move-object v3, p1

    :goto_0
    iput-object v3, p0, Llyiahf/vczjk/wh7;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/wh7;->L$1:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/wh7;->label:I

    invoke-virtual {v1, p0}, Llyiahf/vczjk/ej0;->OooO0O0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-eqz p1, :cond_3

    invoke-virtual {v1}, Llyiahf/vczjk/ej0;->OooO0OO()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/xn6;

    invoke-virtual {p1}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/b61;

    invoke-virtual {p1}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ze3;

    new-instance v5, Llyiahf/vczjk/tr1;

    iget-object v6, p0, Llyiahf/vczjk/wh7;->this$0:Llyiahf/vczjk/ai7;

    sget-object v7, Llyiahf/vczjk/ai7;->OooOOO:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v7, v6}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->getAndIncrement(Ljava/lang/Object;)I

    move-result v6

    const-string v7, "orbit-intent-"

    invoke-static {v6, v7}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object v6

    invoke-direct {v5, v6}, Llyiahf/vczjk/tr1;-><init>(Ljava/lang/String;)V

    invoke-static {v5, v4}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v5

    iget-object v6, p0, Llyiahf/vczjk/wh7;->this$0:Llyiahf/vczjk/ai7;

    iget-object v6, v6, Llyiahf/vczjk/ai7;->OooO00o:Llyiahf/vczjk/oi7;

    iget-object v6, v6, Llyiahf/vczjk/oi7;->OooO0Oo:Llyiahf/vczjk/qr1;

    invoke-interface {v5, v6}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v5

    new-instance v6, Llyiahf/vczjk/uh7;

    iget-object v7, p0, Llyiahf/vczjk/wh7;->this$0:Llyiahf/vczjk/ai7;

    const/4 v8, 0x0

    invoke-direct {v6, p1, v7, v8}, Llyiahf/vczjk/uh7;-><init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/ai7;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x2

    invoke-static {v3, v5, v8, v6, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p1

    new-instance v5, Llyiahf/vczjk/vh7;

    invoke-direct {v5, v4}, Llyiahf/vczjk/vh7;-><init>(Llyiahf/vczjk/b61;)V

    invoke-virtual {p1, v5}, Llyiahf/vczjk/k84;->OoooO00(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/sc2;

    goto :goto_0

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
