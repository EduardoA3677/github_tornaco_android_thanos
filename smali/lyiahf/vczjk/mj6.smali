.class public final Llyiahf/vczjk/mj6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/pj6;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/pj6;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/pj6;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mj6;->this$0:Llyiahf/vczjk/pj6;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/mj6;

    iget-object v1, p0, Llyiahf/vczjk/mj6;->this$0:Llyiahf/vczjk/pj6;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/mj6;-><init>(Llyiahf/vczjk/pj6;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/mj6;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/mj6;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/mj6;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/mj6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/mj6;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/mj6;->L$2:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/h43;

    iget-object v3, p0, Llyiahf/vczjk/mj6;->L$1:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/jt5;

    iget-object v4, p0, Llyiahf/vczjk/mj6;->L$0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/qj6;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/mj6;->L$0:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/h43;

    iget-object p1, p0, Llyiahf/vczjk/mj6;->this$0:Llyiahf/vczjk/pj6;

    iget-object v4, p1, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object p1, v4, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object v4, p0, Llyiahf/vczjk/mj6;->L$0:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/mj6;->L$1:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/mj6;->L$2:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/mj6;->label:I

    invoke-virtual {p1, p0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v0, :cond_3

    goto :goto_1

    :cond_3
    move-object v3, p1

    :goto_0
    const/4 p1, 0x0

    :try_start_0
    iget-object v4, v4, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iget-object v4, v4, Llyiahf/vczjk/tj6;->OooOO0:Llyiahf/vczjk/ed5;

    invoke-virtual {v4}, Llyiahf/vczjk/ed5;->Oooo0oo()Llyiahf/vczjk/r25;

    move-result-object v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-interface {v3, p1}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    new-instance v3, Llyiahf/vczjk/ji6;

    invoke-direct {v3, v4, p1}, Llyiahf/vczjk/ji6;-><init>(Llyiahf/vczjk/r25;Llyiahf/vczjk/r25;)V

    iput-object p1, p0, Llyiahf/vczjk/mj6;->L$0:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/mj6;->L$1:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/mj6;->L$2:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/mj6;->label:I

    invoke-interface {v1, v3, p0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_1
    return-object v0

    :cond_4
    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :catchall_0
    move-exception v0

    invoke-interface {v3, p1}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v0
.end method
