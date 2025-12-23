.class public final Llyiahf/vczjk/ze;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/af;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/af;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ze;->this$0:Llyiahf/vczjk/af;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ze;

    iget-object v1, p0, Llyiahf/vczjk/ze;->this$0:Llyiahf/vczjk/af;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/ze;-><init>(Llyiahf/vczjk/af;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/ze;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/r04;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ze;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ze;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ze;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ze;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-eq v1, v2, :cond_0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ze;->L$1:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/af;

    iget-object v0, p0, Llyiahf/vczjk/ze;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/r04;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ze;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/r04;

    iget-object v1, p0, Llyiahf/vczjk/ze;->this$0:Llyiahf/vczjk/af;

    iput-object p1, p0, Llyiahf/vczjk/ze;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/ze;->L$1:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/ze;->label:I

    new-instance v3, Llyiahf/vczjk/yp0;

    invoke-static {p0}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object v4

    invoke-direct {v3, v2, v4}, Llyiahf/vczjk/yp0;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-virtual {v3}, Llyiahf/vczjk/yp0;->OooOOoo()V

    iget-object v2, v1, Llyiahf/vczjk/af;->OooOOO:Llyiahf/vczjk/tl9;

    iget-object v4, v2, Llyiahf/vczjk/tl9;->OooO00o:Llyiahf/vczjk/tx6;

    invoke-interface {v4}, Llyiahf/vczjk/tx6;->OooO0O0()V

    new-instance v5, Llyiahf/vczjk/yl9;

    invoke-direct {v5, v2, v4}, Llyiahf/vczjk/yl9;-><init>(Llyiahf/vczjk/tl9;Llyiahf/vczjk/tx6;)V

    iget-object v2, v2, Llyiahf/vczjk/tl9;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v2, v5}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    new-instance v2, Llyiahf/vczjk/ye;

    invoke-direct {v2, p1, v1}, Llyiahf/vczjk/ye;-><init>(Llyiahf/vczjk/r04;Llyiahf/vczjk/af;)V

    invoke-virtual {v3, v2}, Llyiahf/vczjk/yp0;->OooOo0(Llyiahf/vczjk/oe3;)V

    invoke-virtual {v3}, Llyiahf/vczjk/yp0;->OooOOo()Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1
.end method
