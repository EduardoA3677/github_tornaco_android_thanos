.class public final Llyiahf/vczjk/u95;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/w95;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/w95;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/u95;->this$0:Llyiahf/vczjk/w95;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/u95;

    iget-object v0, p0, Llyiahf/vczjk/u95;->this$0:Llyiahf/vczjk/w95;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/u95;-><init>(Llyiahf/vczjk/w95;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/u95;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/u95;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/u95;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/u95;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :cond_3
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/u95;->this$0:Llyiahf/vczjk/w95;

    iget-object p1, p1, Llyiahf/vczjk/w95;->Oooo0OO:Llyiahf/vczjk/jj0;

    if-eqz p1, :cond_4

    iput v3, p0, Llyiahf/vczjk/u95;->label:I

    invoke-virtual {p1, p0}, Llyiahf/vczjk/jj0;->OooO00o(Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    goto :goto_2

    :cond_4
    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/u95;->this$0:Llyiahf/vczjk/w95;

    iget-object p1, p1, Llyiahf/vczjk/w95;->Oooo000:Llyiahf/vczjk/hx6;

    if-eqz p1, :cond_3

    sget-object p1, Llyiahf/vczjk/k65;->OooOOOO:Llyiahf/vczjk/k65;

    iput v2, p0, Llyiahf/vczjk/u95;->label:I

    invoke-interface {p0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/vc6;->OooOoo0(Llyiahf/vczjk/or1;)Llyiahf/vczjk/xn5;

    move-result-object v1

    new-instance v4, Llyiahf/vczjk/yn5;

    invoke-direct {v4, p1}, Llyiahf/vczjk/yn5;-><init>(Llyiahf/vczjk/oe3;)V

    invoke-interface {v1, p0, v4}, Llyiahf/vczjk/xn5;->o0ooOO0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    :goto_2
    return-object v0

    :cond_5
    :goto_3
    iget-object p1, p0, Llyiahf/vczjk/u95;->this$0:Llyiahf/vczjk/w95;

    iget-object p1, p1, Llyiahf/vczjk/w95;->Oooo000:Llyiahf/vczjk/hx6;

    if-eqz p1, :cond_3

    check-cast p1, Llyiahf/vczjk/jx6;

    invoke-virtual {p1}, Llyiahf/vczjk/jx6;->OooO0Oo()V

    goto :goto_0
.end method
