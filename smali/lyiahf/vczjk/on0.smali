.class public final Llyiahf/vczjk/on0;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field label:I


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/yq5;

    check-cast p2, Llyiahf/vczjk/yq5;

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/on0;

    const/4 v1, 0x3

    invoke-direct {v0, v1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/on0;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/on0;->L$1:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/on0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/on0;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/on0;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yq5;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/on0;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/yq5;

    iget-object v1, p0, Llyiahf/vczjk/on0;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/yq5;

    iput-object v1, p0, Llyiahf/vczjk/on0;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/on0;->label:I

    iget-object p1, p1, Llyiahf/vczjk/yq5;->OooO0O0:Llyiahf/vczjk/jn0;

    iget-object p1, p1, Llyiahf/vczjk/jn0;->OooO0Oo:Llyiahf/vczjk/r09;

    const/4 v2, 0x0

    invoke-virtual {p1, v2}, Llyiahf/vczjk/k84;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    return-object v1
.end method
