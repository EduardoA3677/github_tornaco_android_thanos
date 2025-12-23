.class public final Llyiahf/vczjk/i71;
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

    check-cast p1, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    check-cast p2, Ljava/lang/String;

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/i71;

    const/4 v1, 0x3

    invoke-direct {v0, v1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/i71;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/i71;->L$1:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/i71;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/i71;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/i71;->L$1:Ljava/lang/Object;

    check-cast v0, Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/i71;->L$0:Ljava/lang/Object;

    check-cast v1, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/i71;->L$0:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    iget-object p1, p0, Llyiahf/vczjk/i71;->L$1:Ljava/lang/Object;

    check-cast p1, Ljava/lang/String;

    if-nez v1, :cond_2

    new-instance p1, Llyiahf/vczjk/p7a;

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-direct {p1, v0}, Llyiahf/vczjk/p7a;-><init>(Ljava/lang/Object;)V

    return-object p1

    :cond_2
    sget-object v3, Llyiahf/vczjk/km8;->OooO00o:Llyiahf/vczjk/km8;

    iput-object v1, p0, Llyiahf/vczjk/i71;->L$0:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/i71;->L$1:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/i71;->label:I

    invoke-virtual {v3, p0}, Llyiahf/vczjk/km8;->OooO0O0(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v0, :cond_3

    return-object v0

    :cond_3
    move-object v0, p1

    move-object p1, v2

    :goto_0
    check-cast p1, Lgithub/tornaco/android/thanos/core/IThanosLite;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getUserId()I

    move-result v2

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v2, v1}, Lgithub/tornaco/android/thanos/core/IThanosLite;->getActivities(ILjava/lang/String;)Ljava/util/List;

    move-result-object p1

    const-string v1, "getActivities(...)"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_4
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_5

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;->getName()Ljava/lang/String;

    move-result-object v3

    const-string v4, "getName(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v4, 0x0

    invoke-static {v3, v0, v4}, Llyiahf/vczjk/z69;->Oooo0OO(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_5
    new-instance p1, Llyiahf/vczjk/p7a;

    invoke-direct {p1, v1}, Llyiahf/vczjk/p7a;-><init>(Ljava/lang/Object;)V

    return-object p1
.end method
