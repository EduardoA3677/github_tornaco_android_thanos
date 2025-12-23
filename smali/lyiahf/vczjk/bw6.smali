.class public final Llyiahf/vczjk/bw6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/gw6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gw6;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bw6;->this$0:Llyiahf/vczjk/gw6;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Ljava/lang/String;

    check-cast p2, Llyiahf/vczjk/mw;

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/bw6;

    iget-object v1, p0, Llyiahf/vczjk/bw6;->this$0:Llyiahf/vczjk/gw6;

    invoke-direct {v0, v1, p3}, Llyiahf/vczjk/bw6;-><init>(Llyiahf/vczjk/gw6;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/bw6;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/bw6;->L$1:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/bw6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/bw6;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/bw6;->L$1:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/mw;

    iget-object v1, p0, Llyiahf/vczjk/bw6;->L$0:Ljava/lang/Object;

    check-cast v1, Ljava/lang/String;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/bw6;->L$0:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Ljava/lang/String;

    iget-object p1, p0, Llyiahf/vczjk/bw6;->L$1:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/mw;

    sget-object v3, Llyiahf/vczjk/km8;->OooO00o:Llyiahf/vczjk/km8;

    iput-object v1, p0, Llyiahf/vczjk/bw6;->L$0:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/bw6;->L$1:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/bw6;->label:I

    invoke-virtual {v3, p0}, Llyiahf/vczjk/km8;->OooO0O0(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v0, :cond_2

    return-object v0

    :cond_2
    move-object v0, p1

    move-object p1, v3

    :goto_0
    check-cast p1, Lgithub/tornaco/android/thanos/core/IThanosLite;

    invoke-interface {p1}, Lgithub/tornaco/android/thanos/core/IThanosLite;->getSFUnSelectedPkgs()Ljava/util/List;

    move-result-object v3

    iget-object v4, p0, Llyiahf/vczjk/bw6;->this$0:Llyiahf/vczjk/gw6;

    iget-object v4, v4, Llyiahf/vczjk/gw6;->OooO0o:Lgithub/tornaco/android/thanos/core/Logger;

    invoke-static {v3}, Ljava/util/Objects;->toString(Ljava/lang/Object;)Ljava/lang/String;

    sget-object v4, Llyiahf/vczjk/pw;->OooO0O0:Llyiahf/vczjk/mw;

    invoke-static {v0, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_3

    new-instance v0, Ljava/lang/Integer;

    invoke-direct {v0, v2}, Ljava/lang/Integer;-><init>(I)V

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    goto :goto_1

    :cond_3
    new-instance v0, Ljava/lang/Integer;

    const/4 v2, 0x2

    invoke-direct {v0, v2}, Ljava/lang/Integer;-><init>(I)V

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    :goto_1
    iget-object v2, p0, Llyiahf/vczjk/bw6;->this$0:Llyiahf/vczjk/gw6;

    iget-object v2, v2, Llyiahf/vczjk/gw6;->OooO0o:Lgithub/tornaco/android/thanos/core/Logger;

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_4
    :goto_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_5

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getUserId()I

    move-result v4

    invoke-interface {p1, v5, v4}, Lgithub/tornaco/android/thanos/core/IThanosLite;->getAppInfoForUser(Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v4

    if-eqz v4, :cond_4

    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_5
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_6
    :goto_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_8

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getFlags()I

    move-result v5

    new-instance v6, Ljava/lang/Integer;

    invoke-direct {v6, v5}, Ljava/lang/Integer;-><init>(I)V

    invoke-interface {v0, v6}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_6

    invoke-static {v1}, Llyiahf/vczjk/z69;->OoooOO0(Ljava/lang/CharSequence;)Z

    move-result v5

    if-nez v5, :cond_7

    invoke-static {v4, v1}, Llyiahf/vczjk/t51;->OooOoO(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;)Z

    move-result v4

    if-eqz v4, :cond_6

    :cond_7
    invoke-virtual {p1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_8
    new-instance v0, Llyiahf/vczjk/jm4;

    const/16 v1, 0xc

    invoke-direct {v0, v1}, Llyiahf/vczjk/jm4;-><init>(I)V

    new-instance v1, Llyiahf/vczjk/ib;

    const/4 v2, 0x6

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/ib;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1, v1}, Llyiahf/vczjk/d21;->o0000O00(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method
