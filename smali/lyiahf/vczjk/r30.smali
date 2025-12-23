.class public final Llyiahf/vczjk/r30;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/gf3;


# instance fields
.field private synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field synthetic L$2:Ljava/lang/Object;

.field synthetic L$3:Ljava/lang/Object;

.field synthetic L$4:Ljava/lang/Object;

.field synthetic L$5:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;)V
    .locals 1

    const/4 v0, 0x7

    invoke-direct {p0, v0, p1}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/io/Serializable;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p2, Ljava/util/List;

    check-cast p3, Ljava/util/List;

    check-cast p4, Ljava/lang/String;

    check-cast p5, Llyiahf/vczjk/mw;

    check-cast p6, Llyiahf/vczjk/mw;

    check-cast p7, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/r30;

    invoke-direct {v0, p7}, Llyiahf/vczjk/r30;-><init>(Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/r30;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/r30;->L$1:Ljava/lang/Object;

    iput-object p3, v0, Llyiahf/vczjk/r30;->L$2:Ljava/lang/Object;

    iput-object p4, v0, Llyiahf/vczjk/r30;->L$3:Ljava/lang/Object;

    iput-object p5, v0, Llyiahf/vczjk/r30;->L$4:Ljava/lang/Object;

    iput-object p6, v0, Llyiahf/vczjk/r30;->L$5:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r30;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/r30;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_5

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/r30;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/h43;

    iget-object v1, p0, Llyiahf/vczjk/r30;->L$1:Ljava/lang/Object;

    check-cast v1, Ljava/util/List;

    iget-object v3, p0, Llyiahf/vczjk/r30;->L$2:Ljava/lang/Object;

    check-cast v3, Ljava/util/List;

    iget-object v4, p0, Llyiahf/vczjk/r30;->L$3:Ljava/lang/Object;

    check-cast v4, Ljava/lang/String;

    iget-object v5, p0, Llyiahf/vczjk/r30;->L$4:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/mw;

    iget-object v6, p0, Llyiahf/vczjk/r30;->L$5:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/mw;

    sget-object v7, Llyiahf/vczjk/pw;->OooO0O0:Llyiahf/vczjk/mw;

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2

    new-instance v5, Ljava/lang/Integer;

    invoke-direct {v5, v2}, Ljava/lang/Integer;-><init>(I)V

    invoke-static {v5}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v5

    goto :goto_0

    :cond_2
    new-instance v5, Ljava/lang/Integer;

    const/4 v7, 0x2

    invoke-direct {v5, v7}, Ljava/lang/Integer;-><init>(I)V

    invoke-static {v5}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v5

    :goto_0
    new-instance v7, Ljava/util/ArrayList;

    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_3
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_4

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    move-object v9, v8

    check-cast v9, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v9}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getFlags()I

    move-result v9

    new-instance v10, Ljava/lang/Integer;

    invoke-direct {v10, v9}, Ljava/lang/Integer;-><init>(I)V

    invoke-interface {v5, v10}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_3

    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_4
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :cond_5
    :goto_2
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_8

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    move-object v8, v7

    check-cast v8, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-interface {v3, v8}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v8

    sget-object v9, Llyiahf/vczjk/j40;->OooO0OO:Llyiahf/vczjk/mw;

    invoke-static {v6, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-nez v9, :cond_7

    sget-object v9, Llyiahf/vczjk/j40;->OooO00o:Llyiahf/vczjk/mw;

    invoke-static {v6, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_6

    if-nez v8, :cond_7

    :cond_6
    sget-object v9, Llyiahf/vczjk/j40;->OooO0O0:Llyiahf/vczjk/mw;

    invoke-static {v6, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_5

    if-nez v8, :cond_5

    :cond_7
    invoke-virtual {v1, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_8
    new-instance v5, Llyiahf/vczjk/v1;

    const/16 v6, 0x10

    invoke-direct {v5, v6}, Llyiahf/vczjk/v1;-><init>(I)V

    new-instance v6, Llyiahf/vczjk/ib;

    const/4 v7, 0x2

    invoke-direct {v6, v5, v7}, Llyiahf/vczjk/ib;-><init>(Ljava/lang/Object;I)V

    invoke-static {v1, v6}, Llyiahf/vczjk/d21;->o0000O00(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    move-result-object v1

    invoke-static {v4}, Llyiahf/vczjk/z69;->OoooOO0(Ljava/lang/CharSequence;)Z

    move-result v5

    if-eqz v5, :cond_9

    goto :goto_4

    :cond_9
    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_a
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_d

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    move-object v7, v6

    check-cast v7, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v7}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v8

    const-string v9, "getAppLabel(...)"

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v8, v4, v2}, Llyiahf/vczjk/z69;->Oooo0OO(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    move-result v8

    if-nez v8, :cond_c

    invoke-virtual {v4}, Ljava/lang/String;->length()I

    move-result v8

    const/4 v9, 0x3

    if-le v8, v9, :cond_b

    invoke-virtual {v7}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v8

    const-string v9, "getPkgName(...)"

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v8, v4, v2}, Llyiahf/vczjk/z69;->Oooo0OO(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    move-result v8

    if-nez v8, :cond_c

    :cond_b
    invoke-virtual {v7}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v7

    const-string v8, ""

    invoke-static {v7, v8}, Llyiahf/vczjk/kh6;->Oooo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    const-string v8, "toPinyin(...)"

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v7, v4, v2}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v7

    if-eqz v7, :cond_a

    :cond_c
    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_d
    move-object v1, v5

    :goto_4
    new-instance v4, Llyiahf/vczjk/p7a;

    new-instance v5, Llyiahf/vczjk/m20;

    invoke-direct {v5, v1, v3}, Llyiahf/vczjk/m20;-><init>(Ljava/util/List;Ljava/util/List;)V

    invoke-direct {v4, v5}, Llyiahf/vczjk/p7a;-><init>(Ljava/lang/Object;)V

    const/4 v1, 0x0

    iput-object v1, p0, Llyiahf/vczjk/r30;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/r30;->L$1:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/r30;->L$2:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/r30;->L$3:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/r30;->L$4:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/r30;->label:I

    invoke-interface {p1, v4, p0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_e

    return-object v0

    :cond_e
    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
