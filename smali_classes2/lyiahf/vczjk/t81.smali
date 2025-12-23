.class public abstract Llyiahf/vczjk/t81;
.super Llyiahf/vczjk/dha;
.source "SourceFile"


# instance fields
.field public final OooO:Llyiahf/vczjk/s29;

.field public final OooO0O0:Landroid/content/Context;

.field public final OooO0OO:Llyiahf/vczjk/sc9;

.field public final OooO0Oo:Llyiahf/vczjk/s29;

.field public final OooO0o:Llyiahf/vczjk/s29;

.field public final OooO0o0:Llyiahf/vczjk/s29;

.field public final OooO0oO:Llyiahf/vczjk/s29;

.field public final OooO0oo:Llyiahf/vczjk/s29;

.field public final OooOO0:Llyiahf/vczjk/s29;

.field public final OooOO0O:Llyiahf/vczjk/s29;

.field public final OooOO0o:Llyiahf/vczjk/gh7;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 9

    const/4 v0, 0x1

    const/4 v1, 0x0

    invoke-direct {p0}, Llyiahf/vczjk/dha;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/t81;->OooO0O0:Landroid/content/Context;

    new-instance v2, Llyiahf/vczjk/v71;

    const/16 v3, 0x8

    invoke-direct {v2, p0, v3}, Llyiahf/vczjk/v71;-><init>(Llyiahf/vczjk/t81;I)V

    invoke-static {v2}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/t81;->OooO0OO:Llyiahf/vczjk/sc9;

    invoke-static {}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->dummy()Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/t81;->OooO0Oo:Llyiahf/vczjk/s29;

    const-string v2, ""

    invoke-static {v2}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object v3

    iput-object v3, p0, Llyiahf/vczjk/t81;->OooO0o0:Llyiahf/vczjk/s29;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object v3

    iput-object v3, p0, Llyiahf/vczjk/t81;->OooO0o:Llyiahf/vczjk/s29;

    sget-object v3, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    invoke-static {v3}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object v4

    iput-object v4, p0, Llyiahf/vczjk/t81;->OooO0oO:Llyiahf/vczjk/s29;

    new-instance v4, Llyiahf/vczjk/cr5;

    invoke-direct {v4, v3, v1}, Llyiahf/vczjk/cr5;-><init>(Ljava/util/Set;Z)V

    invoke-static {v4}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object v3

    iput-object v3, p0, Llyiahf/vczjk/t81;->OooO0oo:Llyiahf/vczjk/s29;

    new-instance v3, Llyiahf/vczjk/ka0;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/ka0;-><init>(ZLjava/lang/String;)V

    invoke-static {v3}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/t81;->OooO:Llyiahf/vczjk/s29;

    sget-object v2, Llyiahf/vczjk/y03;->OooOOO0:Llyiahf/vczjk/y03;

    invoke-static {v2}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/t81;->OooOO0:Llyiahf/vczjk/s29;

    invoke-static {p1}, Llyiahf/vczjk/n27;->OooO0O0(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1, v2, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object p1

    sget-object v2, Llyiahf/vczjk/yia;->OooOOO0:Llyiahf/vczjk/yia;

    const-string v2, "ComponentList.ViewType"

    invoke-interface {p1, v2, v1}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    move-result p1

    :try_start_0
    sget-object v2, Llyiahf/vczjk/yia;->OooOOOo:Llyiahf/vczjk/np2;

    invoke-virtual {v2, p1}, Llyiahf/vczjk/np2;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/yia;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    :goto_0
    sget-object v2, Llyiahf/vczjk/yia;->OooOOO0:Llyiahf/vczjk/yia;

    instance-of v3, p1, Llyiahf/vczjk/ts7;

    if-eqz v3, :cond_0

    move-object p1, v2

    :cond_0
    check-cast p1, Llyiahf/vczjk/yia;

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/t81;->OooOO0O:Llyiahf/vczjk/s29;

    iget-object v2, p0, Llyiahf/vczjk/t81;->OooO0Oo:Llyiahf/vczjk/s29;

    iget-object v3, p0, Llyiahf/vczjk/t81;->OooO0o0:Llyiahf/vczjk/s29;

    iget-object v4, p0, Llyiahf/vczjk/t81;->OooOO0:Llyiahf/vczjk/s29;

    iget-object v5, p0, Llyiahf/vczjk/t81;->OooO0o:Llyiahf/vczjk/s29;

    new-instance v6, Llyiahf/vczjk/p81;

    const/4 v7, 0x0

    invoke-direct {v6, p0, v7}, Llyiahf/vczjk/p81;-><init>(Llyiahf/vczjk/t81;Llyiahf/vczjk/yo1;)V

    const/4 v8, 0x5

    new-array v8, v8, [Llyiahf/vczjk/f43;

    aput-object v2, v8, v1

    aput-object v3, v8, v0

    const/4 v1, 0x2

    aput-object v4, v8, v1

    const/4 v1, 0x3

    aput-object p1, v8, v1

    const/4 p1, 0x4

    aput-object v5, v8, p1

    new-instance p1, Llyiahf/vczjk/b73;

    invoke-direct {p1, v8, v7, v6}, Llyiahf/vczjk/b73;-><init>([Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;Llyiahf/vczjk/gf3;)V

    new-instance v1, Llyiahf/vczjk/s48;

    invoke-direct {v1, p1}, Llyiahf/vczjk/s48;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance p1, Llyiahf/vczjk/q81;

    invoke-direct {p1, p0, v7}, Llyiahf/vczjk/q81;-><init>(Llyiahf/vczjk/t81;Llyiahf/vczjk/yo1;)V

    new-instance v2, Llyiahf/vczjk/w53;

    invoke-direct {v2, v1, p1, v0}, Llyiahf/vczjk/w53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;I)V

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/ql8;->OooO0O0:Llyiahf/vczjk/e86;

    sget-object v1, Llyiahf/vczjk/q7a;->OooO00o:Llyiahf/vczjk/q7a;

    invoke-static {v2, p1, v0, v1}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/t81;->OooOO0o:Llyiahf/vczjk/gh7;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/e71;Z)V
    .locals 3

    const-string v0, "model"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/t81;->OooO0oo:Llyiahf/vczjk/s29;

    if-eqz p2, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/cr5;

    iget-object p2, p2, Llyiahf/vczjk/cr5;->OooO0O0:Ljava/util/Set;

    invoke-static {p2, p1}, Llyiahf/vczjk/mh8;->o000oOoO(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    move-result-object p1

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/cr5;

    iget-object p2, p2, Llyiahf/vczjk/cr5;->OooO0O0:Ljava/util/Set;

    invoke-static {p2, p1}, Llyiahf/vczjk/mh8;->OoooO0(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    move-result p2

    xor-int/lit8 p2, p2, 0x1

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/cr5;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/cr5;

    invoke-direct {v2, p1, p2}, Llyiahf/vczjk/cr5;-><init>(Ljava/util/Set;Z)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    return-void
.end method

.method public abstract OooO0o(Lgithub/tornaco/android/thanos/core/app/ThanosManager;ILjava/lang/String;I)Ljava/util/List;
.end method

.method public final OooO0o0(Llyiahf/vczjk/b71;Z)V
    .locals 4

    const-string v0, "group"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/t81;->OooO0oO:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Ljava/util/Set;

    iget-object v3, p1, Llyiahf/vczjk/b71;->OooO0OO:Ljava/lang/String;

    if-eqz p2, :cond_1

    invoke-static {v2, v3}, Llyiahf/vczjk/mh8;->OoooO0(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    move-result-object v2

    goto :goto_0

    :cond_1
    invoke-static {v2, v3}, Llyiahf/vczjk/mh8;->o000oOoO(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    move-result-object v2

    :goto_0
    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    return-void
.end method

.method public final OooO0oO()Lgithub/tornaco/android/thanos/core/app/ThanosManager;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/t81;->OooO0OO:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    const-string v1, "getValue(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    return-object v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/b71;Z)V
    .locals 3

    const-string v0, "group"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/t81;->OooO0oo:Llyiahf/vczjk/s29;

    iget-object p1, p1, Llyiahf/vczjk/b71;->OooO0O0:Ljava/util/List;

    if-eqz p2, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/cr5;

    iget-object p2, p2, Llyiahf/vczjk/cr5;->OooO0O0:Ljava/util/Set;

    invoke-static {p2, p1}, Llyiahf/vczjk/mh8;->OoooOO0(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    move-result-object p1

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/cr5;

    iget-object p2, p2, Llyiahf/vczjk/cr5;->OooO0O0:Ljava/util/Set;

    invoke-static {p1}, Llyiahf/vczjk/d21;->o0000OOo(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    invoke-static {p2, p1}, Llyiahf/vczjk/mh8;->OoooO0O(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object p1

    :goto_0
    move-object p2, p1

    check-cast p2, Ljava/util/Collection;

    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    move-result p2

    xor-int/lit8 p2, p2, 0x1

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/cr5;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/cr5;

    invoke-direct {v2, p1, p2}, Llyiahf/vczjk/cr5;-><init>(Ljava/util/Set;Z)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    return-void
.end method

.method public final OooOO0(Z)V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/t81;->OooOO0o:Llyiahf/vczjk/gh7;

    iget-object v0, v0, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v0, Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/p7a;

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/p7a;

    goto :goto_0

    :cond_0
    move-object v0, v2

    :goto_0
    if-nez v0, :cond_1

    goto :goto_3

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/t81;->OooO:Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/ka0;

    const/4 v5, 0x2

    invoke-static {v4, v2, v5}, Llyiahf/vczjk/ka0;->OooO0O0(Llyiahf/vczjk/ka0;Ljava/lang/String;I)Llyiahf/vczjk/ka0;

    move-result-object v4

    invoke-virtual {v1, v3, v4}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    const/4 v3, 0x0

    iget-object v0, v0, Llyiahf/vczjk/p7a;->OooO00o:Ljava/lang/Object;

    if-eqz p1, :cond_2

    check-cast v0, Ljava/lang/Iterable;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/b71;

    const/4 v2, 0x1

    invoke-virtual {p0, v0, v2}, Llyiahf/vczjk/t81;->OooO0oo(Llyiahf/vczjk/b71;Z)V

    goto :goto_1

    :cond_2
    check-cast v0, Ljava/lang/Iterable;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/b71;

    invoke-virtual {p0, v0, v3}, Llyiahf/vczjk/t81;->OooO0oo(Llyiahf/vczjk/b71;Z)V

    goto :goto_2

    :cond_3
    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p1

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/ka0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, ""

    invoke-static {v0, v3}, Llyiahf/vczjk/ka0;->OooO00o(Ljava/lang/String;Z)Llyiahf/vczjk/ka0;

    move-result-object v0

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_3

    :goto_3
    return-void
.end method

.method public final OooOO0O(Llyiahf/vczjk/e71;Z)Z
    .locals 4

    const-string v0, "componentModel"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "setComponentState: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/t81;->OooO0Oo:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const/4 v1, 0x1

    if-eqz p2, :cond_0

    move p2, v1

    goto :goto_0

    :cond_0
    const/4 p2, 0x2

    :goto_0
    iget v2, p1, Llyiahf/vczjk/e71;->OooOOOo:I

    const/4 v3, 0x0

    if-ne p2, v2, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/t81;->OooO0oO()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v2

    if-eqz v2, :cond_2

    iput p2, p1, Llyiahf/vczjk/e71;->OooOOOo:I

    invoke-virtual {p0}, Llyiahf/vczjk/t81;->OooO0oO()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v2

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v0

    iget-object p1, p1, Llyiahf/vczjk/e71;->OooOOO:Landroid/content/ComponentName;

    invoke-virtual {v2, v0, p1, p2, v3}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->setComponentEnabledSetting(ILandroid/content/ComponentName;II)V

    return v1

    :cond_2
    :goto_1
    return v3
.end method
