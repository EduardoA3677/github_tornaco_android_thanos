.class public final Llyiahf/vczjk/o38;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/i48;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/i48;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/o38;->this$0:Llyiahf/vczjk/i48;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/o38;

    iget-object v0, p0, Llyiahf/vczjk/o38;->this$0:Llyiahf/vczjk/i48;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/o38;-><init>(Llyiahf/vczjk/i48;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/o38;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/o38;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/o38;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/o38;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/o38;->this$0:Llyiahf/vczjk/i48;

    iget-object p1, p1, Llyiahf/vczjk/i48;->OooOOO:Llyiahf/vczjk/gh7;

    iget-object p1, p1, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast p1, Llyiahf/vczjk/s29;

    invoke-virtual {p1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/String;

    if-eqz p1, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/o38;->this$0:Llyiahf/vczjk/i48;

    sget-object v4, Lgithub/tornaco/android/thanos/core/pm/PrebuiltPkgSets;->INSTANCE:Lgithub/tornaco/android/thanos/core/pm/PrebuiltPkgSets;

    invoke-virtual {v4, p1}, Lgithub/tornaco/android/thanos/core/pm/PrebuiltPkgSets;->isPrebuiltId(Ljava/lang/String;)Z

    move-result v4

    if-nez v4, :cond_3

    iget-object v4, v1, Llyiahf/vczjk/i48;->OooO0oO:Llyiahf/vczjk/f28;

    iget-object v1, v1, Llyiahf/vczjk/i48;->OooOO0:Llyiahf/vczjk/gh7;

    iget-object v1, v1, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v1, Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/j28;

    iget-object v1, v1, Llyiahf/vczjk/j28;->OooO0Oo:Ljava/util/Set;

    check-cast v1, Ljava/lang/Iterable;

    invoke-static {v1}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v1

    iput v3, p0, Llyiahf/vczjk/o38;->label:I

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    iget-object v5, v4, Llyiahf/vczjk/f28;->OooO0OO:Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    invoke-virtual {v5, v3, p1}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->removeFromPackageSet(Lgithub/tornaco/android/thanos/core/pm/Pkg;Ljava/lang/String;)V

    goto :goto_0

    :cond_2
    if-ne v2, v0, :cond_3

    return-object v0

    :cond_3
    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/o38;->this$0:Llyiahf/vczjk/i48;

    invoke-static {p1}, Llyiahf/vczjk/i48;->OooO0oo(Llyiahf/vczjk/i48;)V

    return-object v2
.end method
