.class public final Llyiahf/vczjk/yka;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/bla;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bla;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yka;->this$0:Llyiahf/vczjk/bla;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/yka;

    iget-object v0, p0, Llyiahf/vczjk/yka;->this$0:Llyiahf/vczjk/bla;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/yka;-><init>(Llyiahf/vczjk/bla;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/yka;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/yka;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/yka;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/yka;->label:I

    if-nez v0, :cond_3

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/yka;->this$0:Llyiahf/vczjk/bla;

    iget-object p1, p1, Llyiahf/vczjk/bla;->OooO0o:Llyiahf/vczjk/s29;

    invoke-virtual {p1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/td0;

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v2, 0x1

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/16 v8, 0x3e

    invoke-static/range {v1 .. v8}, Llyiahf/vczjk/td0;->OooO00o(Llyiahf/vczjk/td0;ZZLjava/util/List;Ljava/util/List;Llyiahf/vczjk/nw;ZI)Llyiahf/vczjk/td0;

    move-result-object v0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v1, 0x0

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    iget-object p1, p0, Llyiahf/vczjk/yka;->this$0:Llyiahf/vczjk/bla;

    iget-object p1, p1, Llyiahf/vczjk/bla;->OooO0oO:Llyiahf/vczjk/gh7;

    iget-object p1, p1, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast p1, Llyiahf/vczjk/s29;

    invoke-virtual {p1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/td0;

    iget-object p1, p1, Llyiahf/vczjk/td0;->OooO0o0:Llyiahf/vczjk/nw;

    const/4 v0, 0x1

    if-eqz p1, :cond_1

    iget-object v2, p0, Llyiahf/vczjk/yka;->this$0:Llyiahf/vczjk/bla;

    invoke-virtual {v2}, Llyiahf/vczjk/bla;->OooOO0()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v2

    iget-object p1, p1, Llyiahf/vczjk/nw;->OooO00o:Ljava/lang/String;

    invoke-virtual {v2, p1, v0, v0}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getPackageSetById(Ljava/lang/String;ZZ)Lgithub/tornaco/android/thanos/core/pm/PackageSet;

    move-result-object p1

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/PackageSet;->getPkgList()Ljava/util/List;

    move-result-object p1

    const-string v2, "getPkgList(...)"

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v4

    const-string v5, "github.tornaco.android.thanos"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_0

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    sget-object v2, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/yka;->this$0:Llyiahf/vczjk/bla;

    invoke-virtual {p1}, Llyiahf/vczjk/bla;->OooOO0()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object p1

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPowerManager()Lgithub/tornaco/android/thanos/core/power/PowerManager;

    move-result-object p1

    iget-object v3, p0, Llyiahf/vczjk/yka;->this$0:Llyiahf/vczjk/bla;

    iget-object v3, v3, Llyiahf/vczjk/bla;->OooO0oO:Llyiahf/vczjk/gh7;

    iget-object v3, v3, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v3, Llyiahf/vczjk/s29;

    invoke-virtual {v3}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/td0;

    iget-boolean v3, v3, Llyiahf/vczjk/td0;->OooO0o:Z

    invoke-virtual {p1, v0, v3}, Lgithub/tornaco/android/thanos/core/power/PowerManager;->getSeenWakeLocksStats(ZZ)Ljava/util/List;

    move-result-object v3

    const-string v4, "getSeenWakeLocksStats(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v3}, Llyiahf/vczjk/d21;->o00Oo0(Ljava/util/List;)Ljava/util/ArrayList;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/d21;->Oooooo(Ljava/lang/Iterable;)Llyiahf/vczjk/vy;

    move-result-object v3

    new-instance v4, Llyiahf/vczjk/w45;

    const/16 v5, 0x1b

    invoke-direct {v4, v2, v5}, Llyiahf/vczjk/w45;-><init>(Ljava/lang/Object;I)V

    new-instance v2, Llyiahf/vczjk/e13;

    invoke-direct {v2, v3, v0, v4}, Llyiahf/vczjk/e13;-><init>(Llyiahf/vczjk/wf8;ZLlyiahf/vczjk/oe3;)V

    iget-object v0, p0, Llyiahf/vczjk/yka;->this$0:Llyiahf/vczjk/bla;

    new-instance v3, Llyiahf/vczjk/gu6;

    const/16 v4, 0x13

    invoke-direct {v3, v4, v0, p1}, Llyiahf/vczjk/gu6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-static {v2, v3}, Llyiahf/vczjk/ag8;->Oooo(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/e13;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/m99;

    const/16 v2, 0xb

    const/4 v3, 0x0

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/m99;-><init>(IB)V

    new-instance v2, Llyiahf/vczjk/ib;

    const/16 v3, 0x9

    invoke-direct {v2, v0, v3}, Llyiahf/vczjk/ib;-><init>(Ljava/lang/Object;I)V

    new-instance v0, Llyiahf/vczjk/b62;

    const/4 v3, 0x2

    invoke-direct {v0, v3, p1, v2}, Llyiahf/vczjk/b62;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-static {v0}, Llyiahf/vczjk/ag8;->OoooO00(Llyiahf/vczjk/wf8;)Ljava/util/List;

    move-result-object v7

    iget-object p1, p0, Llyiahf/vczjk/yka;->this$0:Llyiahf/vczjk/bla;

    iget-object p1, p1, Llyiahf/vczjk/bla;->OooO0o:Llyiahf/vczjk/s29;

    invoke-virtual {p1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v4, v0

    check-cast v4, Llyiahf/vczjk/td0;

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v8, 0x0

    const/16 v11, 0x3a

    invoke-static/range {v4 .. v11}, Llyiahf/vczjk/td0;->OooO00o(Llyiahf/vczjk/td0;ZZLjava/util/List;Ljava/util/List;Llyiahf/vczjk/nw;ZI)Llyiahf/vczjk/td0;

    move-result-object v0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
