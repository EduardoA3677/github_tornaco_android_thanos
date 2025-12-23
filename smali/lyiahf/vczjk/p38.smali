.class public final Llyiahf/vczjk/p38;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/h48;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/h48;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/p38;->this$0:Llyiahf/vczjk/h48;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/p38;

    iget-object v0, p0, Llyiahf/vczjk/p38;->this$0:Llyiahf/vczjk/h48;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/p38;-><init>(Llyiahf/vczjk/h48;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/p38;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/p38;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/p38;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/p38;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/p38;->L$2:Ljava/lang/Object;

    check-cast v1, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    iget-object v4, p0, Llyiahf/vczjk/p38;->L$1:Ljava/lang/Object;

    check-cast v4, Ljava/util/Iterator;

    iget-object v5, p0, Llyiahf/vczjk/p38;->L$0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/h48;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_4

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/p38;->L$2:Ljava/lang/Object;

    check-cast v1, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    iget-object v4, p0, Llyiahf/vczjk/p38;->L$1:Ljava/lang/Object;

    check-cast v4, Ljava/util/Iterator;

    iget-object v5, p0, Llyiahf/vczjk/p38;->L$0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/h48;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/p38;->this$0:Llyiahf/vczjk/h48;

    iget-object p1, p1, Llyiahf/vczjk/h48;->OooO:Llyiahf/vczjk/gh7;

    iget-object p1, p1, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast p1, Llyiahf/vczjk/s29;

    invoke-virtual {p1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/i28;

    iget-object p1, p1, Llyiahf/vczjk/i28;->OooO0O0:Ljava/util/Set;

    check-cast p1, Ljava/lang/Iterable;

    iget-object v1, p0, Llyiahf/vczjk/p38;->this$0:Llyiahf/vczjk/h48;

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    sget-object v5, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz v4, :cond_7

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    iget-object v6, v1, Llyiahf/vczjk/h48;->OooO0o:Llyiahf/vczjk/e28;

    invoke-static {v4}, Lgithub/tornaco/android/thanos/core/ExtensionsKt;->toAppPkg(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Ltornaco/apps/thanox/core/proto/common/AppPkg;

    move-result-object v7

    iput-object v1, p0, Llyiahf/vczjk/p38;->L$0:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/p38;->L$1:Ljava/lang/Object;

    iput-object v4, p0, Llyiahf/vczjk/p38;->L$2:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/p38;->label:I

    iget-object v6, v6, Llyiahf/vczjk/e28;->OooO00o:Llyiahf/vczjk/u18;

    iget-object v6, v6, Llyiahf/vczjk/u18;->OooO00o:Landroid/content/Context;

    invoke-static {v6}, Llyiahf/vczjk/h28;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object v6

    new-instance v8, Llyiahf/vczjk/h18;

    const/4 v9, 0x0

    invoke-direct {v8, v7, v9}, Llyiahf/vczjk/h18;-><init>(Ltornaco/apps/thanox/core/proto/common/AppPkg;Llyiahf/vczjk/yo1;)V

    invoke-interface {v6, v8, p0}, Llyiahf/vczjk/ay1;->OooO00o(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne v6, v7, :cond_3

    goto :goto_1

    :cond_3
    move-object v6, v5

    :goto_1
    if-ne v6, v7, :cond_4

    move-object v5, v6

    :cond_4
    if-ne v5, v0, :cond_5

    goto :goto_3

    :cond_5
    move-object v5, v1

    move-object v1, v4

    move-object v4, p1

    :goto_2
    invoke-virtual {v5, v1}, Llyiahf/vczjk/h48;->OooOO0(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V

    sget-object p1, Llyiahf/vczjk/km8;->OooO00o:Llyiahf/vczjk/km8;

    iput-object v5, p0, Llyiahf/vczjk/p38;->L$0:Ljava/lang/Object;

    iput-object v4, p0, Llyiahf/vczjk/p38;->L$1:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/p38;->L$2:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/p38;->label:I

    invoke-virtual {p1, p0}, Llyiahf/vczjk/km8;->OooO0O0(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_6

    :goto_3
    return-object v0

    :cond_6
    :goto_4
    check-cast p1, Lgithub/tornaco/android/thanos/core/IThanosLite;

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    const/4 v6, 0x0

    invoke-interface {p1, v1, v6}, Lgithub/tornaco/android/thanos/core/IThanosLite;->freezePkgs(Ljava/util/List;Z)V

    move-object p1, v4

    move-object v1, v5

    goto :goto_0

    :cond_7
    return-object v5
.end method
