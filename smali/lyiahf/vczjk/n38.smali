.class public final Llyiahf/vczjk/n38;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/h48;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/h48;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/n38;->this$0:Llyiahf/vczjk/h48;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/n38;

    iget-object v0, p0, Llyiahf/vczjk/n38;->this$0:Llyiahf/vczjk/h48;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/n38;-><init>(Llyiahf/vczjk/h48;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/n38;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/n38;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/n38;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/n38;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/n38;->this$0:Llyiahf/vczjk/h48;

    iget-object v1, p1, Llyiahf/vczjk/h48;->OooO0o:Llyiahf/vczjk/e28;

    iget-object p1, p1, Llyiahf/vczjk/h48;->OooOO0O:Llyiahf/vczjk/gh7;

    iget-object p1, p1, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast p1, Llyiahf/vczjk/s29;

    invoke-virtual {p1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p1

    const-string v4, "<get-value>(...)"

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Ljava/lang/String;

    iget-object v4, p0, Llyiahf/vczjk/n38;->this$0:Llyiahf/vczjk/h48;

    iget-object v4, v4, Llyiahf/vczjk/h48;->OooO:Llyiahf/vczjk/gh7;

    iget-object v4, v4, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v4, Llyiahf/vczjk/s29;

    invoke-virtual {v4}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/i28;

    iget-object v4, v4, Llyiahf/vczjk/i28;->OooO0O0:Ljava/util/Set;

    check-cast v4, Ljava/lang/Iterable;

    new-instance v5, Ljava/util/ArrayList;

    const/16 v6, 0xa

    invoke-static {v4, v6}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v6

    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_2

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-static {v6}, Lgithub/tornaco/android/thanos/core/ExtensionsKt;->toAppPkg(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Ltornaco/apps/thanox/core/proto/common/AppPkg;

    move-result-object v6

    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    iput v3, p0, Llyiahf/vczjk/n38;->label:I

    iget-object v1, v1, Llyiahf/vczjk/e28;->OooO00o:Llyiahf/vczjk/u18;

    iget-object v1, v1, Llyiahf/vczjk/u18;->OooO00o:Landroid/content/Context;

    invoke-static {v1}, Llyiahf/vczjk/mw6;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object v1

    new-instance v3, Llyiahf/vczjk/i18;

    const/4 v4, 0x0

    invoke-direct {v3, p1, v5, v4}, Llyiahf/vczjk/i18;-><init>(Ljava/lang/String;Ljava/util/List;Llyiahf/vczjk/yo1;)V

    invoke-interface {v1, v3, p0}, Llyiahf/vczjk/ay1;->OooO00o(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v1, :cond_3

    goto :goto_1

    :cond_3
    move-object p1, v2

    :goto_1
    if-ne p1, v1, :cond_4

    goto :goto_2

    :cond_4
    move-object p1, v2

    :goto_2
    if-ne p1, v0, :cond_5

    return-object v0

    :cond_5
    return-object v2
.end method
