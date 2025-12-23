.class public final Llyiahf/vczjk/sx7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ux7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ux7;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sx7;->this$0:Llyiahf/vczjk/ux7;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/sx7;

    iget-object v0, p0, Llyiahf/vczjk/sx7;->this$0:Llyiahf/vczjk/ux7;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/sx7;-><init>(Llyiahf/vczjk/ux7;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/sx7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/sx7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/sx7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/sx7;->label:I

    sget-object v2, Llyiahf/vczjk/r02;->OooO0oO:Llyiahf/vczjk/hs1;

    sget-object v3, Llyiahf/vczjk/ux7;->OooO0O0:Llyiahf/vczjk/tx7;

    const/4 v4, 0x0

    const/4 v5, 0x2

    const/4 v6, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v6, :cond_1

    if-ne v1, v5, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/sx7;->L$0:Ljava/lang/Object;

    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/tx7;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/sx7;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/tx7;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/ux7;->OooO0OO:Ljava/util/Map;

    if-nez p1, :cond_4

    iget-object p1, p0, Llyiahf/vczjk/sx7;->this$0:Llyiahf/vczjk/ux7;

    iput-object v3, p0, Llyiahf/vczjk/sx7;->L$0:Ljava/lang/Object;

    iput v6, p0, Llyiahf/vczjk/sx7;->label:I

    iget-object p1, p1, Llyiahf/vczjk/ux7;->OooO00o:Llyiahf/vczjk/sw7;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v1, "SELECT * from rules_table"

    invoke-static {v4, v1}, Llyiahf/vczjk/xu7;->OooOOOO(ILjava/lang/String;)Llyiahf/vczjk/xu7;

    move-result-object v1

    new-instance v6, Landroid/os/CancellationSignal;

    invoke-direct {v6}, Landroid/os/CancellationSignal;-><init>()V

    new-instance v7, Llyiahf/vczjk/rw7;

    const/4 v8, 0x0

    invoke-direct {v7, p1, v1, v8}, Llyiahf/vczjk/rw7;-><init>(Ljava/lang/Object;Llyiahf/vczjk/xu7;I)V

    iget-object p1, p1, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast p1, Lcom/absinthe/rulesbundle/RuleDatabase_Impl;

    invoke-virtual {v2, p1, v6, v7, p0}, Llyiahf/vczjk/hs1;->OooO00o(Lcom/absinthe/rulesbundle/RuleDatabase_Impl;Landroid/os/CancellationSignal;Ljava/util/concurrent/Callable;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    move-object v1, v3

    :goto_0
    check-cast p1, Ljava/lang/Iterable;

    invoke-static {p1}, Llyiahf/vczjk/d21;->Oooooo(Ljava/lang/Iterable;)Llyiahf/vczjk/vy;

    move-result-object p1

    sget-object v6, Llyiahf/vczjk/x77;->OooOOoo:Llyiahf/vczjk/x77;

    invoke-static {p1, v6}, Llyiahf/vczjk/ag8;->Oooo0oo(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/jy9;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/lc5;->o0OO00O(Llyiahf/vczjk/jy9;)Ljava/util/Map;

    move-result-object p1

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sput-object p1, Llyiahf/vczjk/ux7;->OooO0OO:Ljava/util/Map;

    :cond_4
    sget-object p1, Llyiahf/vczjk/ux7;->OooO0Oo:Ljava/util/Map;

    if-nez p1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/sx7;->this$0:Llyiahf/vczjk/ux7;

    iput-object v3, p0, Llyiahf/vczjk/sx7;->L$0:Ljava/lang/Object;

    iput v5, p0, Llyiahf/vczjk/sx7;->label:I

    iget-object p1, p1, Llyiahf/vczjk/ux7;->OooO00o:Llyiahf/vczjk/sw7;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v1, "SELECT * from rules_table WHERE isRegexRule = 1"

    invoke-static {v4, v1}, Llyiahf/vczjk/xu7;->OooOOOO(ILjava/lang/String;)Llyiahf/vczjk/xu7;

    move-result-object v1

    new-instance v4, Landroid/os/CancellationSignal;

    invoke-direct {v4}, Landroid/os/CancellationSignal;-><init>()V

    new-instance v5, Llyiahf/vczjk/rw7;

    const/4 v6, 0x1

    invoke-direct {v5, p1, v1, v6}, Llyiahf/vczjk/rw7;-><init>(Ljava/lang/Object;Llyiahf/vczjk/xu7;I)V

    iget-object p1, p1, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast p1, Lcom/absinthe/rulesbundle/RuleDatabase_Impl;

    invoke-virtual {v2, p1, v4, v5, p0}, Llyiahf/vczjk/hs1;->OooO00o(Lcom/absinthe/rulesbundle/RuleDatabase_Impl;Landroid/os/CancellationSignal;Ljava/util/concurrent/Callable;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    :goto_1
    return-object v0

    :cond_5
    :goto_2
    check-cast p1, Ljava/lang/Iterable;

    invoke-static {p1}, Llyiahf/vczjk/d21;->Oooooo(Ljava/lang/Iterable;)Llyiahf/vczjk/vy;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/x77;->OooOo00:Llyiahf/vczjk/x77;

    invoke-static {p1, v0}, Llyiahf/vczjk/ag8;->Oooo0oo(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/jy9;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/lc5;->o0OO00O(Llyiahf/vczjk/jy9;)Ljava/util/Map;

    move-result-object p1

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sput-object p1, Llyiahf/vczjk/ux7;->OooO0Oo:Ljava/util/Map;

    :cond_6
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
