.class public final Llyiahf/vczjk/u0a;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/b1a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/b1a;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/u0a;->this$0:Llyiahf/vczjk/b1a;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/u0a;

    iget-object v1, p0, Llyiahf/vczjk/u0a;->this$0:Llyiahf/vczjk/b1a;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/u0a;-><init>(Llyiahf/vczjk/b1a;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/u0a;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/ay9;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/u0a;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/u0a;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/u0a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/u0a;->label:I

    sget-object v2, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v4, :cond_1

    if-ne v1, v3, :cond_0

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Landroid/database/SQLException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/u0a;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ay9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/u0a;->L$0:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/ay9;

    iput-object v1, p0, Llyiahf/vczjk/u0a;->L$0:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/u0a;->label:I

    invoke-interface {v1, p0}, Llyiahf/vczjk/ay9;->OooO0OO(Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    :goto_0
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-eqz p1, :cond_4

    goto :goto_3

    :cond_4
    :try_start_1
    sget-object p1, Llyiahf/vczjk/zx9;->OooOOO:Llyiahf/vczjk/zx9;

    new-instance v4, Llyiahf/vczjk/t0a;

    iget-object v5, p0, Llyiahf/vczjk/u0a;->this$0:Llyiahf/vczjk/b1a;

    const/4 v6, 0x0

    invoke-direct {v4, v5, v6}, Llyiahf/vczjk/t0a;-><init>(Llyiahf/vczjk/b1a;Llyiahf/vczjk/yo1;)V

    iput-object v6, p0, Llyiahf/vczjk/u0a;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/u0a;->label:I

    invoke-interface {v1, p1, v4, p0}, Llyiahf/vczjk/ay9;->OooO0O0(Llyiahf/vczjk/zx9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    :goto_1
    return-object v0

    :cond_5
    :goto_2
    check-cast p1, Ljava/util/Set;
    :try_end_1
    .catch Landroid/database/SQLException; {:try_start_1 .. :try_end_1} :catch_0

    return-object p1

    :catch_0
    :goto_3
    return-object v2
.end method
