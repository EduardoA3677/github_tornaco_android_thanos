.class public final Llyiahf/vczjk/q92;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/r92;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/r92;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/q92;->this$0:Llyiahf/vczjk/r92;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/q92;

    iget-object v0, p0, Llyiahf/vczjk/q92;->this$0:Llyiahf/vczjk/r92;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/q92;-><init>(Llyiahf/vczjk/r92;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/q92;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/q92;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/q92;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/q92;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_2
    :goto_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :cond_3
    iget-object p1, p0, Llyiahf/vczjk/q92;->this$0:Llyiahf/vczjk/r92;

    iget-boolean v1, p1, Llyiahf/vczjk/r92;->OooO0O0:Z

    if-eqz v1, :cond_5

    iput v3, p0, Llyiahf/vczjk/q92;->label:I

    iget-object v1, p1, Llyiahf/vczjk/r92;->OooO00o:Landroid/content/Context;

    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/ServicesKt;->getPowerManager(Landroid/content/Context;)Landroid/os/PowerManager;

    move-result-object v1

    invoke-virtual {v1}, Landroid/os/PowerManager;->isInteractive()Z

    move-result v1

    iget-boolean v4, p1, Llyiahf/vczjk/r92;->OooO0Oo:Z

    sget-object v5, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eq v1, v4, :cond_4

    iput-boolean v1, p1, Llyiahf/vczjk/r92;->OooO0Oo:Z

    iget-object p1, p1, Llyiahf/vczjk/r92;->OooO0OO:Llyiahf/vczjk/jl8;

    new-instance v4, Llyiahf/vczjk/p92;

    invoke-direct {v4, v1}, Llyiahf/vczjk/p92;-><init>(Z)V

    invoke-virtual {p1, v4, p0}, Llyiahf/vczjk/jl8;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v1, :cond_4

    move-object v5, p1

    :cond_4
    if-ne v5, v0, :cond_5

    goto :goto_2

    :cond_5
    :goto_1
    iput v2, p0, Llyiahf/vczjk/q92;->label:I

    const-wide/16 v4, 0x3e8

    invoke-static {v4, v5, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    :goto_2
    return-object v0
.end method
