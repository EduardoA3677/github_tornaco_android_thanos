.class public final Llyiahf/vczjk/k7a;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $this_isSystemInDarkTheme:Landroidx/activity/ComponentActivity;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Landroidx/activity/ComponentActivity;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/k7a;->$this_isSystemInDarkTheme:Landroidx/activity/ComponentActivity;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/k7a;

    iget-object v1, p0, Llyiahf/vczjk/k7a;->$this_isSystemInDarkTheme:Landroidx/activity/ComponentActivity;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/k7a;-><init>(Landroidx/activity/ComponentActivity;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/k7a;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/s77;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/k7a;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/k7a;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/k7a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/k7a;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/k7a;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s77;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/r77;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v3, p0, Llyiahf/vczjk/k7a;->$this_isSystemInDarkTheme:Landroidx/activity/ComponentActivity;

    invoke-virtual {v3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v3

    invoke-virtual {v3}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object v3

    const-string v4, "getConfiguration(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v3}, Llyiahf/vczjk/ll6;->OooOO0O(Landroid/content/res/Configuration;)Z

    move-result v3

    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v3

    invoke-virtual {v1, v3}, Llyiahf/vczjk/r77;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v1, Llyiahf/vczjk/j7a;

    const/4 v3, 0x0

    invoke-direct {v1, p1, v3}, Llyiahf/vczjk/j7a;-><init>(Llyiahf/vczjk/s77;I)V

    iget-object v3, p0, Llyiahf/vczjk/k7a;->$this_isSystemInDarkTheme:Landroidx/activity/ComponentActivity;

    invoke-virtual {v3, v1}, Landroidx/activity/ComponentActivity;->OooOOOO(Llyiahf/vczjk/ol1;)V

    iget-object v3, p0, Llyiahf/vczjk/k7a;->$this_isSystemInDarkTheme:Landroidx/activity/ComponentActivity;

    new-instance v4, Llyiahf/vczjk/w77;

    const/16 v5, 0xc

    invoke-direct {v4, v5, v3, v1}, Llyiahf/vczjk/w77;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iput v2, p0, Llyiahf/vczjk/k7a;->label:I

    invoke-static {p1, v4, p0}, Llyiahf/vczjk/v34;->OooOOo(Llyiahf/vczjk/s77;Llyiahf/vczjk/le3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
