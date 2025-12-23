.class public final Llyiahf/vczjk/wb6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $context:Landroid/content/Context;

.field final synthetic $viewModel:Llyiahf/vczjk/nc6;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nc6;Landroid/content/Context;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wb6;->$viewModel:Llyiahf/vczjk/nc6;

    iput-object p2, p0, Llyiahf/vczjk/wb6;->$context:Landroid/content/Context;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/wb6;

    iget-object v0, p0, Llyiahf/vczjk/wb6;->$viewModel:Llyiahf/vczjk/nc6;

    iget-object v1, p0, Llyiahf/vczjk/wb6;->$context:Landroid/content/Context;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/wb6;-><init>(Llyiahf/vczjk/nc6;Landroid/content/Context;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/wb6;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wb6;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/wb6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/wb6;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-eq v1, v2, :cond_0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/wb6;->$viewModel:Llyiahf/vczjk/nc6;

    iget-object p1, p1, Llyiahf/vczjk/nc6;->OooO0o:Llyiahf/vczjk/jl8;

    new-instance v1, Llyiahf/vczjk/vb6;

    iget-object v3, p0, Llyiahf/vczjk/wb6;->$context:Landroid/content/Context;

    const/4 v4, 0x0

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/vb6;-><init>(Landroid/content/Context;I)V

    iput v2, p0, Llyiahf/vczjk/wb6;->label:I

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/jl8;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    return-object v0
.end method
