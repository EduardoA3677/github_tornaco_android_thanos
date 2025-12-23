.class public final Llyiahf/vczjk/or6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $context:Landroid/content/Context;

.field final synthetic $viewModel:Llyiahf/vczjk/vr6;

.field label:I

.field final synthetic this$0:Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PatternSettingsActivity;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vr6;Landroid/content/Context;Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PatternSettingsActivity;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/or6;->$viewModel:Llyiahf/vczjk/vr6;

    iput-object p2, p0, Llyiahf/vczjk/or6;->$context:Landroid/content/Context;

    iput-object p3, p0, Llyiahf/vczjk/or6;->this$0:Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PatternSettingsActivity;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/or6;

    iget-object v0, p0, Llyiahf/vczjk/or6;->$viewModel:Llyiahf/vczjk/vr6;

    iget-object v1, p0, Llyiahf/vczjk/or6;->$context:Landroid/content/Context;

    iget-object v2, p0, Llyiahf/vczjk/or6;->this$0:Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PatternSettingsActivity;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/or6;-><init>(Llyiahf/vczjk/vr6;Landroid/content/Context;Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PatternSettingsActivity;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/or6;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/or6;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/or6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/or6;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/or6;->$viewModel:Llyiahf/vczjk/vr6;

    iget-object p1, p1, Llyiahf/vczjk/vr6;->OooO0oo:Llyiahf/vczjk/jl8;

    new-instance v1, Llyiahf/vczjk/tx3;

    iget-object v3, p0, Llyiahf/vczjk/or6;->$context:Landroid/content/Context;

    iget-object v4, p0, Llyiahf/vczjk/or6;->this$0:Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PatternSettingsActivity;

    const/4 v5, 0x4

    invoke-direct {v1, v5, v3, v4}, Llyiahf/vczjk/tx3;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iput v2, p0, Llyiahf/vczjk/or6;->label:I

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/jl8;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    return-object v0
.end method
