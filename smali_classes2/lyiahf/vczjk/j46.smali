.class public final Llyiahf/vczjk/j46;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $context:Landroid/content/Context;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/l46;


# direct methods
.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/yo1;Llyiahf/vczjk/l46;)V
    .locals 0

    iput-object p3, p0, Llyiahf/vczjk/j46;->this$0:Llyiahf/vczjk/l46;

    iput-object p1, p0, Llyiahf/vczjk/j46;->$context:Landroid/content/Context;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/j46;

    iget-object v0, p0, Llyiahf/vczjk/j46;->this$0:Llyiahf/vczjk/l46;

    iget-object v1, p0, Llyiahf/vczjk/j46;->$context:Landroid/content/Context;

    invoke-direct {p1, v1, p2, v0}, Llyiahf/vczjk/j46;-><init>(Landroid/content/Context;Llyiahf/vczjk/yo1;Llyiahf/vczjk/l46;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/j46;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/j46;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/j46;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/j46;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/j46;->this$0:Llyiahf/vczjk/l46;

    iget-object p1, p1, Llyiahf/vczjk/l46;->OooO0o0:Llyiahf/vczjk/jj0;

    sget-object v1, Llyiahf/vczjk/dl2;->OooO00o:Llyiahf/vczjk/dl2;

    iput v3, p0, Llyiahf/vczjk/j46;->label:I

    invoke-interface {p1, v1, p0}, Llyiahf/vczjk/if8;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    :goto_0
    sget-object p1, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object p1, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    new-instance v1, Llyiahf/vczjk/i46;

    iget-object v3, p0, Llyiahf/vczjk/j46;->$context:Landroid/content/Context;

    iget-object v4, p0, Llyiahf/vczjk/j46;->this$0:Llyiahf/vczjk/l46;

    const/4 v5, 0x0

    invoke-direct {v1, v3, v5, v4}, Llyiahf/vczjk/i46;-><init>(Landroid/content/Context;Llyiahf/vczjk/yo1;Llyiahf/vczjk/l46;)V

    iput v2, p0, Llyiahf/vczjk/j46;->label:I

    invoke-static {p1, v1, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_1
    return-object v0

    :cond_4
    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
