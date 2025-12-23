.class public final Llyiahf/vczjk/u30;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $enabled:Z

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/i40;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/i40;ZLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/u30;->this$0:Llyiahf/vczjk/i40;

    iput-boolean p2, p0, Llyiahf/vczjk/u30;->$enabled:Z

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/u30;

    iget-object v0, p0, Llyiahf/vczjk/u30;->this$0:Llyiahf/vczjk/i40;

    iget-boolean v1, p0, Llyiahf/vczjk/u30;->$enabled:Z

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/u30;-><init>(Llyiahf/vczjk/i40;ZLlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/u30;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/u30;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/u30;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/u30;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/u30;->this$0:Llyiahf/vczjk/i40;

    iget-object p1, p1, Llyiahf/vczjk/i40;->OooO0o:Llyiahf/vczjk/o30;

    iget-boolean v1, p0, Llyiahf/vczjk/u30;->$enabled:Z

    iput v3, p0, Llyiahf/vczjk/u30;->label:I

    iget-object p1, p1, Llyiahf/vczjk/o30;->OooO00o:Llyiahf/vczjk/l30;

    iget-object p1, p1, Llyiahf/vczjk/l30;->OooO00o:Landroid/content/Context;

    invoke-static {p1}, Llyiahf/vczjk/p30;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object p1

    new-instance v3, Llyiahf/vczjk/h30;

    const/4 v4, 0x0

    invoke-direct {v3, v1, v4}, Llyiahf/vczjk/h30;-><init>(ZLlyiahf/vczjk/yo1;)V

    invoke-interface {p1, v3, p0}, Llyiahf/vczjk/ay1;->OooO00o(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    move-object p1, v2

    :goto_1
    if-ne p1, v0, :cond_4

    return-object v0

    :cond_4
    return-object v2
.end method
