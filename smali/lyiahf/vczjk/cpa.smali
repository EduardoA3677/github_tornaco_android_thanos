.class public final Llyiahf/vczjk/cpa;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $newRecomposer:Llyiahf/vczjk/oj7;

.field final synthetic $rootView:Landroid/view/View;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oj7;Landroid/view/View;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/cpa;->$newRecomposer:Llyiahf/vczjk/oj7;

    iput-object p2, p0, Llyiahf/vczjk/cpa;->$rootView:Landroid/view/View;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/cpa;

    iget-object v0, p0, Llyiahf/vczjk/cpa;->$newRecomposer:Llyiahf/vczjk/oj7;

    iget-object v1, p0, Llyiahf/vczjk/cpa;->$rootView:Landroid/view/View;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/cpa;-><init>(Llyiahf/vczjk/oj7;Landroid/view/View;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/cpa;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/cpa;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/cpa;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/cpa;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x0

    const/4 v4, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v4, :cond_0

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_1
    iget-object p1, p0, Llyiahf/vczjk/cpa;->$newRecomposer:Llyiahf/vczjk/oj7;

    iput v4, p0, Llyiahf/vczjk/cpa;->label:I

    iget-object p1, p1, Llyiahf/vczjk/oj7;->OooOo00:Llyiahf/vczjk/s29;

    new-instance v1, Llyiahf/vczjk/fj7;

    const/4 v4, 0x2

    invoke-direct {v1, v4, v3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-static {p1, v1, p0}, Llyiahf/vczjk/rs;->OooOoOO(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-ne p1, v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/cpa;->$rootView:Landroid/view/View;

    invoke-static {p1}, Llyiahf/vczjk/kpa;->OooO0O0(Landroid/view/View;)Llyiahf/vczjk/lg1;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/cpa;->$newRecomposer:Llyiahf/vczjk/oj7;

    if-ne p1, v0, :cond_4

    iget-object p1, p0, Llyiahf/vczjk/cpa;->$rootView:Landroid/view/View;

    sget v0, Landroidx/compose/ui/R$id;->androidx_compose_ui_view_composition_context:I

    invoke-virtual {p1, v0, v3}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    :cond_4
    return-object v2

    :goto_2
    iget-object v0, p0, Llyiahf/vczjk/cpa;->$rootView:Landroid/view/View;

    invoke-static {v0}, Llyiahf/vczjk/kpa;->OooO0O0(Landroid/view/View;)Llyiahf/vczjk/lg1;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/cpa;->$newRecomposer:Llyiahf/vczjk/oj7;

    if-ne v0, v1, :cond_5

    iget-object v0, p0, Llyiahf/vczjk/cpa;->$rootView:Landroid/view/View;

    sget v1, Landroidx/compose/ui/R$id;->androidx_compose_ui_view_composition_context:I

    invoke-virtual {v0, v1, v3}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    :cond_5
    throw p1
.end method
