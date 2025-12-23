.class public final Llyiahf/vczjk/tv5;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $composeNavigator:Llyiahf/vczjk/ae1;

.field final synthetic $currentBackStack$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $inPredictiveBack$delegate:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field

.field final synthetic $progress$delegate:Llyiahf/vczjk/lr5;

.field synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ae1;Llyiahf/vczjk/p29;Llyiahf/vczjk/lr5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tv5;->$composeNavigator:Llyiahf/vczjk/ae1;

    iput-object p2, p0, Llyiahf/vczjk/tv5;->$currentBackStack$delegate:Llyiahf/vczjk/p29;

    iput-object p3, p0, Llyiahf/vczjk/tv5;->$progress$delegate:Llyiahf/vczjk/lr5;

    iput-object p4, p0, Llyiahf/vczjk/tv5;->$inPredictiveBack$delegate:Llyiahf/vczjk/qs5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/tv5;

    iget-object v1, p0, Llyiahf/vczjk/tv5;->$composeNavigator:Llyiahf/vczjk/ae1;

    iget-object v2, p0, Llyiahf/vczjk/tv5;->$currentBackStack$delegate:Llyiahf/vczjk/p29;

    iget-object v3, p0, Llyiahf/vczjk/tv5;->$progress$delegate:Llyiahf/vczjk/lr5;

    iget-object v4, p0, Llyiahf/vczjk/tv5;->$inPredictiveBack$delegate:Llyiahf/vczjk/qs5;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/tv5;-><init>(Llyiahf/vczjk/ae1;Llyiahf/vczjk/p29;Llyiahf/vczjk/lr5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/tv5;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/f43;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/tv5;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/tv5;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/tv5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/tv5;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tv5;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ku5;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/tv5;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/f43;

    iget-object v1, p0, Llyiahf/vczjk/tv5;->$currentBackStack$delegate:Llyiahf/vczjk/p29;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    if-le v1, v2, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/tv5;->$progress$delegate:Llyiahf/vczjk/lr5;

    check-cast v1, Llyiahf/vczjk/zv8;

    const/4 v3, 0x0

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    iget-object v1, p0, Llyiahf/vczjk/tv5;->$currentBackStack$delegate:Llyiahf/vczjk/p29;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/List;

    invoke-static {v1}, Llyiahf/vczjk/d21;->o0OO00O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ku5;

    iget-object v3, p0, Llyiahf/vczjk/tv5;->$composeNavigator:Llyiahf/vczjk/ae1;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v3, v1}, Llyiahf/vczjk/ae1;->OooO0oO(Llyiahf/vczjk/ku5;)V

    iget-object v3, p0, Llyiahf/vczjk/tv5;->$currentBackStack$delegate:Llyiahf/vczjk/p29;

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/List;

    iget-object v4, p0, Llyiahf/vczjk/tv5;->$currentBackStack$delegate:Llyiahf/vczjk/p29;

    invoke-interface {v4}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/util/List;

    invoke-interface {v4}, Ljava/util/List;->size()I

    move-result v4

    add-int/lit8 v4, v4, -0x2

    invoke-interface {v3, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ku5;

    iget-object v4, p0, Llyiahf/vczjk/tv5;->$composeNavigator:Llyiahf/vczjk/ae1;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/ae1;->OooO0oO(Llyiahf/vczjk/ku5;)V

    goto :goto_0

    :cond_2
    const/4 v1, 0x0

    :goto_0
    :try_start_1
    new-instance v3, Llyiahf/vczjk/nk;

    iget-object v4, p0, Llyiahf/vczjk/tv5;->$currentBackStack$delegate:Llyiahf/vczjk/p29;

    iget-object v5, p0, Llyiahf/vczjk/tv5;->$inPredictiveBack$delegate:Llyiahf/vczjk/qs5;

    iget-object v6, p0, Llyiahf/vczjk/tv5;->$progress$delegate:Llyiahf/vczjk/lr5;

    invoke-direct {v3, v4, v5, v6}, Llyiahf/vczjk/nk;-><init>(Llyiahf/vczjk/p29;Llyiahf/vczjk/qs5;Llyiahf/vczjk/lr5;)V

    iput-object v1, p0, Llyiahf/vczjk/tv5;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/tv5;->label:I

    invoke-interface {p1, v3, p0}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    move-object v0, v1

    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/tv5;->$currentBackStack$delegate:Llyiahf/vczjk/p29;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result p1

    if-le p1, v2, :cond_4

    iget-object p1, p0, Llyiahf/vczjk/tv5;->$inPredictiveBack$delegate:Llyiahf/vczjk/qs5;

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-interface {p1, v1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/tv5;->$composeNavigator:Llyiahf/vczjk/ae1;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const/4 v1, 0x0

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/ae1;->OooO0o0(Llyiahf/vczjk/ku5;Z)V
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0

    goto :goto_2

    :catch_0
    iget-object p1, p0, Llyiahf/vczjk/tv5;->$currentBackStack$delegate:Llyiahf/vczjk/p29;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result p1

    if-le p1, v2, :cond_4

    iget-object p1, p0, Llyiahf/vczjk/tv5;->$inPredictiveBack$delegate:Llyiahf/vczjk/qs5;

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-interface {p1, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    :cond_4
    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
