.class public final Llyiahf/vczjk/uv5;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $currentBackStack$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $progress$delegate:Llyiahf/vczjk/lr5;

.field final synthetic $transitionState:Llyiahf/vczjk/xc8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/xc8;"
        }
    .end annotation
.end field

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xc8;Llyiahf/vczjk/p29;Llyiahf/vczjk/lr5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/uv5;->$transitionState:Llyiahf/vczjk/xc8;

    iput-object p2, p0, Llyiahf/vczjk/uv5;->$currentBackStack$delegate:Llyiahf/vczjk/p29;

    iput-object p3, p0, Llyiahf/vczjk/uv5;->$progress$delegate:Llyiahf/vczjk/lr5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/uv5;

    iget-object v0, p0, Llyiahf/vczjk/uv5;->$transitionState:Llyiahf/vczjk/xc8;

    iget-object v1, p0, Llyiahf/vczjk/uv5;->$currentBackStack$delegate:Llyiahf/vczjk/p29;

    iget-object v2, p0, Llyiahf/vczjk/uv5;->$progress$delegate:Llyiahf/vczjk/lr5;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/uv5;-><init>(Llyiahf/vczjk/xc8;Llyiahf/vczjk/p29;Llyiahf/vczjk/lr5;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/uv5;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/uv5;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/uv5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/uv5;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/uv5;->$currentBackStack$delegate:Llyiahf/vczjk/p29;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/List;

    iget-object v1, p0, Llyiahf/vczjk/uv5;->$currentBackStack$delegate:Llyiahf/vczjk/p29;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    add-int/lit8 v1, v1, -0x2

    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ku5;

    iget-object v1, p0, Llyiahf/vczjk/uv5;->$transitionState:Llyiahf/vczjk/xc8;

    iget-object v3, p0, Llyiahf/vczjk/uv5;->$progress$delegate:Llyiahf/vczjk/lr5;

    check-cast v3, Llyiahf/vczjk/zv8;

    invoke-virtual {v3}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v3

    iput v2, p0, Llyiahf/vczjk/uv5;->label:I

    invoke-virtual {v1, v3, p1, p0}, Llyiahf/vczjk/xc8;->OooOOO(FLjava/lang/Object;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
