.class public final Llyiahf/vczjk/v7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$this$coroutineScope:Llyiahf/vczjk/xr1;

.field final synthetic $block:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $latestInputs:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ze3;Ljava/lang/Object;Llyiahf/vczjk/xr1;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/v7;->$block:Llyiahf/vczjk/ze3;

    iput-object p2, p0, Llyiahf/vczjk/v7;->$latestInputs:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/v7;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/v7;

    iget-object v0, p0, Llyiahf/vczjk/v7;->$block:Llyiahf/vczjk/ze3;

    iget-object v1, p0, Llyiahf/vczjk/v7;->$latestInputs:Ljava/lang/Object;

    iget-object v2, p0, Llyiahf/vczjk/v7;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/v7;-><init>(Llyiahf/vczjk/ze3;Ljava/lang/Object;Llyiahf/vczjk/xr1;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/v7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/v7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/v7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/v7;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/v7;->$block:Llyiahf/vczjk/ze3;

    iget-object v1, p0, Llyiahf/vczjk/v7;->$latestInputs:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/v7;->label:I

    invoke-interface {p1, v1, p0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/v7;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    new-instance v0, Llyiahf/vczjk/j7;

    invoke-direct {v0}, Llyiahf/vczjk/j7;-><init>()V

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo0(Llyiahf/vczjk/xr1;Ljava/util/concurrent/CancellationException;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
