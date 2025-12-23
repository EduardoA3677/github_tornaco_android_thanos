.class public final Llyiahf/vczjk/uh3;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $builder:Llyiahf/vczjk/h09;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/h09;"
        }
    .end annotation
.end field

.field final synthetic $glideRequestType:Llyiahf/vczjk/bi3;

.field final synthetic $imageOptions:Llyiahf/vczjk/hv3;

.field final synthetic $recomposeKey:Llyiahf/vczjk/h09;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/h09;"
        }
    .end annotation
.end field

.field final synthetic $requestListener:Llyiahf/vczjk/h09;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/h09;"
        }
    .end annotation
.end field

.field final synthetic $requestManager:Lcom/bumptech/glide/RequestManager;

.field final synthetic $target:Llyiahf/vczjk/k43;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k43;Lcom/bumptech/glide/RequestManager;Llyiahf/vczjk/bi3;Llyiahf/vczjk/h09;Llyiahf/vczjk/h09;Llyiahf/vczjk/h09;Llyiahf/vczjk/hv3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/uh3;->$target:Llyiahf/vczjk/k43;

    iput-object p2, p0, Llyiahf/vczjk/uh3;->$requestManager:Lcom/bumptech/glide/RequestManager;

    iput-object p3, p0, Llyiahf/vczjk/uh3;->$glideRequestType:Llyiahf/vczjk/bi3;

    iput-object p4, p0, Llyiahf/vczjk/uh3;->$recomposeKey:Llyiahf/vczjk/h09;

    iput-object p5, p0, Llyiahf/vczjk/uh3;->$builder:Llyiahf/vczjk/h09;

    iput-object p6, p0, Llyiahf/vczjk/uh3;->$requestListener:Llyiahf/vczjk/h09;

    iput-object p7, p0, Llyiahf/vczjk/uh3;->$imageOptions:Llyiahf/vczjk/hv3;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p8}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/uh3;->create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/uh3;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/uh3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 9

    new-instance v0, Llyiahf/vczjk/uh3;

    iget-object v1, p0, Llyiahf/vczjk/uh3;->$target:Llyiahf/vczjk/k43;

    iget-object v2, p0, Llyiahf/vczjk/uh3;->$requestManager:Lcom/bumptech/glide/RequestManager;

    iget-object v3, p0, Llyiahf/vczjk/uh3;->$glideRequestType:Llyiahf/vczjk/bi3;

    iget-object v4, p0, Llyiahf/vczjk/uh3;->$recomposeKey:Llyiahf/vczjk/h09;

    iget-object v5, p0, Llyiahf/vczjk/uh3;->$builder:Llyiahf/vczjk/h09;

    iget-object v6, p0, Llyiahf/vczjk/uh3;->$requestListener:Llyiahf/vczjk/h09;

    iget-object v7, p0, Llyiahf/vczjk/uh3;->$imageOptions:Llyiahf/vczjk/hv3;

    move-object v8, p1

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/uh3;-><init>(Llyiahf/vczjk/k43;Lcom/bumptech/glide/RequestManager;Llyiahf/vczjk/bi3;Llyiahf/vczjk/h09;Llyiahf/vczjk/h09;Llyiahf/vczjk/h09;Llyiahf/vczjk/hv3;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/uh3;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance v1, Llyiahf/vczjk/th3;

    iget-object v2, p0, Llyiahf/vczjk/uh3;->$target:Llyiahf/vczjk/k43;

    iget-object v3, p0, Llyiahf/vczjk/uh3;->$requestManager:Lcom/bumptech/glide/RequestManager;

    iget-object v4, p0, Llyiahf/vczjk/uh3;->$glideRequestType:Llyiahf/vczjk/bi3;

    iget-object v5, p0, Llyiahf/vczjk/uh3;->$recomposeKey:Llyiahf/vczjk/h09;

    iget-object v6, p0, Llyiahf/vczjk/uh3;->$builder:Llyiahf/vczjk/h09;

    iget-object v7, p0, Llyiahf/vczjk/uh3;->$requestListener:Llyiahf/vczjk/h09;

    iget-object v8, p0, Llyiahf/vczjk/uh3;->$imageOptions:Llyiahf/vczjk/hv3;

    const/4 v9, 0x0

    invoke-direct/range {v1 .. v9}, Llyiahf/vczjk/th3;-><init>(Llyiahf/vczjk/k43;Lcom/bumptech/glide/RequestManager;Llyiahf/vczjk/bi3;Llyiahf/vczjk/h09;Llyiahf/vczjk/h09;Llyiahf/vczjk/h09;Llyiahf/vczjk/hv3;Llyiahf/vczjk/yo1;)V

    invoke-static {v1}, Llyiahf/vczjk/rs;->OooOO0O(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/lo0;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
