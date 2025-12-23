.class public final Llyiahf/vczjk/th3;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


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

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k43;Lcom/bumptech/glide/RequestManager;Llyiahf/vczjk/bi3;Llyiahf/vczjk/h09;Llyiahf/vczjk/h09;Llyiahf/vczjk/h09;Llyiahf/vczjk/hv3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/th3;->$target:Llyiahf/vczjk/k43;

    iput-object p2, p0, Llyiahf/vczjk/th3;->$requestManager:Lcom/bumptech/glide/RequestManager;

    iput-object p3, p0, Llyiahf/vczjk/th3;->$glideRequestType:Llyiahf/vczjk/bi3;

    iput-object p4, p0, Llyiahf/vczjk/th3;->$recomposeKey:Llyiahf/vczjk/h09;

    iput-object p5, p0, Llyiahf/vczjk/th3;->$builder:Llyiahf/vczjk/h09;

    iput-object p6, p0, Llyiahf/vczjk/th3;->$requestListener:Llyiahf/vczjk/h09;

    iput-object p7, p0, Llyiahf/vczjk/th3;->$imageOptions:Llyiahf/vczjk/hv3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p8}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 9

    new-instance v0, Llyiahf/vczjk/th3;

    iget-object v1, p0, Llyiahf/vczjk/th3;->$target:Llyiahf/vczjk/k43;

    iget-object v2, p0, Llyiahf/vczjk/th3;->$requestManager:Lcom/bumptech/glide/RequestManager;

    iget-object v3, p0, Llyiahf/vczjk/th3;->$glideRequestType:Llyiahf/vczjk/bi3;

    iget-object v4, p0, Llyiahf/vczjk/th3;->$recomposeKey:Llyiahf/vczjk/h09;

    iget-object v5, p0, Llyiahf/vczjk/th3;->$builder:Llyiahf/vczjk/h09;

    iget-object v6, p0, Llyiahf/vczjk/th3;->$requestListener:Llyiahf/vczjk/h09;

    iget-object v7, p0, Llyiahf/vczjk/th3;->$imageOptions:Llyiahf/vczjk/hv3;

    move-object v8, p2

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/th3;-><init>(Llyiahf/vczjk/k43;Lcom/bumptech/glide/RequestManager;Llyiahf/vczjk/bi3;Llyiahf/vczjk/h09;Llyiahf/vczjk/h09;Llyiahf/vczjk/h09;Llyiahf/vczjk/hv3;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/th3;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/s77;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/th3;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/th3;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/th3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/th3;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/th3;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s77;

    iget-object v1, p0, Llyiahf/vczjk/th3;->$target:Llyiahf/vczjk/k43;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v3, "producerScope"

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p1, v1, Llyiahf/vczjk/k43;->OooOOOO:Llyiahf/vczjk/s77;

    new-instance v1, Llyiahf/vczjk/t73;

    iget-object v3, p0, Llyiahf/vczjk/th3;->$target:Llyiahf/vczjk/k43;

    new-instance v4, Llyiahf/vczjk/o000OO;

    const/16 v5, 0x18

    invoke-direct {v4, v3, v5}, Llyiahf/vczjk/o000OO;-><init>(Ljava/lang/Object;I)V

    invoke-direct {v1, p1, v4}, Llyiahf/vczjk/t73;-><init>(Llyiahf/vczjk/s77;Llyiahf/vczjk/o000OO;)V

    iget-object v3, p0, Llyiahf/vczjk/th3;->$requestManager:Lcom/bumptech/glide/RequestManager;

    iget-object v4, p0, Llyiahf/vczjk/th3;->$glideRequestType:Llyiahf/vczjk/bi3;

    iget-object v5, p0, Llyiahf/vczjk/th3;->$recomposeKey:Llyiahf/vczjk/h09;

    iget-object v6, p0, Llyiahf/vczjk/th3;->$builder:Llyiahf/vczjk/h09;

    iget-object v7, p0, Llyiahf/vczjk/th3;->$requestListener:Llyiahf/vczjk/h09;

    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    move-result v4

    const-string v8, "addListener(...)"

    if-eqz v4, :cond_4

    if-eq v4, v2, :cond_3

    const/4 v9, 0x2

    if-ne v4, v9, :cond_2

    invoke-virtual {v3}, Lcom/bumptech/glide/RequestManager;->asGif()Lcom/bumptech/glide/RequestBuilder;

    move-result-object v3

    iget-object v4, v5, Llyiahf/vczjk/h09;->OooO00o:Ljava/lang/Object;

    invoke-virtual {v3, v4}, Lcom/bumptech/glide/RequestBuilder;->load(Ljava/lang/Object;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v3

    iget-object v4, v6, Llyiahf/vczjk/h09;->OooO00o:Ljava/lang/Object;

    check-cast v4, Lcom/bumptech/glide/request/BaseRequestOptions;

    invoke-virtual {v3, v4}, Lcom/bumptech/glide/RequestBuilder;->apply(Lcom/bumptech/glide/request/BaseRequestOptions;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v3

    invoke-virtual {v3, v1}, Lcom/bumptech/glide/RequestBuilder;->addListener(Lcom/bumptech/glide/request/RequestListener;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v1

    iget-object v3, v7, Llyiahf/vczjk/h09;->OooO00o:Ljava/lang/Object;

    check-cast v3, Lcom/bumptech/glide/request/RequestListener;

    invoke-virtual {v1, v3}, Lcom/bumptech/glide/RequestBuilder;->addListener(Lcom/bumptech/glide/request/RequestListener;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v1

    invoke-static {v1, v8}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_0

    :cond_2
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_3
    invoke-virtual {v3}, Lcom/bumptech/glide/RequestManager;->asBitmap()Lcom/bumptech/glide/RequestBuilder;

    move-result-object v3

    iget-object v4, v5, Llyiahf/vczjk/h09;->OooO00o:Ljava/lang/Object;

    invoke-virtual {v3, v4}, Lcom/bumptech/glide/RequestBuilder;->load(Ljava/lang/Object;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v3

    iget-object v4, v6, Llyiahf/vczjk/h09;->OooO00o:Ljava/lang/Object;

    check-cast v4, Lcom/bumptech/glide/request/BaseRequestOptions;

    invoke-virtual {v3, v4}, Lcom/bumptech/glide/RequestBuilder;->apply(Lcom/bumptech/glide/request/BaseRequestOptions;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v3

    invoke-virtual {v3, v1}, Lcom/bumptech/glide/RequestBuilder;->addListener(Lcom/bumptech/glide/request/RequestListener;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v1

    iget-object v3, v7, Llyiahf/vczjk/h09;->OooO00o:Ljava/lang/Object;

    check-cast v3, Lcom/bumptech/glide/request/RequestListener;

    invoke-virtual {v1, v3}, Lcom/bumptech/glide/RequestBuilder;->addListener(Lcom/bumptech/glide/request/RequestListener;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v1

    invoke-static {v1, v8}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_0

    :cond_4
    invoke-virtual {v3}, Lcom/bumptech/glide/RequestManager;->asDrawable()Lcom/bumptech/glide/RequestBuilder;

    move-result-object v3

    iget-object v4, v5, Llyiahf/vczjk/h09;->OooO00o:Ljava/lang/Object;

    invoke-virtual {v3, v4}, Lcom/bumptech/glide/RequestBuilder;->load(Ljava/lang/Object;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v3

    iget-object v4, v6, Llyiahf/vczjk/h09;->OooO00o:Ljava/lang/Object;

    check-cast v4, Lcom/bumptech/glide/request/BaseRequestOptions;

    invoke-virtual {v3, v4}, Lcom/bumptech/glide/RequestBuilder;->apply(Lcom/bumptech/glide/request/BaseRequestOptions;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v3

    invoke-virtual {v3, v1}, Lcom/bumptech/glide/RequestBuilder;->addListener(Lcom/bumptech/glide/request/RequestListener;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v1

    iget-object v3, v7, Llyiahf/vczjk/h09;->OooO00o:Ljava/lang/Object;

    check-cast v3, Lcom/bumptech/glide/request/RequestListener;

    invoke-virtual {v1, v3}, Lcom/bumptech/glide/RequestBuilder;->addListener(Lcom/bumptech/glide/request/RequestListener;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v1

    invoke-static {v1, v8}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/th3;->$imageOptions:Llyiahf/vczjk/hv3;

    iget-wide v3, v3, Llyiahf/vczjk/hv3;->OooO0o:J

    const/16 v5, 0x20

    shr-long v5, v3, v5

    long-to-int v5, v5

    if-lez v5, :cond_5

    const-wide v6, 0xffffffffL

    and-long/2addr v3, v6

    long-to-int v3, v3

    if-lez v3, :cond_5

    invoke-virtual {v1, v5, v3}, Lcom/bumptech/glide/request/BaseRequestOptions;->override(II)Lcom/bumptech/glide/request/BaseRequestOptions;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v1, Lcom/bumptech/glide/RequestBuilder;

    :cond_5
    iget-object v3, p0, Llyiahf/vczjk/th3;->$target:Llyiahf/vczjk/k43;

    invoke-virtual {v1, v3}, Lcom/bumptech/glide/RequestBuilder;->into(Lcom/bumptech/glide/request/target/Target;)Lcom/bumptech/glide/request/target/Target;

    new-instance v1, Llyiahf/vczjk/oOOO0OO0;

    const/16 v3, 0x16

    invoke-direct {v1, v3}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    iput v2, p0, Llyiahf/vczjk/th3;->label:I

    invoke-static {p1, v1, p0}, Llyiahf/vczjk/v34;->OooOOo(Llyiahf/vczjk/s77;Llyiahf/vczjk/le3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_6

    return-object v0

    :cond_6
    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
