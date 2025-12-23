.class public final Llyiahf/vczjk/lt0;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $element:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field

.field final synthetic $this_trySendBlocking:Llyiahf/vczjk/if8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/if8;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/if8;Ljava/lang/Object;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/lt0;->$this_trySendBlocking:Llyiahf/vczjk/if8;

    iput-object p2, p0, Llyiahf/vczjk/lt0;->$element:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/lt0;

    iget-object v1, p0, Llyiahf/vczjk/lt0;->$this_trySendBlocking:Llyiahf/vczjk/if8;

    iget-object v2, p0, Llyiahf/vczjk/lt0;->$element:Ljava/lang/Object;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/lt0;-><init>(Llyiahf/vczjk/if8;Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/lt0;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/lt0;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/lt0;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/lt0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/lt0;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/lt0;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    iget-object p1, p0, Llyiahf/vczjk/lt0;->$this_trySendBlocking:Llyiahf/vczjk/if8;

    iget-object v1, p0, Llyiahf/vczjk/lt0;->$element:Ljava/lang/Object;

    :try_start_1
    iput v3, p0, Llyiahf/vczjk/lt0;->label:I

    invoke-interface {p1, v1, p0}, Llyiahf/vczjk/if8;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    move-object p1, v2

    goto :goto_2

    :goto_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    :goto_2
    instance-of v0, p1, Llyiahf/vczjk/ts7;

    if-nez v0, :cond_3

    goto :goto_3

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object p1

    new-instance v2, Llyiahf/vczjk/ht0;

    invoke-direct {v2, p1}, Llyiahf/vczjk/ht0;-><init>(Ljava/lang/Throwable;)V

    :goto_3
    new-instance p1, Llyiahf/vczjk/jt0;

    invoke-direct {p1, v2}, Llyiahf/vczjk/jt0;-><init>(Ljava/lang/Object;)V

    return-object p1
.end method
