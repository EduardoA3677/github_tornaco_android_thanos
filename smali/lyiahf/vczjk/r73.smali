.class public final Llyiahf/vczjk/r73;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $this_asFlow:Llyiahf/vczjk/m25;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/m25;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/m25;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/r73;->$this_asFlow:Llyiahf/vczjk/m25;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/r73;

    iget-object v1, p0, Llyiahf/vczjk/r73;->$this_asFlow:Llyiahf/vczjk/m25;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/r73;-><init>(Llyiahf/vczjk/m25;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/r73;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/s77;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/r73;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/r73;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/r73;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/r73;->label:I

    const/4 v2, 0x0

    const/4 v3, 0x3

    const/4 v4, 0x2

    const/4 v5, 0x1

    if-eqz v1, :cond_3

    if-eq v1, v5, :cond_2

    if-eq v1, v4, :cond_1

    if-eq v1, v3, :cond_0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/r73;->L$0:Ljava/lang/Object;

    check-cast v0, Ljava/lang/Throwable;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/r73;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/k86;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/r73;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/k86;

    :try_start_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/r73;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s77;

    new-instance v1, Llyiahf/vczjk/dc0;

    const/4 v6, 0x7

    invoke-direct {v1, p1, v6}, Llyiahf/vczjk/dc0;-><init>(Ljava/lang/Object;I)V

    :try_start_2
    sget-object p1, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object p1, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    iget-object p1, p1, Llyiahf/vczjk/xl3;->OooOOo:Llyiahf/vczjk/xl3;

    new-instance v6, Llyiahf/vczjk/p73;

    iget-object v7, p0, Llyiahf/vczjk/r73;->$this_asFlow:Llyiahf/vczjk/m25;

    invoke-direct {v6, v7, v1, v2}, Llyiahf/vczjk/p73;-><init>(Llyiahf/vczjk/m25;Llyiahf/vczjk/k86;Llyiahf/vczjk/yo1;)V

    iput-object v1, p0, Llyiahf/vczjk/r73;->L$0:Ljava/lang/Object;

    iput v5, p0, Llyiahf/vczjk/r73;->label:I

    invoke-static {p1, v6, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    goto :goto_2

    :cond_4
    :goto_0
    iput-object v1, p0, Llyiahf/vczjk/r73;->L$0:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/r73;->label:I

    invoke-static {p0}, Llyiahf/vczjk/yi4;->OooOooO(Llyiahf/vczjk/zo1;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    return-object v0

    :goto_1
    sget-object v4, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v4, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    iget-object v4, v4, Llyiahf/vczjk/xl3;->OooOOo:Llyiahf/vczjk/xl3;

    sget-object v5, Llyiahf/vczjk/h26;->OooOOO:Llyiahf/vczjk/h26;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4, v5}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v4

    new-instance v5, Llyiahf/vczjk/q73;

    iget-object v6, p0, Llyiahf/vczjk/r73;->$this_asFlow:Llyiahf/vczjk/m25;

    invoke-direct {v5, v6, v1, v2}, Llyiahf/vczjk/q73;-><init>(Llyiahf/vczjk/m25;Llyiahf/vczjk/k86;Llyiahf/vczjk/yo1;)V

    iput-object p1, p0, Llyiahf/vczjk/r73;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/r73;->label:I

    invoke-static {v4, v5, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_5

    :goto_2
    return-object v0

    :cond_5
    move-object v0, p1

    :goto_3
    throw v0
.end method
