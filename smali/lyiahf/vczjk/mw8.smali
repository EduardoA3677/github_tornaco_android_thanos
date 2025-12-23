.class public final Llyiahf/vczjk/mw8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $context:Llyiahf/vczjk/or1;

.field final synthetic $this_collectAsState:Llyiahf/vczjk/f43;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/f43;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/or1;Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mw8;->$context:Llyiahf/vczjk/or1;

    iput-object p2, p0, Llyiahf/vczjk/mw8;->$this_collectAsState:Llyiahf/vczjk/f43;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/mw8;

    iget-object v1, p0, Llyiahf/vczjk/mw8;->$context:Llyiahf/vczjk/or1;

    iget-object v2, p0, Llyiahf/vczjk/mw8;->$this_collectAsState:Llyiahf/vczjk/f43;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/mw8;-><init>(Llyiahf/vczjk/or1;Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/mw8;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/p77;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/mw8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/mw8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/mw8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/mw8;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :goto_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/mw8;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/p77;

    iget-object v1, p0, Llyiahf/vczjk/mw8;->$context:Llyiahf/vczjk/or1;

    sget-object v4, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/mw8;->$this_collectAsState:Llyiahf/vczjk/f43;

    new-instance v2, Llyiahf/vczjk/l43;

    const/4 v4, 0x2

    invoke-direct {v2, p1, v4}, Llyiahf/vczjk/l43;-><init>(Llyiahf/vczjk/p77;I)V

    iput v3, p0, Llyiahf/vczjk/mw8;->label:I

    invoke-interface {v1, v2, p0}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    goto :goto_1

    :cond_3
    iget-object v1, p0, Llyiahf/vczjk/mw8;->$context:Llyiahf/vczjk/or1;

    new-instance v3, Llyiahf/vczjk/lw8;

    iget-object v4, p0, Llyiahf/vczjk/mw8;->$this_collectAsState:Llyiahf/vczjk/f43;

    const/4 v5, 0x0

    invoke-direct {v3, v4, p1, v5}, Llyiahf/vczjk/lw8;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/p77;Llyiahf/vczjk/yo1;)V

    iput v2, p0, Llyiahf/vczjk/mw8;->label:I

    invoke-static {v1, v3, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_1
    return-object v0

    :cond_4
    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
