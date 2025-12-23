.class public final Llyiahf/vczjk/mj8;
.super Llyiahf/vczjk/rs7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/nj8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nj8;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mj8;->this$0:Llyiahf/vczjk/nj8;

    invoke-direct {p0, p2}, Llyiahf/vczjk/rs7;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/mj8;

    iget-object v1, p0, Llyiahf/vczjk/mj8;->this$0:Llyiahf/vczjk/nj8;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/mj8;-><init>(Llyiahf/vczjk/nj8;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/mj8;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xf8;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/mj8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/mj8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/mj8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/mj8;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_4

    const/4 v3, 0x2

    if-eq v1, v2, :cond_1

    if-ne v1, v3, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/mj8;->L$1:Ljava/lang/Object;

    check-cast v1, Ljava/util/Iterator;

    iget-object v2, p0, Llyiahf/vczjk/mj8;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/xf8;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/mj8;->L$0:Ljava/lang/Object;

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/xf8;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/mj8;->this$0:Llyiahf/vczjk/nj8;

    iget-object p1, p1, Llyiahf/vczjk/nj8;->OooO0OO:Ljava/util/ArrayList;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/nj8;

    iget-object v4, v4, Llyiahf/vczjk/nj8;->OooO0Oo:Llyiahf/vczjk/vy;

    invoke-static {v1, v4}, Llyiahf/vczjk/j21;->OoooOoO(Ljava/util/ArrayList;Llyiahf/vczjk/vy;)V

    goto :goto_0

    :cond_2
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result p1

    if-eqz p1, :cond_3

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/nj8;

    iput-object v2, p0, Llyiahf/vczjk/mj8;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/mj8;->L$1:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/mj8;->label:I

    invoke-virtual {v2, p1, p0}, Llyiahf/vczjk/xf8;->OooO0O0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object v0

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_4
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/mj8;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xf8;

    iget-object v1, p0, Llyiahf/vczjk/mj8;->this$0:Llyiahf/vczjk/nj8;

    iput-object p1, p0, Llyiahf/vczjk/mj8;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/mj8;->label:I

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/xf8;->OooO0O0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method
