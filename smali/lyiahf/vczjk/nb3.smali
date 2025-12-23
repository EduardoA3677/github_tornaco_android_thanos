.class public final Llyiahf/vczjk/nb3;
.super Llyiahf/vczjk/rs7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $block:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $currentContext:Llyiahf/vczjk/or1;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nb3;->$currentContext:Llyiahf/vczjk/or1;

    iput-object p2, p0, Llyiahf/vczjk/nb3;->$block:Llyiahf/vczjk/ze3;

    invoke-direct {p0, p3}, Llyiahf/vczjk/rs7;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/nb3;

    iget-object v1, p0, Llyiahf/vczjk/nb3;->$currentContext:Llyiahf/vczjk/or1;

    iget-object v2, p0, Llyiahf/vczjk/nb3;->$block:Llyiahf/vczjk/ze3;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/nb3;-><init>(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/nb3;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/kb9;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/nb3;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/nb3;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/nb3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/nb3;->label:I

    const/4 v2, 0x3

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v1, :cond_4

    if-eq v1, v4, :cond_3

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/nb3;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/kb9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/nb3;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/kb9;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0

    :cond_2
    :goto_0
    move-object p1, v1

    goto :goto_1

    :catch_0
    move-exception p1

    goto :goto_3

    :cond_3
    iget-object v1, p0, Llyiahf/vczjk/nb3;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/kb9;

    :try_start_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0

    goto :goto_2

    :cond_4
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/nb3;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/kb9;

    :goto_1
    iget-object v1, p0, Llyiahf/vczjk/nb3;->$currentContext:Llyiahf/vczjk/or1;

    invoke-static {v1}, Llyiahf/vczjk/zsa;->Oooooo0(Llyiahf/vczjk/or1;)Z

    move-result v1

    if-eqz v1, :cond_7

    :try_start_2
    iget-object v1, p0, Llyiahf/vczjk/nb3;->$block:Llyiahf/vczjk/ze3;

    iput-object p1, p0, Llyiahf/vczjk/nb3;->L$0:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/nb3;->label:I

    invoke-interface {v1, p1, p0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1
    :try_end_2
    .catch Ljava/util/concurrent/CancellationException; {:try_start_2 .. :try_end_2} :catch_1

    if-ne v1, v0, :cond_5

    goto :goto_4

    :cond_5
    move-object v1, p1

    :goto_2
    :try_start_3
    iput-object v1, p0, Llyiahf/vczjk/nb3;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/nb3;->label:I

    sget-object p1, Llyiahf/vczjk/fy6;->OooOOOO:Llyiahf/vczjk/fy6;

    invoke-static {v1, p1, p0}, Llyiahf/vczjk/u34;->OooO0Oo(Llyiahf/vczjk/kb9;Llyiahf/vczjk/fy6;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object p1
    :try_end_3
    .catch Ljava/util/concurrent/CancellationException; {:try_start_3 .. :try_end_3} :catch_0

    if-ne p1, v0, :cond_2

    goto :goto_4

    :catch_1
    move-exception v1

    move-object v6, v1

    move-object v1, p1

    move-object p1, v6

    :goto_3
    iget-object v5, p0, Llyiahf/vczjk/nb3;->$currentContext:Llyiahf/vczjk/or1;

    invoke-static {v5}, Llyiahf/vczjk/zsa;->Oooooo0(Llyiahf/vczjk/or1;)Z

    move-result v5

    if-eqz v5, :cond_6

    iput-object v1, p0, Llyiahf/vczjk/nb3;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/nb3;->label:I

    sget-object p1, Llyiahf/vczjk/fy6;->OooOOOO:Llyiahf/vczjk/fy6;

    invoke-static {v1, p1, p0}, Llyiahf/vczjk/u34;->OooO0Oo(Llyiahf/vczjk/kb9;Llyiahf/vczjk/fy6;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    :goto_4
    return-object v0

    :cond_6
    throw p1

    :cond_7
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
