.class public final Llyiahf/vczjk/fq8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $block:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $priority:I

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/gq8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gq8;ILlyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fq8;->this$0:Llyiahf/vczjk/gq8;

    iput p2, p0, Llyiahf/vczjk/fq8;->$priority:I

    iput-object p3, p0, Llyiahf/vczjk/fq8;->$block:Llyiahf/vczjk/oe3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/fq8;

    iget-object v1, p0, Llyiahf/vczjk/fq8;->this$0:Llyiahf/vczjk/gq8;

    iget v2, p0, Llyiahf/vczjk/fq8;->$priority:I

    iget-object v3, p0, Llyiahf/vczjk/fq8;->$block:Llyiahf/vczjk/oe3;

    invoke-direct {v0, v1, v2, v3, p2}, Llyiahf/vczjk/fq8;-><init>(Llyiahf/vczjk/gq8;ILlyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/fq8;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/fq8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/fq8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fq8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/fq8;->label:I

    const/4 v2, 0x4

    const/4 v3, 0x3

    const/4 v4, 0x2

    const/4 v5, 0x1

    if-eqz v1, :cond_4

    if-eq v1, v5, :cond_3

    if-eq v1, v4, :cond_2

    if-eq v1, v3, :cond_1

    if-eq v1, v2, :cond_0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/fq8;->L$0:Ljava/lang/Object;

    check-cast v0, Ljava/lang/Throwable;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_4

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_5

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/fq8;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v74;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_3
    iget-object v1, p0, Llyiahf/vczjk/fq8;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v74;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_4
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/fq8;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    invoke-interface {p1}, Llyiahf/vczjk/xr1;->OoooOO0()Llyiahf/vczjk/or1;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/ws7;->OooOOo0:Llyiahf/vczjk/ws7;

    invoke-interface {p1, v1}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p1

    if-eqz p1, :cond_9

    check-cast p1, Llyiahf/vczjk/v74;

    iget-object v1, p0, Llyiahf/vczjk/fq8;->this$0:Llyiahf/vczjk/gq8;

    iget-object v1, v1, Llyiahf/vczjk/gq8;->OooO00o:Llyiahf/vczjk/dq8;

    iget v6, p0, Llyiahf/vczjk/fq8;->$priority:I

    iput-object p1, p0, Llyiahf/vczjk/fq8;->L$0:Ljava/lang/Object;

    iput v5, p0, Llyiahf/vczjk/fq8;->label:I

    invoke-virtual {v1, v6, p1, p0}, Llyiahf/vczjk/dq8;->OooO0O0(ILlyiahf/vczjk/v74;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_5

    goto :goto_3

    :cond_5
    move-object v7, v1

    move-object v1, p1

    move-object p1, v7

    :goto_0
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-eqz p1, :cond_8

    :try_start_1
    iget-object p1, p0, Llyiahf/vczjk/fq8;->$block:Llyiahf/vczjk/oe3;

    iput-object v1, p0, Llyiahf/vczjk/fq8;->L$0:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/fq8;->label:I

    invoke-interface {p1, p0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-ne p1, v0, :cond_6

    goto :goto_3

    :cond_6
    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/fq8;->this$0:Llyiahf/vczjk/gq8;

    iget-object p1, p1, Llyiahf/vczjk/gq8;->OooO00o:Llyiahf/vczjk/dq8;

    const/4 v2, 0x0

    iput-object v2, p0, Llyiahf/vczjk/fq8;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/fq8;->label:I

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/dq8;->OooO00o(Llyiahf/vczjk/v74;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_8

    goto :goto_3

    :goto_2
    iget-object v3, p0, Llyiahf/vczjk/fq8;->this$0:Llyiahf/vczjk/gq8;

    iget-object v3, v3, Llyiahf/vczjk/gq8;->OooO00o:Llyiahf/vczjk/dq8;

    iput-object p1, p0, Llyiahf/vczjk/fq8;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/fq8;->label:I

    invoke-virtual {v3, v1, p0}, Llyiahf/vczjk/dq8;->OooO00o(Llyiahf/vczjk/v74;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_7

    :goto_3
    return-object v0

    :cond_7
    move-object v0, p1

    :goto_4
    throw v0

    :cond_8
    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_9
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Internal error. coroutineScope should\'ve created a job."

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
