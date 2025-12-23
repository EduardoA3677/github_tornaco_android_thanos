.class public final Llyiahf/vczjk/ez1;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $transform:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/jz1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/jz1;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jz1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ez1;->this$0:Llyiahf/vczjk/jz1;

    iput-object p2, p0, Llyiahf/vczjk/ez1;->$transform:Llyiahf/vczjk/ze3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/ez1;

    iget-object v1, p0, Llyiahf/vczjk/ez1;->this$0:Llyiahf/vczjk/jz1;

    iget-object v2, p0, Llyiahf/vczjk/ez1;->$transform:Llyiahf/vczjk/ze3;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/ez1;-><init>(Llyiahf/vczjk/jz1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/ez1;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ez1;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ez1;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ez1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ez1;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ez1;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    invoke-static {}, Llyiahf/vczjk/l4a;->OooO0O0()Llyiahf/vczjk/v51;

    move-result-object v1

    iget-object v3, p0, Llyiahf/vczjk/ez1;->this$0:Llyiahf/vczjk/jz1;

    iget-object v3, v3, Llyiahf/vczjk/jz1;->OooO0oo:Llyiahf/vczjk/oO0OOo0o;

    invoke-virtual {v3}, Llyiahf/vczjk/oO0OOo0o;->Oooo00O()Llyiahf/vczjk/n29;

    move-result-object v3

    new-instance v4, Llyiahf/vczjk/ni5;

    iget-object v5, p0, Llyiahf/vczjk/ez1;->$transform:Llyiahf/vczjk/ze3;

    invoke-interface {p1}, Llyiahf/vczjk/xr1;->OoooOO0()Llyiahf/vczjk/or1;

    move-result-object p1

    invoke-direct {v4, v5, v1, v3, p1}, Llyiahf/vczjk/ni5;-><init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/v51;Llyiahf/vczjk/n29;Llyiahf/vczjk/or1;)V

    iget-object p1, p0, Llyiahf/vczjk/ez1;->this$0:Llyiahf/vczjk/jz1;

    iget-object p1, p1, Llyiahf/vczjk/jz1;->OooOO0o:Llyiahf/vczjk/zn8;

    iget-object v3, p1, Llyiahf/vczjk/zn8;->OooO0OO:Llyiahf/vczjk/jj0;

    invoke-interface {v3, v4}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    instance-of v4, v3, Llyiahf/vczjk/ht0;

    const/4 v5, 0x0

    if-eqz v4, :cond_5

    if-eqz v3, :cond_2

    check-cast v3, Llyiahf/vczjk/ht0;

    goto :goto_0

    :cond_2
    move-object v3, v5

    :goto_0
    if-eqz v3, :cond_3

    iget-object v5, v3, Llyiahf/vczjk/ht0;->OooO00o:Ljava/lang/Throwable;

    :cond_3
    if-nez v5, :cond_4

    new-instance v5, Llyiahf/vczjk/p01;

    const-string p1, "Channel was closed normally"

    invoke-direct {v5, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    :cond_4
    throw v5

    :cond_5
    instance-of v3, v3, Llyiahf/vczjk/it0;

    if-nez v3, :cond_8

    iget-object v3, p1, Llyiahf/vczjk/zn8;->OooO0Oo:Llyiahf/vczjk/oO0OOo0o;

    iget-object v3, v3, Llyiahf/vczjk/oO0OOo0o;->OooOOO:Ljava/lang/Object;

    check-cast v3, Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-virtual {v3}, Ljava/util/concurrent/atomic/AtomicInteger;->getAndIncrement()I

    move-result v3

    if-nez v3, :cond_6

    new-instance v3, Llyiahf/vczjk/yn8;

    invoke-direct {v3, p1, v5}, Llyiahf/vczjk/yn8;-><init>(Llyiahf/vczjk/zn8;Llyiahf/vczjk/yo1;)V

    iget-object p1, p1, Llyiahf/vczjk/zn8;->OooO00o:Llyiahf/vczjk/xr1;

    const/4 v4, 0x3

    invoke-static {p1, v5, v5, v3, v4}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_6
    iput v2, p0, Llyiahf/vczjk/ez1;->label:I

    invoke-virtual {v1, p0}, Llyiahf/vczjk/k84;->OooOOo0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_7

    return-object v0

    :cond_7
    return-object p1

    :cond_8
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Check failed."

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
