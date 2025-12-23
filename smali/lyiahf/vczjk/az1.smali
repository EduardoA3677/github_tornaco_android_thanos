.class public final Llyiahf/vczjk/az1;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $requireLock:Z

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/jz1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/jz1;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jz1;ZLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/az1;->this$0:Llyiahf/vczjk/jz1;

    iput-boolean p2, p0, Llyiahf/vczjk/az1;->$requireLock:Z

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/az1;

    iget-object v0, p0, Llyiahf/vczjk/az1;->this$0:Llyiahf/vczjk/jz1;

    iget-boolean v1, p0, Llyiahf/vczjk/az1;->$requireLock:Z

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/az1;-><init>(Llyiahf/vczjk/jz1;ZLlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/az1;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/az1;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/az1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/az1;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_3

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/az1;->this$0:Llyiahf/vczjk/jz1;

    iget-object p1, p1, Llyiahf/vczjk/jz1;->OooO0oo:Llyiahf/vczjk/oO0OOo0o;

    invoke-virtual {p1}, Llyiahf/vczjk/oO0OOo0o;->Oooo00O()Llyiahf/vczjk/n29;

    move-result-object p1

    instance-of p1, p1, Llyiahf/vczjk/f13;

    if-eqz p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/az1;->this$0:Llyiahf/vczjk/jz1;

    iget-object p1, p1, Llyiahf/vczjk/jz1;->OooO0oo:Llyiahf/vczjk/oO0OOo0o;

    invoke-virtual {p1}, Llyiahf/vczjk/oO0OOo0o;->Oooo00O()Llyiahf/vczjk/n29;

    move-result-object p1

    return-object p1

    :cond_3
    :try_start_1
    iget-object p1, p0, Llyiahf/vczjk/az1;->this$0:Llyiahf/vczjk/jz1;

    iput v3, p0, Llyiahf/vczjk/az1;->label:I

    invoke-virtual {p1, p0}, Llyiahf/vczjk/jz1;->OooO0oo(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-ne p1, v0, :cond_4

    goto :goto_1

    :cond_4
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/az1;->this$0:Llyiahf/vczjk/jz1;

    iget-boolean v1, p0, Llyiahf/vczjk/az1;->$requireLock:Z

    iput v2, p0, Llyiahf/vczjk/az1;->label:I

    invoke-static {p1, v1, p0}, Llyiahf/vczjk/jz1;->OooO0o0(Llyiahf/vczjk/jz1;ZLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    :goto_1
    return-object v0

    :cond_5
    :goto_2
    check-cast p1, Llyiahf/vczjk/n29;

    return-object p1

    :goto_3
    new-instance v0, Llyiahf/vczjk/ug7;

    const/4 v1, -0x1

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/ug7;-><init>(ILjava/lang/Throwable;)V

    return-object v0
.end method
