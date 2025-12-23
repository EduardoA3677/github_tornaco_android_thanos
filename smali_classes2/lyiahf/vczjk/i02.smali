.class public final Llyiahf/vczjk/i02;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/k02;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k02;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/i02;->this$0:Llyiahf/vczjk/k02;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/i02;

    iget-object v0, p0, Llyiahf/vczjk/i02;->this$0:Llyiahf/vczjk/k02;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/i02;-><init>(Llyiahf/vczjk/k02;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/i02;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/i02;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/i02;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/i02;->label:I

    if-nez v1, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/i02;->this$0:Llyiahf/vczjk/k02;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/k02;->OooO0o0(Llyiahf/vczjk/k02;)Ljava/util/ArrayList;

    move-result-object v1

    iget-object p1, p1, Llyiahf/vczjk/k02;->OooO0Oo:Llyiahf/vczjk/s29;

    invoke-virtual {p1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/m02;

    const/4 v3, 0x2

    const/4 v4, 0x0

    invoke-static {v2, v1, v4, v3}, Llyiahf/vczjk/m02;->OooO00o(Llyiahf/vczjk/m02;Ljava/util/ArrayList;Ljava/util/List;I)Llyiahf/vczjk/m02;

    move-result-object v1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1, v4, v1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    move-object p1, v0

    goto :goto_0

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    :goto_0
    invoke-static {p1}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object p1

    if-eqz p1, :cond_0

    const-string v1, "loadPendingWorks error"

    invoke-static {v1, p1}, Llyiahf/vczjk/zsa;->Oooo0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    :cond_0
    return-object v0

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
