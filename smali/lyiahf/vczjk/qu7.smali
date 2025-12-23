.class public final Llyiahf/vczjk/qu7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $hasForeignKeys:Z

.field final synthetic $tableNames:[Ljava/lang/String;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ru7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ru7;Z[Ljava/lang/String;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qu7;->this$0:Llyiahf/vczjk/ru7;

    iput-boolean p2, p0, Llyiahf/vczjk/qu7;->$hasForeignKeys:Z

    iput-object p3, p0, Llyiahf/vczjk/qu7;->$tableNames:[Ljava/lang/String;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/qu7;

    iget-object v0, p0, Llyiahf/vczjk/qu7;->this$0:Llyiahf/vczjk/ru7;

    iget-boolean v1, p0, Llyiahf/vczjk/qu7;->$hasForeignKeys:Z

    iget-object v2, p0, Llyiahf/vczjk/qu7;->$tableNames:[Ljava/lang/String;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/qu7;-><init>(Llyiahf/vczjk/ru7;Z[Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/qu7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/qu7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/qu7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/qu7;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/qu7;->this$0:Llyiahf/vczjk/ru7;

    invoke-static {p1}, Llyiahf/vczjk/ru7;->access$getConnectionManager$p(Llyiahf/vczjk/ru7;)Llyiahf/vczjk/ju7;

    move-result-object p1

    const/4 v1, 0x0

    if-eqz p1, :cond_3

    new-instance v3, Llyiahf/vczjk/pu7;

    iget-object v4, p0, Llyiahf/vczjk/qu7;->this$0:Llyiahf/vczjk/ru7;

    iget-boolean v5, p0, Llyiahf/vczjk/qu7;->$hasForeignKeys:Z

    iget-object v6, p0, Llyiahf/vczjk/qu7;->$tableNames:[Ljava/lang/String;

    invoke-direct {v3, v4, v5, v6, v1}, Llyiahf/vczjk/pu7;-><init>(Llyiahf/vczjk/ru7;Z[Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    iput v2, p0, Llyiahf/vczjk/qu7;->label:I

    iget-object p1, p1, Llyiahf/vczjk/ju7;->OooO0o:Llyiahf/vczjk/fi1;

    const/4 v1, 0x0

    invoke-interface {p1, v1, v3, p0}, Llyiahf/vczjk/fi1;->OooOo00(ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_3
    const-string p1, "connectionManager"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1
.end method
