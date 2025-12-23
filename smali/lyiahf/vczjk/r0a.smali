.class public final Llyiahf/vczjk/r0a;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $emitInitialState:Z

.field final synthetic $resolvedTableNames:[Ljava/lang/String;

.field final synthetic $tableIds:[I

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/b1a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/b1a;[IZ[Ljava/lang/String;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/r0a;->this$0:Llyiahf/vczjk/b1a;

    iput-object p2, p0, Llyiahf/vczjk/r0a;->$tableIds:[I

    iput-boolean p3, p0, Llyiahf/vczjk/r0a;->$emitInitialState:Z

    iput-object p4, p0, Llyiahf/vczjk/r0a;->$resolvedTableNames:[Ljava/lang/String;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/r0a;

    iget-object v1, p0, Llyiahf/vczjk/r0a;->this$0:Llyiahf/vczjk/b1a;

    iget-object v2, p0, Llyiahf/vczjk/r0a;->$tableIds:[I

    iget-boolean v3, p0, Llyiahf/vczjk/r0a;->$emitInitialState:Z

    iget-object v4, p0, Llyiahf/vczjk/r0a;->$resolvedTableNames:[Ljava/lang/String;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/r0a;-><init>(Llyiahf/vczjk/b1a;[IZ[Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/r0a;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/r0a;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/r0a;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/r0a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/r0a;->label:I

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
    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :catchall_0
    move-exception v0

    move-object p1, v0

    goto/16 :goto_4

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/r0a;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/h43;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/r0a;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/h43;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/r0a;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/h43;

    iget-object v1, p0, Llyiahf/vczjk/r0a;->this$0:Llyiahf/vczjk/b1a;

    iget-object v1, v1, Llyiahf/vczjk/b1a;->OooO0oo:Llyiahf/vczjk/zu1;

    iget-object v6, p0, Llyiahf/vczjk/r0a;->$tableIds:[I

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zu1;->OooO([I)Z

    move-result v1

    if-eqz v1, :cond_6

    iget-object v1, p0, Llyiahf/vczjk/r0a;->this$0:Llyiahf/vczjk/b1a;

    iget-object v1, v1, Llyiahf/vczjk/b1a;->OooO00o:Llyiahf/vczjk/ru7;

    iput-object p1, p0, Llyiahf/vczjk/r0a;->L$0:Ljava/lang/Object;

    iput v5, p0, Llyiahf/vczjk/r0a;->label:I

    invoke-static {v1, p0}, Llyiahf/vczjk/u34;->OooOo0o(Llyiahf/vczjk/ru7;Llyiahf/vczjk/zo1;)Llyiahf/vczjk/or1;

    move-result-object v1

    if-ne v1, v0, :cond_4

    goto :goto_1

    :cond_4
    move-object v10, v1

    move-object v1, p1

    move-object p1, v10

    :goto_0
    check-cast p1, Llyiahf/vczjk/or1;

    new-instance v5, Llyiahf/vczjk/o0a;

    iget-object v6, p0, Llyiahf/vczjk/r0a;->this$0:Llyiahf/vczjk/b1a;

    invoke-direct {v5, v6, v2}, Llyiahf/vczjk/o0a;-><init>(Llyiahf/vczjk/b1a;Llyiahf/vczjk/yo1;)V

    iput-object v1, p0, Llyiahf/vczjk/r0a;->L$0:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/r0a;->label:I

    invoke-static {p1, v5, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    :goto_1
    return-object v0

    :cond_5
    :goto_2
    move-object v7, v1

    goto :goto_3

    :cond_6
    move-object v7, p1

    :goto_3
    :try_start_1
    new-instance v5, Llyiahf/vczjk/hl7;

    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    iget-object p1, p0, Llyiahf/vczjk/r0a;->this$0:Llyiahf/vczjk/b1a;

    iget-object p1, p1, Llyiahf/vczjk/b1a;->OooO:Llyiahf/vczjk/i86;

    new-instance v4, Llyiahf/vczjk/q0a;

    iget-boolean v6, p0, Llyiahf/vczjk/r0a;->$emitInitialState:Z

    iget-object v8, p0, Llyiahf/vczjk/r0a;->$resolvedTableNames:[Ljava/lang/String;

    iget-object v9, p0, Llyiahf/vczjk/r0a;->$tableIds:[I

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/q0a;-><init>(Llyiahf/vczjk/hl7;ZLlyiahf/vczjk/h43;[Ljava/lang/String;[I)V

    iput-object v2, p0, Llyiahf/vczjk/r0a;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/r0a;->label:I

    invoke-virtual {p1, v4, p0}, Llyiahf/vczjk/i86;->OooO00o(Llyiahf/vczjk/q0a;Llyiahf/vczjk/zo1;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    return-object v0

    :goto_4
    iget-object v0, p0, Llyiahf/vczjk/r0a;->this$0:Llyiahf/vczjk/b1a;

    iget-object v0, v0, Llyiahf/vczjk/b1a;->OooO0oo:Llyiahf/vczjk/zu1;

    iget-object v1, p0, Llyiahf/vczjk/r0a;->$tableIds:[I

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zu1;->OooOO0([I)Z

    throw p1
.end method
