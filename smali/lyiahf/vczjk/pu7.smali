.class public final Llyiahf/vczjk/pu7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $hasForeignKeys:Z

.field final synthetic $tableNames:[Ljava/lang/String;

.field synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ru7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ru7;Z[Ljava/lang/String;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pu7;->this$0:Llyiahf/vczjk/ru7;

    iput-boolean p2, p0, Llyiahf/vczjk/pu7;->$hasForeignKeys:Z

    iput-object p3, p0, Llyiahf/vczjk/pu7;->$tableNames:[Ljava/lang/String;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/pu7;

    iget-object v1, p0, Llyiahf/vczjk/pu7;->this$0:Llyiahf/vczjk/ru7;

    iget-boolean v2, p0, Llyiahf/vczjk/pu7;->$hasForeignKeys:Z

    iget-object v3, p0, Llyiahf/vczjk/pu7;->$tableNames:[Ljava/lang/String;

    invoke-direct {v0, v1, v2, v3, p2}, Llyiahf/vczjk/pu7;-><init>(Llyiahf/vczjk/ru7;Z[Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/pu7;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/ay9;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/pu7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/pu7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/pu7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/pu7;->label:I

    const/4 v2, 0x0

    packed-switch v1, :pswitch_data_0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_6

    :pswitch_1
    iget-object v1, p0, Llyiahf/vczjk/pu7;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ay9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_4

    :pswitch_2
    iget-object v1, p0, Llyiahf/vczjk/pu7;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ay9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_3

    :pswitch_3
    iget-object v1, p0, Llyiahf/vczjk/pu7;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ay9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :pswitch_4
    iget-object v1, p0, Llyiahf/vczjk/pu7;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ay9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :pswitch_5
    iget-object v1, p0, Llyiahf/vczjk/pu7;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ay9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :pswitch_6
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/pu7;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/ay9;

    iput-object p1, p0, Llyiahf/vczjk/pu7;->L$0:Ljava/lang/Object;

    const/4 v1, 0x1

    iput v1, p0, Llyiahf/vczjk/pu7;->label:I

    invoke-interface {p1, p0}, Llyiahf/vczjk/ay9;->OooO0OO(Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_0

    goto :goto_5

    :cond_0
    move-object v6, v1

    move-object v1, p1

    move-object p1, v6

    :goto_0
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-nez p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/pu7;->this$0:Llyiahf/vczjk/ru7;

    invoke-virtual {p1}, Llyiahf/vczjk/ru7;->getInvalidationTracker()Llyiahf/vczjk/q44;

    move-result-object p1

    iput-object v1, p0, Llyiahf/vczjk/pu7;->L$0:Ljava/lang/Object;

    const/4 v3, 0x2

    iput v3, p0, Llyiahf/vczjk/pu7;->label:I

    invoke-virtual {p1, p0}, Llyiahf/vczjk/q44;->OooO00o(Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_1

    goto :goto_5

    :cond_1
    :goto_1
    sget-object p1, Llyiahf/vczjk/zx9;->OooOOO:Llyiahf/vczjk/zx9;

    new-instance v3, Llyiahf/vczjk/ou7;

    iget-boolean v4, p0, Llyiahf/vczjk/pu7;->$hasForeignKeys:Z

    iget-object v5, p0, Llyiahf/vczjk/pu7;->$tableNames:[Ljava/lang/String;

    invoke-direct {v3, v4, v5, v2}, Llyiahf/vczjk/ou7;-><init>(Z[Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    iput-object v1, p0, Llyiahf/vczjk/pu7;->L$0:Ljava/lang/Object;

    const/4 v4, 0x3

    iput v4, p0, Llyiahf/vczjk/pu7;->label:I

    invoke-interface {v1, p1, v3, p0}, Llyiahf/vczjk/ay9;->OooO0O0(Llyiahf/vczjk/zx9;Llyiahf/vczjk/ze3;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto :goto_5

    :cond_2
    :goto_2
    iput-object v1, p0, Llyiahf/vczjk/pu7;->L$0:Ljava/lang/Object;

    const/4 p1, 0x4

    iput p1, p0, Llyiahf/vczjk/pu7;->label:I

    invoke-interface {v1, p0}, Llyiahf/vczjk/ay9;->OooO0OO(Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_5

    :cond_3
    :goto_3
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-nez p1, :cond_6

    iput-object v1, p0, Llyiahf/vczjk/pu7;->L$0:Ljava/lang/Object;

    const/4 p1, 0x5

    iput p1, p0, Llyiahf/vczjk/pu7;->label:I

    const-string p1, "PRAGMA wal_checkpoint(FULL)"

    invoke-static {v1, p1, p0}, Llyiahf/vczjk/rl6;->OooOOO0(Llyiahf/vczjk/gz6;Ljava/lang/String;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    goto :goto_5

    :cond_4
    :goto_4
    iput-object v2, p0, Llyiahf/vczjk/pu7;->L$0:Ljava/lang/Object;

    const/4 p1, 0x6

    iput p1, p0, Llyiahf/vczjk/pu7;->label:I

    const-string p1, "VACUUM"

    invoke-static {v1, p1, p0}, Llyiahf/vczjk/rl6;->OooOOO0(Llyiahf/vczjk/gz6;Ljava/lang/String;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    :goto_5
    return-object v0

    :cond_5
    :goto_6
    iget-object p1, p0, Llyiahf/vczjk/pu7;->this$0:Llyiahf/vczjk/ru7;

    invoke-virtual {p1}, Llyiahf/vczjk/ru7;->getInvalidationTracker()Llyiahf/vczjk/q44;

    move-result-object p1

    iget-object v0, p1, Llyiahf/vczjk/q44;->OooO0oO:Llyiahf/vczjk/n44;

    iget-object v1, p1, Llyiahf/vczjk/q44;->OooO0OO:Llyiahf/vczjk/b1a;

    iget-object p1, p1, Llyiahf/vczjk/q44;->OooO0o:Llyiahf/vczjk/n44;

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/b1a;->OooO0o0(Llyiahf/vczjk/n44;Llyiahf/vczjk/n44;)V

    :cond_6
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
