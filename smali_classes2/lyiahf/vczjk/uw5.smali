.class public final Llyiahf/vczjk/uw5;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $showLoading:Z

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/vw5;


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/vw5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/uw5;->$showLoading:Z

    iput-object p2, p0, Llyiahf/vczjk/uw5;->this$0:Llyiahf/vczjk/vw5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/uw5;

    iget-boolean v0, p0, Llyiahf/vczjk/uw5;->$showLoading:Z

    iget-object v1, p0, Llyiahf/vczjk/uw5;->this$0:Llyiahf/vczjk/vw5;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/uw5;-><init>(ZLlyiahf/vczjk/vw5;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/uw5;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/uw5;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/uw5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    move-object/from16 v0, p0

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/uw5;->label:I

    const/4 v3, 0x1

    const/4 v4, 0x0

    if-eqz v2, :cond_1

    if-ne v2, v3, :cond_0

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v2, p1

    goto :goto_0

    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-boolean v2, v0, Llyiahf/vczjk/uw5;->$showLoading:Z

    if-eqz v2, :cond_2

    iget-object v2, v0, Llyiahf/vczjk/uw5;->this$0:Llyiahf/vczjk/vw5;

    iget-object v2, v2, Llyiahf/vczjk/vw5;->OooO0o:Llyiahf/vczjk/s29;

    invoke-virtual {v2}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v5

    move-object v6, v5

    check-cast v6, Llyiahf/vczjk/ow5;

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/4 v7, 0x1

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/16 v16, 0x1fe

    invoke-static/range {v6 .. v16}, Llyiahf/vczjk/ow5;->OooO00o(Llyiahf/vczjk/ow5;ZLjava/util/ArrayList;Llyiahf/vczjk/x39;Llyiahf/vczjk/oO00o0;ZZZLjava/util/List;ZI)Llyiahf/vczjk/ow5;

    move-result-object v5

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2, v4, v5}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    :cond_2
    iget-object v2, v0, Llyiahf/vczjk/uw5;->this$0:Llyiahf/vczjk/vw5;

    iput v3, v0, Llyiahf/vczjk/uw5;->label:I

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v3, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v3, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    new-instance v5, Llyiahf/vczjk/qw5;

    invoke-direct {v5, v2, v4}, Llyiahf/vczjk/qw5;-><init>(Llyiahf/vczjk/vw5;Llyiahf/vczjk/yo1;)V

    invoke-static {v3, v5, v0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v1, :cond_3

    return-object v1

    :cond_3
    :goto_0
    move-object v8, v2

    check-cast v8, Llyiahf/vczjk/x39;

    iget-object v1, v0, Llyiahf/vczjk/uw5;->this$0:Llyiahf/vczjk/vw5;

    iget-object v1, v1, Llyiahf/vczjk/vw5;->OooO0o:Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    move-object v5, v2

    check-cast v5, Llyiahf/vczjk/ow5;

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/16 v15, 0x1fa

    invoke-static/range {v5 .. v15}, Llyiahf/vczjk/ow5;->OooO00o(Llyiahf/vczjk/ow5;ZLjava/util/ArrayList;Llyiahf/vczjk/x39;Llyiahf/vczjk/oO00o0;ZZZLjava/util/List;ZI)Llyiahf/vczjk/ow5;

    move-result-object v2

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v1, v4, v2}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
