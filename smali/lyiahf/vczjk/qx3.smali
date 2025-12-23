.class public final Llyiahf/vczjk/qx3;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/vx3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vx3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qx3;->this$0:Llyiahf/vczjk/vx3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/qx3;

    iget-object v0, p0, Llyiahf/vczjk/qx3;->this$0:Llyiahf/vczjk/vx3;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/qx3;-><init>(Llyiahf/vczjk/vx3;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/qx3;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/qx3;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/qx3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/qx3;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/qx3;->this$0:Llyiahf/vczjk/vx3;

    iget-object v3, p1, Llyiahf/vczjk/vx3;->Oooo0O0:Llyiahf/vczjk/gi;

    if-eqz v3, :cond_5

    iget-object v1, p1, Llyiahf/vczjk/vx3;->Oooo0:Llyiahf/vczjk/ei9;

    if-nez v1, :cond_2

    sget-object v1, Llyiahf/vczjk/li9;->OooO00o:Llyiahf/vczjk/li9;

    sget-object v1, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-static {p1, v1}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/x21;

    sget-object v4, Llyiahf/vczjk/jn9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-static {p1, v4}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/in9;

    invoke-static {v1, p1}, Llyiahf/vczjk/li9;->OooO0OO(Llyiahf/vczjk/x21;Llyiahf/vczjk/in9;)Llyiahf/vczjk/ei9;

    move-result-object v1

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/qx3;->this$0:Llyiahf/vczjk/vx3;

    iget-boolean v4, p1, Llyiahf/vczjk/vx3;->OooOoo:Z

    iget-boolean p1, p1, Llyiahf/vczjk/vx3;->Oooo00O:Z

    const/4 v5, 0x0

    invoke-virtual {v1, v4, v5, p1}, Llyiahf/vczjk/ei9;->OooO0OO(ZZZ)J

    move-result-wide v4

    move-wide v5, v4

    new-instance v4, Llyiahf/vczjk/n21;

    invoke-direct {v4, v5, v6}, Llyiahf/vczjk/n21;-><init>(J)V

    iget-object p1, p0, Llyiahf/vczjk/qx3;->this$0:Llyiahf/vczjk/vx3;

    iget-boolean v1, p1, Llyiahf/vczjk/vx3;->OooOoo:Z

    if-eqz v1, :cond_3

    sget-object v1, Llyiahf/vczjk/we5;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-static {p1, v1}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/yo5;

    sget-object v1, Llyiahf/vczjk/zo5;->OooOOOo:Llyiahf/vczjk/zo5;

    invoke-static {p1, v1}, Llyiahf/vczjk/so8;->OooOoo0(Llyiahf/vczjk/yo5;Llyiahf/vczjk/zo5;)Llyiahf/vczjk/p13;

    move-result-object p1

    :goto_0
    move-object v5, p1

    goto :goto_1

    :cond_3
    invoke-static {}, Llyiahf/vczjk/ng0;->OoooOOo()Llyiahf/vczjk/ev8;

    move-result-object p1

    goto :goto_0

    :goto_1
    iput v2, p0, Llyiahf/vczjk/qx3;->label:I

    const/4 v6, 0x0

    const/16 v8, 0xc

    move-object v7, p0

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/gi;->OooO0O0(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/wl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    return-object v0

    :cond_4
    :goto_2
    check-cast p1, Llyiahf/vczjk/el;

    :cond_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
