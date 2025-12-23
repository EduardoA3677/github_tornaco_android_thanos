.class public final Llyiahf/vczjk/rd;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$this$launchTextInputSession:Llyiahf/vczjk/ux6;

.field final synthetic $initializeRequest:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $node:Llyiahf/vczjk/ex4;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/td;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ux6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/td;Llyiahf/vczjk/ex4;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/rd;->$$this$launchTextInputSession:Llyiahf/vczjk/ux6;

    iput-object p2, p0, Llyiahf/vczjk/rd;->$initializeRequest:Llyiahf/vczjk/oe3;

    iput-object p3, p0, Llyiahf/vczjk/rd;->this$0:Llyiahf/vczjk/td;

    iput-object p4, p0, Llyiahf/vczjk/rd;->$node:Llyiahf/vczjk/ex4;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/rd;

    iget-object v1, p0, Llyiahf/vczjk/rd;->$$this$launchTextInputSession:Llyiahf/vczjk/ux6;

    iget-object v2, p0, Llyiahf/vczjk/rd;->$initializeRequest:Llyiahf/vczjk/oe3;

    iget-object v3, p0, Llyiahf/vczjk/rd;->this$0:Llyiahf/vczjk/td;

    iget-object v4, p0, Llyiahf/vczjk/rd;->$node:Llyiahf/vczjk/ex4;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/rd;-><init>(Llyiahf/vczjk/ux6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/td;Llyiahf/vczjk/ex4;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/rd;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/rd;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/rd;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/rd;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/rd;->label:I

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eqz v1, :cond_1

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
    move-exception p1

    goto :goto_0

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/rd;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    sget-object v1, Llyiahf/vczjk/hx4;->OooO00o:Llyiahf/vczjk/gx4;

    iget-object v4, p0, Llyiahf/vczjk/rd;->$$this$launchTextInputSession:Llyiahf/vczjk/ux6;

    check-cast v4, Llyiahf/vczjk/af;

    iget-object v4, v4, Llyiahf/vczjk/af;->OooOOO0:Landroid/view/View;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/p04;

    invoke-direct {v1, v4}, Llyiahf/vczjk/p04;-><init>(Landroid/view/View;)V

    new-instance v4, Llyiahf/vczjk/nx4;

    iget-object v5, p0, Llyiahf/vczjk/rd;->$$this$launchTextInputSession:Llyiahf/vczjk/ux6;

    check-cast v5, Llyiahf/vczjk/af;

    iget-object v5, v5, Llyiahf/vczjk/af;->OooOOO0:Landroid/view/View;

    new-instance v6, Llyiahf/vczjk/qd;

    iget-object v7, p0, Llyiahf/vczjk/rd;->$node:Llyiahf/vczjk/ex4;

    invoke-direct {v6, v7}, Llyiahf/vczjk/qd;-><init>(Llyiahf/vczjk/ex4;)V

    invoke-direct {v4, v5, v6, v1}, Llyiahf/vczjk/nx4;-><init>(Landroid/view/View;Llyiahf/vczjk/qd;Llyiahf/vczjk/p04;)V

    sget-boolean v5, Llyiahf/vczjk/o79;->OooO00o:Z

    if-eqz v5, :cond_2

    new-instance v5, Llyiahf/vczjk/pd;

    iget-object v6, p0, Llyiahf/vczjk/rd;->this$0:Llyiahf/vczjk/td;

    invoke-direct {v5, v6, v1, v2}, Llyiahf/vczjk/pd;-><init>(Llyiahf/vczjk/td;Llyiahf/vczjk/l04;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    invoke-static {p1, v2, v2, v5, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/rd;->$initializeRequest:Llyiahf/vczjk/oe3;

    if-eqz p1, :cond_3

    invoke-interface {p1, v4}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_3
    iget-object p1, p0, Llyiahf/vczjk/rd;->this$0:Llyiahf/vczjk/td;

    iput-object v4, p1, Llyiahf/vczjk/td;->OooO0OO:Llyiahf/vczjk/nx4;

    :try_start_1
    iget-object p1, p0, Llyiahf/vczjk/rd;->$$this$launchTextInputSession:Llyiahf/vczjk/ux6;

    iput v3, p0, Llyiahf/vczjk/rd;->label:I

    check-cast p1, Llyiahf/vczjk/af;

    invoke-virtual {p1, v4, p0}, Llyiahf/vczjk/af;->OooO00o(Llyiahf/vczjk/nx4;Llyiahf/vczjk/zo1;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    return-object v0

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/rd;->this$0:Llyiahf/vczjk/td;

    iput-object v2, v0, Llyiahf/vczjk/td;->OooO0OO:Llyiahf/vczjk/nx4;

    throw p1
.end method
