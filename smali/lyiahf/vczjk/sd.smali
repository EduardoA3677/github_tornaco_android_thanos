.class public final Llyiahf/vczjk/sd;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
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
.method public constructor <init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/td;Llyiahf/vczjk/ex4;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sd;->$initializeRequest:Llyiahf/vczjk/oe3;

    iput-object p2, p0, Llyiahf/vczjk/sd;->this$0:Llyiahf/vczjk/td;

    iput-object p3, p0, Llyiahf/vczjk/sd;->$node:Llyiahf/vczjk/ex4;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/sd;

    iget-object v1, p0, Llyiahf/vczjk/sd;->$initializeRequest:Llyiahf/vczjk/oe3;

    iget-object v2, p0, Llyiahf/vczjk/sd;->this$0:Llyiahf/vczjk/td;

    iget-object v3, p0, Llyiahf/vczjk/sd;->$node:Llyiahf/vczjk/ex4;

    invoke-direct {v0, v1, v2, v3, p2}, Llyiahf/vczjk/sd;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/td;Llyiahf/vczjk/ex4;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/sd;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/ux6;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/sd;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/sd;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/sd;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/sd;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-eq v1, v2, :cond_0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/sd;->L$0:Ljava/lang/Object;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/ux6;

    new-instance v3, Llyiahf/vczjk/rd;

    iget-object v5, p0, Llyiahf/vczjk/sd;->$initializeRequest:Llyiahf/vczjk/oe3;

    iget-object v6, p0, Llyiahf/vczjk/sd;->this$0:Llyiahf/vczjk/td;

    iget-object v7, p0, Llyiahf/vczjk/sd;->$node:Llyiahf/vczjk/ex4;

    const/4 v8, 0x0

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/rd;-><init>(Llyiahf/vczjk/ux6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/td;Llyiahf/vczjk/ex4;Llyiahf/vczjk/yo1;)V

    iput v2, p0, Llyiahf/vczjk/sd;->label:I

    invoke-static {v3, p0}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1
.end method
