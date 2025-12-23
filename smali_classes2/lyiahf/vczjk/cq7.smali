.class public final Llyiahf/vczjk/cq7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $draggingItem:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field

.field final synthetic $targetItem:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/fq7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/fq7;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fq7;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/cq7;->this$0:Llyiahf/vczjk/fq7;

    iput-object p2, p0, Llyiahf/vczjk/cq7;->$draggingItem:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/cq7;->$targetItem:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/cq7;

    iget-object v0, p0, Llyiahf/vczjk/cq7;->this$0:Llyiahf/vczjk/fq7;

    iget-object v1, p0, Llyiahf/vczjk/cq7;->$draggingItem:Ljava/lang/Object;

    iget-object v2, p0, Llyiahf/vczjk/cq7;->$targetItem:Ljava/lang/Object;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/cq7;-><init>(Llyiahf/vczjk/fq7;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/cq7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/cq7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/cq7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/cq7;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/cq7;->this$0:Llyiahf/vczjk/fq7;

    iget-object v1, p1, Llyiahf/vczjk/fq7;->OooO0OO:Llyiahf/vczjk/ze3;

    new-instance v4, Llyiahf/vczjk/f54;

    iget-object v5, p0, Llyiahf/vczjk/cq7;->$draggingItem:Ljava/lang/Object;

    invoke-virtual {p1, v5}, Llyiahf/vczjk/fq7;->OooOO0(Ljava/lang/Object;)I

    move-result p1

    iget-object v5, p0, Llyiahf/vczjk/cq7;->this$0:Llyiahf/vczjk/fq7;

    iget-object v6, p0, Llyiahf/vczjk/cq7;->$draggingItem:Ljava/lang/Object;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/fq7;->OooOO0O(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    invoke-direct {v4, p1, v5}, Llyiahf/vczjk/f54;-><init>(ILjava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/f54;

    iget-object v5, p0, Llyiahf/vczjk/cq7;->this$0:Llyiahf/vczjk/fq7;

    iget-object v6, p0, Llyiahf/vczjk/cq7;->$targetItem:Ljava/lang/Object;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/fq7;->OooOO0(Ljava/lang/Object;)I

    move-result v5

    iget-object v6, p0, Llyiahf/vczjk/cq7;->this$0:Llyiahf/vczjk/fq7;

    iget-object v7, p0, Llyiahf/vczjk/cq7;->$targetItem:Ljava/lang/Object;

    invoke-virtual {v6, v7}, Llyiahf/vczjk/fq7;->OooOO0O(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    invoke-direct {p1, v5, v6}, Llyiahf/vczjk/f54;-><init>(ILjava/lang/Object;)V

    invoke-interface {v1, v4, p1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object p1, p0, Llyiahf/vczjk/cq7;->this$0:Llyiahf/vczjk/fq7;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/yp7;

    iget-object v1, v1, Llyiahf/vczjk/yp7;->OooOOO0:Llyiahf/vczjk/dw4;

    iget-object v1, v1, Llyiahf/vczjk/dw4;->OooO0Oo:Llyiahf/vczjk/tq4;

    invoke-virtual {v1}, Llyiahf/vczjk/tq4;->OooO00o()I

    move-result v1

    iget-object v4, p0, Llyiahf/vczjk/cq7;->this$0:Llyiahf/vczjk/fq7;

    check-cast v4, Llyiahf/vczjk/yp7;

    iget-object v4, v4, Llyiahf/vczjk/yp7;->OooOOO0:Llyiahf/vczjk/dw4;

    iget-object v4, v4, Llyiahf/vczjk/dw4;->OooO0Oo:Llyiahf/vczjk/tq4;

    invoke-virtual {v4}, Llyiahf/vczjk/tq4;->OooO0O0()I

    move-result v4

    iput v3, p0, Llyiahf/vczjk/cq7;->label:I

    check-cast p1, Llyiahf/vczjk/yp7;

    iget-object p1, p1, Llyiahf/vczjk/yp7;->OooOOO0:Llyiahf/vczjk/dw4;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v3, Llyiahf/vczjk/bw4;

    const/4 v5, 0x0

    invoke-direct {v3, p1, v1, v4, v5}, Llyiahf/vczjk/bw4;-><init>(Llyiahf/vczjk/dw4;IILlyiahf/vczjk/yo1;)V

    sget-object v1, Llyiahf/vczjk/at5;->OooOOO0:Llyiahf/vczjk/at5;

    invoke-virtual {p1, v1, v3, p0}, Llyiahf/vczjk/dw4;->OooO0OO(Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    move-object p1, v2

    :goto_1
    if-ne p1, v0, :cond_4

    return-object v0

    :cond_4
    return-object v2
.end method
