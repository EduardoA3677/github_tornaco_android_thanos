.class public final Llyiahf/vczjk/dz1;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $callerContext:Llyiahf/vczjk/or1;

.field final synthetic $transform:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/jz1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/jz1;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jz1;Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/dz1;->this$0:Llyiahf/vczjk/jz1;

    iput-object p2, p0, Llyiahf/vczjk/dz1;->$callerContext:Llyiahf/vczjk/or1;

    iput-object p3, p0, Llyiahf/vczjk/dz1;->$transform:Llyiahf/vczjk/ze3;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/dz1;->create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/dz1;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/dz1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/dz1;

    iget-object v1, p0, Llyiahf/vczjk/dz1;->this$0:Llyiahf/vczjk/jz1;

    iget-object v2, p0, Llyiahf/vczjk/dz1;->$callerContext:Llyiahf/vczjk/or1;

    iget-object v3, p0, Llyiahf/vczjk/dz1;->$transform:Llyiahf/vczjk/ze3;

    invoke-direct {v0, v1, v2, v3, p1}, Llyiahf/vczjk/dz1;-><init>(Llyiahf/vczjk/jz1;Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/dz1;->label:I

    const/4 v2, 0x3

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v1, :cond_3

    if-eq v1, v4, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/dz1;->L$0:Ljava/lang/Object;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/dz1;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/nw1;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/dz1;->this$0:Llyiahf/vczjk/jz1;

    iput v4, p0, Llyiahf/vczjk/dz1;->label:I

    invoke-static {p1, v4, p0}, Llyiahf/vczjk/jz1;->OooO0o(Llyiahf/vczjk/jz1;ZLlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    goto :goto_3

    :cond_4
    :goto_0
    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/nw1;

    iget-object p1, p0, Llyiahf/vczjk/dz1;->$callerContext:Llyiahf/vczjk/or1;

    new-instance v5, Llyiahf/vczjk/cz1;

    iget-object v6, p0, Llyiahf/vczjk/dz1;->$transform:Llyiahf/vczjk/ze3;

    const/4 v7, 0x0

    invoke-direct {v5, v6, v1, v7}, Llyiahf/vczjk/cz1;-><init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/nw1;Llyiahf/vczjk/yo1;)V

    iput-object v1, p0, Llyiahf/vczjk/dz1;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/dz1;->label:I

    invoke-static {p1, v5, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    goto :goto_3

    :cond_5
    :goto_1
    iget-object v3, v1, Llyiahf/vczjk/nw1;->OooO0O0:Ljava/lang/Object;

    if-eqz v3, :cond_6

    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    move-result v3

    goto :goto_2

    :cond_6
    const/4 v3, 0x0

    :goto_2
    iget v5, v1, Llyiahf/vczjk/nw1;->OooO0OO:I

    if-ne v3, v5, :cond_8

    iget-object v1, v1, Llyiahf/vczjk/nw1;->OooO0O0:Ljava/lang/Object;

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_7

    iget-object v1, p0, Llyiahf/vczjk/dz1;->this$0:Llyiahf/vczjk/jz1;

    iput-object p1, p0, Llyiahf/vczjk/dz1;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/dz1;->label:I

    invoke-virtual {v1, p1, v4, p0}, Llyiahf/vczjk/jz1;->OooOO0(Ljava/lang/Object;ZLlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_7

    :goto_3
    return-object v0

    :cond_7
    return-object p1

    :cond_8
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Data in DataStore was mutated but DataStore is only compatible with Immutable types."

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
