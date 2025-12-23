.class public final Llyiahf/vczjk/ny1;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/jz1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/jz1;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jz1;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ny1;->this$0:Llyiahf/vczjk/jz1;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ny1;

    iget-object v1, p0, Llyiahf/vczjk/ny1;->this$0:Llyiahf/vczjk/jz1;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/ny1;-><init>(Llyiahf/vczjk/jz1;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/ny1;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ny1;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ny1;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ny1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ny1;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x3

    const/4 v4, 0x1

    const/4 v5, 0x2

    const/4 v6, 0x0

    if-eqz v1, :cond_3

    if-eq v1, v4, :cond_2

    if-eq v1, v5, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/ny1;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/n29;

    iget-object v4, p0, Llyiahf/vczjk/ny1;->L$0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/h43;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/ny1;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/h43;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v4, v1

    goto :goto_0

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ny1;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/h43;

    iget-object v1, p0, Llyiahf/vczjk/ny1;->this$0:Llyiahf/vczjk/jz1;

    iput-object p1, p0, Llyiahf/vczjk/ny1;->L$0:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/ny1;->label:I

    iget-object v4, v1, Llyiahf/vczjk/jz1;->OooO0OO:Llyiahf/vczjk/xr1;

    invoke-interface {v4}, Llyiahf/vczjk/xr1;->OoooOO0()Llyiahf/vczjk/or1;

    move-result-object v4

    new-instance v7, Llyiahf/vczjk/az1;

    const/4 v8, 0x0

    invoke-direct {v7, v1, v8, v6}, Llyiahf/vczjk/az1;-><init>(Llyiahf/vczjk/jz1;ZLlyiahf/vczjk/yo1;)V

    invoke-static {v4, v7, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_4

    goto :goto_2

    :cond_4
    move-object v4, p1

    move-object p1, v1

    :goto_0
    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/n29;

    instance-of p1, v1, Llyiahf/vczjk/nw1;

    if-eqz p1, :cond_5

    move-object p1, v1

    check-cast p1, Llyiahf/vczjk/nw1;

    iget-object p1, p1, Llyiahf/vczjk/nw1;->OooO0O0:Ljava/lang/Object;

    iput-object v4, p0, Llyiahf/vczjk/ny1;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/ny1;->L$1:Ljava/lang/Object;

    iput v5, p0, Llyiahf/vczjk/ny1;->label:I

    invoke-interface {v4, p1, p0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_6

    goto :goto_2

    :cond_5
    instance-of p1, v1, Llyiahf/vczjk/s7a;

    if-nez p1, :cond_9

    instance-of p1, v1, Llyiahf/vczjk/ug7;

    if-nez p1, :cond_8

    instance-of p1, v1, Llyiahf/vczjk/f13;

    if-eqz p1, :cond_6

    goto :goto_3

    :cond_6
    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/ny1;->this$0:Llyiahf/vczjk/jz1;

    iget-object v7, p1, Llyiahf/vczjk/jz1;->OooO0oo:Llyiahf/vczjk/oO0OOo0o;

    iget-object v7, v7, Llyiahf/vczjk/oO0OOo0o;->OooOOO:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/s29;

    new-instance v8, Llyiahf/vczjk/hy1;

    invoke-direct {v8, p1, v6}, Llyiahf/vczjk/hy1;-><init>(Llyiahf/vczjk/jz1;Llyiahf/vczjk/yo1;)V

    new-instance p1, Llyiahf/vczjk/l53;

    invoke-direct {p1, v7, v8}, Llyiahf/vczjk/l53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;)V

    new-instance v7, Llyiahf/vczjk/iy1;

    invoke-direct {v7, v5, v6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    new-instance v5, Llyiahf/vczjk/a63;

    invoke-direct {v5, p1, v7}, Llyiahf/vczjk/a63;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;)V

    new-instance p1, Llyiahf/vczjk/jy1;

    invoke-direct {p1, v1, v6}, Llyiahf/vczjk/jy1;-><init>(Llyiahf/vczjk/n29;Llyiahf/vczjk/yo1;)V

    new-instance v1, Llyiahf/vczjk/w53;

    const/4 v7, 0x0

    invoke-direct {v1, v5, p1, v7}, Llyiahf/vczjk/w53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;I)V

    new-instance p1, Llyiahf/vczjk/y30;

    const/4 v5, 0x1

    invoke-direct {p1, v1, v5}, Llyiahf/vczjk/y30;-><init>(Ljava/lang/Object;I)V

    new-instance v1, Llyiahf/vczjk/ky1;

    iget-object v5, p0, Llyiahf/vczjk/ny1;->this$0:Llyiahf/vczjk/jz1;

    invoke-direct {v1, v5, v6}, Llyiahf/vczjk/ky1;-><init>(Llyiahf/vczjk/jz1;Llyiahf/vczjk/yo1;)V

    new-instance v5, Llyiahf/vczjk/j53;

    invoke-direct {v5, p1, v1}, Llyiahf/vczjk/j53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;)V

    iput-object v6, p0, Llyiahf/vczjk/ny1;->L$0:Ljava/lang/Object;

    iput-object v6, p0, Llyiahf/vczjk/ny1;->L$1:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/ny1;->label:I

    invoke-static {v4, v5, p0}, Llyiahf/vczjk/rs;->OooOo0o(Llyiahf/vczjk/h43;Llyiahf/vczjk/f43;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_7

    :goto_2
    return-object v0

    :cond_7
    :goto_3
    return-object v2

    :cond_8
    check-cast v1, Llyiahf/vczjk/ug7;

    iget-object p1, v1, Llyiahf/vczjk/ug7;->OooO0O0:Ljava/lang/Throwable;

    throw p1

    :cond_9
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "This is a bug in DataStore. Please file a bug at: https://issuetracker.google.com/issues/new?component=907884&template=1466542"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
