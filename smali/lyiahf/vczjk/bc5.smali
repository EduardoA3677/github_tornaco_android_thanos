.class public final Llyiahf/vczjk/bc5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/cc5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/h43;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/cc5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bc5;->OooOOO0:Llyiahf/vczjk/h43;

    iput-object p2, p0, Llyiahf/vczjk/bc5;->OooOOO:Llyiahf/vczjk/cc5;

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 9

    instance-of v0, p2, Llyiahf/vczjk/ac5;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/ac5;

    iget v1, v0, Llyiahf/vczjk/ac5;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/ac5;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/ac5;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/ac5;-><init>(Llyiahf/vczjk/bc5;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/ac5;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/ac5;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    check-cast p1, Llyiahf/vczjk/j24;

    instance-of p2, p1, Llyiahf/vczjk/q37;

    iget-object v2, p0, Llyiahf/vczjk/bc5;->OooOOO:Llyiahf/vczjk/cc5;

    if-eqz p2, :cond_3

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/q37;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v4, Llyiahf/vczjk/q37;

    iget-wide v5, p2, Llyiahf/vczjk/q37;->OooO00o:J

    iget-wide v7, v2, Llyiahf/vczjk/cc5;->OooO00o:J

    invoke-static {v5, v6, v7, v8}, Llyiahf/vczjk/p86;->OooO0o0(JJ)J

    move-result-wide v5

    invoke-direct {v4, v5, v6}, Llyiahf/vczjk/q37;-><init>(J)V

    iget-object p2, v2, Llyiahf/vczjk/cc5;->OooO0O0:Ljava/util/LinkedHashMap;

    invoke-interface {p2, p1, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-object p1, v4

    goto :goto_1

    :cond_3
    instance-of p2, p1, Llyiahf/vczjk/p37;

    if-eqz p2, :cond_5

    iget-object p2, v2, Llyiahf/vczjk/cc5;->OooO0O0:Ljava/util/LinkedHashMap;

    check-cast p1, Llyiahf/vczjk/p37;

    iget-object v2, p1, Llyiahf/vczjk/p37;->OooO00o:Llyiahf/vczjk/q37;

    invoke-interface {p2, v2}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/q37;

    if-nez p2, :cond_4

    goto :goto_1

    :cond_4
    new-instance p1, Llyiahf/vczjk/p37;

    invoke-direct {p1, p2}, Llyiahf/vczjk/p37;-><init>(Llyiahf/vczjk/q37;)V

    goto :goto_1

    :cond_5
    instance-of p2, p1, Llyiahf/vczjk/r37;

    if-eqz p2, :cond_7

    iget-object p2, v2, Llyiahf/vczjk/cc5;->OooO0O0:Ljava/util/LinkedHashMap;

    check-cast p1, Llyiahf/vczjk/r37;

    iget-object v2, p1, Llyiahf/vczjk/r37;->OooO00o:Llyiahf/vczjk/q37;

    invoke-interface {p2, v2}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/q37;

    if-nez p2, :cond_6

    goto :goto_1

    :cond_6
    new-instance p1, Llyiahf/vczjk/r37;

    invoke-direct {p1, p2}, Llyiahf/vczjk/r37;-><init>(Llyiahf/vczjk/q37;)V

    :cond_7
    :goto_1
    iput v3, v0, Llyiahf/vczjk/ac5;->label:I

    iget-object p2, p0, Llyiahf/vczjk/bc5;->OooOOO0:Llyiahf/vczjk/h43;

    invoke-interface {p2, p1, v0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_8

    return-object v1

    :cond_8
    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
