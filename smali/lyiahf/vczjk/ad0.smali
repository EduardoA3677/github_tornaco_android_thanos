.class public final Llyiahf/vczjk/ad0;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/nv3;

.field public final OooO0O0:Llyiahf/vczjk/hf6;

.field public final OooO0OO:Llyiahf/vczjk/ff8;

.field public final OooO0Oo:Llyiahf/vczjk/zs2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nv3;Llyiahf/vczjk/hf6;Llyiahf/vczjk/ff8;Llyiahf/vczjk/zs2;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ad0;->OooO00o:Llyiahf/vczjk/nv3;

    iput-object p2, p0, Llyiahf/vczjk/ad0;->OooO0O0:Llyiahf/vczjk/hf6;

    iput-object p3, p0, Llyiahf/vczjk/ad0;->OooO0OO:Llyiahf/vczjk/ff8;

    iput-object p4, p0, Llyiahf/vczjk/ad0;->OooO0Oo:Llyiahf/vczjk/zs2;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 7

    instance-of v0, p1, Llyiahf/vczjk/zc0;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/zc0;

    iget v1, v0, Llyiahf/vczjk/zc0;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/zc0;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/zc0;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/zc0;-><init>(Llyiahf/vczjk/ad0;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/zc0;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/zc0;->label:I

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v2, :cond_3

    if-eq v2, v4, :cond_2

    if-ne v2, v3, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/zc0;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/bf8;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_3

    :catchall_0
    move-exception p1

    goto :goto_5

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object v2, v0, Llyiahf/vczjk/zc0;->L$1:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/bf8;

    iget-object v4, v0, Llyiahf/vczjk/zc0;->L$0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/ad0;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p1, v2

    goto :goto_1

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iput-object p0, v0, Llyiahf/vczjk/zc0;->L$0:Ljava/lang/Object;

    iget-object p1, p0, Llyiahf/vczjk/ad0;->OooO0OO:Llyiahf/vczjk/ff8;

    iput-object p1, v0, Llyiahf/vczjk/zc0;->L$1:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/zc0;->label:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ef8;->OooO00o(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v1, :cond_4

    goto :goto_2

    :cond_4
    move-object v4, p0

    :goto_1
    :try_start_1
    new-instance v2, Llyiahf/vczjk/k1;

    const/16 v5, 0xf

    invoke-direct {v2, v4, v5}, Llyiahf/vczjk/k1;-><init>(Ljava/lang/Object;I)V

    iput-object p1, v0, Llyiahf/vczjk/zc0;->L$0:Ljava/lang/Object;

    const/4 v4, 0x0

    iput-object v4, v0, Llyiahf/vczjk/zc0;->L$1:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/zc0;->label:I

    sget-object v3, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    new-instance v5, Llyiahf/vczjk/l34;

    invoke-direct {v5, v2, v4}, Llyiahf/vczjk/l34;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/yo1;)V

    invoke-static {v3, v5, v0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-ne v0, v1, :cond_5

    :goto_2
    return-object v1

    :cond_5
    move-object v6, v0

    move-object v0, p1

    move-object p1, v6

    :goto_3
    :try_start_2
    check-cast p1, Llyiahf/vczjk/d12;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    check-cast v0, Llyiahf/vczjk/ef8;

    invoke-virtual {v0}, Llyiahf/vczjk/ef8;->OooO0OO()V

    return-object p1

    :goto_4
    move-object v6, v0

    move-object v0, p1

    move-object p1, v6

    goto :goto_5

    :catchall_1
    move-exception v0

    goto :goto_4

    :goto_5
    check-cast v0, Llyiahf/vczjk/ef8;

    invoke-virtual {v0}, Llyiahf/vczjk/ef8;->OooO0OO()V

    throw p1
.end method
