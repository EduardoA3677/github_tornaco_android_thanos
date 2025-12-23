.class public final Llyiahf/vczjk/wh0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/th0;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ws5;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/ws5;

    const/16 v1, 0x10

    new-array v1, v1, [Llyiahf/vczjk/xh0;

    invoke-direct {v0, v1}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object v0, p0, Llyiahf/vczjk/wh0;->OooO00o:Llyiahf/vczjk/ws5;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/wj7;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 8

    instance-of v0, p2, Llyiahf/vczjk/uh0;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/uh0;

    iget v1, v0, Llyiahf/vczjk/uh0;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/uh0;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/uh0;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/uh0;-><init>(Llyiahf/vczjk/wh0;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/uh0;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/uh0;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget p1, v0, Llyiahf/vczjk/uh0;->I$1:I

    iget v2, v0, Llyiahf/vczjk/uh0;->I$0:I

    iget-object v4, v0, Llyiahf/vczjk/uh0;->L$1:Ljava/lang/Object;

    check-cast v4, [Ljava/lang/Object;

    iget-object v5, v0, Llyiahf/vczjk/uh0;->L$0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/wj7;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p2, v5

    goto :goto_2

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/wh0;->OooO00o:Llyiahf/vczjk/ws5;

    iget-object v2, p2, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget p2, p2, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v4, 0x0

    move v7, p2

    move-object p2, p1

    move p1, v7

    move v7, v4

    move-object v4, v2

    move v2, v7

    :goto_1
    if-ge v2, p1, :cond_4

    aget-object v5, v4, v2

    check-cast v5, Llyiahf/vczjk/xh0;

    new-instance v6, Llyiahf/vczjk/vh0;

    invoke-direct {v6, p2}, Llyiahf/vczjk/vh0;-><init>(Llyiahf/vczjk/wj7;)V

    iput-object p2, v0, Llyiahf/vczjk/uh0;->L$0:Ljava/lang/Object;

    iput-object v4, v0, Llyiahf/vczjk/uh0;->L$1:Ljava/lang/Object;

    iput v2, v0, Llyiahf/vczjk/uh0;->I$0:I

    iput p1, v0, Llyiahf/vczjk/uh0;->I$1:I

    iput v3, v0, Llyiahf/vczjk/uh0;->label:I

    invoke-static {v5, v6, v0}, Llyiahf/vczjk/so8;->OooOOo(Llyiahf/vczjk/l52;Llyiahf/vczjk/le3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v1, :cond_3

    return-object v1

    :cond_3
    :goto_2
    add-int/2addr v2, v3

    goto :goto_1

    :cond_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
