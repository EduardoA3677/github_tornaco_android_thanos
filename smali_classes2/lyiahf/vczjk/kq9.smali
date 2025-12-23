.class public final Llyiahf/vczjk/kq9;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/kq9;

.field public static final OooO0O0:Llyiahf/vczjk/xo8;

.field public static final OooO0OO:Llyiahf/vczjk/to1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/kq9;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/kq9;->OooO00o:Llyiahf/vczjk/kq9;

    new-instance v0, Llyiahf/vczjk/xo8;

    new-instance v1, Llyiahf/vczjk/na9;

    const/4 v2, 0x3

    invoke-direct {v1, v2}, Llyiahf/vczjk/na9;-><init>(I)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/xo8;-><init>(Llyiahf/vczjk/le3;)V

    sput-object v0, Llyiahf/vczjk/kq9;->OooO0O0:Llyiahf/vczjk/xo8;

    invoke-static {}, Llyiahf/vczjk/vl6;->OooO0O0()Llyiahf/vczjk/u99;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v1, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    iget-object v1, v1, Llyiahf/vczjk/xl3;->OooOOo:Llyiahf/vczjk/xl3;

    invoke-static {v0, v1}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooO0oO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/to1;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/kq9;->OooO0OO:Llyiahf/vczjk/to1;

    return-void
.end method


# virtual methods
.method public final OooO00o(Landroid/content/Context;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 9

    instance-of v0, p2, Llyiahf/vczjk/fq9;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/fq9;

    iget v1, v0, Llyiahf/vczjk/fq9;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/fq9;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/fq9;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/fq9;-><init>(Llyiahf/vczjk/kq9;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/fq9;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/fq9;->label:I

    const/4 v3, 0x3

    const/4 v4, 0x0

    const/4 v5, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v5, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/fq9;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/n17;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance p2, Llyiahf/vczjk/n17;

    invoke-direct {p2, p1}, Llyiahf/vczjk/n17;-><init>(Landroid/content/Context;)V

    new-instance p1, Llyiahf/vczjk/jq9;

    invoke-direct {p1, v3, v4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    new-instance v2, Llyiahf/vczjk/y63;

    iget-object v6, p2, Llyiahf/vczjk/n17;->OooO0OO:Llyiahf/vczjk/wh;

    iget-object v7, p2, Llyiahf/vczjk/n17;->OooO0O0:Llyiahf/vczjk/wh;

    invoke-direct {v2, v6, v7, p1}, Llyiahf/vczjk/y63;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;)V

    iput-object p2, v0, Llyiahf/vczjk/fq9;->L$0:Ljava/lang/Object;

    iput v5, v0, Llyiahf/vczjk/fq9;->label:I

    invoke-static {v2, v0}, Llyiahf/vczjk/rs;->OooOoO(Llyiahf/vczjk/f43;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_3

    return-object v1

    :cond_3
    move-object v8, p2

    move-object p2, p1

    move-object p1, v8

    :goto_1
    check-cast p2, Llyiahf/vczjk/pq9;

    sget-object v0, Llyiahf/vczjk/kq9;->OooO0O0:Llyiahf/vczjk/xo8;

    iget-object v0, v0, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rs5;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/rs5;

    check-cast v0, Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/eq9;

    const-string v2, "$this$updateState"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/eq9;

    invoke-direct {v0, p2}, Llyiahf/vczjk/eq9;-><init>(Llyiahf/vczjk/pq9;)V

    check-cast v1, Llyiahf/vczjk/s29;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/s29;->OooOOOO(Ljava/lang/Object;)V

    new-instance p2, Llyiahf/vczjk/iq9;

    invoke-direct {p2, p1, v4}, Llyiahf/vczjk/iq9;-><init>(Llyiahf/vczjk/n17;Llyiahf/vczjk/yo1;)V

    sget-object p1, Llyiahf/vczjk/kq9;->OooO0OO:Llyiahf/vczjk/to1;

    invoke-static {p1, v4, v4, p2, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
