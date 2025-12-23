.class public final Llyiahf/vczjk/cq1;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $bringIntoViewRequester:Llyiahf/vczjk/th0;

.field final synthetic $layoutResult:Llyiahf/vczjk/nm9;

.field final synthetic $offsetMapping:Llyiahf/vczjk/s86;

.field final synthetic $state:Llyiahf/vczjk/lx4;

.field final synthetic $value:Llyiahf/vczjk/gl9;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/th0;Llyiahf/vczjk/gl9;Llyiahf/vczjk/lx4;Llyiahf/vczjk/nm9;Llyiahf/vczjk/s86;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/cq1;->$bringIntoViewRequester:Llyiahf/vczjk/th0;

    iput-object p2, p0, Llyiahf/vczjk/cq1;->$value:Llyiahf/vczjk/gl9;

    iput-object p3, p0, Llyiahf/vczjk/cq1;->$state:Llyiahf/vczjk/lx4;

    iput-object p4, p0, Llyiahf/vczjk/cq1;->$layoutResult:Llyiahf/vczjk/nm9;

    iput-object p5, p0, Llyiahf/vczjk/cq1;->$offsetMapping:Llyiahf/vczjk/s86;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/cq1;

    iget-object v1, p0, Llyiahf/vczjk/cq1;->$bringIntoViewRequester:Llyiahf/vczjk/th0;

    iget-object v2, p0, Llyiahf/vczjk/cq1;->$value:Llyiahf/vczjk/gl9;

    iget-object v3, p0, Llyiahf/vczjk/cq1;->$state:Llyiahf/vczjk/lx4;

    iget-object v4, p0, Llyiahf/vczjk/cq1;->$layoutResult:Llyiahf/vczjk/nm9;

    iget-object v5, p0, Llyiahf/vczjk/cq1;->$offsetMapping:Llyiahf/vczjk/s86;

    move-object v6, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/cq1;-><init>(Llyiahf/vczjk/th0;Llyiahf/vczjk/gl9;Llyiahf/vczjk/lx4;Llyiahf/vczjk/nm9;Llyiahf/vczjk/s86;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/cq1;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/cq1;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/cq1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/cq1;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/cq1;->$bringIntoViewRequester:Llyiahf/vczjk/th0;

    iget-object v1, p0, Llyiahf/vczjk/cq1;->$value:Llyiahf/vczjk/gl9;

    iget-object v4, p0, Llyiahf/vczjk/cq1;->$state:Llyiahf/vczjk/lx4;

    iget-object v4, v4, Llyiahf/vczjk/lx4;->OooO00o:Llyiahf/vczjk/yh9;

    iget-object v5, p0, Llyiahf/vczjk/cq1;->$layoutResult:Llyiahf/vczjk/nm9;

    iget-object v5, v5, Llyiahf/vczjk/nm9;->OooO00o:Llyiahf/vczjk/mm9;

    iget-object v6, p0, Llyiahf/vczjk/cq1;->$offsetMapping:Llyiahf/vczjk/s86;

    iput v3, p0, Llyiahf/vczjk/cq1;->label:I

    iget-wide v7, v1, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v7, v8}, Llyiahf/vczjk/gn9;->OooO0Oo(J)I

    move-result v1

    invoke-interface {v6, v1}, Llyiahf/vczjk/s86;->OooOO0(I)I

    move-result v1

    iget-object v6, v5, Llyiahf/vczjk/mm9;->OooO00o:Llyiahf/vczjk/lm9;

    iget-object v6, v6, Llyiahf/vczjk/lm9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v6, v6, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v6}, Ljava/lang/String;->length()I

    move-result v6

    if-ge v1, v6, :cond_2

    invoke-virtual {v5, v1}, Llyiahf/vczjk/mm9;->OooO0O0(I)Llyiahf/vczjk/wj7;

    move-result-object v1

    goto :goto_0

    :cond_2
    if-eqz v1, :cond_3

    sub-int/2addr v1, v3

    invoke-virtual {v5, v1}, Llyiahf/vczjk/mm9;->OooO0O0(I)Llyiahf/vczjk/wj7;

    move-result-object v1

    goto :goto_0

    :cond_3
    iget-object v1, v4, Llyiahf/vczjk/yh9;->OooO0oO:Llyiahf/vczjk/f62;

    iget-object v3, v4, Llyiahf/vczjk/yh9;->OooO0oo:Llyiahf/vczjk/aa3;

    iget-object v4, v4, Llyiahf/vczjk/yh9;->OooO0O0:Llyiahf/vczjk/rn9;

    invoke-static {v4, v1, v3}, Llyiahf/vczjk/oi9;->OooO0O0(Llyiahf/vczjk/rn9;Llyiahf/vczjk/f62;Llyiahf/vczjk/aa3;)J

    move-result-wide v3

    new-instance v1, Llyiahf/vczjk/wj7;

    const-wide v5, 0xffffffffL

    and-long/2addr v3, v5

    long-to-int v3, v3

    int-to-float v3, v3

    const/4 v4, 0x0

    const/high16 v5, 0x3f800000    # 1.0f

    invoke-direct {v1, v4, v4, v5, v3}, Llyiahf/vczjk/wj7;-><init>(FFFF)V

    :goto_0
    check-cast p1, Llyiahf/vczjk/wh0;

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/wh0;->OooO00o(Llyiahf/vczjk/wj7;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    goto :goto_1

    :cond_4
    move-object p1, v2

    :goto_1
    if-ne p1, v0, :cond_5

    return-object v0

    :cond_5
    return-object v2
.end method
