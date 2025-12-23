.class public final Llyiahf/vczjk/v63;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/fl7;

.field public final synthetic OooOOO0:Llyiahf/vczjk/h43;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/fl7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/v63;->OooOOO0:Llyiahf/vczjk/h43;

    iput-object p2, p0, Llyiahf/vczjk/v63;->OooOOO:Llyiahf/vczjk/fl7;

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 6

    instance-of v0, p2, Llyiahf/vczjk/u63;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/u63;

    iget v1, v0, Llyiahf/vczjk/u63;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/u63;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/u63;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/u63;-><init>(Llyiahf/vczjk/v63;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/u63;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/u63;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance p2, Llyiahf/vczjk/kx3;

    iget-object v2, p0, Llyiahf/vczjk/v63;->OooOOO:Llyiahf/vczjk/fl7;

    iget v4, v2, Llyiahf/vczjk/fl7;->element:I

    add-int/lit8 v5, v4, 0x1

    iput v5, v2, Llyiahf/vczjk/fl7;->element:I

    if-ltz v4, :cond_4

    invoke-direct {p2, v4, p1}, Llyiahf/vczjk/kx3;-><init>(ILjava/lang/Object;)V

    iput v3, v0, Llyiahf/vczjk/u63;->label:I

    iget-object p1, p0, Llyiahf/vczjk/v63;->OooOOO0:Llyiahf/vczjk/h43;

    invoke-interface {p1, p2, v0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_3

    return-object v1

    :cond_3
    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_4
    new-instance p1, Ljava/lang/ArithmeticException;

    const-string p2, "Index overflow has happened"

    invoke-direct {p1, p2}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
