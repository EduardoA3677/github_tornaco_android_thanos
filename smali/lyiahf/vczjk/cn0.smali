.class public final Llyiahf/vczjk/cn0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/h43;

.field public final synthetic OooOOO0:Llyiahf/vczjk/fl7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/fl7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/cn0;->OooOOO0:Llyiahf/vczjk/fl7;

    iput-object p1, p0, Llyiahf/vczjk/cn0;->OooOOO:Llyiahf/vczjk/h43;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/kx3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 4

    instance-of v0, p2, Llyiahf/vczjk/bn0;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/bn0;

    iget v1, v0, Llyiahf/vczjk/bn0;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/bn0;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/bn0;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/bn0;-><init>(Llyiahf/vczjk/cn0;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/bn0;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/bn0;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/bn0;->L$1:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/kx3;

    iget-object v0, v0, Llyiahf/vczjk/bn0;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cn0;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/cn0;->OooOOO0:Llyiahf/vczjk/fl7;

    iget p2, p2, Llyiahf/vczjk/fl7;->element:I

    iget v2, p1, Llyiahf/vczjk/kx3;->OooO00o:I

    if-le v2, p2, :cond_4

    iput-object p0, v0, Llyiahf/vczjk/bn0;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/bn0;->L$1:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/bn0;->label:I

    iget-object p2, p0, Llyiahf/vczjk/cn0;->OooOOO:Llyiahf/vczjk/h43;

    iget-object v2, p1, Llyiahf/vczjk/kx3;->OooO0O0:Ljava/lang/Object;

    invoke-interface {p2, v2, v0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v1, :cond_3

    return-object v1

    :cond_3
    move-object v0, p0

    :goto_1
    iget-object p2, v0, Llyiahf/vczjk/cn0;->OooOOO0:Llyiahf/vczjk/fl7;

    iget p1, p1, Llyiahf/vczjk/kx3;->OooO00o:I

    iput p1, p2, Llyiahf/vczjk/fl7;->element:I

    :cond_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final bridge synthetic emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/kx3;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/cn0;->OooO00o(Llyiahf/vczjk/kx3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
