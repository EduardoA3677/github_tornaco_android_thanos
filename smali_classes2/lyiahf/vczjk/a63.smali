.class public final Llyiahf/vczjk/a63;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/eb9;

.field public final synthetic OooOOO0:Llyiahf/vczjk/f43;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/a63;->OooOOO0:Llyiahf/vczjk/f43;

    check-cast p2, Llyiahf/vczjk/eb9;

    iput-object p2, p0, Llyiahf/vczjk/a63;->OooOOO:Llyiahf/vczjk/eb9;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 5

    instance-of v0, p2, Llyiahf/vczjk/z53;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/z53;

    iget v1, v0, Llyiahf/vczjk/z53;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/z53;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/z53;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/z53;-><init>(Llyiahf/vczjk/a63;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/z53;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/z53;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/z53;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/c63;

    :try_start_0
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Llyiahf/vczjk/o000oOoO; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_2

    :catch_0
    move-exception p2

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/a63;->OooOOO0:Llyiahf/vczjk/f43;

    new-instance v2, Llyiahf/vczjk/c63;

    iget-object v4, p0, Llyiahf/vczjk/a63;->OooOOO:Llyiahf/vczjk/eb9;

    invoke-direct {v2, p1, v4}, Llyiahf/vczjk/c63;-><init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/ze3;)V

    :try_start_1
    iput-object v2, v0, Llyiahf/vczjk/z53;->L$0:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/z53;->label:I

    invoke-interface {p2, v2, v0}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catch Llyiahf/vczjk/o000oOoO; {:try_start_1 .. :try_end_1} :catch_1

    if-ne p1, v1, :cond_3

    return-object v1

    :catch_1
    move-exception p2

    move-object p1, v2

    :goto_1
    iget-object v1, p2, Llyiahf/vczjk/o000oOoO;->OooOOO0:Llyiahf/vczjk/h43;

    if-ne v1, p1, :cond_4

    invoke-interface {v0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Oooo0oo(Llyiahf/vczjk/or1;)V

    :cond_3
    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_4
    throw p2
.end method
