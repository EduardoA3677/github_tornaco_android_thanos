.class public final Llyiahf/vczjk/sf4;
.super Llyiahf/vczjk/ij1;
.source "SourceFile"


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hy0;I)V
    .locals 1

    new-instance v0, Llyiahf/vczjk/my0;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/my0;-><init>(Llyiahf/vczjk/hy0;I)V

    new-instance p1, Llyiahf/vczjk/qf4;

    invoke-direct {p1, v0}, Llyiahf/vczjk/qf4;-><init>(Llyiahf/vczjk/my0;)V

    invoke-direct {p0, p1}, Llyiahf/vczjk/ij1;-><init>(Ljava/lang/Object;)V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/cm5;)Llyiahf/vczjk/uk4;
    .locals 8

    const-string v0, "module"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/d3a;->OooOOOO:Llyiahf/vczjk/d3a;

    invoke-interface {p1}, Llyiahf/vczjk/cm5;->OooOO0O()Llyiahf/vczjk/hk4;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/w09;->OoooO00:Llyiahf/vczjk/ic3;

    invoke-virtual {v2}, Llyiahf/vczjk/ic3;->OooO0oO()Llyiahf/vczjk/hc3;

    move-result-object v2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/hk4;->OooOO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/by0;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/f19;

    iget-object v3, p0, Llyiahf/vczjk/ij1;->OooO00o:Ljava/lang/Object;

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/rf4;

    instance-of v5, v4, Llyiahf/vczjk/pf4;

    if-eqz v5, :cond_0

    check-cast v3, Llyiahf/vczjk/pf4;

    iget-object p1, v3, Llyiahf/vczjk/pf4;->OooO00o:Llyiahf/vczjk/uk4;

    goto :goto_1

    :cond_0
    instance-of v4, v4, Llyiahf/vczjk/qf4;

    if-eqz v4, :cond_3

    check-cast v3, Llyiahf/vczjk/qf4;

    iget-object v3, v3, Llyiahf/vczjk/qf4;->OooO00o:Llyiahf/vczjk/my0;

    iget-object v4, v3, Llyiahf/vczjk/my0;->OooO00o:Llyiahf/vczjk/hy0;

    invoke-static {p1, v4}, Llyiahf/vczjk/r02;->OooOOo0(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hy0;)Llyiahf/vczjk/by0;

    move-result-object v5

    iget v3, v3, Llyiahf/vczjk/my0;->OooO0O0:I

    if-nez v5, :cond_1

    sget-object p1, Llyiahf/vczjk/tq2;->OooOOO:Llyiahf/vczjk/tq2;

    invoke-virtual {v4}, Llyiahf/vczjk/hy0;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v3

    filled-new-array {v4, v3}, [Ljava/lang/String;

    move-result-object v3

    invoke-static {p1, v3}, Llyiahf/vczjk/uq2;->OooO0OO(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object p1

    goto :goto_1

    :cond_1
    invoke-interface {v5}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v4

    const-string v5, "getDefaultType(...)"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v4}, Llyiahf/vczjk/fu6;->OooOoO0(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object v4

    const/4 v5, 0x0

    :goto_0
    if-ge v5, v3, :cond_2

    invoke-interface {p1}, Llyiahf/vczjk/cm5;->OooOO0O()Llyiahf/vczjk/hk4;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    invoke-virtual {v6, v4}, Llyiahf/vczjk/hk4;->OooO0oo(Llyiahf/vczjk/iaa;)Llyiahf/vczjk/dp8;

    move-result-object v4

    add-int/lit8 v5, v5, 0x1

    goto :goto_0

    :cond_2
    move-object p1, v4

    :goto_1
    invoke-direct {v2, p1}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/uk4;)V

    invoke-static {v2}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    invoke-static {v0, v1, p1}, Llyiahf/vczjk/so8;->Oooo0o(Llyiahf/vczjk/d3a;Llyiahf/vczjk/by0;Ljava/util/List;)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1

    :cond_3
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1
.end method
