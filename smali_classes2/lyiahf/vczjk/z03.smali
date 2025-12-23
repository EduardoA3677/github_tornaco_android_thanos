.class public final Llyiahf/vczjk/z03;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ko;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/m5a;

.field public final OooOOO0:Llyiahf/vczjk/ko;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ko;Llyiahf/vczjk/m5a;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/z03;->OooOOO0:Llyiahf/vczjk/ko;

    iput-object p2, p0, Llyiahf/vczjk/z03;->OooOOO:Llyiahf/vczjk/m5a;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/hc3;)Z
    .locals 1

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/z03;->OooOOO:Llyiahf/vczjk/m5a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/m5a;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/z03;->OooOOO0:Llyiahf/vczjk/ko;

    invoke-interface {v0, p1}, Llyiahf/vczjk/ko;->OooO0o0(Llyiahf/vczjk/hc3;)Z

    move-result p1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0oO(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/un;
    .locals 1

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/z03;->OooOOO:Llyiahf/vczjk/m5a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/m5a;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/z03;->OooOOO0:Llyiahf/vczjk/ko;

    invoke-interface {v0, p1}, Llyiahf/vczjk/ko;->OooO0oO(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/un;

    move-result-object p1

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final isEmpty()Z
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/z03;->OooOOO0:Llyiahf/vczjk/ko;

    instance-of v1, v0, Ljava/util/Collection;

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    move-object v1, v0

    check-cast v1, Ljava/util/Collection;

    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/un;

    invoke-interface {v1}, Llyiahf/vczjk/un;->OooO0oo()Llyiahf/vczjk/hc3;

    move-result-object v1

    if-eqz v1, :cond_1

    iget-object v3, p0, Llyiahf/vczjk/z03;->OooOOO:Llyiahf/vczjk/m5a;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/m5a;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    if-eqz v1, :cond_1

    const/4 v2, 0x1

    :cond_2
    :goto_0
    return v2
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 5

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/z03;->OooOOO0:Llyiahf/vczjk/ko;

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/un;

    invoke-interface {v3}, Llyiahf/vczjk/un;->OooO0oo()Llyiahf/vczjk/hc3;

    move-result-object v3

    if-eqz v3, :cond_0

    iget-object v4, p0, Llyiahf/vczjk/z03;->OooOOO:Llyiahf/vczjk/m5a;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/m5a;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Boolean;

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    return-object v0
.end method
