.class public final Llyiahf/vczjk/tf;
.super Llyiahf/vczjk/cu7;
.source "SourceFile"


# instance fields
.field public Oooo0OO:Llyiahf/vczjk/wt7;

.field public Oooo0o0:Llyiahf/vczjk/xt7;


# virtual methods
.method public final o000OOo()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/tf;->Oooo0OO:Llyiahf/vczjk/wt7;

    if-eqz v0, :cond_1

    const/4 v1, 0x0

    iput-object v1, p0, Llyiahf/vczjk/tf;->Oooo0o0:Llyiahf/vczjk/xt7;

    invoke-static {p0}, Llyiahf/vczjk/ye5;->OooOoO0(Llyiahf/vczjk/fg2;)V

    iget-object v1, v0, Llyiahf/vczjk/wt7;->OooOOOo:Llyiahf/vczjk/era;

    iget-object v2, v1, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v2, Ljava/util/LinkedHashMap;

    invoke-virtual {v2, p0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/xt7;

    if-eqz v2, :cond_1

    invoke-virtual {v2}, Llyiahf/vczjk/xt7;->OooO0OO()V

    iget-object v3, v1, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v3, Ljava/util/LinkedHashMap;

    invoke-virtual {v3, p0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/xt7;

    if-eqz v4, :cond_0

    iget-object v1, v1, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast v1, Ljava/util/LinkedHashMap;

    invoke-interface {v1, v4}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/tf;

    :cond_0
    invoke-interface {v3, p0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v0, v0, Llyiahf/vczjk/wt7;->OooOOOO:Ljava/util/ArrayList;

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_1
    return-void
.end method
