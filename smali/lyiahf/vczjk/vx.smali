.class public final Llyiahf/vczjk/vx;
.super Llyiahf/vczjk/u11;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# virtual methods
.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/u3a;->OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final bridge synthetic OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p3, Ljava/util/Collection;

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/vx;->OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object p1

    return-object p1
.end method

.method public final OoooOoO(Llyiahf/vczjk/v72;)Ljava/util/Collection;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public final OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Collection;)Ljava/util/Collection;
    .locals 1

    if-eqz p3, :cond_0

    invoke-super {p0, p1, p2, p3}, Llyiahf/vczjk/u11;->OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result p3

    const/4 v0, 0x1

    if-nez p3, :cond_1

    new-instance p3, Ljava/util/concurrent/ArrayBlockingQueue;

    invoke-direct {p3, v0}, Ljava/util/concurrent/ArrayBlockingQueue;-><init>(I)V

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/u11;->Ooooo00(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object p1

    return-object p1

    :cond_1
    new-instance p3, Ljava/util/ArrayList;

    invoke-direct {p3}, Ljava/util/ArrayList;-><init>()V

    invoke-super {p0, p1, p2, p3}, Llyiahf/vczjk/u11;->OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    move-result p2

    const/4 p3, 0x0

    if-eqz p2, :cond_2

    new-instance p1, Ljava/util/concurrent/ArrayBlockingQueue;

    invoke-direct {p1, v0, p3}, Ljava/util/concurrent/ArrayBlockingQueue;-><init>(IZ)V

    return-object p1

    :cond_2
    new-instance p2, Ljava/util/concurrent/ArrayBlockingQueue;

    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result v0

    invoke-direct {p2, v0, p3, p1}, Ljava/util/concurrent/ArrayBlockingQueue;-><init>(IZLjava/util/Collection;)V

    return-object p2
.end method

.method public final Ooooo0o(Llyiahf/vczjk/e94;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)Llyiahf/vczjk/u11;
    .locals 8

    new-instance v0, Llyiahf/vczjk/vx;

    iget-object v1, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    iget-object v4, p0, Llyiahf/vczjk/u11;->_valueInstantiator:Llyiahf/vczjk/nca;

    move-object v5, p1

    move-object v2, p2

    move-object v3, p3

    move-object v6, p4

    move-object v7, p5

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/u11;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/nca;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    return-object v0
.end method
