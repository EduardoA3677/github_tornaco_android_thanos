.class public final Llyiahf/vczjk/hb0;
.super Llyiahf/vczjk/ib0;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1dL


# virtual methods
.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ib0;->_objectIdWriter:Llyiahf/vczjk/z66;

    if-eqz v0, :cond_0

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->OoooOO0(Ljava/lang/Object;)V

    const/4 v0, 0x1

    invoke-virtual {p0, p1, p2, p3, v0}, Llyiahf/vczjk/ib0;->OooOOOO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Z)V

    return-void

    :cond_0
    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o0000oOO(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/ib0;->_propertyFilterId:Ljava/lang/Object;

    if-nez v0, :cond_1

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/ib0;->OooOOoo(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    invoke-virtual {p2}, Llyiahf/vczjk/u94;->o00000o0()V

    return-void

    :cond_1
    invoke-virtual {p0, p3}, Llyiahf/vczjk/ib0;->OooOo00(Llyiahf/vczjk/tg8;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooO0oo(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/zb4;
    .locals 1

    new-instance v0, Llyiahf/vczjk/kaa;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/kaa;-><init>(Llyiahf/vczjk/ib0;Llyiahf/vczjk/wt5;)V

    return-object v0
.end method

.method public final OooOOo0()Llyiahf/vczjk/ib0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ib0;->_objectIdWriter:Llyiahf/vczjk/z66;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ib0;->_anyGetterWriter:Llyiahf/vczjk/to;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ib0;->_propertyFilterId:Ljava/lang/Object;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/va0;

    invoke-direct {v0, p0}, Llyiahf/vczjk/va0;-><init>(Llyiahf/vczjk/hb0;)V

    return-object v0

    :cond_0
    return-object p0
.end method

.method public final OooOo([Llyiahf/vczjk/gb0;[Llyiahf/vczjk/gb0;)Llyiahf/vczjk/ib0;
    .locals 1

    new-instance v0, Llyiahf/vczjk/hb0;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/ib0;-><init>(Llyiahf/vczjk/ib0;[Llyiahf/vczjk/gb0;[Llyiahf/vczjk/gb0;)V

    return-object v0
.end method

.method public final OooOo0(Ljava/lang/Object;)Llyiahf/vczjk/ib0;
    .locals 2

    new-instance v0, Llyiahf/vczjk/hb0;

    iget-object v1, p0, Llyiahf/vczjk/ib0;->_objectIdWriter:Llyiahf/vczjk/z66;

    invoke-direct {v0, p0, v1, p1}, Llyiahf/vczjk/ib0;-><init>(Llyiahf/vczjk/ib0;Llyiahf/vczjk/z66;Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooOo0O(Ljava/util/Set;)Llyiahf/vczjk/ib0;
    .locals 1

    new-instance v0, Llyiahf/vczjk/hb0;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/ib0;-><init>(Llyiahf/vczjk/ib0;Ljava/util/Set;)V

    return-object v0
.end method

.method public final OooOo0o(Llyiahf/vczjk/z66;)Llyiahf/vczjk/ib0;
    .locals 2

    new-instance v0, Llyiahf/vczjk/hb0;

    iget-object v1, p0, Llyiahf/vczjk/ib0;->_propertyFilterId:Ljava/lang/Object;

    invoke-direct {v0, p0, p1, v1}, Llyiahf/vczjk/ib0;-><init>(Llyiahf/vczjk/ib0;Llyiahf/vczjk/z66;Ljava/lang/Object;)V

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/b59;->OooO0OO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    const-string v1, "BeanSerializer for "

    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
