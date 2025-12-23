.class public final Llyiahf/vczjk/mf3;
.super Llyiahf/vczjk/o0O0O00;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0OO:Llyiahf/vczjk/nf3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nf3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mf3;->OooO0OO:Llyiahf/vczjk/nf3;

    iget-object p1, p1, Llyiahf/vczjk/nf3;->OooOOo0:Llyiahf/vczjk/q45;

    invoke-direct {p0, p1}, Llyiahf/vczjk/o0O0O00;-><init>(Llyiahf/vczjk/q45;)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/gz0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mf3;->OooO0OO:Llyiahf/vczjk/nf3;

    return-object v0
.end method

.method public final OooO0OO()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mf3;->OooO0OO:Llyiahf/vczjk/nf3;

    iget-object v0, v0, Llyiahf/vczjk/nf3;->OooOo0o:Ljava/util/List;

    return-object v0
.end method

.method public final OooO0Oo()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooO0o()Ljava/util/Collection;
    .locals 12

    const/4 v0, 0x1

    iget-object v1, p0, Llyiahf/vczjk/mf3;->OooO0OO:Llyiahf/vczjk/nf3;

    iget-object v2, v1, Llyiahf/vczjk/nf3;->OooOOoo:Llyiahf/vczjk/bg3;

    sget-object v3, Llyiahf/vczjk/xf3;->OooO0OO:Llyiahf/vczjk/xf3;

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    sget-object v2, Llyiahf/vczjk/nf3;->OooOo:Llyiahf/vczjk/hy0;

    invoke-static {v2}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    goto :goto_0

    :cond_0
    sget-object v4, Llyiahf/vczjk/yf3;->OooO0OO:Llyiahf/vczjk/yf3;

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    iget v5, v1, Llyiahf/vczjk/nf3;->OooOo00:I

    if-eqz v4, :cond_1

    sget-object v2, Llyiahf/vczjk/nf3;->OooOoO0:Llyiahf/vczjk/hy0;

    new-instance v4, Llyiahf/vczjk/hy0;

    sget-object v6, Llyiahf/vczjk/x09;->OooOO0o:Llyiahf/vczjk/hc3;

    invoke-virtual {v3, v5}, Llyiahf/vczjk/bg3;->OooO00o(I)Llyiahf/vczjk/qt5;

    move-result-object v3

    invoke-direct {v4, v6, v3}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    filled-new-array {v2, v4}, [Llyiahf/vczjk/hy0;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    goto :goto_0

    :cond_1
    sget-object v3, Llyiahf/vczjk/ag3;->OooO0OO:Llyiahf/vczjk/ag3;

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_2

    sget-object v2, Llyiahf/vczjk/nf3;->OooOo:Llyiahf/vczjk/hy0;

    invoke-static {v2}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    goto :goto_0

    :cond_2
    sget-object v4, Llyiahf/vczjk/zf3;->OooO0OO:Llyiahf/vczjk/zf3;

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_c

    sget-object v2, Llyiahf/vczjk/nf3;->OooOoO0:Llyiahf/vczjk/hy0;

    new-instance v4, Llyiahf/vczjk/hy0;

    sget-object v6, Llyiahf/vczjk/x09;->OooO0o:Llyiahf/vczjk/hc3;

    invoke-virtual {v3, v5}, Llyiahf/vczjk/bg3;->OooO00o(I)Llyiahf/vczjk/qt5;

    move-result-object v3

    invoke-direct {v4, v6, v3}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    filled-new-array {v2, v4}, [Llyiahf/vczjk/hy0;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    :goto_0
    iget-object v3, v1, Llyiahf/vczjk/nf3;->OooOOo:Llyiahf/vczjk/hk0;

    check-cast v3, Llyiahf/vczjk/ih6;

    invoke-virtual {v3}, Llyiahf/vczjk/ih6;->o0000O0()Llyiahf/vczjk/cm5;

    move-result-object v3

    new-instance v4, Ljava/util/ArrayList;

    const/16 v5, 0xa

    invoke-static {v2, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v6

    invoke-direct {v4, v6}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_b

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/hy0;

    invoke-static {v3, v6}, Llyiahf/vczjk/r02;->OooOOo0(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hy0;)Llyiahf/vczjk/by0;

    move-result-object v7

    if-eqz v7, :cond_a

    invoke-interface {v7}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v6

    invoke-interface {v6}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v6

    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v6

    const-string v8, "<this>"

    iget-object v9, v1, Llyiahf/vczjk/nf3;->OooOo0o:Ljava/util/List;

    invoke-static {v9, v8}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-ltz v6, :cond_9

    if-nez v6, :cond_3

    sget-object v6, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    goto :goto_4

    :cond_3
    invoke-interface {v9}, Ljava/util/List;->size()I

    move-result v8

    if-lt v6, v8, :cond_4

    invoke-static {v9}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v6

    goto :goto_4

    :cond_4
    if-ne v6, v0, :cond_5

    invoke-static {v9}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v6

    invoke-static {v6}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v6

    goto :goto_4

    :cond_5
    new-instance v10, Ljava/util/ArrayList;

    invoke-direct {v10, v6}, Ljava/util/ArrayList;-><init>(I)V

    instance-of v11, v9, Ljava/util/RandomAccess;

    if-eqz v11, :cond_6

    sub-int v6, v8, v6

    :goto_2
    if-ge v6, v8, :cond_7

    invoke-interface {v9, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v11

    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/2addr v6, v0

    goto :goto_2

    :cond_6
    sub-int/2addr v8, v6

    invoke-interface {v9, v8}, Ljava/util/List;->listIterator(I)Ljava/util/ListIterator;

    move-result-object v6

    :goto_3
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_7

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_7
    move-object v6, v10

    :goto_4
    new-instance v8, Ljava/util/ArrayList;

    invoke-static {v6, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v9

    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :goto_5
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    if-eqz v9, :cond_8

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/t4a;

    new-instance v10, Llyiahf/vczjk/f19;

    invoke-interface {v9}, Llyiahf/vczjk/gz0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v9

    invoke-direct {v10, v9}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/uk4;)V

    invoke-virtual {v8, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_5

    :cond_8
    sget-object v6, Llyiahf/vczjk/d3a;->OooOOO:Llyiahf/vczjk/xo8;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/d3a;->OooOOOO:Llyiahf/vczjk/d3a;

    invoke-static {v6, v7, v8}, Llyiahf/vczjk/so8;->Oooo0o(Llyiahf/vczjk/d3a;Llyiahf/vczjk/by0;Ljava/util/List;)Llyiahf/vczjk/dp8;

    move-result-object v6

    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto/16 :goto_1

    :cond_9
    const-string v0, "Requested element count "

    const-string v1, " is less than zero."

    invoke-static {v6, v0, v1}, Llyiahf/vczjk/ii5;->OooO0o(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Built-in class "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, " not found"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_b
    invoke-static {v4}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :cond_c
    sget v0, Llyiahf/vczjk/l1;->OooO00o:I

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "should not be called"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OooO0oo()Llyiahf/vczjk/sp3;
    .locals 1

    sget-object v0, Llyiahf/vczjk/sp3;->OooOo00:Llyiahf/vczjk/sp3;

    return-object v0
.end method

.method public final OooOOO()Llyiahf/vczjk/by0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mf3;->OooO0OO:Llyiahf/vczjk/nf3;

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mf3;->OooO0OO:Llyiahf/vczjk/nf3;

    invoke-virtual {v0}, Llyiahf/vczjk/nf3;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
