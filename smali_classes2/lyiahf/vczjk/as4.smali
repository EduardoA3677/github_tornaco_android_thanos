.class public final Llyiahf/vczjk/as4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/ds4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ds4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/as4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/as4;->OooOOO:Llyiahf/vczjk/ds4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 8

    iget v0, p0, Llyiahf/vczjk/as4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    sget-object v0, Llyiahf/vczjk/e72;->OooOOOO:Llyiahf/vczjk/e72;

    const/4 v1, 0x0

    iget-object v2, p0, Llyiahf/vczjk/as4;->OooOOO:Llyiahf/vczjk/ds4;

    invoke-virtual {v2, v0, v1}, Llyiahf/vczjk/ds4;->OooO0oo(Llyiahf/vczjk/e72;Llyiahf/vczjk/g13;)Ljava/util/Set;

    move-result-object v0

    return-object v0

    :pswitch_0
    sget-object v0, Llyiahf/vczjk/e72;->OooOOo0:Llyiahf/vczjk/e72;

    iget-object v1, p0, Llyiahf/vczjk/as4;->OooOOO:Llyiahf/vczjk/ds4;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ds4;->OooOOOO(Llyiahf/vczjk/e72;)Ljava/util/Set;

    move-result-object v0

    return-object v0

    :pswitch_1
    sget-object v0, Llyiahf/vczjk/e72;->OooOOOo:Llyiahf/vczjk/e72;

    const/4 v1, 0x0

    iget-object v2, p0, Llyiahf/vczjk/as4;->OooOOO:Llyiahf/vczjk/ds4;

    invoke-virtual {v2, v0, v1}, Llyiahf/vczjk/ds4;->OooO(Llyiahf/vczjk/e72;Llyiahf/vczjk/g13;)Ljava/util/Set;

    move-result-object v0

    return-object v0

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/as4;->OooOOO:Llyiahf/vczjk/ds4;

    invoke-virtual {v0}, Llyiahf/vczjk/ds4;->OooOO0O()Llyiahf/vczjk/c12;

    move-result-object v0

    return-object v0

    :pswitch_3
    sget-object v0, Llyiahf/vczjk/e72;->OooOOO0:Llyiahf/vczjk/e72;

    sget-object v1, Llyiahf/vczjk/jg5;->OooO00o:Llyiahf/vczjk/tp3;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/g13;->OooOoo:Llyiahf/vczjk/g13;

    iget-object v2, p0, Llyiahf/vczjk/as4;->OooOOO:Llyiahf/vczjk/ds4;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v3, "kindFilter"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/h16;->OooOOOo:Llyiahf/vczjk/h16;

    new-instance v4, Ljava/util/LinkedHashSet;

    invoke-direct {v4}, Ljava/util/LinkedHashSet;-><init>()V

    sget v5, Llyiahf/vczjk/e72;->OooOO0o:I

    invoke-virtual {v0, v5}, Llyiahf/vczjk/e72;->OooO00o(I)Z

    move-result v5

    if-eqz v5, :cond_0

    invoke-virtual {v2, v0, v1}, Llyiahf/vczjk/ds4;->OooO0oo(Llyiahf/vczjk/e72;Llyiahf/vczjk/g13;)Ljava/util/Set;

    move-result-object v5

    invoke-interface {v5}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_0

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/qt5;

    invoke-virtual {v1, v6}, Llyiahf/vczjk/g13;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v2, v6, v3}, Llyiahf/vczjk/kg5;->OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;

    move-result-object v6

    invoke-static {v4, v6}, Llyiahf/vczjk/t51;->OooOO0o(Ljava/util/AbstractCollection;Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    sget v5, Llyiahf/vczjk/e72;->OooO:I

    invoke-virtual {v0, v5}, Llyiahf/vczjk/e72;->OooO00o(I)Z

    move-result v5

    iget-object v6, v0, Llyiahf/vczjk/e72;->OooO00o:Ljava/util/List;

    if-eqz v5, :cond_1

    sget-object v5, Llyiahf/vczjk/a72;->OooO00o:Llyiahf/vczjk/a72;

    invoke-interface {v6, v5}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_1

    invoke-virtual {v2, v0, v1}, Llyiahf/vczjk/ds4;->OooO(Llyiahf/vczjk/e72;Llyiahf/vczjk/g13;)Ljava/util/Set;

    move-result-object v5

    invoke-interface {v5}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :goto_1
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_1

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/qt5;

    invoke-virtual {v1, v7}, Llyiahf/vczjk/g13;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v2, v7, v3}, Llyiahf/vczjk/ds4;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object v7

    invoke-virtual {v4, v7}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    goto :goto_1

    :cond_1
    sget v5, Llyiahf/vczjk/e72;->OooOO0:I

    invoke-virtual {v0, v5}, Llyiahf/vczjk/e72;->OooO00o(I)Z

    move-result v5

    if-eqz v5, :cond_2

    sget-object v5, Llyiahf/vczjk/a72;->OooO00o:Llyiahf/vczjk/a72;

    invoke-interface {v6, v5}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_2

    invoke-virtual {v2, v0}, Llyiahf/vczjk/ds4;->OooOOOO(Llyiahf/vczjk/e72;)Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/qt5;

    invoke-virtual {v1, v5}, Llyiahf/vczjk/g13;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v2, v5, v3}, Llyiahf/vczjk/ds4;->OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    goto :goto_2

    :cond_2
    invoke-static {v4}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
