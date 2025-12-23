.class public final Llyiahf/vczjk/gw4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/hw4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/hw4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/gw4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/gw4;->OooOOO:Llyiahf/vczjk/hw4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 5

    iget v0, p0, Llyiahf/vczjk/gw4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/gw4;->OooOOO:Llyiahf/vczjk/hw4;

    iget-object v1, v0, Llyiahf/vczjk/hw4;->OooOo0:Llyiahf/vczjk/o45;

    sget-object v2, Llyiahf/vczjk/hw4;->OooOo0o:[Llyiahf/vczjk/th4;

    const/4 v3, 0x1

    aget-object v3, v2, v3

    invoke-static {v1, v3}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    if-eqz v1, :cond_0

    sget-object v0, Llyiahf/vczjk/ig5;->OooO0O0:Llyiahf/vczjk/ig5;

    goto :goto_1

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/hw4;->OooOo00:Llyiahf/vczjk/o45;

    const/4 v3, 0x0

    aget-object v2, v2, v3

    invoke-static {v1, v2}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/List;

    new-instance v2, Ljava/util/ArrayList;

    const/16 v3, 0xa

    invoke-static {v1, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/hh6;

    invoke-interface {v3}, Llyiahf/vczjk/hh6;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    new-instance v1, Llyiahf/vczjk/h89;

    iget-object v3, v0, Llyiahf/vczjk/hw4;->OooOOo:Llyiahf/vczjk/dm5;

    iget-object v0, v0, Llyiahf/vczjk/hw4;->OooOOoo:Llyiahf/vczjk/hc3;

    invoke-direct {v1, v3, v0}, Llyiahf/vczjk/h89;-><init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hc3;)V

    invoke-static {v2, v1}, Llyiahf/vczjk/d21;->o00000O(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v4, "package view scope for "

    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, " in "

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0, v1}, Llyiahf/vczjk/rs;->OooOOoo(Ljava/lang/String;Ljava/util/List;)Llyiahf/vczjk/jg5;

    move-result-object v0

    :goto_1
    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/gw4;->OooOOO:Llyiahf/vczjk/hw4;

    iget-object v1, v0, Llyiahf/vczjk/hw4;->OooOOo:Llyiahf/vczjk/dm5;

    invoke-virtual {v1}, Llyiahf/vczjk/dm5;->o0000oO()V

    iget-object v1, v1, Llyiahf/vczjk/dm5;->OooOoO:Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ig1;

    iget-object v0, v0, Llyiahf/vczjk/hw4;->OooOOoo:Llyiahf/vczjk/hc3;

    invoke-static {v1, v0}, Llyiahf/vczjk/kh6;->Oooo00O(Llyiahf/vczjk/lh6;Llyiahf/vczjk/hc3;)Z

    move-result v0

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/gw4;->OooOOO:Llyiahf/vczjk/hw4;

    iget-object v1, v0, Llyiahf/vczjk/hw4;->OooOOo:Llyiahf/vczjk/dm5;

    invoke-virtual {v1}, Llyiahf/vczjk/dm5;->o0000oO()V

    iget-object v1, v1, Llyiahf/vczjk/dm5;->OooOoO:Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ig1;

    iget-object v0, v0, Llyiahf/vczjk/hw4;->OooOOoo:Llyiahf/vczjk/hc3;

    invoke-static {v1, v0}, Llyiahf/vczjk/kh6;->Oooo0oO(Llyiahf/vczjk/lh6;Llyiahf/vczjk/hc3;)Ljava/util/ArrayList;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
