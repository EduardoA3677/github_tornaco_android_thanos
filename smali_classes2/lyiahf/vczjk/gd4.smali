.class public final Llyiahf/vczjk/gd4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/dm5;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/dm5;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/gd4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/gd4;->OooOOO:Llyiahf/vczjk/dm5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/gd4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    sget-object v0, Llyiahf/vczjk/x09;->OooO:Llyiahf/vczjk/hc3;

    iget-object v1, p0, Llyiahf/vczjk/gd4;->OooOOO:Llyiahf/vczjk/dm5;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/dm5;->OooooO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/vh6;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/hw4;

    iget-object v0, v0, Llyiahf/vczjk/hw4;->OooOo0O:Llyiahf/vczjk/pw4;

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/gd4;->OooOOO:Llyiahf/vczjk/dm5;

    iget-object v1, v0, Llyiahf/vczjk/dm5;->OooOo0O:Llyiahf/vczjk/tg7;

    if-eqz v1, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/dm5;->o0000oO()V

    iget-object v1, v1, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v1, Ljava/util/List;

    invoke-interface {v1, v0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/dm5;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto :goto_0

    :cond_0
    new-instance v2, Ljava/util/ArrayList;

    const/16 v3, 0xa

    invoke-static {v1, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/dm5;

    iget-object v3, v3, Llyiahf/vczjk/dm5;->OooOo0o:Llyiahf/vczjk/lh6;

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_1
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v3, "CompositeProvider@ModuleDescriptor for "

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/ig1;

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/ig1;-><init>(Ljava/util/List;Ljava/lang/String;)V

    return-object v1

    :cond_2
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Dependencies of module "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/qt5;->OooOOO0:Ljava/lang/String;

    const-string v2, "toString(...)"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, " were not set before querying module content"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/AssertionError;

    invoke-direct {v1, v0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v1

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/id4;

    iget-object v1, p0, Llyiahf/vczjk/gd4;->OooOOO:Llyiahf/vczjk/dm5;

    invoke-direct {v0, v1}, Llyiahf/vczjk/id4;-><init>(Llyiahf/vczjk/dm5;)V

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
