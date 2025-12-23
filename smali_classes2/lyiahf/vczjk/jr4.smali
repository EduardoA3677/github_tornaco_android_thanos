.class public final Llyiahf/vczjk/jr4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/kr4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kr4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/jr4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/jr4;->OooOOO:Llyiahf/vczjk/kr4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 6

    iget v0, p0, Llyiahf/vczjk/jr4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/jr4;->OooOOO:Llyiahf/vczjk/kr4;

    iget-object v1, v0, Llyiahf/vczjk/kr4;->OooO0O0:Llyiahf/vczjk/sl7;

    invoke-virtual {v1}, Llyiahf/vczjk/sl7;->OooO0O0()Ljava/util/ArrayList;

    move-result-object v1

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/y54;

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/tl7;

    iget-object v4, v4, Llyiahf/vczjk/tl7;->OooO00o:Llyiahf/vczjk/qt5;

    if-nez v4, :cond_1

    sget-object v4, Llyiahf/vczjk/dd4;->OooO0O0:Llyiahf/vczjk/qt5;

    :cond_1
    invoke-virtual {v0, v3}, Llyiahf/vczjk/kr4;->OooO00o(Llyiahf/vczjk/y54;)Llyiahf/vczjk/ij1;

    move-result-object v3

    if-eqz v3, :cond_2

    new-instance v5, Llyiahf/vczjk/xn6;

    invoke-direct {v5, v4, v3}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_1

    :cond_2
    const/4 v5, 0x0

    :goto_1
    if-eqz v5, :cond_0

    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_3
    invoke-static {v2}, Llyiahf/vczjk/lc5;->o0OOO0o(Ljava/util/List;)Ljava/util/Map;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/jr4;->OooOOO:Llyiahf/vczjk/kr4;

    invoke-virtual {v0}, Llyiahf/vczjk/kr4;->OooO0oo()Llyiahf/vczjk/hc3;

    move-result-object v1

    iget-object v2, v0, Llyiahf/vczjk/kr4;->OooO0O0:Llyiahf/vczjk/sl7;

    if-nez v1, :cond_4

    sget-object v0, Llyiahf/vczjk/tq2;->Oooo0oo:Llyiahf/vczjk/tq2;

    invoke-virtual {v2}, Llyiahf/vczjk/sl7;->toString()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/uq2;->OooO0OO(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object v0

    goto :goto_3

    :cond_4
    iget-object v0, v0, Llyiahf/vczjk/kr4;->OooO00o:Llyiahf/vczjk/ld9;

    iget-object v3, v0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/s64;

    iget-object v3, v3, Llyiahf/vczjk/s64;->OooOOOO:Llyiahf/vczjk/dm5;

    iget-object v3, v3, Llyiahf/vczjk/dm5;->OooOOoo:Llyiahf/vczjk/hk4;

    invoke-static {v1, v3}, Llyiahf/vczjk/e86;->OooOOOo(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hk4;)Llyiahf/vczjk/by0;

    move-result-object v3

    if-nez v3, :cond_6

    new-instance v3, Llyiahf/vczjk/cm7;

    iget-object v2, v2, Llyiahf/vczjk/sl7;->OooO00o:Ljava/lang/annotation/Annotation;

    invoke-static {v2}, Llyiahf/vczjk/rs;->OooOooo(Ljava/lang/annotation/Annotation;)Llyiahf/vczjk/gf4;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v2

    invoke-direct {v3, v2}, Llyiahf/vczjk/cm7;-><init>(Ljava/lang/Class;)V

    iget-object v0, v0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v2, v0, Llyiahf/vczjk/s64;->OooOO0O:Llyiahf/vczjk/as7;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, v2, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/uz5;

    if-eqz v2, :cond_5

    invoke-virtual {v2, v3}, Llyiahf/vczjk/uz5;->Ooooo0o(Llyiahf/vczjk/cm7;)Llyiahf/vczjk/by0;

    move-result-object v3

    if-nez v3, :cond_6

    new-instance v2, Llyiahf/vczjk/hy0;

    invoke-virtual {v1}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v3

    iget-object v1, v1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v1}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-direct {v2, v3, v1}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    iget-object v1, v0, Llyiahf/vczjk/s64;->OooO0Oo:Llyiahf/vczjk/l82;

    invoke-virtual {v1}, Llyiahf/vczjk/l82;->OooO0OO()Llyiahf/vczjk/s72;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/s72;->OooOO0o:Llyiahf/vczjk/ld9;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooOOOO:Llyiahf/vczjk/dm5;

    invoke-static {v0, v2, v1}, Llyiahf/vczjk/r02;->OooOOoo(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hy0;Llyiahf/vczjk/ld9;)Llyiahf/vczjk/by0;

    move-result-object v3

    goto :goto_2

    :cond_5
    const-string v0, "resolver"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v0, 0x0

    throw v0

    :cond_6
    :goto_2
    invoke-interface {v3}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    :goto_3
    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/jr4;->OooOOO:Llyiahf/vczjk/kr4;

    iget-object v0, v0, Llyiahf/vczjk/kr4;->OooO0O0:Llyiahf/vczjk/sl7;

    iget-object v0, v0, Llyiahf/vczjk/sl7;->OooO00o:Ljava/lang/annotation/Annotation;

    invoke-static {v0}, Llyiahf/vczjk/rs;->OooOooo(Ljava/lang/annotation/Annotation;)Llyiahf/vczjk/gf4;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
