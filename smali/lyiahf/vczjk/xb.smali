.class public final Llyiahf/vczjk/xb;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/pc2;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Ljava/lang/Object;

.field public final synthetic OooO0OO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/xb;->OooO00o:I

    iput-object p2, p0, Llyiahf/vczjk/xb;->OooO0O0:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/xb;->OooO0OO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 5

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/xb;->OooO0OO:Ljava/lang/Object;

    iget-object v2, p0, Llyiahf/vczjk/xb;->OooO0O0:Ljava/lang/Object;

    iget v3, p0, Llyiahf/vczjk/xb;->OooO00o:I

    packed-switch v3, :pswitch_data_0

    check-cast v2, Llyiahf/vczjk/poa;

    iget v3, v2, Llyiahf/vczjk/poa;->OooOo00:I

    add-int/lit8 v3, v3, -0x1

    iput v3, v2, Llyiahf/vczjk/poa;->OooOo00:I

    if-nez v3, :cond_0

    sget-object v3, Llyiahf/vczjk/xfa;->OooO00o:Ljava/util/WeakHashMap;

    check-cast v1, Landroid/view/View;

    invoke-static {v1, v0}, Llyiahf/vczjk/ofa;->OooOOO0(Landroid/view/View;Llyiahf/vczjk/u96;)V

    invoke-static {v1, v0}, Llyiahf/vczjk/xfa;->OooOOo0(Landroid/view/View;Llyiahf/vczjk/i11;)V

    iget-object v0, v2, Llyiahf/vczjk/poa;->OooOo0:Llyiahf/vczjk/a14;

    invoke-virtual {v1, v0}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    :cond_0
    return-void

    :pswitch_0
    check-cast v2, Llyiahf/vczjk/bz9;

    iget-object v0, v2, Llyiahf/vczjk/bz9;->OooO:Llyiahf/vczjk/tw8;

    check-cast v1, Llyiahf/vczjk/uy9;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/tw8;->remove(Ljava/lang/Object;)Z

    return-void

    :pswitch_1
    check-cast v2, Llyiahf/vczjk/bz9;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    check-cast v1, Llyiahf/vczjk/oy9;

    iget-object v0, v1, Llyiahf/vczjk/oy9;->OooO0O0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ny9;

    if-eqz v0, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/ny9;->OooOOO0:Llyiahf/vczjk/uy9;

    iget-object v1, v2, Llyiahf/vczjk/bz9;->OooO:Llyiahf/vczjk/tw8;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/tw8;->remove(Ljava/lang/Object;)Z

    :cond_1
    return-void

    :pswitch_2
    check-cast v2, Llyiahf/vczjk/bz9;

    iget-object v0, v2, Llyiahf/vczjk/bz9;->OooOO0:Llyiahf/vczjk/tw8;

    check-cast v1, Llyiahf/vczjk/bz9;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/tw8;->remove(Ljava/lang/Object;)Z

    return-void

    :pswitch_3
    check-cast v2, Llyiahf/vczjk/zm9;

    iget-object v0, v2, Llyiahf/vczjk/zm9;->OooO0OO:Llyiahf/vczjk/tw8;

    check-cast v1, Llyiahf/vczjk/oe3;

    invoke-interface {v0, v1}, Ljava/util/Collection;->remove(Ljava/lang/Object;)Z

    return-void

    :pswitch_4
    check-cast v2, Llyiahf/vczjk/qs5;

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/q37;

    if-eqz v3, :cond_3

    new-instance v4, Llyiahf/vczjk/p37;

    invoke-direct {v4, v3}, Llyiahf/vczjk/p37;-><init>(Llyiahf/vczjk/q37;)V

    check-cast v1, Llyiahf/vczjk/rr5;

    if-eqz v1, :cond_2

    check-cast v1, Llyiahf/vczjk/sr5;

    invoke-virtual {v1, v4}, Llyiahf/vczjk/sr5;->OooO0OO(Llyiahf/vczjk/j24;)Z

    :cond_2
    invoke-interface {v2, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    :cond_3
    return-void

    :pswitch_5
    check-cast v2, Llyiahf/vczjk/uy4;

    invoke-interface {v2}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v0

    check-cast v1, Llyiahf/vczjk/o0OO00o0;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ky4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    return-void

    :pswitch_6
    check-cast v2, Llyiahf/vczjk/p29;

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/List;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_4

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ku5;

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/ae1;

    invoke-virtual {v3}, Llyiahf/vczjk/sy5;->OooO0O0()Llyiahf/vczjk/pu5;

    move-result-object v3

    invoke-virtual {v3, v2}, Llyiahf/vczjk/pu5;->OooO0OO(Llyiahf/vczjk/ku5;)V

    goto :goto_0

    :cond_4
    return-void

    :pswitch_7
    check-cast v2, Llyiahf/vczjk/lw4;

    iget-object v0, v2, Llyiahf/vczjk/lw4;->OooO0OO:Llyiahf/vczjk/ks5;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ks5;->OooOO0(Ljava/lang/Object;)V

    return-void

    :pswitch_8
    check-cast v2, Llyiahf/vczjk/jy3;

    iget-object v0, v2, Llyiahf/vczjk/jy3;->OooO00o:Llyiahf/vczjk/ws5;

    check-cast v1, Llyiahf/vczjk/dy3;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ws5;->OooOO0(Ljava/lang/Object;)Z

    return-void

    :pswitch_9
    check-cast v2, Llyiahf/vczjk/uy4;

    invoke-interface {v2}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v0

    check-cast v1, Llyiahf/vczjk/p61;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ky4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    return-void

    :pswitch_a
    check-cast v2, Llyiahf/vczjk/ku5;

    iget-object v0, v2, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    iget-object v0, v0, Llyiahf/vczjk/mu5;->OooOO0:Llyiahf/vczjk/wy4;

    check-cast v1, Llyiahf/vczjk/ga2;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/wy4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    return-void

    :pswitch_b
    check-cast v2, Landroid/content/Context;

    invoke-virtual {v2}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v0

    check-cast v1, Llyiahf/vczjk/bc;

    invoke-virtual {v0, v1}, Landroid/content/Context;->unregisterComponentCallbacks(Landroid/content/ComponentCallbacks;)V

    return-void

    :pswitch_c
    check-cast v2, Landroid/content/Context;

    invoke-virtual {v2}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v0

    check-cast v1, Llyiahf/vczjk/zb;

    invoke-virtual {v0, v1}, Landroid/content/Context;->unregisterComponentCallbacks(Landroid/content/ComponentCallbacks;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
