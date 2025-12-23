.class public final Llyiahf/vczjk/if4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/kf4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kf4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/if4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/if4;->OooOOO:Llyiahf/vczjk/kf4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 5

    iget v0, p0, Llyiahf/vczjk/if4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/if4;->OooOOO:Llyiahf/vczjk/kf4;

    invoke-virtual {v0}, Llyiahf/vczjk/kf4;->OooO00o()Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/by0;->Oooo00o()Ljava/util/Collection;

    move-result-object v0

    const-string v1, "getSealedSubclasses(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/Iterable;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/by0;

    const-string v3, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.ClassDescriptor"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2}, Llyiahf/vczjk/mba;->OooOO0O(Llyiahf/vczjk/by0;)Ljava/lang/Class;

    move-result-object v2

    if-eqz v2, :cond_1

    new-instance v3, Llyiahf/vczjk/of4;

    invoke-direct {v3, v2}, Llyiahf/vczjk/of4;-><init>(Ljava/lang/Class;)V

    goto :goto_1

    :cond_1
    const/4 v3, 0x0

    :goto_1
    if-eqz v3, :cond_0

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    return-object v1

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/if4;->OooOOO:Llyiahf/vczjk/kf4;

    invoke-virtual {v0}, Llyiahf/vczjk/kf4;->OooO00o()Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/by0;->o0ooOO0()Llyiahf/vczjk/jg5;

    move-result-object v0

    const/4 v1, 0x0

    const/4 v2, 0x3

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/kh6;->OooOo0(Llyiahf/vczjk/mr7;Llyiahf/vczjk/e72;I)Ljava/util/Collection;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_3
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/v02;

    invoke-static {v4}, Llyiahf/vczjk/n72;->OooOOO0(Llyiahf/vczjk/v02;)Z

    move-result v4

    if-nez v4, :cond_3

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_4
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_5
    :goto_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_9

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/v02;

    instance-of v4, v3, Llyiahf/vczjk/by0;

    if-eqz v4, :cond_6

    check-cast v3, Llyiahf/vczjk/by0;

    goto :goto_4

    :cond_6
    move-object v3, v1

    :goto_4
    if-eqz v3, :cond_7

    invoke-static {v3}, Llyiahf/vczjk/mba;->OooOO0O(Llyiahf/vczjk/by0;)Ljava/lang/Class;

    move-result-object v3

    goto :goto_5

    :cond_7
    move-object v3, v1

    :goto_5
    if-eqz v3, :cond_8

    new-instance v4, Llyiahf/vczjk/of4;

    invoke-direct {v4, v3}, Llyiahf/vczjk/of4;-><init>(Ljava/lang/Class;)V

    goto :goto_6

    :cond_8
    move-object v4, v1

    :goto_6
    if-eqz v4, :cond_5

    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_9
    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/if4;->OooOOO:Llyiahf/vczjk/kf4;

    invoke-virtual {v0}, Llyiahf/vczjk/kf4;->OooO00o()Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/mba;->OooO0Oo(Llyiahf/vczjk/gm;)Ljava/util/ArrayList;

    move-result-object v0

    return-object v0

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/if4;->OooOOO:Llyiahf/vczjk/kf4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/kf4;->OooOO0o:[Llyiahf/vczjk/th4;

    const/16 v2, 0xd

    aget-object v2, v1, v2

    iget-object v2, v0, Llyiahf/vczjk/kf4;->OooOO0:Llyiahf/vczjk/wm7;

    invoke-virtual {v2}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v2

    const-string v3, "getValue(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Ljava/util/Collection;

    const/16 v4, 0xe

    aget-object v1, v1, v4

    iget-object v0, v0, Llyiahf/vczjk/kf4;->OooOO0O:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/util/Collection;

    check-cast v0, Ljava/lang/Iterable;

    invoke-static {v0, v2}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v0

    return-object v0

    :pswitch_3
    iget-object v0, p0, Llyiahf/vczjk/if4;->OooOOO:Llyiahf/vczjk/kf4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/kf4;->OooOO0o:[Llyiahf/vczjk/th4;

    const/16 v2, 0x9

    aget-object v2, v1, v2

    iget-object v2, v0, Llyiahf/vczjk/kf4;->OooO0o:Llyiahf/vczjk/wm7;

    invoke-virtual {v2}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v2

    const-string v3, "getValue(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Ljava/util/Collection;

    const/16 v4, 0xa

    aget-object v1, v1, v4

    iget-object v0, v0, Llyiahf/vczjk/kf4;->OooO0oO:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/util/Collection;

    check-cast v0, Ljava/lang/Iterable;

    invoke-static {v0, v2}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v0

    return-object v0

    :pswitch_4
    iget-object v0, p0, Llyiahf/vczjk/if4;->OooOOO:Llyiahf/vczjk/kf4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/kf4;->OooOO0o:[Llyiahf/vczjk/th4;

    const/16 v2, 0xa

    aget-object v2, v1, v2

    iget-object v2, v0, Llyiahf/vczjk/kf4;->OooO0oO:Llyiahf/vczjk/wm7;

    invoke-virtual {v2}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v2

    const-string v3, "getValue(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Ljava/util/Collection;

    const/16 v4, 0xc

    aget-object v1, v1, v4

    iget-object v0, v0, Llyiahf/vczjk/kf4;->OooO:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/util/Collection;

    check-cast v0, Ljava/lang/Iterable;

    invoke-static {v0, v2}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v0

    return-object v0

    :pswitch_5
    iget-object v0, p0, Llyiahf/vczjk/if4;->OooOOO:Llyiahf/vczjk/kf4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/kf4;->OooOO0o:[Llyiahf/vczjk/th4;

    const/16 v2, 0x9

    aget-object v2, v1, v2

    iget-object v2, v0, Llyiahf/vczjk/kf4;->OooO0o:Llyiahf/vczjk/wm7;

    invoke-virtual {v2}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v2

    const-string v3, "getValue(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Ljava/util/Collection;

    const/16 v4, 0xb

    aget-object v1, v1, v4

    iget-object v0, v0, Llyiahf/vczjk/kf4;->OooO0oo:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/util/Collection;

    check-cast v0, Ljava/lang/Iterable;

    invoke-static {v0, v2}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v0

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
