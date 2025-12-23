.class public final Llyiahf/vczjk/hf4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/of4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/of4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/hf4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/hf4;->OooOOO:Llyiahf/vczjk/of4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 7

    const-string v0, "getStaticScope(...)"

    const/4 v1, 0x0

    iget-object v2, p0, Llyiahf/vczjk/hf4;->OooOOO:Llyiahf/vczjk/of4;

    iget v3, p0, Llyiahf/vczjk/hf4;->OooOOO0:I

    packed-switch v3, :pswitch_data_0

    invoke-virtual {v2}, Llyiahf/vczjk/of4;->OooO0oo()Ljava/util/Collection;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    new-instance v1, Ljava/util/ArrayList;

    const/16 v3, 0xa

    invoke-static {v0, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/il1;

    new-instance v4, Llyiahf/vczjk/bg4;

    invoke-direct {v4, v2, v3}, Llyiahf/vczjk/bg4;-><init>(Llyiahf/vczjk/yf4;Llyiahf/vczjk/rf3;)V

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    return-object v1

    :pswitch_0
    iget-object v0, v2, Llyiahf/vczjk/of4;->OooOOO:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->isAnonymousClass()Z

    move-result v0

    if-eqz v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v2}, Llyiahf/vczjk/of4;->OooOo0()Llyiahf/vczjk/hy0;

    move-result-object v0

    iget-boolean v2, v0, Llyiahf/vczjk/hy0;->OooO0OO:Z

    if-eqz v2, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v0}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v1, v0, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    :goto_1
    return-object v1

    :pswitch_1
    invoke-virtual {v2}, Llyiahf/vczjk/of4;->OooOo0O()Llyiahf/vczjk/by0;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/by0;->OoooO0()Llyiahf/vczjk/jg5;

    move-result-object v1

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/wf4;->OooOOO:Llyiahf/vczjk/wf4;

    invoke-virtual {v2, v1, v0}, Llyiahf/vczjk/yf4;->OooOO0o(Llyiahf/vczjk/jg5;Llyiahf/vczjk/wf4;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :pswitch_2
    invoke-virtual {v2}, Llyiahf/vczjk/of4;->OooOo0O()Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/wf4;->OooOOO:Llyiahf/vczjk/wf4;

    invoke-virtual {v2, v0, v1}, Llyiahf/vczjk/yf4;->OooOO0o(Llyiahf/vczjk/jg5;Llyiahf/vczjk/wf4;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :pswitch_3
    invoke-virtual {v2}, Llyiahf/vczjk/of4;->OooOo0O()Llyiahf/vczjk/by0;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/by0;->OoooO0()Llyiahf/vczjk/jg5;

    move-result-object v1

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/wf4;->OooOOO0:Llyiahf/vczjk/wf4;

    invoke-virtual {v2, v1, v0}, Llyiahf/vczjk/yf4;->OooOO0o(Llyiahf/vczjk/jg5;Llyiahf/vczjk/wf4;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :pswitch_4
    invoke-virtual {v2}, Llyiahf/vczjk/of4;->OooOo0O()Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/wf4;->OooOOO0:Llyiahf/vczjk/wf4;

    invoke-virtual {v2, v0, v1}, Llyiahf/vczjk/yf4;->OooOO0o(Llyiahf/vczjk/jg5;Llyiahf/vczjk/wf4;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :pswitch_5
    sget v0, Llyiahf/vczjk/of4;->OooOOOo:I

    invoke-virtual {v2}, Llyiahf/vczjk/of4;->OooOo0()Llyiahf/vczjk/hy0;

    move-result-object v0

    iget-object v3, v2, Llyiahf/vczjk/of4;->OooOOOO:Ljava/lang/Object;

    invoke-interface {v3}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/kf4;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/vf4;->OooO0O0:[Llyiahf/vczjk/th4;

    const/4 v5, 0x0

    aget-object v4, v4, v5

    iget-object v3, v3, Llyiahf/vczjk/vf4;->OooO00o:Llyiahf/vczjk/wm7;

    invoke-virtual {v3}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v3

    const-string v4, "getValue(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v3, Llyiahf/vczjk/gz7;

    iget-object v4, v3, Llyiahf/vczjk/gz7;->OooO00o:Llyiahf/vczjk/s72;

    iget-boolean v5, v0, Llyiahf/vczjk/hy0;->OooO0OO:Z

    iget-object v2, v2, Llyiahf/vczjk/of4;->OooOOO:Ljava/lang/Class;

    if-eqz v5, :cond_3

    const-class v5, Lkotlin/Metadata;

    invoke-virtual {v2, v5}, Ljava/lang/Class;->isAnnotationPresent(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_3

    invoke-virtual {v4, v0}, Llyiahf/vczjk/s72;->OooO0O0(Llyiahf/vczjk/hy0;)Llyiahf/vczjk/by0;

    move-result-object v4

    goto :goto_2

    :cond_3
    iget-object v4, v4, Llyiahf/vczjk/s72;->OooO0O0:Llyiahf/vczjk/cm5;

    invoke-static {v4, v0}, Llyiahf/vczjk/r02;->OooOOo0(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hy0;)Llyiahf/vczjk/by0;

    move-result-object v4

    :goto_2
    if-nez v4, :cond_7

    invoke-virtual {v2}, Ljava/lang/Class;->isSynthetic()Z

    move-result v4

    if-eqz v4, :cond_4

    invoke-static {v0, v3}, Llyiahf/vczjk/of4;->OooOo00(Llyiahf/vczjk/hy0;Llyiahf/vczjk/gz7;)Llyiahf/vczjk/ey0;

    move-result-object v4

    goto :goto_4

    :cond_4
    invoke-static {v2}, Llyiahf/vczjk/eo6;->OooO0oo(Ljava/lang/Class;)Llyiahf/vczjk/tm7;

    move-result-object v4

    if-eqz v4, :cond_5

    iget-object v1, v4, Llyiahf/vczjk/tm7;->OooO0O0:Llyiahf/vczjk/fq3;

    iget-object v1, v1, Llyiahf/vczjk/fq3;->OooO0OO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ik4;

    :cond_5
    if-nez v1, :cond_6

    const/4 v4, -0x1

    goto :goto_3

    :cond_6
    sget-object v4, Llyiahf/vczjk/lf4;->OooO00o:[I

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v5

    aget v4, v4, v5

    :goto_3
    const/16 v5, 0x29

    const-string v6, " (kind = "

    packed-switch v4, :pswitch_data_1

    :pswitch_6
    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :pswitch_7
    new-instance v0, Llyiahf/vczjk/es1;

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Unknown class: "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw v0

    :pswitch_8
    invoke-static {v0, v3}, Llyiahf/vczjk/of4;->OooOo00(Llyiahf/vczjk/hy0;Llyiahf/vczjk/gz7;)Llyiahf/vczjk/ey0;

    move-result-object v4

    goto :goto_4

    :pswitch_9
    new-instance v0, Llyiahf/vczjk/es1;

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Unresolved class: "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_7
    :goto_4
    return-object v4

    :pswitch_a
    new-instance v0, Llyiahf/vczjk/kf4;

    invoke-direct {v0, v2}, Llyiahf/vczjk/kf4;-><init>(Llyiahf/vczjk/of4;)V

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_a
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    :pswitch_data_1
    .packed-switch -0x1
        :pswitch_9
        :pswitch_6
        :pswitch_8
        :pswitch_8
        :pswitch_8
        :pswitch_8
        :pswitch_7
        :pswitch_9
    .end packed-switch
.end method
