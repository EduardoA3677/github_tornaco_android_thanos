.class public final Llyiahf/vczjk/ug4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/wg4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/wg4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ug4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ug4;->OooOOO:Llyiahf/vczjk/wg4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 12

    iget v0, p0, Llyiahf/vczjk/ug4;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ug4;->OooOOO:Llyiahf/vczjk/wg4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/wg4;->OooO0oO:[Llyiahf/vczjk/th4;

    const/4 v2, 0x0

    aget-object v1, v1, v2

    iget-object v0, v0, Llyiahf/vczjk/wg4;->OooO0OO:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/tm7;

    if-eqz v0, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/tm7;->OooO0O0:Llyiahf/vczjk/fq3;

    iget-object v1, v0, Llyiahf/vczjk/fq3;->OooO0o0:Ljava/lang/Object;

    check-cast v1, [Ljava/lang/String;

    if-eqz v1, :cond_0

    iget-object v2, v0, Llyiahf/vczjk/fq3;->OooO0oO:Ljava/lang/Object;

    check-cast v2, [Ljava/lang/String;

    if-eqz v2, :cond_0

    invoke-static {v1, v2}, Llyiahf/vczjk/ve4;->OooO0oo([Ljava/lang/String;[Ljava/lang/String;)Llyiahf/vczjk/xn6;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/be4;

    invoke-virtual {v1}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/tc7;

    new-instance v3, Llyiahf/vczjk/d1a;

    iget-object v0, v0, Llyiahf/vczjk/fq3;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yi5;

    invoke-direct {v3, v1, v2, v0}, Llyiahf/vczjk/d1a;-><init>(Ljava/io/Serializable;Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    return-object v3

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/ug4;->OooOOO:Llyiahf/vczjk/wg4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/wg4;->OooO0oO:[Llyiahf/vczjk/th4;

    const/4 v2, 0x0

    aget-object v1, v1, v2

    iget-object v1, v0, Llyiahf/vczjk/wg4;->OooO0OO:Llyiahf/vczjk/wm7;

    invoke-virtual {v1}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/tm7;

    if-eqz v1, :cond_b

    sget-object v3, Llyiahf/vczjk/vf4;->OooO0O0:[Llyiahf/vczjk/th4;

    aget-object v2, v3, v2

    iget-object v0, v0, Llyiahf/vczjk/vf4;->OooO00o:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    const-string v2, "getValue(...)"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/gz7;

    iget-object v0, v0, Llyiahf/vczjk/gz7;->OooO0O0:Llyiahf/vczjk/ed5;

    iget-object v2, v0, Llyiahf/vczjk/ed5;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Ljava/util/concurrent/ConcurrentHashMap;

    iget-object v3, v1, Llyiahf/vczjk/tm7;->OooO00o:Ljava/lang/Class;

    invoke-static {v3}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v4

    invoke-virtual {v2, v4}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    if-nez v5, :cond_a

    invoke-static {v3}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v3

    iget-object v5, v1, Llyiahf/vczjk/tm7;->OooO0O0:Llyiahf/vczjk/fq3;

    sget-object v6, Llyiahf/vczjk/ik4;->OooOOoo:Llyiahf/vczjk/ik4;

    iget-object v7, v0, Llyiahf/vczjk/ed5;->OooOOO:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/l82;

    iget-object v8, v5, Llyiahf/vczjk/fq3;->OooO0OO:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/ik4;

    if-ne v8, v6, :cond_5

    const/4 v9, 0x0

    if-ne v8, v6, :cond_1

    iget-object v5, v5, Llyiahf/vczjk/fq3;->OooO0o0:Ljava/lang/Object;

    check-cast v5, [Ljava/lang/String;

    goto :goto_1

    :cond_1
    move-object v5, v9

    :goto_1
    if-eqz v5, :cond_2

    invoke-static {v5}, Llyiahf/vczjk/sy;->Oooooo0([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v9

    :cond_2
    if-nez v9, :cond_3

    sget-object v9, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :cond_3
    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :cond_4
    :goto_2
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_6

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/lang/String;

    invoke-static {v8}, Llyiahf/vczjk/rd4;->OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/rd4;

    move-result-object v8

    new-instance v9, Llyiahf/vczjk/hc3;

    const/16 v10, 0x2e

    iget-object v8, v8, Llyiahf/vczjk/rd4;->OooO00o:Ljava/lang/String;

    const/16 v11, 0x2f

    invoke-virtual {v8, v11, v10}, Ljava/lang/String;->replace(CC)Ljava/lang/String;

    move-result-object v8

    invoke-direct {v9, v8}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v8, Llyiahf/vczjk/hy0;

    invoke-virtual {v9}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v10

    iget-object v9, v9, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v9}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v9

    invoke-direct {v8, v10, v9}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    invoke-virtual {v7}, Llyiahf/vczjk/l82;->OooO0OO()Llyiahf/vczjk/s72;

    move-result-object v9

    iget-object v9, v9, Llyiahf/vczjk/s72;->OooO0OO:Llyiahf/vczjk/pp3;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v9, Llyiahf/vczjk/yi5;->OooO0oO:Llyiahf/vczjk/yi5;

    iget-object v10, v0, Llyiahf/vczjk/ed5;->OooOOOO:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/tg7;

    invoke-static {v10, v8, v9}, Llyiahf/vczjk/dn8;->OoooOOo(Llyiahf/vczjk/tg7;Llyiahf/vczjk/hy0;Llyiahf/vczjk/yi5;)Llyiahf/vczjk/tm7;

    move-result-object v8

    if-eqz v8, :cond_4

    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_5
    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v5

    :cond_6
    new-instance v0, Llyiahf/vczjk/dn2;

    invoke-virtual {v7}, Llyiahf/vczjk/l82;->OooO0OO()Llyiahf/vczjk/s72;

    move-result-object v6

    iget-object v6, v6, Llyiahf/vczjk/s72;->OooO0O0:Llyiahf/vczjk/cm5;

    iget-object v3, v3, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    const/4 v8, 0x0

    invoke-direct {v0, v6, v3, v8}, Llyiahf/vczjk/dn2;-><init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hc3;I)V

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :cond_7
    :goto_3
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_8

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/tm7;

    invoke-virtual {v7, v0, v8}, Llyiahf/vczjk/l82;->OooO00o(Llyiahf/vczjk/hh6;Llyiahf/vczjk/tm7;)Llyiahf/vczjk/s82;

    move-result-object v8

    if-eqz v8, :cond_7

    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_8
    invoke-static {v6}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    new-instance v5, Ljava/lang/StringBuilder;

    const-string v6, "package "

    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v3, " ("

    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, v0}, Llyiahf/vczjk/rs;->OooOOoo(Ljava/lang/String;Ljava/util/List;)Llyiahf/vczjk/jg5;

    move-result-object v0

    invoke-virtual {v2, v4, v0}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_9

    move-object v5, v0

    goto :goto_4

    :cond_9
    move-object v5, v1

    :cond_a
    :goto_4
    const-string v0, "getOrPut(...)"

    invoke-static {v5, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v5, Llyiahf/vczjk/jg5;

    goto :goto_5

    :cond_b
    sget-object v5, Llyiahf/vczjk/ig5;->OooO0O0:Llyiahf/vczjk/ig5;

    :goto_5
    return-object v5

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
