.class public final Llyiahf/vczjk/o0oOO;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/oe3;
.implements Llyiahf/vczjk/io0;


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/o0oOO;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/o0oOO;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/o0oOO;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    const/4 v0, 0x0

    const/4 v1, 0x1

    const/16 v2, 0x24

    const/16 v3, 0x2e

    const-string v4, "name"

    const/4 v5, 0x0

    sget-object v6, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v7, p0, Llyiahf/vczjk/o0oOO;->OooOOOO:Ljava/lang/Object;

    iget-object v8, p0, Llyiahf/vczjk/o0oOO;->OooOOO:Ljava/lang/Object;

    iget v9, p0, Llyiahf/vczjk/o0oOO;->OooOOO0:I

    packed-switch v9, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/eo0;

    check-cast v8, Llyiahf/vczjk/c6a;

    check-cast v7, Llyiahf/vczjk/eo0;

    const-string v0, "second"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v8, v7, p1}, Llyiahf/vczjk/c6a;->Oooo000(Llyiahf/vczjk/eo0;Llyiahf/vczjk/eo0;)V

    return-object v6

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/ww2;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v8, Llyiahf/vczjk/oe3;

    if-eqz v8, :cond_0

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    check-cast v7, Llyiahf/vczjk/qs5;

    invoke-interface {v7, p1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    :cond_0
    return-object v6

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/vr4;

    const-string v0, "request"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/hy0;

    check-cast v8, Llyiahf/vczjk/zr4;

    iget-object v1, v8, Llyiahf/vczjk/zr4;->OooOOOO:Llyiahf/vczjk/tr4;

    iget-object v1, v1, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    iget-object v4, p1, Llyiahf/vczjk/vr4;->OooO00o:Llyiahf/vczjk/qt5;

    invoke-direct {v0, v1, v4}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    check-cast v7, Llyiahf/vczjk/ld9;

    iget-object v1, v8, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object v4, v7, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/s64;

    iget-object p1, p1, Llyiahf/vczjk/vr4;->OooO0O0:Llyiahf/vczjk/cm7;

    if-eqz p1, :cond_3

    iget-object v6, v1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/s64;

    iget-object v6, v6, Llyiahf/vczjk/s64;->OooO0Oo:Llyiahf/vczjk/l82;

    invoke-virtual {v6}, Llyiahf/vczjk/l82;->OooO0OO()Llyiahf/vczjk/s72;

    move-result-object v6

    iget-object v6, v6, Llyiahf/vczjk/s72;->OooO0OO:Llyiahf/vczjk/pp3;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/yi5;->OooO0oO:Llyiahf/vczjk/yi5;

    iget-object v9, v4, Llyiahf/vczjk/s64;->OooO0OO:Llyiahf/vczjk/tg7;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v10, "metadataVersion"

    invoke-static {v6, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Llyiahf/vczjk/cm7;->OooO0OO()Llyiahf/vczjk/hc3;

    move-result-object v6

    if-eqz v6, :cond_2

    iget-object v6, v6, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v6, v6, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    if-nez v6, :cond_1

    goto :goto_0

    :cond_1
    iget-object v9, v9, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v9, Ljava/lang/ClassLoader;

    invoke-static {v9, v6}, Llyiahf/vczjk/tn6;->OooOo0O(Ljava/lang/ClassLoader;Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v6

    if-eqz v6, :cond_2

    invoke-static {v6}, Llyiahf/vczjk/eo6;->OooO0oo(Ljava/lang/Class;)Llyiahf/vczjk/tm7;

    move-result-object v6

    if-eqz v6, :cond_2

    new-instance v9, Llyiahf/vczjk/oO0OOo0o;

    const/16 v10, 0x17

    invoke-direct {v9, v6, v10}, Llyiahf/vczjk/oO0OOo0o;-><init>(Ljava/lang/Object;I)V

    goto :goto_1

    :cond_2
    :goto_0
    move-object v9, v5

    goto :goto_1

    :cond_3
    iget-object v6, v1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/s64;

    iget-object v6, v6, Llyiahf/vczjk/s64;->OooO0Oo:Llyiahf/vczjk/l82;

    invoke-virtual {v6}, Llyiahf/vczjk/l82;->OooO0OO()Llyiahf/vczjk/s72;

    move-result-object v6

    iget-object v6, v6, Llyiahf/vczjk/s72;->OooO0OO:Llyiahf/vczjk/pp3;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/yi5;->OooO0oO:Llyiahf/vczjk/yi5;

    iget-object v9, v4, Llyiahf/vczjk/s64;->OooO0OO:Llyiahf/vczjk/tg7;

    invoke-virtual {v9, v0, v6}, Llyiahf/vczjk/tg7;->OooOOo(Llyiahf/vczjk/hy0;Llyiahf/vczjk/yi5;)Llyiahf/vczjk/oO0OOo0o;

    move-result-object v9

    :goto_1
    if-eqz v9, :cond_4

    iget-object v6, v9, Llyiahf/vczjk/oO0OOo0o;->OooOOO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/tm7;

    goto :goto_2

    :cond_4
    move-object v6, v5

    :goto_2
    if-eqz v6, :cond_5

    iget-object v9, v6, Llyiahf/vczjk/tm7;->OooO00o:Ljava/lang/Class;

    invoke-static {v9}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v9

    goto :goto_3

    :cond_5
    move-object v9, v5

    :goto_3
    if-eqz v9, :cond_6

    invoke-virtual {v9}, Llyiahf/vczjk/hy0;->OooO0oO()Z

    move-result v10

    if-nez v10, :cond_12

    iget-boolean v9, v9, Llyiahf/vczjk/hy0;->OooO0OO:Z

    if-eqz v9, :cond_6

    goto/16 :goto_9

    :cond_6
    sget-object v9, Llyiahf/vczjk/xr4;->OooO0o:Llyiahf/vczjk/xr4;

    if-nez v6, :cond_7

    goto :goto_5

    :cond_7
    iget-object v10, v6, Llyiahf/vczjk/tm7;->OooO0O0:Llyiahf/vczjk/fq3;

    sget-object v11, Llyiahf/vczjk/ik4;->OooOOOo:Llyiahf/vczjk/ik4;

    iget-object v10, v10, Llyiahf/vczjk/fq3;->OooO0OO:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/ik4;

    if-ne v10, v11, :cond_9

    iget-object v1, v1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s64;

    iget-object v1, v1, Llyiahf/vczjk/s64;->OooO0Oo:Llyiahf/vczjk/l82;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v1, v6}, Llyiahf/vczjk/l82;->OooO0oO(Llyiahf/vczjk/tm7;)Llyiahf/vczjk/vx0;

    move-result-object v10

    if-nez v10, :cond_8

    move-object v1, v5

    goto :goto_4

    :cond_8
    invoke-virtual {v1}, Llyiahf/vczjk/l82;->OooO0OO()Llyiahf/vczjk/s72;

    move-result-object v1

    iget-object v6, v6, Llyiahf/vczjk/tm7;->OooO00o:Ljava/lang/Class;

    invoke-static {v6}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v6

    iget-object v1, v1, Llyiahf/vczjk/s72;->OooOo00:Llyiahf/vczjk/gy0;

    invoke-virtual {v1, v6, v10}, Llyiahf/vczjk/gy0;->OooO00o(Llyiahf/vczjk/hy0;Llyiahf/vczjk/vx0;)Llyiahf/vczjk/by0;

    move-result-object v1

    :goto_4
    if-eqz v1, :cond_a

    new-instance v9, Llyiahf/vczjk/wr4;

    invoke-direct {v9, v1}, Llyiahf/vczjk/wr4;-><init>(Llyiahf/vczjk/by0;)V

    goto :goto_5

    :cond_9
    sget-object v9, Llyiahf/vczjk/yr4;->OooO0o:Llyiahf/vczjk/yr4;

    :cond_a
    :goto_5
    instance-of v1, v9, Llyiahf/vczjk/wr4;

    if-eqz v1, :cond_b

    check-cast v9, Llyiahf/vczjk/wr4;

    iget-object v5, v9, Llyiahf/vczjk/wr4;->OooO0o:Llyiahf/vczjk/by0;

    goto/16 :goto_9

    :cond_b
    instance-of v1, v9, Llyiahf/vczjk/yr4;

    if-eqz v1, :cond_c

    goto/16 :goto_9

    :cond_c
    instance-of v1, v9, Llyiahf/vczjk/xr4;

    if-eqz v1, :cond_13

    if-nez p1, :cond_f

    iget-object p1, v4, Llyiahf/vczjk/s64;->OooO0O0:Llyiahf/vczjk/bh6;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, v0, Llyiahf/vczjk/hy0;->OooO0O0:Llyiahf/vczjk/hc3;

    iget-object v1, v1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v1, v1, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    invoke-static {v1, v3, v2}, Llyiahf/vczjk/g79;->OooOooo(Ljava/lang/String;CC)Ljava/lang/String;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    iget-object v2, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v2}, Llyiahf/vczjk/ic3;->OooO0OO()Z

    move-result v2

    if-eqz v2, :cond_d

    goto :goto_6

    :cond_d
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v0, v0, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    :goto_6
    iget-object p1, p1, Llyiahf/vczjk/bh6;->OooOOO0:Ljava/lang/Object;

    check-cast p1, Ljava/lang/ClassLoader;

    invoke-static {p1, v1}, Llyiahf/vczjk/tn6;->OooOo0O(Ljava/lang/ClassLoader;Ljava/lang/String;)Ljava/lang/Class;

    move-result-object p1

    if-eqz p1, :cond_e

    new-instance v0, Llyiahf/vczjk/cm7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/cm7;-><init>(Ljava/lang/Class;)V

    move-object p1, v0

    goto :goto_7

    :cond_e
    move-object p1, v5

    :cond_f
    :goto_7
    sget-object v0, Llyiahf/vczjk/yy4;->OooOOO0:[Llyiahf/vczjk/yy4;

    if-eqz p1, :cond_10

    invoke-virtual {p1}, Llyiahf/vczjk/cm7;->OooO0OO()Llyiahf/vczjk/hc3;

    move-result-object v0

    goto :goto_8

    :cond_10
    move-object v0, v5

    :goto_8
    if-eqz v0, :cond_12

    iget-object v1, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v1}, Llyiahf/vczjk/ic3;->OooO0OO()Z

    move-result v1

    if-nez v1, :cond_12

    invoke-virtual {v0}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v0

    iget-object v1, v8, Llyiahf/vczjk/zr4;->OooOOOO:Llyiahf/vczjk/tr4;

    iget-object v2, v1, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/hc3;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_11

    goto :goto_9

    :cond_11
    new-instance v0, Llyiahf/vczjk/nr4;

    invoke-direct {v0, v7, v1, p1, v5}, Llyiahf/vczjk/nr4;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/v02;Llyiahf/vczjk/cm7;Llyiahf/vczjk/by0;)V

    iget-object p1, v4, Llyiahf/vczjk/s64;->OooOOoo:Llyiahf/vczjk/sp3;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-object v5, v0

    :cond_12
    :goto_9
    return-object v5

    :cond_13
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/qt5;

    const-string v0, "accessorName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v8, Llyiahf/vczjk/ho8;

    invoke-virtual {v8}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_14

    invoke-static {v8}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    goto :goto_a

    :cond_14
    check-cast v7, Llyiahf/vczjk/rr4;

    invoke-virtual {v7, p1}, Llyiahf/vczjk/rr4;->Oooo0oO(Llyiahf/vczjk/qt5;)Ljava/util/ArrayList;

    move-result-object v0

    invoke-virtual {v7, p1}, Llyiahf/vczjk/rr4;->Oooo0oo(Llyiahf/vczjk/qt5;)Ljava/util/ArrayList;

    move-result-object p1

    invoke-static {p1, v0}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object p1

    :goto_a
    return-object p1

    :pswitch_3
    check-cast p1, Llyiahf/vczjk/qt5;

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v8, Llyiahf/vczjk/rr4;

    iget-object v0, v8, Llyiahf/vczjk/rr4;->OooOOo:Llyiahf/vczjk/o45;

    invoke-virtual {v0}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Set;

    invoke-interface {v0, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v0

    iget-object v6, v8, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    check-cast v7, Llyiahf/vczjk/ld9;

    if-eqz v0, :cond_17

    iget-object v0, v7, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    invoke-static {v6}, Llyiahf/vczjk/p72;->OooO0o(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/hy0;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v1, p1}, Llyiahf/vczjk/hy0;->OooO0Oo(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hy0;

    move-result-object p1

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooO0O0:Llyiahf/vczjk/bh6;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, p1, Llyiahf/vczjk/hy0;->OooO0O0:Llyiahf/vczjk/hc3;

    iget-object v1, v1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v1, v1, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    invoke-static {v1, v3, v2}, Llyiahf/vczjk/g79;->OooOooo(Ljava/lang/String;CC)Ljava/lang/String;

    move-result-object v1

    iget-object p1, p1, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    iget-object v2, p1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v2}, Llyiahf/vczjk/ic3;->OooO0OO()Z

    move-result v2

    if-eqz v2, :cond_15

    goto :goto_b

    :cond_15
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    iget-object p1, p1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object p1, p1, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    :goto_b
    iget-object p1, v0, Llyiahf/vczjk/bh6;->OooOOO0:Ljava/lang/Object;

    check-cast p1, Ljava/lang/ClassLoader;

    invoke-static {p1, v1}, Llyiahf/vczjk/tn6;->OooOo0O(Ljava/lang/ClassLoader;Ljava/lang/String;)Ljava/lang/Class;

    move-result-object p1

    if-eqz p1, :cond_16

    new-instance v0, Llyiahf/vczjk/cm7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/cm7;-><init>(Ljava/lang/Class;)V

    goto :goto_c

    :cond_16
    move-object v0, v5

    :goto_c
    if-eqz v0, :cond_1a

    new-instance p1, Llyiahf/vczjk/nr4;

    invoke-direct {p1, v7, v6, v0, v5}, Llyiahf/vczjk/nr4;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/v02;Llyiahf/vczjk/cm7;Llyiahf/vczjk/by0;)V

    iget-object v0, v7, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooOOoo:Llyiahf/vczjk/sp3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-object v5, p1

    goto/16 :goto_d

    :cond_17
    iget-object v0, v8, Llyiahf/vczjk/rr4;->OooOOoo:Llyiahf/vczjk/o45;

    invoke-virtual {v0}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Set;

    invoke-interface {v0, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_19

    invoke-static {}, Llyiahf/vczjk/r02;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object v0

    iget-object v2, v7, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s64;

    iget-object v2, v2, Llyiahf/vczjk/s64;->OooOo:Llyiahf/vczjk/zc9;

    check-cast v2, Llyiahf/vczjk/up3;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v2, "thisDescriptor"

    invoke-static {v6, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "c"

    invoke-static {v7, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/y05;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/o00O0O0O;->OooO00o()I

    move-result v0

    if-eqz v0, :cond_1a

    if-ne v0, v1, :cond_18

    invoke-static {p1}, Llyiahf/vczjk/d21;->o00000o0(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/by0;

    goto :goto_d

    :cond_18
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Multiple classes with same name are generated: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_19
    iget-object v0, v8, Llyiahf/vczjk/rr4;->OooOo00:Llyiahf/vczjk/o45;

    invoke-virtual {v0}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Map;

    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/im7;

    if-eqz v0, :cond_1a

    iget-object v1, v7, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s64;

    iget-object v1, v1, Llyiahf/vczjk/s64;->OooO00o:Llyiahf/vczjk/q45;

    new-instance v2, Llyiahf/vczjk/pr4;

    const/4 v3, 0x2

    invoke-direct {v2, v8, v3}, Llyiahf/vczjk/pr4;-><init>(Llyiahf/vczjk/rr4;I)V

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v3, Llyiahf/vczjk/o45;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iget-object v1, v7, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s64;

    move-object v2, v0

    iget-object v0, v1, Llyiahf/vczjk/s64;->OooO00o:Llyiahf/vczjk/q45;

    invoke-static {v7, v2}, Llyiahf/vczjk/dn8;->o00oO0o(Llyiahf/vczjk/ld9;Llyiahf/vczjk/b64;)Llyiahf/vczjk/lr4;

    move-result-object v4

    iget-object v1, v1, Llyiahf/vczjk/s64;->OooOO0:Llyiahf/vczjk/rp3;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/rp3;->OooOo0O(Llyiahf/vczjk/k64;)Llyiahf/vczjk/hz7;

    move-result-object v5

    iget-object v1, v8, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    move-object v2, p1

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/rp2;->o00ooo(Llyiahf/vczjk/q45;Llyiahf/vczjk/by0;Llyiahf/vczjk/qt5;Llyiahf/vczjk/o45;Llyiahf/vczjk/ko;Llyiahf/vczjk/sx8;)Llyiahf/vczjk/rp2;

    move-result-object v5

    :cond_1a
    :goto_d
    return-object v5

    :pswitch_4
    check-cast p1, Llyiahf/vczjk/qt5;

    invoke-static {p1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v8, Llyiahf/vczjk/ld9;

    iget-object v1, v8, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Ljava/util/LinkedHashMap;

    invoke-virtual {v1, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/kc7;

    if-eqz v1, :cond_1b

    check-cast v7, Llyiahf/vczjk/h82;

    iget-object v2, v7, Llyiahf/vczjk/h82;->OooOo:Llyiahf/vczjk/u72;

    iget-object v2, v2, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s72;

    iget-object v6, v2, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    iget-object v2, v8, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    move-object v9, v2

    check-cast v9, Llyiahf/vczjk/o45;

    new-instance v10, Llyiahf/vczjk/x72;

    iget-object v2, v7, Llyiahf/vczjk/h82;->OooOo:Llyiahf/vczjk/u72;

    iget-object v2, v2, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s72;

    iget-object v2, v2, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance v3, Llyiahf/vczjk/o0O000;

    const/16 v4, 0xb

    invoke-direct {v3, v4, v7, v1, v0}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    invoke-direct {v10, v2, v3}, Llyiahf/vczjk/x72;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    sget-object v11, Llyiahf/vczjk/sx8;->OooOO0O:Llyiahf/vczjk/up3;

    move-object v8, p1

    invoke-static/range {v6 .. v11}, Llyiahf/vczjk/rp2;->o00ooo(Llyiahf/vczjk/q45;Llyiahf/vczjk/by0;Llyiahf/vczjk/qt5;Llyiahf/vczjk/o45;Llyiahf/vczjk/ko;Llyiahf/vczjk/sx8;)Llyiahf/vczjk/rp2;

    move-result-object v5

    :cond_1b
    return-object v5

    :pswitch_5
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    check-cast v8, Llyiahf/vczjk/ze3;

    check-cast v7, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;

    invoke-interface {v8, v7, p1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object v6

    :pswitch_6
    check-cast p1, Ljava/lang/Throwable;

    check-cast v8, Landroid/os/CancellationSignal;

    if-eqz v8, :cond_1c

    invoke-virtual {v8}, Landroid/os/CancellationSignal;->cancel()V

    :cond_1c
    check-cast v7, Llyiahf/vczjk/r09;

    invoke-virtual {v7, v5}, Llyiahf/vczjk/k84;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    return-object v6

    :pswitch_7
    check-cast p1, Ljava/lang/Throwable;

    :try_start_0
    check-cast v8, Llyiahf/vczjk/mh7;

    invoke-virtual {v8}, Llyiahf/vczjk/mh7;->cancel()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :catchall_0
    return-object v6

    :pswitch_8
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    check-cast v7, Llyiahf/vczjk/qs5;

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xw;

    check-cast v8, Llyiahf/vczjk/ze3;

    invoke-interface {v8, v0, p1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object v6

    :pswitch_9
    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    check-cast v8, Llyiahf/vczjk/x3a;

    if-eqz v8, :cond_1d

    iget-object v0, v8, Llyiahf/vczjk/x3a;->OooO00o:Ljava/util/LinkedHashMap;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/f74;

    if-nez v0, :cond_1f

    :cond_1d
    if-ltz p1, :cond_1e

    check-cast v7, [Llyiahf/vczjk/f74;

    array-length v0, v7

    if-ge p1, v0, :cond_1e

    aget-object v0, v7, p1

    goto :goto_e

    :cond_1e
    sget-object v0, Llyiahf/vczjk/f74;->OooO0o0:Llyiahf/vczjk/f74;

    :cond_1f
    :goto_e
    return-object v0

    :pswitch_a
    const-string v2, "$this$extractNullability"

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v7, Llyiahf/vczjk/o0O00o0;

    check-cast v8, Llyiahf/vczjk/bv0;

    check-cast p1, Llyiahf/vczjk/un;

    instance-of v2, p1, Llyiahf/vczjk/f07;

    if-eqz v2, :cond_20

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/f07;

    :cond_20
    instance-of v2, p1, Llyiahf/vczjk/kr4;

    iget-object v3, v8, Llyiahf/vczjk/bv0;->OooO0Oo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ld9;

    if-eqz v2, :cond_21

    iget-object v2, v3, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s64;

    iget-object v2, v2, Llyiahf/vczjk/s64;->OooOo00:Llyiahf/vczjk/wp3;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/kr4;

    iget-boolean v2, v2, Llyiahf/vczjk/kr4;->OooO0oO:Z

    if-nez v2, :cond_25

    sget-object v2, Llyiahf/vczjk/bo;->OooOOo0:Llyiahf/vczjk/bo;

    iget-object v4, v8, Llyiahf/vczjk/bv0;->OooO0o0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/bo;

    if-eq v4, v2, :cond_25

    :cond_21
    iget-object v2, v7, Llyiahf/vczjk/o0O00o0;->OooO00o:Llyiahf/vczjk/yk4;

    if-eqz v2, :cond_26

    check-cast v2, Llyiahf/vczjk/uk4;

    sget-object v4, Llyiahf/vczjk/hk4;->OooO0o0:Llyiahf/vczjk/qt5;

    invoke-virtual {v2}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v2

    if-eqz v2, :cond_26

    invoke-static {v2}, Llyiahf/vczjk/hk4;->OooOOoo(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/q47;

    move-result-object v2

    if-eqz v2, :cond_26

    iget-object v2, v3, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s64;

    iget-object v2, v2, Llyiahf/vczjk/s64;->OooOOo0:Llyiahf/vczjk/eo;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/w09;->OooOo00:Llyiahf/vczjk/hc3;

    invoke-static {p1, v2}, Llyiahf/vczjk/eo;->OooO0OO(Ljava/lang/Object;Llyiahf/vczjk/hc3;)Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_22

    goto :goto_f

    :cond_22
    invoke-static {p1, v0}, Llyiahf/vczjk/eo;->OooO00o(Ljava/lang/Object;Z)Ljava/util/ArrayList;

    move-result-object p1

    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_23

    goto :goto_f

    :cond_23
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_24
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_26

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    const-string v4, "TYPE"

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_24

    iget-object p1, v3, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s64;

    iget-object p1, p1, Llyiahf/vczjk/s64;->OooOo00:Llyiahf/vczjk/wp3;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_25
    move v0, v1

    :cond_26
    :goto_f
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
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

.method public OooOOOO(Llyiahf/vczjk/is7;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o0oOO;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yp0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    return-void
.end method

.method public Oooo0OO(Llyiahf/vczjk/mh7;Ljava/io/IOException;)V
    .locals 0

    iget-boolean p1, p1, Llyiahf/vczjk/mh7;->OooOoO0:Z

    if-nez p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/o0oOO;->OooOOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/yp0;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p2

    invoke-virtual {p1, p2}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    :cond_0
    return-void
.end method
