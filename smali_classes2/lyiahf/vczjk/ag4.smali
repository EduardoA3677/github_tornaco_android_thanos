.class public final Llyiahf/vczjk/ag4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/bg4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/bg4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ag4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ag4;->OooOOO:Llyiahf/vczjk/bg4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 18

    move-object/from16 v0, p0

    const-string v1, "desc"

    const/16 v2, 0xa

    const-string v3, "getValueParameters(...)"

    const-string v4, "getContainingDeclaration(...)"

    iget-object v5, v0, Llyiahf/vczjk/ag4;->OooOOO:Llyiahf/vczjk/bg4;

    const/4 v6, 0x0

    const/4 v7, 0x1

    iget v8, v0, Llyiahf/vczjk/ag4;->OooOOO0:I

    packed-switch v8, :pswitch_data_0

    sget-object v8, Llyiahf/vczjk/iz7;->OooO00o:Llyiahf/vczjk/hy0;

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/iz7;->OooO0OO(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/ng0;

    move-result-object v8

    instance-of v9, v8, Llyiahf/vczjk/yd4;

    const/4 v10, 0x0

    iget-object v11, v5, Llyiahf/vczjk/bg4;->OooOOOO:Llyiahf/vczjk/yf4;

    if-eqz v9, :cond_b

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v2

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2}, Llyiahf/vczjk/uz3;->OooO0Oo(Llyiahf/vczjk/v02;)Z

    move-result v2

    if-eqz v2, :cond_1

    instance-of v2, v1, Llyiahf/vczjk/il1;

    if-eqz v2, :cond_1

    check-cast v1, Llyiahf/vczjk/il1;

    invoke-interface {v1}, Llyiahf/vczjk/il1;->OooOoOO()Z

    move-result v1

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    new-instance v1, Llyiahf/vczjk/es1;

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v3

    invoke-interface {v3}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v3, " cannot have default arguments"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1
    :goto_0
    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object v2

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    move-result v6

    if-eqz v6, :cond_2

    goto :goto_1

    :cond_2
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_4

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/tca;

    invoke-virtual {v6}, Llyiahf/vczjk/tca;->o0000O0O()Z

    move-result v6

    if-eqz v6, :cond_3

    goto :goto_4

    :cond_4
    :goto_1
    invoke-interface {v1}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v2

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2}, Llyiahf/vczjk/uz3;->OooO0o(Llyiahf/vczjk/v02;)Z

    move-result v2

    if-eqz v2, :cond_9

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOO0O()Llyiahf/vczjk/so0;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/so0;->OooO00o()Ljava/lang/reflect/Member;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {v2}, Ljava/lang/reflect/Member;->getModifiers()I

    move-result v2

    invoke-static {v2}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result v2

    if-eqz v2, :cond_9

    invoke-static {v1}, Llyiahf/vczjk/p72;->OooOO0o(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/oz2;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/d13;

    invoke-direct {v2, v1}, Llyiahf/vczjk/d13;-><init>(Llyiahf/vczjk/oz2;)V

    :cond_5
    :goto_2
    invoke-virtual {v2}, Llyiahf/vczjk/d13;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_8

    invoke-virtual {v2}, Llyiahf/vczjk/d13;->next()Ljava/lang/Object;

    move-result-object v1

    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/eo0;

    invoke-interface {v4}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object v4

    invoke-static {v4, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v4}, Ljava/util/Collection;->isEmpty()Z

    move-result v6

    if-eqz v6, :cond_6

    goto :goto_2

    :cond_6
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :cond_7
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_5

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/tca;

    invoke-virtual {v6}, Llyiahf/vczjk/tca;->o0000O0O()Z

    move-result v6

    if-eqz v6, :cond_7

    goto :goto_3

    :cond_8
    move-object v1, v10

    :goto_3
    instance-of v2, v1, Llyiahf/vczjk/rf3;

    if-eqz v2, :cond_9

    check-cast v1, Llyiahf/vczjk/rf3;

    goto :goto_5

    :cond_9
    :goto_4
    move-object v1, v10

    :goto_5
    if-eqz v1, :cond_a

    invoke-static {v1}, Llyiahf/vczjk/iz7;->OooO0OO(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/ng0;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/yd4;

    iget-object v1, v1, Llyiahf/vczjk/yd4;->OooOO0o:Llyiahf/vczjk/ae4;

    iget-object v2, v1, Llyiahf/vczjk/ae4;->OooOO0:Ljava/lang/String;

    iget-object v1, v1, Llyiahf/vczjk/ae4;->OooO:Ljava/lang/String;

    invoke-virtual {v11, v1, v2, v7}, Llyiahf/vczjk/yf4;->OooO0o(Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/reflect/Method;

    move-result-object v1

    goto/16 :goto_8

    :cond_a
    check-cast v8, Llyiahf/vczjk/yd4;

    iget-object v1, v8, Llyiahf/vczjk/yd4;->OooOO0o:Llyiahf/vczjk/ae4;

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOO0O()Llyiahf/vczjk/so0;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/so0;->OooO00o()Ljava/lang/reflect/Member;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {v2}, Ljava/lang/reflect/Member;->getModifiers()I

    move-result v2

    invoke-static {v2}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result v2

    xor-int/2addr v2, v7

    iget-object v3, v1, Llyiahf/vczjk/ae4;->OooOO0:Ljava/lang/String;

    iget-object v1, v1, Llyiahf/vczjk/ae4;->OooO:Ljava/lang/String;

    invoke-virtual {v11, v1, v3, v2}, Llyiahf/vczjk/yf4;->OooO0o(Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/reflect/Method;

    move-result-object v1

    goto/16 :goto_8

    :cond_b
    instance-of v3, v8, Llyiahf/vczjk/xd4;

    if-eqz v3, :cond_e

    invoke-virtual {v5}, Llyiahf/vczjk/ff4;->OooOOOo()Z

    move-result v3

    if-eqz v3, :cond_d

    invoke-interface {v11}, Llyiahf/vczjk/tx0;->OooO0Oo()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v5}, Llyiahf/vczjk/ff4;->OooOOOO()Ljava/util/List;

    move-result-object v3

    new-instance v4, Ljava/util/ArrayList;

    invoke-static {v3, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v4, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_6
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_c

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ah4;

    check-cast v3, Llyiahf/vczjk/dh4;

    invoke-virtual {v3}, Llyiahf/vczjk/dh4;->OooO0O0()Ljava/lang/String;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_6

    :cond_c
    sget-object v2, Llyiahf/vczjk/pn;->OooOOO0:Llyiahf/vczjk/pn;

    sget-object v3, Llyiahf/vczjk/qn;->OooOOO0:Llyiahf/vczjk/qn;

    new-instance v10, Llyiahf/vczjk/rn;

    invoke-direct {v10, v1, v4, v2}, Llyiahf/vczjk/rn;-><init>(Ljava/lang/Class;Ljava/util/ArrayList;Llyiahf/vczjk/pn;)V

    goto/16 :goto_b

    :cond_d
    check-cast v8, Llyiahf/vczjk/xd4;

    iget-object v2, v8, Llyiahf/vczjk/xd4;->OooOO0o:Llyiahf/vczjk/ae4;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, v2, Llyiahf/vczjk/ae4;->OooOO0:Ljava/lang/String;

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v11}, Llyiahf/vczjk/tx0;->OooO0Oo()Ljava/lang/Class;

    move-result-object v1

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v11, v2, v6}, Llyiahf/vczjk/yf4;->OooOOOo(Ljava/lang/String;Z)Llyiahf/vczjk/n62;

    move-result-object v2

    iget-object v2, v2, Llyiahf/vczjk/n62;->OooOOO:Ljava/lang/Object;

    check-cast v2, Ljava/util/ArrayList;

    invoke-static {v3, v2, v7}, Llyiahf/vczjk/yf4;->OooO0o0(Ljava/util/ArrayList;Ljava/util/ArrayList;Z)V

    invoke-static {v1, v3}, Llyiahf/vczjk/yf4;->OooOOo(Ljava/lang/Class;Ljava/util/ArrayList;)Ljava/lang/reflect/Constructor;

    move-result-object v1

    goto :goto_8

    :cond_e
    instance-of v1, v8, Llyiahf/vczjk/ud4;

    if-eqz v1, :cond_10

    check-cast v8, Llyiahf/vczjk/ud4;

    invoke-interface {v11}, Llyiahf/vczjk/tx0;->OooO0Oo()Ljava/lang/Class;

    move-result-object v13

    new-instance v14, Ljava/util/ArrayList;

    iget-object v1, v8, Llyiahf/vczjk/ud4;->OooOO0o:Ljava/util/List;

    invoke-static {v1, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v14, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_7
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_f

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/reflect/Method;

    invoke-virtual {v3}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v14, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_7

    :cond_f
    sget-object v15, Llyiahf/vczjk/pn;->OooOOO0:Llyiahf/vczjk/pn;

    sget-object v16, Llyiahf/vczjk/qn;->OooOOO0:Llyiahf/vczjk/qn;

    new-instance v12, Llyiahf/vczjk/rn;

    move-object/from16 v17, v1

    invoke-direct/range {v12 .. v17}, Llyiahf/vczjk/rn;-><init>(Ljava/lang/Class;Ljava/util/ArrayList;Llyiahf/vczjk/pn;Llyiahf/vczjk/qn;Ljava/util/List;)V

    move-object v10, v12

    goto/16 :goto_b

    :cond_10
    move-object v1, v10

    :goto_8
    instance-of v2, v1, Ljava/lang/reflect/Constructor;

    if-eqz v2, :cond_11

    check-cast v1, Ljava/lang/reflect/Constructor;

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v2

    invoke-virtual {v5, v1, v2, v7}, Llyiahf/vczjk/bg4;->OooOOoo(Ljava/lang/reflect/Constructor;Llyiahf/vczjk/rf3;Z)Llyiahf/vczjk/jp0;

    move-result-object v1

    goto :goto_a

    :cond_11
    instance-of v2, v1, Ljava/lang/reflect/Method;

    if-eqz v2, :cond_14

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/l21;

    invoke-virtual {v2}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/mba;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-interface {v2, v3}, Llyiahf/vczjk/ko;->OooO0oO(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/un;

    move-result-object v2

    if-eqz v2, :cond_13

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v2

    const-string v3, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.ClassDescriptor"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Llyiahf/vczjk/by0;

    invoke-interface {v2}, Llyiahf/vczjk/by0;->OooOo()Z

    move-result v2

    if-nez v2, :cond_13

    check-cast v1, Ljava/lang/reflect/Method;

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOOo0()Z

    move-result v2

    if-eqz v2, :cond_12

    new-instance v2, Llyiahf/vczjk/ep0;

    invoke-direct {v2, v1}, Llyiahf/vczjk/ep0;-><init>(Ljava/lang/reflect/Method;)V

    :goto_9
    move-object v1, v2

    goto :goto_a

    :cond_12
    new-instance v2, Llyiahf/vczjk/hp0;

    invoke-direct {v2, v1, v7}, Llyiahf/vczjk/hp0;-><init>(Ljava/lang/reflect/Method;I)V

    goto :goto_9

    :cond_13
    check-cast v1, Ljava/lang/reflect/Method;

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOO0O()Llyiahf/vczjk/so0;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/so0;->OooO0OO()Z

    move-result v2

    invoke-virtual {v5, v1, v2}, Llyiahf/vczjk/bg4;->OooOo00(Ljava/lang/reflect/Method;Z)Llyiahf/vczjk/ip0;

    move-result-object v1

    goto :goto_a

    :cond_14
    move-object v1, v10

    :goto_a
    if-eqz v1, :cond_15

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v2

    invoke-static {v1, v2, v7}, Llyiahf/vczjk/qu6;->OooO0o(Llyiahf/vczjk/so0;Llyiahf/vczjk/rf3;Z)Llyiahf/vczjk/so0;

    move-result-object v10

    :cond_15
    :goto_b
    return-object v10

    :pswitch_0
    sget-object v8, Llyiahf/vczjk/iz7;->OooO00o:Llyiahf/vczjk/hy0;

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/iz7;->OooO0OO(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/ng0;

    move-result-object v8

    instance-of v9, v8, Llyiahf/vczjk/xd4;

    iget-object v10, v5, Llyiahf/vczjk/bg4;->OooOOOO:Llyiahf/vczjk/yf4;

    if-eqz v9, :cond_18

    invoke-virtual {v5}, Llyiahf/vczjk/ff4;->OooOOOo()Z

    move-result v3

    if-eqz v3, :cond_17

    invoke-interface {v10}, Llyiahf/vczjk/tx0;->OooO0Oo()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v5}, Llyiahf/vczjk/ff4;->OooOOOO()Ljava/util/List;

    move-result-object v3

    new-instance v4, Ljava/util/ArrayList;

    invoke-static {v3, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v4, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_c
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_16

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ah4;

    check-cast v3, Llyiahf/vczjk/dh4;

    invoke-virtual {v3}, Llyiahf/vczjk/dh4;->OooO0O0()Ljava/lang/String;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_c

    :cond_16
    sget-object v2, Llyiahf/vczjk/pn;->OooOOO:Llyiahf/vczjk/pn;

    sget-object v3, Llyiahf/vczjk/qn;->OooOOO0:Llyiahf/vczjk/qn;

    new-instance v3, Llyiahf/vczjk/rn;

    invoke-direct {v3, v1, v4, v2}, Llyiahf/vczjk/rn;-><init>(Ljava/lang/Class;Ljava/util/ArrayList;Llyiahf/vczjk/pn;)V

    goto/16 :goto_11

    :cond_17
    check-cast v8, Llyiahf/vczjk/xd4;

    iget-object v2, v8, Llyiahf/vczjk/xd4;->OooOO0o:Llyiahf/vczjk/ae4;

    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, v2, Llyiahf/vczjk/ae4;->OooOO0:Ljava/lang/String;

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v10}, Llyiahf/vczjk/tx0;->OooO0Oo()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v10, v2, v6}, Llyiahf/vczjk/yf4;->OooOOOo(Ljava/lang/String;Z)Llyiahf/vczjk/n62;

    move-result-object v2

    iget-object v2, v2, Llyiahf/vczjk/n62;->OooOOO:Ljava/lang/Object;

    check-cast v2, Ljava/util/ArrayList;

    invoke-static {v1, v2}, Llyiahf/vczjk/yf4;->OooOOo(Ljava/lang/Class;Ljava/util/ArrayList;)Ljava/lang/reflect/Constructor;

    move-result-object v1

    goto :goto_d

    :cond_18
    instance-of v1, v8, Llyiahf/vczjk/yd4;

    if-eqz v1, :cond_1a

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v2

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2}, Llyiahf/vczjk/uz3;->OooO0Oo(Llyiahf/vczjk/v02;)Z

    move-result v2

    if-eqz v2, :cond_19

    instance-of v2, v1, Llyiahf/vczjk/il1;

    if-eqz v2, :cond_19

    check-cast v1, Llyiahf/vczjk/il1;

    invoke-interface {v1}, Llyiahf/vczjk/il1;->OooOoOO()Z

    move-result v1

    if-eqz v1, :cond_19

    new-instance v1, Llyiahf/vczjk/dca;

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v2

    check-cast v8, Llyiahf/vczjk/yd4;

    iget-object v4, v8, Llyiahf/vczjk/yd4;->OooOO0o:Llyiahf/vczjk/ae4;

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v5

    invoke-interface {v5}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object v5

    invoke-static {v5, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v3, v4, Llyiahf/vczjk/ae4;->OooOO0:Ljava/lang/String;

    invoke-direct {v1, v2, v10, v3, v5}, Llyiahf/vczjk/dca;-><init>(Llyiahf/vczjk/rf3;Llyiahf/vczjk/yf4;Ljava/lang/String;Ljava/util/List;)V

    move-object v3, v1

    goto/16 :goto_11

    :cond_19
    check-cast v8, Llyiahf/vczjk/yd4;

    iget-object v1, v8, Llyiahf/vczjk/yd4;->OooOO0o:Llyiahf/vczjk/ae4;

    iget-object v2, v1, Llyiahf/vczjk/ae4;->OooOO0:Ljava/lang/String;

    iget-object v1, v1, Llyiahf/vczjk/ae4;->OooO:Ljava/lang/String;

    invoke-virtual {v10, v1, v2}, Llyiahf/vczjk/yf4;->OooO0oO(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/reflect/Method;

    move-result-object v1

    goto :goto_d

    :cond_1a
    instance-of v1, v8, Llyiahf/vczjk/wd4;

    const-string v3, "null cannot be cast to non-null type java.lang.reflect.Member"

    if-eqz v1, :cond_1b

    check-cast v8, Llyiahf/vczjk/wd4;

    iget-object v1, v8, Llyiahf/vczjk/wd4;->OooOO0o:Ljava/lang/reflect/Method;

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_d

    :cond_1b
    instance-of v1, v8, Llyiahf/vczjk/vd4;

    if-eqz v1, :cond_22

    check-cast v8, Llyiahf/vczjk/vd4;

    iget-object v1, v8, Llyiahf/vczjk/vd4;->OooOO0o:Ljava/lang/reflect/Constructor;

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    :goto_d
    instance-of v2, v1, Ljava/lang/reflect/Constructor;

    if-eqz v2, :cond_1c

    check-cast v1, Ljava/lang/reflect/Constructor;

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v2

    invoke-virtual {v5, v1, v2, v6}, Llyiahf/vczjk/bg4;->OooOOoo(Ljava/lang/reflect/Constructor;Llyiahf/vczjk/rf3;Z)Llyiahf/vczjk/jp0;

    move-result-object v1

    goto :goto_f

    :cond_1c
    instance-of v2, v1, Ljava/lang/reflect/Method;

    if-eqz v2, :cond_21

    check-cast v1, Ljava/lang/reflect/Method;

    invoke-virtual {v1}, Ljava/lang/reflect/Method;->getModifiers()I

    move-result v2

    invoke-static {v2}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result v2

    if-nez v2, :cond_1e

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOOo0()Z

    move-result v2

    if-eqz v2, :cond_1d

    new-instance v2, Llyiahf/vczjk/dp0;

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v3

    iget-object v4, v5, Llyiahf/vczjk/bg4;->OooOOo0:Ljava/lang/Object;

    invoke-static {v4, v3}, Llyiahf/vczjk/qu6;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/eo0;)Ljava/lang/Object;

    move-result-object v3

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/dp0;-><init>(Ljava/lang/reflect/Method;Ljava/lang/Object;)V

    :goto_e
    move-object v1, v2

    goto :goto_f

    :cond_1d
    new-instance v2, Llyiahf/vczjk/hp0;

    invoke-direct {v2, v1, v6}, Llyiahf/vczjk/hp0;-><init>(Ljava/lang/reflect/Method;I)V

    goto :goto_e

    :cond_1e
    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/l21;

    invoke-virtual {v2}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/mba;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-interface {v2, v3}, Llyiahf/vczjk/ko;->OooO0oO(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/un;

    move-result-object v2

    if-eqz v2, :cond_20

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOOo0()Z

    move-result v2

    if-eqz v2, :cond_1f

    new-instance v2, Llyiahf/vczjk/ep0;

    invoke-direct {v2, v1}, Llyiahf/vczjk/ep0;-><init>(Ljava/lang/reflect/Method;)V

    goto :goto_e

    :cond_1f
    new-instance v2, Llyiahf/vczjk/hp0;

    invoke-direct {v2, v1, v7}, Llyiahf/vczjk/hp0;-><init>(Ljava/lang/reflect/Method;I)V

    goto :goto_e

    :cond_20
    invoke-virtual {v5, v1, v6}, Llyiahf/vczjk/bg4;->OooOo00(Ljava/lang/reflect/Method;Z)Llyiahf/vczjk/ip0;

    move-result-object v1

    :goto_f
    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v2

    invoke-static {v1, v2, v6}, Llyiahf/vczjk/qu6;->OooO0o(Llyiahf/vczjk/so0;Llyiahf/vczjk/rf3;Z)Llyiahf/vczjk/so0;

    move-result-object v3

    goto :goto_11

    :cond_21
    new-instance v2, Llyiahf/vczjk/es1;

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Could not compute caller for function: "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v4, " (member = "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v2, v1}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw v2

    :cond_22
    instance-of v1, v8, Llyiahf/vczjk/ud4;

    if-eqz v1, :cond_24

    check-cast v8, Llyiahf/vczjk/ud4;

    invoke-interface {v10}, Llyiahf/vczjk/tx0;->OooO0Oo()Ljava/lang/Class;

    move-result-object v12

    new-instance v13, Ljava/util/ArrayList;

    iget-object v1, v8, Llyiahf/vczjk/ud4;->OooOO0o:Ljava/util/List;

    invoke-static {v1, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v13, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_10
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_23

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/reflect/Method;

    invoke-virtual {v3}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v13, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_10

    :cond_23
    sget-object v14, Llyiahf/vczjk/pn;->OooOOO:Llyiahf/vczjk/pn;

    sget-object v15, Llyiahf/vczjk/qn;->OooOOO0:Llyiahf/vczjk/qn;

    new-instance v11, Llyiahf/vczjk/rn;

    move-object/from16 v16, v1

    invoke-direct/range {v11 .. v16}, Llyiahf/vczjk/rn;-><init>(Ljava/lang/Class;Ljava/util/ArrayList;Llyiahf/vczjk/pn;Llyiahf/vczjk/qn;Ljava/util/List;)V

    move-object v3, v11

    :goto_11
    return-object v3

    :cond_24
    new-instance v1, Llyiahf/vczjk/k61;

    invoke-direct {v1}, Ljava/lang/RuntimeException;-><init>()V

    throw v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
