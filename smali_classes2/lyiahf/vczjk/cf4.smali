.class public final Llyiahf/vczjk/cf4;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/ff4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ff4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/cf4;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/cf4;->OooOOO:Llyiahf/vczjk/ff4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 11

    const/4 v0, 0x0

    const/4 v1, 0x0

    iget-object v2, p0, Llyiahf/vczjk/cf4;->OooOOO:Llyiahf/vczjk/ff4;

    const/4 v3, 0x1

    iget v4, p0, Llyiahf/vczjk/cf4;->OooOOO0:I

    packed-switch v4, :pswitch_data_0

    invoke-interface {v2}, Llyiahf/vczjk/bf4;->OooOOo()Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/ff4;->OooOO0O()Llyiahf/vczjk/so0;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/so0;->OooO0O0()Ljava/util/List;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/d21;->o0OO00O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v1

    instance-of v3, v1, Ljava/lang/reflect/ParameterizedType;

    if-eqz v3, :cond_0

    check-cast v1, Ljava/lang/reflect/ParameterizedType;

    goto :goto_0

    :cond_0
    move-object v1, v0

    :goto_0
    if-eqz v1, :cond_1

    invoke-interface {v1}, Ljava/lang/reflect/ParameterizedType;->getRawType()Ljava/lang/reflect/Type;

    move-result-object v3

    goto :goto_1

    :cond_1
    move-object v3, v0

    :goto_1
    const-class v4, Llyiahf/vczjk/yo1;

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-interface {v1}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    move-result-object v1

    const-string v3, "getActualTypeArguments(...)"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/sy;->o0000([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    instance-of v3, v1, Ljava/lang/reflect/WildcardType;

    if-eqz v3, :cond_2

    check-cast v1, Ljava/lang/reflect/WildcardType;

    goto :goto_2

    :cond_2
    move-object v1, v0

    :goto_2
    if-eqz v1, :cond_3

    invoke-interface {v1}, Ljava/lang/reflect/WildcardType;->getLowerBounds()[Ljava/lang/reflect/Type;

    move-result-object v1

    if-eqz v1, :cond_3

    invoke-static {v1}, Llyiahf/vczjk/sy;->oo0o0Oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/reflect/Type;

    :cond_3
    if-nez v0, :cond_4

    invoke-virtual {v2}, Llyiahf/vczjk/ff4;->OooOO0O()Llyiahf/vczjk/so0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/so0;->OooOOoo()Ljava/lang/reflect/Type;

    move-result-object v0

    :cond_4
    return-object v0

    :pswitch_0
    invoke-virtual {v2}, Llyiahf/vczjk/ff4;->OooOOOO()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_5

    goto :goto_3

    :cond_5
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_6
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_7

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ah4;

    check-cast v2, Llyiahf/vczjk/dh4;

    invoke-virtual {v2}, Llyiahf/vczjk/dh4;->OooO0OO()Llyiahf/vczjk/di4;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/mba;->OooO0oo(Llyiahf/vczjk/di4;)Z

    move-result v2

    if-eqz v2, :cond_6

    move v1, v3

    :cond_7
    :goto_3
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0

    :pswitch_1
    invoke-virtual {v2}, Llyiahf/vczjk/ff4;->OooOOOO()Ljava/util/List;

    move-result-object v4

    invoke-interface {v4}, Ljava/util/List;->size()I

    move-result v5

    invoke-interface {v2}, Llyiahf/vczjk/bf4;->OooOOo()Z

    move-result v6

    add-int/2addr v6, v5

    iget-object v2, v2, Llyiahf/vczjk/ff4;->OooOOO:Ljava/lang/Object;

    invoke-interface {v2}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Boolean;

    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v5

    if-eqz v5, :cond_b

    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    move v7, v1

    :goto_4
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_f

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/ah4;

    check-cast v8, Llyiahf/vczjk/dh4;

    iget-object v9, v8, Llyiahf/vczjk/dh4;->OooO0OO:Llyiahf/vczjk/zg4;

    sget-object v10, Llyiahf/vczjk/zg4;->OooOOOO:Llyiahf/vczjk/zg4;

    if-ne v9, v10, :cond_a

    invoke-interface {v2}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Boolean;

    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v9

    if-eqz v9, :cond_9

    invoke-virtual {v8}, Llyiahf/vczjk/dh4;->OooO0OO()Llyiahf/vczjk/di4;

    move-result-object v9

    invoke-static {v9}, Llyiahf/vczjk/mba;->OooO0oo(Llyiahf/vczjk/di4;)Z

    move-result v9

    if-eqz v9, :cond_8

    invoke-virtual {v8}, Llyiahf/vczjk/dh4;->OooO0OO()Llyiahf/vczjk/di4;

    move-result-object v8

    iget-object v8, v8, Llyiahf/vczjk/di4;->OooO00o:Llyiahf/vczjk/uk4;

    invoke-static {v8}, Llyiahf/vczjk/vt6;->OooOOOO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/dp8;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/qu6;->OooOO0(Llyiahf/vczjk/dp8;)Ljava/util/ArrayList;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    move-result v8

    goto :goto_5

    :cond_8
    move v8, v3

    goto :goto_5

    :cond_9
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Check if parametersNeedMFVCFlattening is true before"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_a
    move v8, v1

    :goto_5
    add-int/2addr v7, v8

    goto :goto_4

    :cond_b
    invoke-interface {v4}, Ljava/util/Collection;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_c

    move v7, v1

    goto :goto_7

    :cond_c
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    move v7, v1

    :cond_d
    :goto_6
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_f

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ah4;

    check-cast v5, Llyiahf/vczjk/dh4;

    iget-object v5, v5, Llyiahf/vczjk/dh4;->OooO0OO:Llyiahf/vczjk/zg4;

    sget-object v8, Llyiahf/vczjk/zg4;->OooOOOO:Llyiahf/vczjk/zg4;

    if-ne v5, v8, :cond_d

    add-int/2addr v7, v3

    if-ltz v7, :cond_e

    goto :goto_6

    :cond_e
    new-instance v0, Ljava/lang/ArithmeticException;

    const-string v1, "Count overflow has happened."

    invoke-direct {v0, v1}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_f
    :goto_7
    add-int/lit8 v7, v7, 0x1f

    div-int/lit8 v7, v7, 0x20

    add-int v2, v6, v7

    add-int/2addr v2, v3

    new-array v2, v2, [Ljava/lang/Object;

    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :cond_10
    :goto_8
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_1a

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ah4;

    check-cast v5, Llyiahf/vczjk/dh4;

    invoke-virtual {v5}, Llyiahf/vczjk/dh4;->OooO00o()Llyiahf/vczjk/ko6;

    move-result-object v8

    instance-of v9, v8, Llyiahf/vczjk/tca;

    if-eqz v9, :cond_11

    check-cast v8, Llyiahf/vczjk/tca;

    goto :goto_9

    :cond_11
    move-object v8, v0

    :goto_9
    if-eqz v8, :cond_12

    invoke-static {v8}, Llyiahf/vczjk/p72;->OooO00o(Llyiahf/vczjk/tca;)Z

    move-result v8

    goto :goto_a

    :cond_12
    move v8, v1

    :goto_a
    iget v9, v5, Llyiahf/vczjk/dh4;->OooO0O0:I

    if-eqz v8, :cond_18

    invoke-virtual {v5}, Llyiahf/vczjk/dh4;->OooO0OO()Llyiahf/vczjk/di4;

    move-result-object v8

    sget-object v10, Llyiahf/vczjk/mba;->OooO00o:Llyiahf/vczjk/hc3;

    iget-object v8, v8, Llyiahf/vczjk/di4;->OooO00o:Llyiahf/vczjk/uk4;

    if-eqz v8, :cond_13

    invoke-static {v8}, Llyiahf/vczjk/uz3;->OooO0OO(Llyiahf/vczjk/uk4;)Z

    move-result v8

    if-ne v8, v3, :cond_13

    goto :goto_e

    :cond_13
    invoke-virtual {v5}, Llyiahf/vczjk/dh4;->OooO0OO()Llyiahf/vczjk/di4;

    move-result-object v5

    iget-object v8, v5, Llyiahf/vczjk/di4;->OooO0O0:Llyiahf/vczjk/wm7;

    if-eqz v8, :cond_14

    invoke-virtual {v8}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ljava/lang/reflect/Type;

    goto :goto_b

    :cond_14
    move-object v10, v0

    :goto_b
    if-nez v10, :cond_17

    if-eqz v8, :cond_15

    invoke-virtual {v8}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/lang/reflect/Type;

    move-object v10, v8

    goto :goto_c

    :cond_15
    move-object v10, v0

    :goto_c
    if-eqz v10, :cond_16

    goto :goto_d

    :cond_16
    invoke-static {v5, v1}, Llyiahf/vczjk/m6a;->Oooo00O(Llyiahf/vczjk/bi4;Z)Ljava/lang/reflect/Type;

    move-result-object v10

    :cond_17
    :goto_d
    invoke-static {v10}, Llyiahf/vczjk/mba;->OooO0o0(Ljava/lang/reflect/Type;)Ljava/lang/Object;

    move-result-object v5

    aput-object v5, v2, v9

    goto :goto_8

    :cond_18
    :goto_e
    invoke-virtual {v5}, Llyiahf/vczjk/dh4;->OooO00o()Llyiahf/vczjk/ko6;

    move-result-object v8

    instance-of v10, v8, Llyiahf/vczjk/tca;

    if-eqz v10, :cond_10

    check-cast v8, Llyiahf/vczjk/tca;

    iget-object v8, v8, Llyiahf/vczjk/tca;->OooOoO0:Llyiahf/vczjk/uk4;

    if-eqz v8, :cond_10

    invoke-virtual {v5}, Llyiahf/vczjk/dh4;->OooO0OO()Llyiahf/vczjk/di4;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/mc4;->Oooo0O0(Llyiahf/vczjk/bi4;)Llyiahf/vczjk/gf4;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/rs;->Oooo00O(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/Class;->isArray()Z

    move-result v8

    if-eqz v8, :cond_19

    invoke-virtual {v5}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    move-result-object v5

    invoke-static {v5, v1}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;I)Ljava/lang/Object;

    move-result-object v5

    const-string v8, "run(...)"

    invoke-static {v5, v8}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    aput-object v5, v2, v9

    goto/16 :goto_8

    :cond_19
    new-instance v0, Llyiahf/vczjk/es1;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Cannot instantiate the default empty array of type "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, ", because it is not an array type"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1a
    move v0, v1

    :goto_f
    if-ge v0, v7, :cond_1b

    add-int v4, v6, v0

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    aput-object v5, v2, v4

    add-int/2addr v0, v3

    goto :goto_f

    :cond_1b
    return-object v2

    :pswitch_2
    invoke-virtual {v2}, Llyiahf/vczjk/ff4;->OooOOO()Llyiahf/vczjk/eo0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/co0;->OooOOO()Ljava/util/List;

    move-result-object v0

    const-string v1, "getTypeParameters(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ljava/util/ArrayList;

    const/16 v3, 0xa

    invoke-static {v0, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_10
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1c

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/t4a;

    new-instance v4, Llyiahf/vczjk/fi4;

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-direct {v4, v2, v3}, Llyiahf/vczjk/fi4;-><init>(Llyiahf/vczjk/gi4;Llyiahf/vczjk/t4a;)V

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_10

    :cond_1c
    return-object v1

    :pswitch_3
    new-instance v0, Llyiahf/vczjk/di4;

    invoke-virtual {v2}, Llyiahf/vczjk/ff4;->OooOOO()Llyiahf/vczjk/eo0;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/co0;->OooOOoo()Llyiahf/vczjk/uk4;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    new-instance v3, Llyiahf/vczjk/cf4;

    const/4 v4, 0x6

    invoke-direct {v3, v2, v4}, Llyiahf/vczjk/cf4;-><init>(Llyiahf/vczjk/ff4;I)V

    invoke-direct {v0, v1, v3}, Llyiahf/vczjk/di4;-><init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/le3;)V

    return-object v0

    :pswitch_4
    invoke-virtual {v2}, Llyiahf/vczjk/ff4;->OooOOO()Llyiahf/vczjk/eo0;

    move-result-object v0

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v2}, Llyiahf/vczjk/ff4;->OooOOo0()Z

    move-result v5

    if-nez v5, :cond_1e

    invoke-static {v0}, Llyiahf/vczjk/mba;->OooO0oO(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/mp4;

    move-result-object v5

    if-eqz v5, :cond_1d

    new-instance v6, Llyiahf/vczjk/dh4;

    sget-object v7, Llyiahf/vczjk/zg4;->OooOOO0:Llyiahf/vczjk/zg4;

    new-instance v8, Llyiahf/vczjk/df4;

    invoke-direct {v8, v5, v1}, Llyiahf/vczjk/df4;-><init>(Llyiahf/vczjk/mp4;I)V

    invoke-direct {v6, v2, v1, v7, v8}, Llyiahf/vczjk/dh4;-><init>(Llyiahf/vczjk/ff4;ILlyiahf/vczjk/zg4;Llyiahf/vczjk/le3;)V

    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move v5, v3

    goto :goto_11

    :cond_1d
    move v5, v1

    :goto_11
    invoke-interface {v0}, Llyiahf/vczjk/co0;->Ooooooo()Llyiahf/vczjk/mp4;

    move-result-object v6

    if-eqz v6, :cond_1f

    new-instance v7, Llyiahf/vczjk/dh4;

    add-int/lit8 v8, v5, 0x1

    sget-object v9, Llyiahf/vczjk/zg4;->OooOOO:Llyiahf/vczjk/zg4;

    new-instance v10, Llyiahf/vczjk/df4;

    invoke-direct {v10, v6, v3}, Llyiahf/vczjk/df4;-><init>(Llyiahf/vczjk/mp4;I)V

    invoke-direct {v7, v2, v5, v9, v10}, Llyiahf/vczjk/dh4;-><init>(Llyiahf/vczjk/ff4;ILlyiahf/vczjk/zg4;Llyiahf/vczjk/le3;)V

    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move v5, v8

    goto :goto_12

    :cond_1e
    move v5, v1

    :cond_1f
    :goto_12
    invoke-interface {v0}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object v6

    invoke-interface {v6}, Ljava/util/Collection;->size()I

    move-result v6

    :goto_13
    if-ge v1, v6, :cond_20

    new-instance v7, Llyiahf/vczjk/dh4;

    add-int/lit8 v8, v5, 0x1

    sget-object v9, Llyiahf/vczjk/zg4;->OooOOOO:Llyiahf/vczjk/zg4;

    new-instance v10, Llyiahf/vczjk/ef4;

    invoke-direct {v10, v0, v1}, Llyiahf/vczjk/ef4;-><init>(Llyiahf/vczjk/eo0;I)V

    invoke-direct {v7, v2, v5, v9, v10}, Llyiahf/vczjk/dh4;-><init>(Llyiahf/vczjk/ff4;ILlyiahf/vczjk/zg4;Llyiahf/vczjk/le3;)V

    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/2addr v1, v3

    move v5, v8

    goto :goto_13

    :cond_20
    invoke-virtual {v2}, Llyiahf/vczjk/ff4;->OooOOOo()Z

    move-result v1

    if-eqz v1, :cond_21

    instance-of v0, v0, Llyiahf/vczjk/d64;

    if-eqz v0, :cond_21

    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    move-result v0

    if-le v0, v3, :cond_21

    new-instance v0, Llyiahf/vczjk/c60;

    const/16 v1, 0xb

    invoke-direct {v0, v1}, Llyiahf/vczjk/c60;-><init>(I)V

    invoke-static {v4, v0}, Llyiahf/vczjk/i21;->OoooOOo(Ljava/util/List;Ljava/util/Comparator;)V

    :cond_21
    invoke-virtual {v4}, Ljava/util/ArrayList;->trimToSize()V

    return-object v4

    :pswitch_5
    invoke-virtual {v2}, Llyiahf/vczjk/ff4;->OooOOO()Llyiahf/vczjk/eo0;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/mba;->OooO0Oo(Llyiahf/vczjk/gm;)Ljava/util/ArrayList;

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
