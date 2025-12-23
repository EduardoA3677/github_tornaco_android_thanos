.class public final Llyiahf/vczjk/x82;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _cachedDeserializers:Llyiahf/vczjk/kl4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/kl4;"
        }
    .end annotation
.end field

.field protected final _incompleteDeserializers:Ljava/util/HashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashMap<",
            "Llyiahf/vczjk/x64;",
            "Llyiahf/vczjk/e94;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/HashMap;

    const/16 v1, 0x8

    invoke-direct {v0, v1}, Ljava/util/HashMap;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/x82;->_incompleteDeserializers:Ljava/util/HashMap;

    const/16 v0, 0x1f4

    const/16 v1, 0x40

    invoke-static {v1, v0}, Ljava/lang/Math;->min(II)I

    move-result v0

    new-instance v1, Llyiahf/vczjk/kl4;

    const/16 v2, 0x7d0

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/kl4;-><init>(II)V

    iput-object v1, p0, Llyiahf/vczjk/x82;->_cachedDeserializers:Llyiahf/vczjk/kl4;

    return-void
.end method

.method public static OooO0O0(Llyiahf/vczjk/v72;Llyiahf/vczjk/y82;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;
    .locals 18

    move-object/from16 v1, p0

    move-object/from16 v0, p1

    move-object/from16 v2, p2

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v3

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->Ooooo0o()Z

    move-result v4

    if-nez v4, :cond_0

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->ooOO()Z

    move-result v4

    if-nez v4, :cond_0

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OooooO0()Z

    move-result v4

    if-eqz v4, :cond_1

    :cond_0
    invoke-virtual/range {p1 .. p2}, Llyiahf/vczjk/y82;->OooO0OO(Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    :cond_1
    invoke-virtual {v3, v2}, Llyiahf/vczjk/t72;->Oooo00o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v4

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v5

    iget-object v6, v4, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/yn;->OooOO0(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v5

    const/4 v7, 0x0

    if-nez v5, :cond_2

    move-object v5, v7

    goto :goto_1

    :cond_2
    invoke-virtual {v1, v5}, Llyiahf/vczjk/v72;->OoooooO(Ljava/lang/Object;)Llyiahf/vczjk/e94;

    move-result-object v5

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v8

    invoke-virtual {v8, v6}, Llyiahf/vczjk/yn;->OooO(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v8

    if-nez v8, :cond_3

    move-object v8, v7

    goto :goto_0

    :cond_3
    invoke-virtual {v1, v8}, Llyiahf/vczjk/mc4;->OooOo0(Ljava/lang/Object;)Llyiahf/vczjk/gp1;

    move-result-object v8

    :goto_0
    if-nez v8, :cond_4

    goto :goto_1

    :cond_4
    invoke-virtual {v1}, Llyiahf/vczjk/v72;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-object v9, v8

    check-cast v9, Llyiahf/vczjk/j74;

    new-instance v10, Llyiahf/vczjk/k49;

    iget-object v9, v9, Llyiahf/vczjk/j74;->OooO00o:Llyiahf/vczjk/x64;

    invoke-direct {v10, v8, v9, v5}, Llyiahf/vczjk/k49;-><init>(Llyiahf/vczjk/gp1;Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;)V

    move-object v5, v10

    :goto_1
    if-eqz v5, :cond_5

    return-object v5

    :cond_5
    invoke-virtual {v1}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v5

    if-nez v5, :cond_6

    move-object v5, v2

    goto :goto_5

    :cond_6
    invoke-virtual {v2}, Llyiahf/vczjk/x64;->ooOO()Z

    move-result v8

    if-eqz v8, :cond_7

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooO0O()Llyiahf/vczjk/x64;

    move-result-object v8

    if-eqz v8, :cond_7

    invoke-virtual {v8}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v8

    if-nez v8, :cond_7

    invoke-virtual {v5, v6}, Llyiahf/vczjk/yn;->OooOOo(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v8

    if-eqz v8, :cond_7

    invoke-virtual {v1, v8}, Llyiahf/vczjk/v72;->o0000oo(Ljava/lang/Object;)Llyiahf/vczjk/ti4;

    move-result-object v8

    if-eqz v8, :cond_7

    move-object v9, v2

    check-cast v9, Llyiahf/vczjk/ub5;

    invoke-virtual {v9, v8}, Llyiahf/vczjk/ub5;->o0O0O00(Llyiahf/vczjk/ti4;)Llyiahf/vczjk/wb5;

    move-result-object v8

    goto :goto_2

    :cond_7
    move-object v8, v2

    :goto_2
    invoke-virtual {v8}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v9

    if-eqz v9, :cond_c

    invoke-virtual {v9}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v9

    if-nez v9, :cond_c

    invoke-virtual {v5, v6}, Llyiahf/vczjk/yn;->OooO0OO(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v9

    if-eqz v9, :cond_c

    instance-of v10, v9, Llyiahf/vczjk/e94;

    if-eqz v10, :cond_8

    check-cast v9, Llyiahf/vczjk/e94;

    goto :goto_3

    :cond_8
    check-cast v9, Ljava/lang/Class;

    const-class v10, Llyiahf/vczjk/d94;

    if-eq v9, v10, :cond_9

    invoke-static {v9}, Llyiahf/vczjk/vy0;->OooOOo(Ljava/lang/Class;)Z

    move-result v10

    if-eqz v10, :cond_a

    :cond_9
    move-object v9, v7

    :cond_a
    if-eqz v9, :cond_b

    invoke-virtual {v1, v9}, Llyiahf/vczjk/v72;->OoooooO(Ljava/lang/Object;)Llyiahf/vczjk/e94;

    move-result-object v9

    goto :goto_4

    :cond_b
    :goto_3
    move-object v9, v7

    :goto_4
    if-eqz v9, :cond_c

    invoke-virtual {v8, v9}, Llyiahf/vczjk/x64;->o00oO0O(Llyiahf/vczjk/e94;)Llyiahf/vczjk/x64;

    move-result-object v8

    :cond_c
    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v9

    invoke-virtual {v5, v9, v6, v8}, Llyiahf/vczjk/yn;->ooOO(Llyiahf/vczjk/t72;Llyiahf/vczjk/u34;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object v5

    :goto_5
    if-eq v5, v2, :cond_d

    invoke-virtual {v3, v5}, Llyiahf/vczjk/t72;->Oooo00o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v4

    move-object v11, v5

    goto :goto_6

    :cond_d
    move-object v11, v2

    :goto_6
    iget-object v2, v4, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    iget-object v5, v4, Llyiahf/vczjk/h90;->OooO0Oo:Llyiahf/vczjk/yn;

    if-nez v5, :cond_e

    move-object v6, v7

    goto :goto_7

    :cond_e
    invoke-virtual {v5, v2}, Llyiahf/vczjk/yn;->OooOoOO(Llyiahf/vczjk/hm;)Ljava/lang/Class;

    move-result-object v6

    :goto_7
    if-eqz v6, :cond_21

    check-cast v0, Llyiahf/vczjk/ab0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v1, v6}, Llyiahf/vczjk/v72;->Oooooo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v15

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v13

    invoke-virtual {v13}, Llyiahf/vczjk/ec5;->OooO0oO()Llyiahf/vczjk/jy0;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/l90;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v13, v15, v13}, Llyiahf/vczjk/l90;->OooO0OO(Llyiahf/vczjk/ec5;Llyiahf/vczjk/x64;Llyiahf/vczjk/ec5;)Llyiahf/vczjk/hm;

    move-result-object v2

    invoke-virtual {v13}, Llyiahf/vczjk/ec5;->OooOOo()Z

    move-result v3

    if-eqz v3, :cond_f

    invoke-virtual {v13}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v3

    goto :goto_8

    :cond_f
    move-object v3, v7

    :goto_8
    if-nez v3, :cond_10

    move-object v3, v7

    goto :goto_9

    :cond_10
    invoke-virtual {v3, v2}, Llyiahf/vczjk/yn;->OooOoo0(Llyiahf/vczjk/hm;)Llyiahf/vczjk/ya4;

    move-result-object v3

    :goto_9
    if-nez v3, :cond_11

    const-string v3, "with"

    :goto_a
    move-object/from16 v17, v3

    goto :goto_b

    :cond_11
    iget-object v3, v3, Llyiahf/vczjk/ya4;->OooO0OO:Ljava/lang/String;

    goto :goto_a

    :goto_b
    new-instance v12, Llyiahf/vczjk/yg6;

    const/4 v14, 0x0

    move-object/from16 v16, v2

    invoke-direct/range {v12 .. v17}, Llyiahf/vczjk/yg6;-><init>(Llyiahf/vczjk/fc5;ZLlyiahf/vczjk/x64;Llyiahf/vczjk/hm;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/h90;

    invoke-direct {v2, v12}, Llyiahf/vczjk/h90;-><init>(Llyiahf/vczjk/yg6;)V

    :try_start_0
    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/n90;->OooOOOO(Llyiahf/vczjk/h90;Llyiahf/vczjk/v72;)Llyiahf/vczjk/nca;

    move-result-object v3
    :try_end_0
    .catch Ljava/lang/NoClassDefFoundError; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v4

    new-instance v9, Llyiahf/vczjk/za0;

    invoke-direct {v9, v2, v1}, Llyiahf/vczjk/za0;-><init>(Llyiahf/vczjk/h90;Llyiahf/vczjk/v72;)V

    iput-object v3, v9, Llyiahf/vczjk/za0;->OooO:Ljava/lang/Object;

    invoke-virtual {v0, v1, v2, v9}, Llyiahf/vczjk/ab0;->OooOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/za0;)V

    invoke-static {v1, v2, v9}, Llyiahf/vczjk/ab0;->OooOo00(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/za0;)V

    invoke-virtual {v0, v1, v2, v9}, Llyiahf/vczjk/ab0;->OooOOo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/za0;)V

    invoke-static {v2, v9}, Llyiahf/vczjk/ab0;->OooOOoo(Llyiahf/vczjk/h90;Llyiahf/vczjk/za0;)V

    iget-object v1, v2, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    iget-object v2, v2, Llyiahf/vczjk/h90;->OooO0Oo:Llyiahf/vczjk/yn;

    if-nez v2, :cond_12

    move-object v2, v7

    goto :goto_c

    :cond_12
    invoke-virtual {v2, v1}, Llyiahf/vczjk/yn;->OooOoo0(Llyiahf/vczjk/hm;)Llyiahf/vczjk/ya4;

    move-result-object v2

    :goto_c
    if-nez v2, :cond_13

    const-string v2, "build"

    goto :goto_d

    :cond_13
    iget-object v2, v2, Llyiahf/vczjk/ya4;->OooO0O0:Ljava/lang/String;

    :goto_d
    invoke-virtual {v1}, Llyiahf/vczjk/hm;->o00oO0o()Llyiahf/vczjk/um;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/um;->OooOOO:Ljava/io/Serializable;

    check-cast v1, Ljava/util/LinkedHashMap;

    if-nez v1, :cond_14

    move-object v1, v7

    goto :goto_e

    :cond_14
    new-instance v3, Llyiahf/vczjk/fg5;

    invoke-direct {v3, v2, v7}, Llyiahf/vczjk/fg5;-><init>(Ljava/lang/String;[Ljava/lang/Class;)V

    invoke-virtual {v1, v3}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rm;

    :goto_e
    if-eqz v1, :cond_15

    invoke-virtual {v4}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v3

    if-eqz v3, :cond_15

    sget-object v3, Llyiahf/vczjk/gc5;->OooOoO:Llyiahf/vczjk/gc5;

    invoke-virtual {v4, v3}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v3

    iget-object v4, v1, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    invoke-static {v4, v3}, Llyiahf/vczjk/vy0;->OooO0Oo(Ljava/lang/reflect/Member;Z)V

    :cond_15
    iput-object v1, v9, Llyiahf/vczjk/za0;->OooOO0o:Ljava/lang/Object;

    iget-object v1, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v1}, Llyiahf/vczjk/z82;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_17

    iget-object v1, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v1}, Llyiahf/vczjk/z82;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v3

    if-nez v3, :cond_16

    goto :goto_f

    :cond_16
    invoke-static {v1}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_17
    :goto_f
    iget-object v1, v9, Llyiahf/vczjk/za0;->OooOO0o:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/rm;

    iget-object v3, v9, Llyiahf/vczjk/za0;->OooO0Oo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/h90;

    iget-object v4, v9, Llyiahf/vczjk/za0;->OooO0OO:Ljava/io/Serializable;

    check-cast v4, Llyiahf/vczjk/v72;

    if-nez v1, :cond_19

    invoke-virtual {v2}, Ljava/lang/String;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_18

    goto :goto_10

    :cond_18
    iget-object v0, v3, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    invoke-virtual {v3}, Llyiahf/vczjk/h90;->OooO0oO()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    const-string v3, "Builder class "

    const-string v5, " does not have build method (name: \'"

    const-string v6, "\')"

    invoke-static {v3, v1, v5, v2, v6}, Llyiahf/vczjk/ii5;->OooOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v4, v0, v1}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v7

    :cond_19
    iget-object v1, v1, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    invoke-virtual {v1}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v11}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v2

    if-eq v1, v2, :cond_1b

    invoke-virtual {v1, v2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v5

    if-nez v5, :cond_1b

    invoke-virtual {v2, v1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v2

    if-eqz v2, :cond_1a

    goto :goto_10

    :cond_1a
    iget-object v0, v3, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    iget-object v2, v9, Llyiahf/vczjk/za0;->OooOO0o:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/rm;

    invoke-virtual {v2}, Llyiahf/vczjk/rm;->o00oO0O()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v11}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v3

    const-string v5, "Build method \'"

    const-string v6, "\' has wrong return type ("

    const-string v8, "), not compatible with POJO type ("

    invoke-static {v5, v2, v6, v1, v8}, Llyiahf/vczjk/q99;->OooO0oo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, ")"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v4, v0, v1}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v7

    :cond_1b
    :goto_10
    iget-object v1, v9, Llyiahf/vczjk/za0;->OooO0o0:Ljava/lang/Object;

    check-cast v1, Ljava/util/LinkedHashMap;

    invoke-virtual {v1}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    move-result-object v1

    invoke-virtual {v9, v1}, Llyiahf/vczjk/za0;->OooO0O0(Ljava/util/Collection;)V

    invoke-virtual {v9, v1}, Llyiahf/vczjk/za0;->OooO00o(Ljava/util/Collection;)Ljava/util/Map;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/fb0;

    sget-object v4, Llyiahf/vczjk/gc5;->OooOooo:Llyiahf/vczjk/gc5;

    iget-object v5, v9, Llyiahf/vczjk/za0;->OooO0O0:Ljava/io/Serializable;

    check-cast v5, Llyiahf/vczjk/t72;

    invoke-virtual {v5, v4}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v4

    invoke-virtual {v5}, Llyiahf/vczjk/ec5;->OooOO0o()Ljava/util/Locale;

    move-result-object v6

    invoke-direct {v3, v4, v1, v2, v6}, Llyiahf/vczjk/fb0;-><init>(ZLjava/util/Collection;Ljava/util/Map;Ljava/util/Locale;)V

    invoke-virtual {v3}, Llyiahf/vczjk/fb0;->OooO0OO()V

    sget-object v2, Llyiahf/vczjk/gc5;->OooOoo:Llyiahf/vczjk/gc5;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v2

    xor-int/lit8 v4, v2, 0x1

    if-eqz v2, :cond_1d

    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_1c
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1d

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ph8;

    invoke-virtual {v2}, Llyiahf/vczjk/ph8;->OooOo0()Z

    move-result v2

    if-eqz v2, :cond_1c

    const/4 v4, 0x1

    :cond_1d
    move/from16 v16, v4

    iget-object v1, v9, Llyiahf/vczjk/za0;->OooOO0:Ljava/io/Serializable;

    check-cast v1, Llyiahf/vczjk/u66;

    if-eqz v1, :cond_1e

    new-instance v1, Llyiahf/vczjk/y66;

    iget-object v2, v9, Llyiahf/vczjk/za0;->OooOO0:Ljava/io/Serializable;

    check-cast v2, Llyiahf/vczjk/u66;

    sget-object v4, Llyiahf/vczjk/wa7;->OooOOO:Llyiahf/vczjk/wa7;

    invoke-direct {v1, v2, v4}, Llyiahf/vczjk/y66;-><init>(Llyiahf/vczjk/u66;Llyiahf/vczjk/wa7;)V

    invoke-virtual {v3, v1}, Llyiahf/vczjk/fb0;->OooOOO(Llyiahf/vczjk/y66;)Llyiahf/vczjk/fb0;

    move-result-object v3

    :cond_1e
    move-object v12, v3

    new-instance v8, Llyiahf/vczjk/vj0;

    iget-object v1, v9, Llyiahf/vczjk/za0;->OooO0oO:Ljava/lang/Object;

    move-object v13, v1

    check-cast v13, Ljava/util/HashMap;

    iget-object v1, v9, Llyiahf/vczjk/za0;->OooO0oo:Ljava/lang/Object;

    move-object v14, v1

    check-cast v14, Ljava/util/HashSet;

    iget-boolean v15, v9, Llyiahf/vczjk/za0;->OooO00o:Z

    iget-object v1, v9, Llyiahf/vczjk/za0;->OooO0Oo:Ljava/lang/Object;

    move-object v10, v1

    check-cast v10, Llyiahf/vczjk/h90;

    invoke-direct/range {v8 .. v16}, Llyiahf/vczjk/vj0;-><init>(Llyiahf/vczjk/za0;Llyiahf/vczjk/h90;Llyiahf/vczjk/x64;Llyiahf/vczjk/fb0;Ljava/util/HashMap;Ljava/util/HashSet;ZZ)V

    iget-object v1, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v1}, Llyiahf/vczjk/z82;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_20

    iget-object v0, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v0}, Llyiahf/vczjk/z82;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v1

    if-nez v1, :cond_1f

    goto :goto_11

    :cond_1f
    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_20
    :goto_11
    return-object v8

    :catch_0
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v0

    new-instance v3, Llyiahf/vczjk/d44;

    iget-object v1, v1, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {v3, v1, v0, v2}, Llyiahf/vczjk/d44;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/h90;)V

    throw v3

    :catch_1
    move-exception v0

    new-instance v1, Llyiahf/vczjk/qq2;

    invoke-direct {v1, v0}, Llyiahf/vczjk/qq2;-><init>(Ljava/lang/NoClassDefFoundError;)V

    return-object v1

    :cond_21
    if-nez v5, :cond_22

    goto :goto_12

    :cond_22
    invoke-virtual {v5, v2}, Llyiahf/vczjk/yn;->OooO(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v4, v2}, Llyiahf/vczjk/h90;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/gp1;

    move-result-object v7

    :goto_12
    if-nez v7, :cond_23

    invoke-static {v1, v0, v11, v4}, Llyiahf/vczjk/x82;->OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/y82;Llyiahf/vczjk/x64;Llyiahf/vczjk/h90;)Llyiahf/vczjk/e94;

    move-result-object v0

    return-object v0

    :cond_23
    invoke-virtual {v1}, Llyiahf/vczjk/v72;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-object v2, v7

    check-cast v2, Llyiahf/vczjk/j74;

    invoke-virtual {v11}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v5

    iget-object v2, v2, Llyiahf/vczjk/j74;->OooO00o:Llyiahf/vczjk/x64;

    invoke-virtual {v2, v5}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v5

    if-nez v5, :cond_24

    invoke-virtual {v3, v2}, Llyiahf/vczjk/t72;->Oooo00o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v4

    :cond_24
    new-instance v3, Llyiahf/vczjk/k49;

    invoke-static {v1, v0, v2, v4}, Llyiahf/vczjk/x82;->OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/y82;Llyiahf/vczjk/x64;Llyiahf/vczjk/h90;)Llyiahf/vczjk/e94;

    move-result-object v0

    invoke-direct {v3, v7, v2, v0}, Llyiahf/vczjk/k49;-><init>(Llyiahf/vczjk/gp1;Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;)V

    return-object v3
.end method

.method public static OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/y82;Llyiahf/vczjk/x64;Llyiahf/vczjk/h90;)Llyiahf/vczjk/e94;
    .locals 27

    move-object/from16 v1, p0

    move-object/from16 v0, p1

    move-object/from16 v2, p2

    move-object/from16 v3, p3

    const-class v4, Ljava/nio/ByteBuffer;

    const-class v5, Ljava/util/concurrent/atomic/AtomicBoolean;

    const-class v6, Ljava/lang/StackTraceElement;

    const-class v7, Ljava/util/UUID;

    const-class v8, Llyiahf/vczjk/tt9;

    const-class v9, Ljava/sql/Timestamp;

    const-class v10, Ljava/sql/Date;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->Oooooo()Z

    move-result v11

    const/4 v12, 0x0

    const/4 v13, 0x0

    if-eqz v11, :cond_b

    check-cast v0, Llyiahf/vczjk/n90;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v4

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v6

    iget-object v5, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v5}, Llyiahf/vczjk/z82;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v5

    invoke-virtual {v5}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v7

    if-nez v7, :cond_a

    const-class v5, Ljava/lang/Enum;

    if-ne v6, v5, :cond_0

    new-instance v0, Llyiahf/vczjk/o000Oo0;

    invoke-direct {v0, v3}, Llyiahf/vczjk/o000Oo0;-><init>(Llyiahf/vczjk/h90;)V

    return-object v0

    :cond_0
    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/n90;->OooO0oo(Llyiahf/vczjk/h90;Llyiahf/vczjk/v72;)Llyiahf/vczjk/f59;

    move-result-object v9

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v5

    invoke-virtual {v9, v5}, Llyiahf/vczjk/f59;->OooOoO(Llyiahf/vczjk/t72;)[Llyiahf/vczjk/ph8;

    move-result-object v10

    invoke-virtual {v3}, Llyiahf/vczjk/h90;->OooO0oo()Ljava/util/List;

    move-result-object v5

    invoke-interface {v5}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :cond_1
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_6

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/rm;

    invoke-static {v1, v7}, Llyiahf/vczjk/n90;->OooOO0(Llyiahf/vczjk/v72;Llyiahf/vczjk/gn;)Z

    move-result v8

    if-eqz v8, :cond_1

    invoke-virtual {v7}, Llyiahf/vczjk/rm;->o00000()[Ljava/lang/Class;

    move-result-object v5

    array-length v5, v5

    iget-object v8, v7, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    if-nez v5, :cond_3

    sget v1, Llyiahf/vczjk/kp2;->OooOOOO:I

    invoke-virtual {v4}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v1

    if-eqz v1, :cond_2

    sget-object v1, Llyiahf/vczjk/gc5;->OooOoO:Llyiahf/vczjk/gc5;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v1

    invoke-static {v8, v1}, Llyiahf/vczjk/vy0;->OooO0Oo(Ljava/lang/reflect/Member;Z)V

    :cond_2
    new-instance v13, Llyiahf/vczjk/fv2;

    invoke-direct {v13, v6, v7}, Llyiahf/vczjk/fv2;-><init>(Ljava/lang/Class;Llyiahf/vczjk/rm;)V

    goto :goto_0

    :cond_3
    invoke-virtual {v8}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    move-result-object v5

    invoke-virtual {v5, v6}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_5

    sget v1, Llyiahf/vczjk/kp2;->OooOOOO:I

    invoke-virtual {v4}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v1

    if-eqz v1, :cond_4

    sget-object v1, Llyiahf/vczjk/gc5;->OooOoO:Llyiahf/vczjk/gc5;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v1

    invoke-static {v8, v1}, Llyiahf/vczjk/vy0;->OooO0Oo(Ljava/lang/reflect/Member;Z)V

    :cond_4
    new-instance v5, Llyiahf/vczjk/fv2;

    invoke-virtual {v7, v12}, Llyiahf/vczjk/rm;->o000000O(I)Llyiahf/vczjk/x64;

    move-result-object v8

    invoke-direct/range {v5 .. v10}, Llyiahf/vczjk/fv2;-><init>(Ljava/lang/Class;Llyiahf/vczjk/rm;Llyiahf/vczjk/x64;Llyiahf/vczjk/f59;[Llyiahf/vczjk/ph8;)V

    move-object v13, v5

    goto :goto_0

    :cond_5
    invoke-virtual {v7}, Llyiahf/vczjk/rm;->toString()Ljava/lang/String;

    move-result-object v0

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Invalid `@JsonCreator` annotated Enum factory method ["

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, "]: needs to return compatible type"

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v1, v2, v0}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v13

    :cond_6
    :goto_0
    if-nez v13, :cond_7

    new-instance v13, Llyiahf/vczjk/kp2;

    invoke-virtual {v3}, Llyiahf/vczjk/h90;->OooO0o0()Llyiahf/vczjk/pm;

    move-result-object v1

    invoke-static {v6, v4, v1}, Llyiahf/vczjk/n90;->OooOOO0(Ljava/lang/Class;Llyiahf/vczjk/t72;Llyiahf/vczjk/pm;)Llyiahf/vczjk/tp2;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc5;->Oooo000:Llyiahf/vczjk/gc5;

    invoke-virtual {v4, v2}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v2

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v2

    invoke-direct {v13, v1, v2}, Llyiahf/vczjk/kp2;-><init>(Llyiahf/vczjk/tp2;Ljava/lang/Boolean;)V

    :cond_7
    iget-object v1, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v1}, Llyiahf/vczjk/z82;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_9

    iget-object v0, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v0}, Llyiahf/vczjk/z82;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v1

    if-nez v1, :cond_8

    goto :goto_1

    :cond_8
    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_9
    :goto_1
    return-object v13

    :cond_a
    invoke-static {v5}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_b
    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OooooOo()Z

    move-result v11

    const-class v15, Ljava/util/Map;

    const-class v12, Ljava/lang/String;

    move-object/from16 v16, v13

    sget-object v13, Ljava/lang/Character;->TYPE:Ljava/lang/Class;

    sget-object v14, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    move/from16 v18, v11

    sget-object v11, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    move-object/from16 v19, v4

    sget-object v4, Ljava/lang/Float;->TYPE:Ljava/lang/Class;

    move-object/from16 v20, v5

    sget-object v5, Ljava/lang/Short;->TYPE:Ljava/lang/Class;

    move-object/from16 v21, v6

    sget-object v6, Ljava/lang/Byte;->TYPE:Ljava/lang/Class;

    move-object/from16 v22, v7

    sget-object v7, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    move-object/from16 v23, v8

    sget-object v8, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    if-eqz v18, :cond_3a

    move-object/from16 v18, v9

    instance-of v9, v2, Llyiahf/vczjk/oy;

    if-eqz v9, :cond_1a

    check-cast v2, Llyiahf/vczjk/oy;

    check-cast v0, Llyiahf/vczjk/n90;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v1

    invoke-virtual {v2}, Llyiahf/vczjk/oy;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/e94;

    invoke-virtual {v3}, Llyiahf/vczjk/x64;->OoooOOO()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/u3a;

    if-nez v10, :cond_c

    invoke-virtual {v0, v1, v3}, Llyiahf/vczjk/n90;->OooO0O0(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;)Llyiahf/vczjk/v3a;

    move-result-object v10

    :cond_c
    iget-object v1, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v1}, Llyiahf/vczjk/z82;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v15

    if-nez v15, :cond_19

    if-nez v9, :cond_16

    invoke-virtual {v3}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v3}, Llyiahf/vczjk/x64;->o00O0O()Z

    move-result v3

    if-eqz v3, :cond_15

    sget v0, Llyiahf/vczjk/n47;->OooOOOo:I

    if-ne v1, v8, :cond_d

    sget-object v0, Llyiahf/vczjk/k47;->OooOOo0:Llyiahf/vczjk/k47;

    return-object v0

    :cond_d
    if-ne v1, v7, :cond_e

    sget-object v0, Llyiahf/vczjk/l47;->OooOOo0:Llyiahf/vczjk/l47;

    return-object v0

    :cond_e
    if-ne v1, v6, :cond_f

    new-instance v0, Llyiahf/vczjk/g47;

    const-class v1, [B

    invoke-direct {v0, v1}, Llyiahf/vczjk/n47;-><init>(Ljava/lang/Class;)V

    return-object v0

    :cond_f
    if-ne v1, v5, :cond_10

    new-instance v0, Llyiahf/vczjk/m47;

    const-class v1, [S

    invoke-direct {v0, v1}, Llyiahf/vczjk/n47;-><init>(Ljava/lang/Class;)V

    return-object v0

    :cond_10
    if-ne v1, v4, :cond_11

    new-instance v0, Llyiahf/vczjk/j47;

    const-class v1, [F

    invoke-direct {v0, v1}, Llyiahf/vczjk/n47;-><init>(Ljava/lang/Class;)V

    return-object v0

    :cond_11
    if-ne v1, v11, :cond_12

    new-instance v0, Llyiahf/vczjk/i47;

    const-class v1, [D

    invoke-direct {v0, v1}, Llyiahf/vczjk/n47;-><init>(Ljava/lang/Class;)V

    return-object v0

    :cond_12
    if-ne v1, v14, :cond_13

    new-instance v0, Llyiahf/vczjk/f47;

    const-class v1, [Z

    invoke-direct {v0, v1}, Llyiahf/vczjk/n47;-><init>(Ljava/lang/Class;)V

    return-object v0

    :cond_13
    if-ne v1, v13, :cond_14

    new-instance v0, Llyiahf/vczjk/h47;

    const-class v1, [C

    invoke-direct {v0, v1}, Llyiahf/vczjk/n47;-><init>(Ljava/lang/Class;)V

    return-object v0

    :cond_14
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    throw v0

    :cond_15
    if-ne v1, v12, :cond_16

    sget-object v0, Llyiahf/vczjk/j69;->OooOOOo:Llyiahf/vczjk/j69;

    return-object v0

    :cond_16
    new-instance v1, Llyiahf/vczjk/j66;

    invoke-direct {v1, v2, v9, v10}, Llyiahf/vczjk/j66;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;)V

    iget-object v2, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v2}, Llyiahf/vczjk/z82;->OooO0o0()Z

    move-result v2

    if-eqz v2, :cond_18

    iget-object v0, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v0}, Llyiahf/vczjk/z82;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v2

    if-nez v2, :cond_17

    goto :goto_2

    :cond_17
    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_18
    :goto_2
    return-object v1

    :cond_19
    invoke-static {v1}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_1a
    invoke-virtual {v2}, Llyiahf/vczjk/x64;->ooOO()Z

    move-result v9

    move/from16 v24, v9

    sget-object v9, Llyiahf/vczjk/p94;->OooOOo0:Llyiahf/vczjk/p94;

    if-eqz v24, :cond_34

    invoke-virtual {v3}, Llyiahf/vczjk/h90;->OooO0Oo()Llyiahf/vczjk/q94;

    move-result-object v24

    if-eqz v24, :cond_1b

    move-object/from16 v25, v10

    invoke-virtual/range {v24 .. v24}, Llyiahf/vczjk/q94;->OooO0o()Llyiahf/vczjk/p94;

    move-result-object v10

    if-eq v10, v9, :cond_35

    :cond_1b
    check-cast v2, Llyiahf/vczjk/ub5;

    instance-of v4, v2, Llyiahf/vczjk/wb5;

    if-eqz v4, :cond_31

    check-cast v2, Llyiahf/vczjk/wb5;

    check-cast v0, Llyiahf/vczjk/n90;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v4

    invoke-virtual {v2}, Llyiahf/vczjk/ub5;->OoooO0O()Llyiahf/vczjk/x64;

    move-result-object v5

    invoke-virtual {v2}, Llyiahf/vczjk/ub5;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v6

    invoke-virtual {v6}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v7

    move-object v12, v7

    check-cast v12, Llyiahf/vczjk/e94;

    invoke-virtual {v5}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v7

    move-object v11, v7

    check-cast v11, Llyiahf/vczjk/ti4;

    invoke-virtual {v6}, Llyiahf/vczjk/x64;->OoooOOO()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/u3a;

    if-nez v7, :cond_1c

    invoke-virtual {v0, v4, v6}, Llyiahf/vczjk/n90;->OooO0O0(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;)Llyiahf/vczjk/v3a;

    move-result-object v7

    :cond_1c
    move-object v13, v7

    iget-object v6, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v6}, Llyiahf/vczjk/z82;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v6

    invoke-virtual {v6}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v7

    if-nez v7, :cond_30

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v6

    const-class v7, Ljava/util/EnumMap;

    invoke-virtual {v7, v6}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v8

    if-eqz v8, :cond_1f

    if-ne v6, v7, :cond_1d

    move-object/from16 v6, v16

    goto :goto_3

    :cond_1d
    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/n90;->OooOOOO(Llyiahf/vczjk/h90;Llyiahf/vczjk/v72;)Llyiahf/vczjk/nca;

    move-result-object v6

    :goto_3
    invoke-virtual {v5}, Llyiahf/vczjk/x64;->Oooooo0()Z

    move-result v5

    if-eqz v5, :cond_1e

    new-instance v5, Llyiahf/vczjk/sp2;

    invoke-direct {v5, v2, v12, v13, v6}, Llyiahf/vczjk/sp2;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/nca;)V

    move-object v9, v5

    goto :goto_4

    :cond_1e
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Cannot construct EnumMap; generic (key) type not available"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1f
    move-object/from16 v9, v16

    :goto_4
    if-nez v9, :cond_2d

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->Ooooooo()Z

    move-result v5

    if-nez v5, :cond_24

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->Ooooo0o()Z

    move-result v5

    if-eqz v5, :cond_20

    goto :goto_7

    :cond_20
    sget-object v5, Llyiahf/vczjk/k74;->OooO0Oo:Ljava/lang/Class;

    invoke-virtual {v2, v5}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_21

    new-instance v5, Llyiahf/vczjk/j74;

    invoke-virtual {v2, v15}, Llyiahf/vczjk/e3a;->Oooo0o(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v6

    const/4 v7, 0x3

    invoke-direct {v5, v7, v6}, Llyiahf/vczjk/j74;-><init>(ILlyiahf/vczjk/x64;)V

    goto :goto_5

    :cond_21
    sget-object v5, Llyiahf/vczjk/k74;->OooO0oo:Ljava/lang/Class;

    invoke-virtual {v2, v5}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_22

    new-instance v5, Llyiahf/vczjk/j74;

    invoke-virtual {v2, v15}, Llyiahf/vczjk/e3a;->Oooo0o(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v6

    const/4 v7, 0x6

    invoke-direct {v5, v7, v6}, Llyiahf/vczjk/j74;-><init>(ILlyiahf/vczjk/x64;)V

    :goto_5
    new-instance v6, Llyiahf/vczjk/k49;

    invoke-direct {v6, v5}, Llyiahf/vczjk/k49;-><init>(Llyiahf/vczjk/j74;)V

    goto :goto_6

    :cond_22
    move-object/from16 v6, v16

    :goto_6
    if-eqz v6, :cond_23

    return-object v6

    :cond_23
    move-object v9, v2

    move-object v2, v3

    goto :goto_a

    :cond_24
    :goto_7
    sget-object v5, Llyiahf/vczjk/m90;->OooO0O0:Ljava/util/HashMap;

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v5, v6}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Class;

    if-eqz v5, :cond_25

    invoke-virtual {v4}, Llyiahf/vczjk/ec5;->OooOOOO()Llyiahf/vczjk/a4a;

    move-result-object v6

    const/4 v7, 0x1

    invoke-virtual {v6, v2, v5, v7}, Llyiahf/vczjk/a4a;->OooOO0(Llyiahf/vczjk/x64;Ljava/lang/Class;Z)Llyiahf/vczjk/x64;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/wb5;

    move-object v6, v5

    goto :goto_8

    :cond_25
    move-object/from16 v6, v16

    :goto_8
    if-eqz v6, :cond_26

    invoke-virtual {v4}, Llyiahf/vczjk/ec5;->OooO0oO()Llyiahf/vczjk/jy0;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/l90;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4, v6}, Llyiahf/vczjk/l90;->OooO0O0(Llyiahf/vczjk/ec5;Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v2

    if-nez v2, :cond_27

    invoke-static {v4, v6}, Llyiahf/vczjk/l90;->OooO00o(Llyiahf/vczjk/fc5;Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v2

    if-nez v2, :cond_27

    invoke-static {v4, v6, v4}, Llyiahf/vczjk/l90;->OooO0OO(Llyiahf/vczjk/ec5;Llyiahf/vczjk/x64;Llyiahf/vczjk/ec5;)Llyiahf/vczjk/hm;

    move-result-object v7

    new-instance v3, Llyiahf/vczjk/yg6;

    const-string v8, "set"

    const/4 v5, 0x0

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/yg6;-><init>(Llyiahf/vczjk/fc5;ZLlyiahf/vczjk/x64;Llyiahf/vczjk/hm;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/h90;

    invoke-direct {v2, v3}, Llyiahf/vczjk/h90;-><init>(Llyiahf/vczjk/yg6;)V

    goto :goto_9

    :cond_26
    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooOOO()Ljava/lang/Object;

    move-result-object v5

    if-eqz v5, :cond_2c

    new-instance v9, Llyiahf/vczjk/o000Oo0;

    invoke-direct {v9, v3}, Llyiahf/vczjk/o000Oo0;-><init>(Llyiahf/vczjk/h90;)V

    move-object v6, v2

    move-object v2, v3

    :cond_27
    :goto_9
    move-object/from16 v26, v9

    move-object v9, v6

    move-object/from16 v6, v26

    :goto_a
    if-nez v6, :cond_2b

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/n90;->OooOOOO(Llyiahf/vczjk/h90;Llyiahf/vczjk/v72;)Llyiahf/vczjk/nca;

    move-result-object v10

    new-instance v8, Llyiahf/vczjk/jb5;

    invoke-direct/range {v8 .. v13}, Llyiahf/vczjk/jb5;-><init>(Llyiahf/vczjk/wb5;Llyiahf/vczjk/nca;Llyiahf/vczjk/ti4;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;)V

    iget-object v1, v2, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {v4, v15, v1}, Llyiahf/vczjk/fc5;->OooOoO0(Ljava/lang/Class;Llyiahf/vczjk/hm;)Llyiahf/vczjk/ba4;

    move-result-object v1

    if-nez v1, :cond_28

    move-object/from16 v1, v16

    goto :goto_b

    :cond_28
    invoke-virtual {v1}, Llyiahf/vczjk/ba4;->OooO0O0()Ljava/util/Set;

    move-result-object v1

    :goto_b
    if-eqz v1, :cond_2a

    invoke-interface {v1}, Ljava/util/Set;->size()I

    move-result v2

    if-nez v2, :cond_29

    goto :goto_c

    :cond_29
    move-object v13, v1

    goto :goto_d

    :cond_2a
    :goto_c
    move-object/from16 v13, v16

    :goto_d
    iput-object v13, v8, Llyiahf/vczjk/jb5;->_ignorableProperties:Ljava/util/Set;

    move-object v9, v8

    goto :goto_e

    :cond_2b
    move-object v9, v6

    goto :goto_e

    :cond_2c
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v3, "Cannot find a deserializer for non-concrete Map type "

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_2d
    :goto_e
    iget-object v1, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v1}, Llyiahf/vczjk/z82;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_2f

    iget-object v0, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v0}, Llyiahf/vczjk/z82;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v1

    if-nez v1, :cond_2e

    goto :goto_f

    :cond_2e
    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_2f
    :goto_f
    return-object v9

    :cond_30
    invoke-static {v6}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_31
    check-cast v0, Llyiahf/vczjk/n90;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2}, Llyiahf/vczjk/ub5;->OoooO0O()Llyiahf/vczjk/x64;

    move-result-object v3

    invoke-virtual {v2}, Llyiahf/vczjk/ub5;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v2

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v1

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/e94;

    invoke-virtual {v3}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ti4;

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooOOO()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/u3a;

    if-nez v3, :cond_32

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/n90;->OooO0O0(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;)Llyiahf/vczjk/v3a;

    :cond_32
    iget-object v0, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v0}, Llyiahf/vczjk/z82;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v1

    if-nez v1, :cond_33

    goto/16 :goto_11

    :cond_33
    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_34
    move-object/from16 v25, v10

    :cond_35
    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OooooO0()Z

    move-result v10

    if-eqz v10, :cond_3b

    invoke-virtual {v3}, Llyiahf/vczjk/h90;->OooO0Oo()Llyiahf/vczjk/q94;

    move-result-object v10

    if-eqz v10, :cond_36

    invoke-virtual {v10}, Llyiahf/vczjk/q94;->OooO0o()Llyiahf/vczjk/p94;

    move-result-object v10

    if-eq v10, v9, :cond_3b

    :cond_36
    check-cast v2, Llyiahf/vczjk/w11;

    instance-of v4, v2, Llyiahf/vczjk/a21;

    if-eqz v4, :cond_37

    check-cast v2, Llyiahf/vczjk/a21;

    invoke-virtual {v0, v1, v2, v3}, Llyiahf/vczjk/y82;->OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/a21;Llyiahf/vczjk/h90;)Llyiahf/vczjk/e94;

    move-result-object v0

    return-object v0

    :cond_37
    check-cast v0, Llyiahf/vczjk/n90;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2}, Llyiahf/vczjk/w11;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/e94;

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v1

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooOOO()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/u3a;

    if-nez v3, :cond_38

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/n90;->OooO0O0(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;)Llyiahf/vczjk/v3a;

    :cond_38
    iget-object v0, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v0}, Llyiahf/vczjk/z82;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v1

    if-nez v1, :cond_39

    goto :goto_11

    :cond_39
    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_3a
    move-object/from16 v18, v9

    move-object/from16 v25, v10

    :cond_3b
    invoke-virtual {v2}, Llyiahf/vczjk/ok6;->OooOoO0()Z

    move-result v9

    if-eqz v9, :cond_40

    check-cast v2, Llyiahf/vczjk/nl7;

    check-cast v0, Llyiahf/vczjk/n90;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2}, Llyiahf/vczjk/nl7;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/e94;

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v6

    invoke-virtual {v4}, Llyiahf/vczjk/x64;->OoooOOO()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/u3a;

    if-nez v7, :cond_3c

    invoke-virtual {v0, v6, v4}, Llyiahf/vczjk/n90;->OooO0O0(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;)Llyiahf/vczjk/v3a;

    move-result-object v7

    :cond_3c
    iget-object v4, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v4}, Llyiahf/vczjk/z82;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v6

    if-nez v6, :cond_3f

    const-class v4, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v2, v4}, Llyiahf/vczjk/x64;->o00Oo0(Ljava/lang/Class;)Z

    move-result v6

    if-eqz v6, :cond_3e

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v6

    if-ne v6, v4, :cond_3d

    move-object/from16 v13, v16

    goto :goto_10

    :cond_3d
    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/n90;->OooOOOO(Llyiahf/vczjk/h90;Llyiahf/vczjk/v72;)Llyiahf/vczjk/nca;

    move-result-object v13

    :goto_10
    new-instance v0, Llyiahf/vczjk/h10;

    invoke-direct {v0, v2, v5, v7, v13}, Llyiahf/vczjk/ol7;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/nca;)V

    return-object v0

    :cond_3e
    :goto_11
    return-object v16

    :cond_3f
    invoke-static {v4}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_40
    const-class v9, Llyiahf/vczjk/qa4;

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v10

    invoke-virtual {v9, v10}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v9

    if-eqz v9, :cond_44

    check-cast v0, Llyiahf/vczjk/n90;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v0}, Llyiahf/vczjk/z82;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v2

    if-nez v2, :cond_43

    sget-object v0, Llyiahf/vczjk/ta4;->OooOOOO:Llyiahf/vczjk/ta4;

    const-class v0, Llyiahf/vczjk/f76;

    if-ne v1, v0, :cond_41

    sget-object v0, Llyiahf/vczjk/sa4;->OooOOOO:Llyiahf/vczjk/sa4;

    return-object v0

    :cond_41
    const-class v0, Llyiahf/vczjk/ky;

    if-ne v1, v0, :cond_42

    sget-object v0, Llyiahf/vczjk/ra4;->OooOOOO:Llyiahf/vczjk/ra4;

    return-object v0

    :cond_42
    sget-object v0, Llyiahf/vczjk/ta4;->OooOOOO:Llyiahf/vczjk/ta4;

    return-object v0

    :cond_43
    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_44
    check-cast v0, Llyiahf/vczjk/ab0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v9, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v9}, Llyiahf/vczjk/z82;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v9

    invoke-virtual {v9}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v10

    if-nez v10, :cond_98

    const-class v9, Ljava/lang/Throwable;

    iget-object v10, v2, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {v9, v10}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v9

    if-eqz v9, :cond_4b

    new-instance v2, Llyiahf/vczjk/za0;

    invoke-direct {v2, v3, v1}, Llyiahf/vczjk/za0;-><init>(Llyiahf/vczjk/h90;Llyiahf/vczjk/v72;)V

    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/n90;->OooOOOO(Llyiahf/vczjk/h90;Llyiahf/vczjk/v72;)Llyiahf/vczjk/nca;

    move-result-object v4

    iput-object v4, v2, Llyiahf/vczjk/za0;->OooO:Ljava/lang/Object;

    invoke-virtual {v0, v1, v3, v2}, Llyiahf/vczjk/ab0;->OooOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/za0;)V

    sget-object v4, Llyiahf/vczjk/ab0;->OooOOO0:[Ljava/lang/Class;

    iget-object v5, v3, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {v5}, Llyiahf/vczjk/hm;->o00oO0o()Llyiahf/vczjk/um;

    move-result-object v5

    iget-object v5, v5, Llyiahf/vczjk/um;->OooOOO:Ljava/io/Serializable;

    check-cast v5, Ljava/util/LinkedHashMap;

    if-nez v5, :cond_45

    move-object/from16 v7, v16

    goto :goto_12

    :cond_45
    new-instance v6, Llyiahf/vczjk/fg5;

    const-string v7, "initCause"

    invoke-direct {v6, v7, v4}, Llyiahf/vczjk/fg5;-><init>(Ljava/lang/String;[Ljava/lang/Class;)V

    invoke-virtual {v5, v6}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/rm;

    move-object v7, v4

    :goto_12
    if-eqz v7, :cond_46

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v4

    new-instance v8, Llyiahf/vczjk/xa7;

    const-string v5, "cause"

    move-object/from16 v6, v16

    invoke-direct {v8, v5, v6}, Llyiahf/vczjk/xa7;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/bo8;

    invoke-virtual {v4}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v6

    const/4 v9, 0x0

    sget-object v10, Llyiahf/vczjk/eb0;->OooOOO0:Llyiahf/vczjk/fa4;

    invoke-direct/range {v5 .. v10}, Llyiahf/vczjk/bo8;-><init>(Llyiahf/vczjk/yn;Llyiahf/vczjk/pm;Llyiahf/vczjk/xa7;Llyiahf/vczjk/wa7;Llyiahf/vczjk/fa4;)V

    const/4 v4, 0x0

    invoke-virtual {v7, v4}, Llyiahf/vczjk/rm;->o000000O(I)Llyiahf/vczjk/x64;

    move-result-object v6

    invoke-virtual {v0, v1, v3, v5, v6}, Llyiahf/vczjk/ab0;->OooOo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/eb0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/ph8;

    move-result-object v1

    if-eqz v1, :cond_46

    iget-object v3, v2, Llyiahf/vczjk/za0;->OooO0o0:Ljava/lang/Object;

    check-cast v3, Ljava/util/LinkedHashMap;

    iget-object v4, v1, Llyiahf/vczjk/ph8;->_propName:Llyiahf/vczjk/xa7;

    invoke-virtual {v4}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v4

    invoke-interface {v3, v4, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_46
    const-string v1, "localizedMessage"

    invoke-virtual {v2, v1}, Llyiahf/vczjk/za0;->OooO0OO(Ljava/lang/String;)V

    const-string v1, "suppressed"

    invoke-virtual {v2, v1}, Llyiahf/vczjk/za0;->OooO0OO(Ljava/lang/String;)V

    iget-object v1, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v1}, Llyiahf/vczjk/z82;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_48

    iget-object v1, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v1}, Llyiahf/vczjk/z82;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v3

    if-nez v3, :cond_47

    goto :goto_13

    :cond_47
    invoke-static {v1}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_48
    :goto_13
    invoke-virtual {v2}, Llyiahf/vczjk/za0;->OooO0o0()Llyiahf/vczjk/xa0;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/hr9;

    iget-boolean v3, v1, Llyiahf/vczjk/ya0;->_ignoreAllUnknown:Z

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/ya0;-><init>(Llyiahf/vczjk/ya0;Z)V

    const/4 v4, 0x0

    iput-boolean v4, v2, Llyiahf/vczjk/ya0;->_vanillaProcessing:Z

    iget-object v1, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v1}, Llyiahf/vczjk/z82;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_4a

    iget-object v0, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v0}, Llyiahf/vczjk/z82;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v1

    if-nez v1, :cond_49

    goto :goto_14

    :cond_49
    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_4a
    :goto_14
    return-object v2

    :cond_4b
    invoke-virtual {v2}, Llyiahf/vczjk/x64;->Ooooo0o()Z

    move-result v9

    if-eqz v9, :cond_4d

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->o00O0O()Z

    move-result v9

    if-nez v9, :cond_4d

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->Oooooo()Z

    move-result v9

    if-nez v9, :cond_4d

    iget-object v9, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v9}, Llyiahf/vczjk/z82;->OooO00o()Llyiahf/vczjk/yx;

    move-result-object v9

    invoke-virtual {v9}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v10

    if-nez v10, :cond_4c

    goto :goto_15

    :cond_4c
    invoke-static {v9}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_4d
    :goto_15
    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v9

    const-class v10, Ljava/lang/Object;

    move-object/from16 v24, v15

    if-eq v9, v10, :cond_4e

    const-class v15, Ljava/io/Serializable;

    if-ne v9, v15, :cond_4f

    :cond_4e
    const/4 v4, 0x0

    goto/16 :goto_20

    :cond_4f
    if-eq v9, v12, :cond_50

    const-class v12, Ljava/lang/CharSequence;

    if-ne v9, v12, :cond_51

    :cond_50
    const/4 v4, 0x0

    goto/16 :goto_1f

    :cond_51
    const-class v12, Ljava/lang/Iterable;

    if-ne v9, v12, :cond_54

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v12, v2}, Llyiahf/vczjk/a4a;->OooOOO(Ljava/lang/Class;Llyiahf/vczjk/x64;)[Llyiahf/vczjk/x64;

    move-result-object v5

    if-eqz v5, :cond_52

    array-length v6, v5

    const/4 v7, 0x1

    if-eq v6, v7, :cond_53

    :cond_52
    const/4 v12, 0x0

    goto :goto_16

    :cond_53
    const/4 v12, 0x0

    aget-object v5, v5, v12

    goto :goto_17

    :goto_16
    invoke-static {}, Llyiahf/vczjk/a4a;->OooOOOo()Llyiahf/vczjk/ep8;

    move-result-object v5

    :goto_17
    const-class v6, Ljava/util/Collection;

    invoke-virtual {v4, v6, v5}, Llyiahf/vczjk/a4a;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/a21;

    move-result-object v4

    invoke-virtual {v0, v1, v4, v3}, Llyiahf/vczjk/n90;->OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/a21;Llyiahf/vczjk/h90;)Llyiahf/vczjk/e94;

    move-result-object v6

    move v4, v12

    goto/16 :goto_24

    :cond_54
    const/4 v12, 0x0

    const-class v15, Ljava/util/Map$Entry;

    if-ne v9, v15, :cond_56

    invoke-virtual {v2, v12}, Llyiahf/vczjk/x64;->Oooo0o0(I)Llyiahf/vczjk/x64;

    move-result-object v4

    const/4 v12, 0x1

    invoke-virtual {v2, v12}, Llyiahf/vczjk/x64;->Oooo0o0(I)Llyiahf/vczjk/x64;

    move-result-object v5

    invoke-virtual {v5}, Llyiahf/vczjk/x64;->OoooOOO()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/u3a;

    if-nez v6, :cond_55

    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v6

    invoke-virtual {v0, v6, v5}, Llyiahf/vczjk/n90;->OooO0O0(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;)Llyiahf/vczjk/v3a;

    move-result-object v6

    :cond_55
    invoke-virtual {v5}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/e94;

    invoke-virtual {v4}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ti4;

    new-instance v7, Llyiahf/vczjk/nb5;

    invoke-direct {v7, v2, v4, v5, v6}, Llyiahf/vczjk/nb5;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/ti4;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;)V

    move-object v6, v7

    const/4 v4, 0x0

    goto/16 :goto_24

    :cond_56
    const/4 v12, 0x1

    invoke-virtual {v9}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v15

    invoke-virtual {v9}, Ljava/lang/Class;->isPrimitive()Z

    move-result v17

    if-nez v17, :cond_59

    const-string v12, "java."

    invoke-virtual {v15, v12}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v12

    if-eqz v12, :cond_57

    goto :goto_18

    :cond_57
    const/4 v4, 0x0

    :cond_58
    move-object/from16 v5, v23

    goto/16 :goto_1c

    :cond_59
    :goto_18
    sget-object v12, Llyiahf/vczjk/t56;->OooO00o:Ljava/util/HashSet;

    invoke-virtual {v9}, Ljava/lang/Class;->isPrimitive()Z

    move-result v12

    if-eqz v12, :cond_62

    if-ne v9, v8, :cond_5a

    sget-object v6, Llyiahf/vczjk/o56;->OooOOOO:Llyiahf/vczjk/o56;

    goto/16 :goto_19

    :cond_5a
    if-ne v9, v14, :cond_5b

    sget-object v6, Llyiahf/vczjk/j56;->OooOOOO:Llyiahf/vczjk/j56;

    goto/16 :goto_19

    :cond_5b
    if-ne v9, v7, :cond_5c

    sget-object v6, Llyiahf/vczjk/p56;->OooOOOO:Llyiahf/vczjk/p56;

    goto/16 :goto_19

    :cond_5c
    if-ne v9, v11, :cond_5d

    sget-object v6, Llyiahf/vczjk/m56;->OooOOOO:Llyiahf/vczjk/m56;

    goto/16 :goto_19

    :cond_5d
    if-ne v9, v13, :cond_5e

    sget-object v6, Llyiahf/vczjk/l56;->OooOOOO:Llyiahf/vczjk/l56;

    goto/16 :goto_19

    :cond_5e
    if-ne v9, v6, :cond_5f

    sget-object v6, Llyiahf/vczjk/k56;->OooOOOO:Llyiahf/vczjk/k56;

    goto/16 :goto_19

    :cond_5f
    if-ne v9, v5, :cond_60

    sget-object v6, Llyiahf/vczjk/s56;->OooOOOO:Llyiahf/vczjk/s56;

    goto/16 :goto_19

    :cond_60
    if-ne v9, v4, :cond_61

    sget-object v6, Llyiahf/vczjk/n56;->OooOOOO:Llyiahf/vczjk/n56;

    goto/16 :goto_19

    :cond_61
    sget-object v4, Ljava/lang/Void;->TYPE:Ljava/lang/Class;

    if-ne v9, v4, :cond_6d

    sget-object v6, Llyiahf/vczjk/c56;->OooOOOO:Llyiahf/vczjk/c56;

    goto/16 :goto_19

    :cond_62
    sget-object v4, Llyiahf/vczjk/t56;->OooO00o:Ljava/util/HashSet;

    invoke-virtual {v4, v15}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_6e

    const-class v4, Ljava/lang/Integer;

    if-ne v9, v4, :cond_63

    sget-object v6, Llyiahf/vczjk/o56;->OooOOOo:Llyiahf/vczjk/o56;

    goto :goto_19

    :cond_63
    const-class v4, Ljava/lang/Boolean;

    if-ne v9, v4, :cond_64

    sget-object v6, Llyiahf/vczjk/j56;->OooOOOo:Llyiahf/vczjk/j56;

    goto :goto_19

    :cond_64
    const-class v4, Ljava/lang/Long;

    if-ne v9, v4, :cond_65

    sget-object v6, Llyiahf/vczjk/p56;->OooOOOo:Llyiahf/vczjk/p56;

    goto :goto_19

    :cond_65
    const-class v4, Ljava/lang/Double;

    if-ne v9, v4, :cond_66

    sget-object v6, Llyiahf/vczjk/m56;->OooOOOo:Llyiahf/vczjk/m56;

    goto :goto_19

    :cond_66
    const-class v4, Ljava/lang/Character;

    if-ne v9, v4, :cond_67

    sget-object v6, Llyiahf/vczjk/l56;->OooOOOo:Llyiahf/vczjk/l56;

    goto :goto_19

    :cond_67
    const-class v4, Ljava/lang/Byte;

    if-ne v9, v4, :cond_68

    sget-object v6, Llyiahf/vczjk/k56;->OooOOOo:Llyiahf/vczjk/k56;

    goto :goto_19

    :cond_68
    const-class v4, Ljava/lang/Short;

    if-ne v9, v4, :cond_69

    sget-object v6, Llyiahf/vczjk/s56;->OooOOOo:Llyiahf/vczjk/s56;

    goto :goto_19

    :cond_69
    const-class v4, Ljava/lang/Float;

    if-ne v9, v4, :cond_6a

    sget-object v6, Llyiahf/vczjk/n56;->OooOOOo:Llyiahf/vczjk/n56;

    goto :goto_19

    :cond_6a
    const-class v4, Ljava/lang/Number;

    if-ne v9, v4, :cond_6b

    sget-object v6, Llyiahf/vczjk/q56;->OooOOOO:Llyiahf/vczjk/q56;

    goto :goto_19

    :cond_6b
    const-class v4, Ljava/math/BigDecimal;

    if-ne v9, v4, :cond_6c

    sget-object v6, Llyiahf/vczjk/h56;->OooOOOO:Llyiahf/vczjk/h56;

    goto :goto_19

    :cond_6c
    const-class v4, Ljava/math/BigInteger;

    if-ne v9, v4, :cond_6d

    sget-object v6, Llyiahf/vczjk/i56;->OooOOOO:Llyiahf/vczjk/i56;

    goto :goto_19

    :cond_6d
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {v9}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    const-string v2, "Internal error: can\'t find deserializer for "

    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_6e
    const/4 v6, 0x0

    :goto_19
    if-nez v6, :cond_74

    sget-object v4, Llyiahf/vczjk/uz1;->OooO00o:Ljava/util/HashSet;

    invoke-virtual {v4, v15}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_73

    const-class v4, Ljava/util/Calendar;

    if-ne v9, v4, :cond_6f

    new-instance v6, Llyiahf/vczjk/pz1;

    invoke-direct {v6}, Llyiahf/vczjk/pz1;-><init>()V

    goto :goto_1a

    :cond_6f
    const-class v4, Ljava/util/Date;

    if-ne v9, v4, :cond_70

    sget-object v6, Llyiahf/vczjk/rz1;->OooOOOO:Llyiahf/vczjk/rz1;

    goto :goto_1a

    :cond_70
    move-object/from16 v4, v25

    if-ne v9, v4, :cond_71

    new-instance v6, Llyiahf/vczjk/sz1;

    invoke-direct {v6, v4}, Llyiahf/vczjk/qz1;-><init>(Ljava/lang/Class;)V

    goto :goto_1a

    :cond_71
    move-object/from16 v4, v18

    if-ne v9, v4, :cond_72

    new-instance v6, Llyiahf/vczjk/tz1;

    invoke-direct {v6, v4}, Llyiahf/vczjk/qz1;-><init>(Ljava/lang/Class;)V

    goto :goto_1a

    :cond_72
    const-class v4, Ljava/util/GregorianCalendar;

    if-ne v9, v4, :cond_73

    new-instance v6, Llyiahf/vczjk/pz1;

    const/4 v4, 0x0

    invoke-direct {v6, v4}, Llyiahf/vczjk/pz1;-><init>(I)V

    goto :goto_1b

    :cond_73
    const/4 v4, 0x0

    const/4 v6, 0x0

    goto :goto_1b

    :cond_74
    :goto_1a
    const/4 v4, 0x0

    :goto_1b
    if-eqz v6, :cond_58

    goto/16 :goto_24

    :goto_1c
    if-ne v9, v5, :cond_75

    new-instance v6, Llyiahf/vczjk/ut9;

    invoke-direct {v6, v5}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    goto/16 :goto_24

    :cond_75
    sget-object v5, Llyiahf/vczjk/ff6;->OooOOOO:Llyiahf/vczjk/ff6;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/ff6;->OooOOO0:Ljava/lang/Class;

    if-eqz v6, :cond_76

    invoke-virtual {v6, v5}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v6

    if-eqz v6, :cond_76

    const-string v5, "com.fasterxml.jackson.databind.ext.DOMDeserializer$NodeDeserializer"

    invoke-static {v5}, Llyiahf/vczjk/ff6;->OooO00o(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v5

    move-object v6, v5

    check-cast v6, Llyiahf/vczjk/e94;

    goto :goto_1e

    :cond_76
    sget-object v6, Llyiahf/vczjk/ff6;->OooOOO:Ljava/lang/Class;

    if-eqz v6, :cond_77

    invoke-virtual {v6, v5}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v6

    if-eqz v6, :cond_77

    const-string v5, "com.fasterxml.jackson.databind.ext.DOMDeserializer$DocumentDeserializer"

    invoke-static {v5}, Llyiahf/vczjk/ff6;->OooO00o(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v5

    move-object v6, v5

    check-cast v6, Llyiahf/vczjk/e94;

    goto :goto_1e

    :cond_77
    invoke-virtual {v5}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v6

    const-string v7, "javax.xml."

    invoke-virtual {v6, v7}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v6

    if-nez v6, :cond_7a

    :cond_78
    invoke-virtual {v5}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    move-result-object v5

    if-eqz v5, :cond_7b

    if-ne v5, v10, :cond_79

    goto :goto_1d

    :cond_79
    invoke-virtual {v5}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v6, v7}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v6

    if-eqz v6, :cond_78

    :cond_7a
    const-string v5, "com.fasterxml.jackson.databind.ext.CoreXMLDeserializers"

    invoke-static {v5}, Llyiahf/vczjk/ff6;->OooO00o(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v5

    if-nez v5, :cond_83

    :cond_7b
    :goto_1d
    const/4 v6, 0x0

    :goto_1e
    if-eqz v6, :cond_7c

    goto/16 :goto_24

    :cond_7c
    sget-object v5, Llyiahf/vczjk/t74;->OooO00o:Ljava/util/HashSet;

    invoke-virtual {v5, v15}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_82

    invoke-static {v9}, Llyiahf/vczjk/je3;->OoooOoO(Ljava/lang/Class;)Llyiahf/vczjk/ie3;

    move-result-object v6

    if-eqz v6, :cond_7d

    goto/16 :goto_24

    :cond_7d
    move-object/from16 v5, v22

    if-ne v9, v5, :cond_7e

    new-instance v6, Llyiahf/vczjk/f7a;

    invoke-direct {v6, v5}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    goto/16 :goto_24

    :cond_7e
    move-object/from16 v5, v21

    if-ne v9, v5, :cond_7f

    new-instance v6, Llyiahf/vczjk/j09;

    invoke-direct {v6, v5}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    goto :goto_24

    :cond_7f
    move-object/from16 v5, v20

    if-ne v9, v5, :cond_80

    new-instance v6, Llyiahf/vczjk/e10;

    invoke-direct {v6, v5}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    goto :goto_24

    :cond_80
    move-object/from16 v5, v19

    if-ne v9, v5, :cond_81

    new-instance v6, Llyiahf/vczjk/ul0;

    invoke-direct {v6, v5}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    goto :goto_24

    :cond_81
    const-class v5, Ljava/lang/Void;

    if-ne v9, v5, :cond_82

    sget-object v6, Llyiahf/vczjk/c56;->OooOOOO:Llyiahf/vczjk/c56;

    goto :goto_24

    :cond_82
    const/4 v6, 0x0

    goto :goto_24

    :cond_83
    new-instance v0, Ljava/lang/ClassCastException;

    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    throw v0

    :goto_1f
    sget-object v6, Llyiahf/vczjk/p69;->OooOOOO:Llyiahf/vczjk/p69;

    goto :goto_24

    :goto_20
    invoke-virtual {v1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v5

    iget-object v6, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v6}, Llyiahf/vczjk/z82;->OooO0Oo()Z

    move-result v6

    if-eqz v6, :cond_85

    const-class v6, Ljava/util/List;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/ec5;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v7

    invoke-virtual {v0, v7}, Llyiahf/vczjk/n90;->OooO0OO(Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    invoke-virtual {v7, v6}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v6

    if-eqz v6, :cond_84

    const/4 v6, 0x0

    :goto_21
    move-object/from16 v7, v24

    goto :goto_22

    :cond_84
    move-object v6, v7

    goto :goto_21

    :goto_22
    invoke-virtual {v5, v7}, Llyiahf/vczjk/ec5;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v5

    invoke-virtual {v0, v5}, Llyiahf/vczjk/n90;->OooO0OO(Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    invoke-virtual {v5, v7}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v7

    if-eqz v7, :cond_86

    const/4 v5, 0x0

    goto :goto_23

    :cond_85
    const/4 v5, 0x0

    const/4 v6, 0x0

    :cond_86
    :goto_23
    new-instance v7, Llyiahf/vczjk/faa;

    invoke-direct {v7, v6, v5}, Llyiahf/vczjk/faa;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;)V

    move-object v6, v7

    :goto_24
    if-eqz v6, :cond_88

    iget-object v5, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v5}, Llyiahf/vczjk/z82;->OooO0o0()Z

    move-result v5

    if-eqz v5, :cond_88

    iget-object v5, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v5}, Llyiahf/vczjk/z82;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v5

    invoke-virtual {v5}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v7

    if-nez v7, :cond_87

    goto :goto_25

    :cond_87
    invoke-static {v5}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_88
    :goto_25
    if-eqz v6, :cond_89

    return-object v6

    :cond_89
    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/vy0;->OooO0OO(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v6

    const-string v7, ") as a Bean"

    const-string v8, " (of type "

    const-string v9, "Cannot deserialize Class "

    if-nez v6, :cond_97

    invoke-virtual {v5}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v6

    const-string v11, "net.sf.cglib.proxy."

    invoke-virtual {v6, v11}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v11

    if-nez v11, :cond_96

    const-string v11, "org.hibernate.proxy."

    invoke-virtual {v6, v11}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v6

    if-nez v6, :cond_96

    :try_start_0
    invoke-virtual {v5}, Ljava/lang/Class;->getModifiers()I

    move-result v6

    invoke-static {v6}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result v6

    if-nez v6, :cond_8b

    invoke-static {v5}, Llyiahf/vczjk/vy0;->OooOo00(Ljava/lang/Class;)Z

    move-result v6

    if-nez v6, :cond_8a

    invoke-virtual {v5}, Ljava/lang/Class;->getEnclosingMethod()Ljava/lang/reflect/Method;

    move-result-object v6

    if-eqz v6, :cond_8a

    const/4 v12, 0x1

    goto :goto_26

    :cond_8a
    move v12, v4

    :goto_26
    if-eqz v12, :cond_8b

    const-string v6, "local/anonymous"
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_27

    :catch_0
    :cond_8b
    const/4 v6, 0x0

    :goto_27
    if-nez v6, :cond_95

    sget-object v4, Llyiahf/vczjk/v79;->OooO0O0:Llyiahf/vczjk/v79;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v6

    iget-object v4, v4, Llyiahf/vczjk/v79;->OooO00o:Ljava/util/Set;

    invoke-interface {v4, v6}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_94

    invoke-virtual {v5}, Ljava/lang/Class;->isInterface()Z

    move-result v4

    if-eqz v4, :cond_8c

    goto :goto_29

    :cond_8c
    const-string v4, "org.springframework."

    invoke-virtual {v6, v4}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v4

    if-eqz v4, :cond_8d

    :goto_28
    if-eqz v5, :cond_8e

    if-eq v5, v10, :cond_8e

    invoke-virtual {v5}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v4

    const-string v7, "AbstractPointcutAdvisor"

    invoke-virtual {v7, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_94

    const-string v7, "AbstractApplicationContext"

    invoke-virtual {v7, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_94

    invoke-virtual {v5}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    move-result-object v5

    goto :goto_28

    :cond_8d
    const-string v4, "com.mchange.v2.c3p0."

    invoke-virtual {v6, v4}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v4

    if-eqz v4, :cond_8e

    const-string v4, "DataSource"

    invoke-virtual {v6, v4}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    move-result v4

    if-nez v4, :cond_94

    :cond_8e
    :goto_29
    :try_start_1
    invoke-virtual {v0, v3, v1}, Llyiahf/vczjk/n90;->OooOOOO(Llyiahf/vczjk/h90;Llyiahf/vczjk/v72;)Llyiahf/vczjk/nca;

    move-result-object v4
    :try_end_1
    .catch Ljava/lang/NoClassDefFoundError; {:try_start_1 .. :try_end_1} :catch_2
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_1

    new-instance v5, Llyiahf/vczjk/za0;

    invoke-direct {v5, v3, v1}, Llyiahf/vczjk/za0;-><init>(Llyiahf/vczjk/h90;Llyiahf/vczjk/v72;)V

    iput-object v4, v5, Llyiahf/vczjk/za0;->OooO:Ljava/lang/Object;

    invoke-virtual {v0, v1, v3, v5}, Llyiahf/vczjk/ab0;->OooOOo(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/za0;)V

    invoke-static {v1, v3, v5}, Llyiahf/vczjk/ab0;->OooOo00(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/za0;)V

    invoke-virtual {v0, v1, v3, v5}, Llyiahf/vczjk/ab0;->OooOOo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/h90;Llyiahf/vczjk/za0;)V

    invoke-static {v3, v5}, Llyiahf/vczjk/ab0;->OooOOoo(Llyiahf/vczjk/h90;Llyiahf/vczjk/za0;)V

    iget-object v1, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v1}, Llyiahf/vczjk/z82;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_90

    iget-object v1, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v1}, Llyiahf/vczjk/z82;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v3

    if-nez v3, :cond_8f

    goto :goto_2a

    :cond_8f
    invoke-static {v1}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_90
    :goto_2a
    invoke-virtual {v2}, Llyiahf/vczjk/x64;->Ooooo0o()Z

    move-result v1

    if-eqz v1, :cond_91

    invoke-virtual {v4}, Llyiahf/vczjk/nca;->OooOO0O()Z

    move-result v1

    if-nez v1, :cond_91

    new-instance v1, Llyiahf/vczjk/o000Oo0;

    iget-object v2, v5, Llyiahf/vczjk/za0;->OooO0oO:Ljava/lang/Object;

    check-cast v2, Ljava/util/HashMap;

    iget-object v3, v5, Llyiahf/vczjk/za0;->OooO0o0:Ljava/lang/Object;

    check-cast v3, Ljava/util/LinkedHashMap;

    iget-object v4, v5, Llyiahf/vczjk/za0;->OooO0Oo:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/h90;

    invoke-direct {v1, v5, v4, v2, v3}, Llyiahf/vczjk/o000Oo0;-><init>(Llyiahf/vczjk/za0;Llyiahf/vczjk/h90;Ljava/util/HashMap;Ljava/util/LinkedHashMap;)V

    goto :goto_2b

    :cond_91
    invoke-virtual {v5}, Llyiahf/vczjk/za0;->OooO0o0()Llyiahf/vczjk/xa0;

    move-result-object v1

    :goto_2b
    iget-object v2, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v2}, Llyiahf/vczjk/z82;->OooO0o0()Z

    move-result v2

    if-eqz v2, :cond_93

    iget-object v0, v0, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v0}, Llyiahf/vczjk/z82;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v2

    if-nez v2, :cond_92

    goto :goto_2c

    :cond_92
    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :catch_1
    move-exception v0

    iget-object v1, v1, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v0

    new-instance v2, Llyiahf/vczjk/d44;

    invoke-direct {v2, v1, v0, v3}, Llyiahf/vczjk/d44;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/h90;)V

    throw v2

    :catch_2
    move-exception v0

    new-instance v1, Llyiahf/vczjk/qq2;

    invoke-direct {v1, v0}, Llyiahf/vczjk/qq2;-><init>(Ljava/lang/NoClassDefFoundError;)V

    :cond_93
    :goto_2c
    return-object v1

    :cond_94
    const-string v0, "Illegal type (%s) to deserialize: prevented for security reasons"

    filled-new-array {v6}, [Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v1, v3, v0, v2}, Llyiahf/vczjk/v72;->o000OO(Llyiahf/vczjk/h90;Ljava/lang/String;[Ljava/lang/Object;)V

    const/16 v16, 0x0

    throw v16

    :cond_95
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_96
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Cannot deserialize Proxy class "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    const-string v2, " as a Bean"

    invoke-static {v5, v1, v2}, Llyiahf/vczjk/ii5;->OooO0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_97
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_98
    invoke-static {v9}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0
.end method

.method public static OooO0Oo(Llyiahf/vczjk/x64;)Z
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/x64;->OooooOo()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooOOO()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/x64;->ooOO()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/x64;->OoooO0O()Llyiahf/vczjk/x64;

    move-result-object p0

    invoke-virtual {p0}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object p0

    if-eqz p0, :cond_2

    :cond_1
    :goto_0
    const/4 p0, 0x1

    return p0

    :cond_2
    const/4 p0, 0x0

    return p0
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/y82;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;
    .locals 2

    :try_start_0
    invoke-static {p1, p2, p3}, Llyiahf/vczjk/x82;->OooO0O0(Llyiahf/vczjk/v72;Llyiahf/vczjk/y82;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object p2
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    if-nez p2, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-static {p3}, Llyiahf/vczjk/x82;->OooO0Oo(Llyiahf/vczjk/x64;)Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/e94;->OooOOO()Z

    move-result v0

    if-eqz v0, :cond_1

    const/4 v0, 0x1

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    :goto_0
    instance-of v1, p2, Llyiahf/vczjk/nr7;

    if-eqz v1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/x82;->_incompleteDeserializers:Ljava/util/HashMap;

    invoke-virtual {v1, p3, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-object v1, p2

    check-cast v1, Llyiahf/vczjk/nr7;

    invoke-interface {v1, p1}, Llyiahf/vczjk/nr7;->OooO00o(Llyiahf/vczjk/v72;)V

    iget-object p1, p0, Llyiahf/vczjk/x82;->_incompleteDeserializers:Ljava/util/HashMap;

    invoke-virtual {p1, p3}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_2
    if-eqz v0, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/x82;->_cachedDeserializers:Llyiahf/vczjk/kl4;

    invoke-virtual {p1, p3, p2}, Llyiahf/vczjk/kl4;->OooO00o(Ljava/io/Serializable;Ljava/lang/Object;)V

    :cond_3
    return-object p2

    :catch_0
    move-exception p2

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object p3

    new-instance v0, Llyiahf/vczjk/na4;

    iget-object p1, p1, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {v0, p1, p3, p2}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0
.end method

.method public final OooO0o0(Llyiahf/vczjk/v72;Llyiahf/vczjk/y82;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;
    .locals 4

    if-eqz p3, :cond_9

    invoke-static {p3}, Llyiahf/vczjk/x82;->OooO0Oo(Llyiahf/vczjk/x64;)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    move-object v0, v1

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/x82;->_cachedDeserializers:Llyiahf/vczjk/kl4;

    iget-object v0, v0, Llyiahf/vczjk/kl4;->OooOOO:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v0, p3}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/e94;

    :goto_0
    if-nez v0, :cond_8

    iget-object v2, p0, Llyiahf/vczjk/x82;->_incompleteDeserializers:Ljava/util/HashMap;

    monitor-enter v2

    :try_start_0
    invoke-static {p3}, Llyiahf/vczjk/x82;->OooO0Oo(Llyiahf/vczjk/x64;)Z

    move-result v0

    if-eqz v0, :cond_1

    move-object v0, v1

    goto :goto_1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/x82;->_cachedDeserializers:Llyiahf/vczjk/kl4;

    iget-object v0, v0, Llyiahf/vczjk/kl4;->OooOOO:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v0, p3}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/e94;

    :goto_1
    if-eqz v0, :cond_2

    monitor-exit v2

    goto :goto_2

    :catchall_0
    move-exception p1

    goto/16 :goto_3

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/x82;->_incompleteDeserializers:Ljava/util/HashMap;

    invoke-virtual {v0}, Ljava/util/HashMap;->size()I

    move-result v0

    if-lez v0, :cond_3

    iget-object v3, p0, Llyiahf/vczjk/x82;->_incompleteDeserializers:Ljava/util/HashMap;

    invoke-virtual {v3, p3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/e94;

    if-eqz v3, :cond_3

    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    move-object v0, v3

    goto :goto_2

    :cond_3
    :try_start_1
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/x82;->OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/y82;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    if-nez v0, :cond_4

    :try_start_2
    iget-object v0, p0, Llyiahf/vczjk/x82;->_incompleteDeserializers:Ljava/util/HashMap;

    invoke-virtual {v0}, Ljava/util/HashMap;->size()I

    move-result v0

    if-lez v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/x82;->_incompleteDeserializers:Ljava/util/HashMap;

    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    :cond_4
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    move-object v0, p2

    :goto_2
    if-nez v0, :cond_6

    invoke-virtual {p3}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    invoke-virtual {p2}, Ljava/lang/Class;->getModifiers()I

    move-result p2

    and-int/lit16 p2, p2, 0x600

    if-nez p2, :cond_5

    new-instance p2, Ljava/lang/StringBuilder;

    const-string v0, "Cannot find a Value deserializer for type "

    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, p3, p2}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v1

    :cond_5
    new-instance p2, Ljava/lang/StringBuilder;

    const-string v0, "Cannot find a Value deserializer for abstract type "

    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1, p3, p2}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v1

    :cond_6
    return-object v0

    :catchall_1
    move-exception p1

    if-nez v0, :cond_7

    :try_start_3
    iget-object p2, p0, Llyiahf/vczjk/x82;->_incompleteDeserializers:Ljava/util/HashMap;

    invoke-virtual {p2}, Ljava/util/HashMap;->size()I

    move-result p2

    if-lez p2, :cond_7

    iget-object p2, p0, Llyiahf/vczjk/x82;->_incompleteDeserializers:Ljava/util/HashMap;

    invoke-virtual {p2}, Ljava/util/HashMap;->clear()V

    :cond_7
    throw p1

    :goto_3
    monitor-exit v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    throw p1

    :cond_8
    return-object v0

    :cond_9
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "Null JavaType passed"

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public writeReplace()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x82;->_incompleteDeserializers:Ljava/util/HashMap;

    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    return-object p0
.end method
