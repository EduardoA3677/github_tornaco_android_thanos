.class public final Llyiahf/vczjk/kb0;
.super Llyiahf/vczjk/s90;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/kb0;

.field private static final serialVersionUID:J = 0x1L


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/kb0;

    invoke-direct {v0}, Llyiahf/vczjk/s90;-><init>()V

    sput-object v0, Llyiahf/vczjk/kb0;->OooOOOO:Llyiahf/vczjk/kb0;

    return-void
.end method


# virtual methods
.method public final OooO0oO(Llyiahf/vczjk/tg8;Llyiahf/vczjk/eb0;Llyiahf/vczjk/oO00O0o;ZLlyiahf/vczjk/pm;)Llyiahf/vczjk/gb0;
    .locals 19

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v4, p2

    move-object/from16 v0, p3

    const/4 v11, 0x0

    invoke-virtual {v4}, Llyiahf/vczjk/eb0;->getFullName()Llyiahf/vczjk/xa7;

    move-result-object v6

    invoke-virtual/range {p5 .. p5}, Llyiahf/vczjk/u34;->OooOoo()Llyiahf/vczjk/x64;

    move-result-object v7

    new-instance v5, Llyiahf/vczjk/cb0;

    invoke-virtual {v4}, Llyiahf/vczjk/eb0;->OooOOoo()Llyiahf/vczjk/xa7;

    const/4 v8, 0x0

    invoke-virtual {v4}, Llyiahf/vczjk/eb0;->OooO0O0()Llyiahf/vczjk/wa7;

    move-result-object v10

    move-object/from16 v9, p5

    invoke-direct/range {v5 .. v10}, Llyiahf/vczjk/cb0;-><init>(Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/pm;Llyiahf/vczjk/wa7;)V

    move-object v6, v5

    move-object v5, v9

    invoke-static {v2, v5}, Llyiahf/vczjk/s90;->OooO0o0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/u34;)Llyiahf/vczjk/zb4;

    move-result-object v8

    instance-of v9, v8, Llyiahf/vczjk/pr7;

    if-eqz v9, :cond_0

    move-object v9, v8

    check-cast v9, Llyiahf/vczjk/pr7;

    invoke-interface {v9, v2}, Llyiahf/vczjk/pr7;->OooO00o(Llyiahf/vczjk/tg8;)V

    :cond_0
    invoke-virtual {v2, v8, v6}, Llyiahf/vczjk/tg8;->o00000O0(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v8

    invoke-virtual {v7}, Llyiahf/vczjk/x64;->OooooOo()Z

    move-result v6

    if-nez v6, :cond_2

    invoke-virtual {v7}, Llyiahf/vczjk/ok6;->OooOoO0()Z

    move-result v6

    if-eqz v6, :cond_1

    goto :goto_0

    :cond_1
    move-object v6, v11

    goto :goto_1

    :cond_2
    :goto_0
    invoke-virtual {v2}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object v6

    invoke-virtual {v7}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v9

    invoke-virtual {v6}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v10

    invoke-virtual {v10, v6, v5, v7}, Llyiahf/vczjk/yn;->OooOooo(Llyiahf/vczjk/fc5;Llyiahf/vczjk/pm;Llyiahf/vczjk/x64;)Llyiahf/vczjk/b5a;

    move-result-object v10

    if-nez v10, :cond_3

    invoke-virtual {v1, v6, v9}, Llyiahf/vczjk/s90;->OooO0O0(Llyiahf/vczjk/gg8;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e5a;

    move-result-object v6

    goto :goto_1

    :cond_3
    invoke-virtual {v6}, Llyiahf/vczjk/fc5;->OooOooo()Llyiahf/vczjk/k99;

    move-result-object v12

    invoke-virtual {v12, v6, v5, v9}, Llyiahf/vczjk/k99;->OooO0O0(Llyiahf/vczjk/gg8;Llyiahf/vczjk/pm;Llyiahf/vczjk/x64;)Ljava/util/ArrayList;

    move-result-object v12

    check-cast v10, Llyiahf/vczjk/e59;

    invoke-virtual {v10, v6, v9, v12}, Llyiahf/vczjk/e59;->OooO0O0(Llyiahf/vczjk/gg8;Llyiahf/vczjk/x64;Ljava/util/ArrayList;)Llyiahf/vczjk/e5a;

    move-result-object v6

    :goto_1
    invoke-virtual {v2}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object v9

    invoke-virtual {v9}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v10

    invoke-virtual {v10, v9, v5, v7}, Llyiahf/vczjk/yn;->Oooo0OO(Llyiahf/vczjk/fc5;Llyiahf/vczjk/pm;Llyiahf/vczjk/x64;)Llyiahf/vczjk/b5a;

    move-result-object v10

    if-nez v10, :cond_4

    invoke-virtual {v1, v9, v7}, Llyiahf/vczjk/s90;->OooO0O0(Llyiahf/vczjk/gg8;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e5a;

    move-result-object v9

    goto :goto_2

    :cond_4
    invoke-virtual {v9}, Llyiahf/vczjk/fc5;->OooOooo()Llyiahf/vczjk/k99;

    move-result-object v12

    invoke-virtual {v12, v9, v5, v7}, Llyiahf/vczjk/k99;->OooO0O0(Llyiahf/vczjk/gg8;Llyiahf/vczjk/pm;Llyiahf/vczjk/x64;)Ljava/util/ArrayList;

    move-result-object v12

    check-cast v10, Llyiahf/vczjk/e59;

    invoke-virtual {v10, v9, v7, v12}, Llyiahf/vczjk/e59;->OooO0O0(Llyiahf/vczjk/gg8;Llyiahf/vczjk/x64;Ljava/util/ArrayList;)Llyiahf/vczjk/e5a;

    move-result-object v9

    :goto_2
    iget-object v10, v0, Llyiahf/vczjk/oO00O0o;->OooO0OO:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/h90;

    const/4 v12, 0x0

    move/from16 v13, p4

    :try_start_0
    invoke-virtual {v0, v5, v13, v7}, Llyiahf/vczjk/oO00O0o;->OooO0o(Llyiahf/vczjk/pm;ZLlyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object v13
    :try_end_0
    .catch Llyiahf/vczjk/na4; {:try_start_0 .. :try_end_0} :catch_2

    if-eqz v6, :cond_7

    if-nez v13, :cond_5

    move-object v13, v7

    :cond_5
    invoke-virtual {v13}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v14

    if-eqz v14, :cond_6

    invoke-virtual {v13, v6}, Llyiahf/vczjk/x64;->o00oO0o(Ljava/lang/Object;)Llyiahf/vczjk/x64;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-object v13, v6

    goto :goto_3

    :cond_6
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v3, "serialization type "

    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v3, " has no content"

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    new-array v3, v12, [Ljava/lang/Object;

    invoke-virtual {v2, v10, v4, v0, v3}, Llyiahf/vczjk/tg8;->o00000oO(Llyiahf/vczjk/h90;Llyiahf/vczjk/eb0;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v11

    :cond_7
    :goto_3
    if-nez v13, :cond_8

    move-object v6, v7

    goto :goto_4

    :cond_8
    move-object v6, v13

    :goto_4
    invoke-virtual {v4}, Llyiahf/vczjk/eb0;->OooOO0O()Llyiahf/vczjk/pm;

    move-result-object v14

    if-eqz v14, :cond_23

    invoke-virtual {v14}, Llyiahf/vczjk/u34;->OooOoOO()Ljava/lang/Class;

    move-result-object v14

    invoke-virtual {v6}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v15

    iget-object v12, v0, Llyiahf/vczjk/oO00O0o;->OooO0O0:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/gg8;

    invoke-virtual {v12, v15}, Llyiahf/vczjk/fc5;->OooOo(Ljava/lang/Class;)Llyiahf/vczjk/uh1;

    invoke-virtual {v12, v14}, Llyiahf/vczjk/fc5;->OooOo(Ljava/lang/Class;)Llyiahf/vczjk/uh1;

    iget-object v14, v0, Llyiahf/vczjk/oO00O0o;->OooO0o0:Ljava/lang/Object;

    check-cast v14, Llyiahf/vczjk/fa4;

    filled-new-array {v14, v11, v11}, [Llyiahf/vczjk/fa4;

    move-result-object v14

    sget-object v15, Llyiahf/vczjk/fa4;->OooOOO0:Llyiahf/vczjk/fa4;

    const/4 v15, 0x0

    const/16 v17, 0x1

    :goto_5
    const/4 v3, 0x3

    if-ge v15, v3, :cond_b

    aget-object v3, v14, v15

    if-eqz v3, :cond_a

    if-nez v11, :cond_9

    goto :goto_6

    :cond_9
    invoke-virtual {v11, v3}, Llyiahf/vczjk/fa4;->OooO0Oo(Llyiahf/vczjk/fa4;)Llyiahf/vczjk/fa4;

    move-result-object v3

    :goto_6
    move-object v11, v3

    :cond_a
    add-int/lit8 v15, v15, 0x1

    goto :goto_5

    :cond_b
    invoke-virtual {v4}, Llyiahf/vczjk/eb0;->OooO0oO()Llyiahf/vczjk/fa4;

    move-result-object v14

    invoke-virtual {v11, v14}, Llyiahf/vczjk/fa4;->OooO0Oo(Llyiahf/vczjk/fa4;)Llyiahf/vczjk/fa4;

    move-result-object v11

    invoke-virtual {v11}, Llyiahf/vczjk/fa4;->OooO0OO()Llyiahf/vczjk/ea4;

    move-result-object v14

    sget-object v15, Llyiahf/vczjk/ea4;->OooOOo0:Llyiahf/vczjk/ea4;

    if-ne v14, v15, :cond_c

    sget-object v14, Llyiahf/vczjk/ea4;->OooOOO0:Llyiahf/vczjk/ea4;

    :cond_c
    invoke-virtual {v14}, Ljava/lang/Enum;->ordinal()I

    move-result v14

    sget-object v15, Llyiahf/vczjk/ea4;->OooOOOO:Llyiahf/vczjk/ea4;

    move/from16 v3, v17

    if-eq v14, v3, :cond_1e

    const/4 v3, 0x2

    if-eq v14, v3, :cond_1c

    const/4 v3, 0x3

    if-eq v14, v3, :cond_1b

    const/4 v3, 0x4

    if-eq v14, v3, :cond_f

    const/4 v3, 0x5

    if-eq v14, v3, :cond_d

    const/4 v3, 0x0

    goto/16 :goto_13

    :cond_d
    iget-object v3, v11, Llyiahf/vczjk/fa4;->_valueFilter:Ljava/lang/Class;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/tg8;->o00000OO(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v11

    if-nez v11, :cond_e

    :goto_7
    move-object v12, v11

    :goto_8
    const/4 v11, 0x1

    goto/16 :goto_14

    :cond_e
    invoke-virtual {v2, v11}, Llyiahf/vczjk/tg8;->o00000Oo(Ljava/lang/Object;)Z

    move-result v3

    move-object v12, v11

    move v11, v3

    goto/16 :goto_14

    :cond_f
    iget-boolean v3, v0, Llyiahf/vczjk/oO00O0o;->OooO00o:Z

    if-eqz v3, :cond_18

    iget-object v3, v0, Llyiahf/vczjk/oO00O0o;->OooO0o:Ljava/lang/Object;

    if-nez v3, :cond_14

    invoke-virtual {v12}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v3

    iget-object v11, v10, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {v11}, Llyiahf/vczjk/hm;->oo000o()Llyiahf/vczjk/uqa;

    move-result-object v14

    iget-object v14, v14, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v14, Llyiahf/vczjk/jm;

    if-nez v14, :cond_10

    const/4 v14, 0x0

    goto :goto_9

    :cond_10
    if-eqz v3, :cond_11

    iget-object v3, v10, Llyiahf/vczjk/h90;->OooO0OO:Llyiahf/vczjk/ec5;

    sget-object v15, Llyiahf/vczjk/gc5;->OooOoO:Llyiahf/vczjk/gc5;

    invoke-virtual {v3, v15}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v3

    invoke-virtual {v14, v3}, Llyiahf/vczjk/pm;->oo000o(Z)V

    :cond_11
    :try_start_1
    iget-object v3, v14, Llyiahf/vczjk/jm;->_constructor:Ljava/lang/reflect/Constructor;

    const/4 v14, 0x0

    invoke-virtual {v3, v14}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    move-object v14, v3

    :goto_9
    if-nez v14, :cond_12

    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    goto :goto_a

    :cond_12
    move-object v3, v14

    :goto_a
    iput-object v3, v0, Llyiahf/vczjk/oO00O0o;->OooO0o:Ljava/lang/Object;

    goto :goto_c

    :catch_0
    move-exception v0

    :goto_b
    invoke-virtual {v0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object v2

    if-eqz v2, :cond_13

    invoke-virtual {v0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object v0

    goto :goto_b

    :cond_13
    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooOo(Ljava/lang/Throwable;)V

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    new-instance v2, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Failed to instantiate bean of type "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v4, v11, Llyiahf/vczjk/hm;->OooOo0O:Ljava/lang/Class;

    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v4, ": ("

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v4, ") "

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v2, v3, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v2

    :cond_14
    :goto_c
    sget-object v11, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    if-ne v3, v11, :cond_15

    const/4 v11, 0x0

    goto :goto_d

    :cond_15
    iget-object v11, v0, Llyiahf/vczjk/oO00O0o;->OooO0o:Ljava/lang/Object;

    :goto_d
    if-eqz v11, :cond_18

    sget-object v3, Llyiahf/vczjk/gc5;->OooOoO0:Llyiahf/vczjk/gc5;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/tg8;->o00000o0(Llyiahf/vczjk/gc5;)Z

    move-result v3

    if-eqz v3, :cond_16

    sget-object v3, Llyiahf/vczjk/gc5;->OooOoO:Llyiahf/vczjk/gc5;

    invoke-virtual {v12, v3}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v3

    invoke-virtual {v5, v3}, Llyiahf/vczjk/pm;->oo000o(Z)V

    :cond_16
    :try_start_2
    invoke-virtual {v5, v11}, Llyiahf/vczjk/pm;->o0ooOOo(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    const/4 v12, 0x0

    :goto_e
    move-object v11, v3

    goto :goto_10

    :catch_1
    move-exception v0

    invoke-interface {v4}, Llyiahf/vczjk/yt5;->getName()Ljava/lang/String;

    move-result-object v2

    :goto_f
    invoke-virtual {v0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object v3

    if-eqz v3, :cond_17

    invoke-virtual {v0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object v0

    goto :goto_f

    :cond_17
    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooOo(Ljava/lang/Throwable;)V

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v3, "Failed to get property \'"

    const-string v4, "\' of default "

    invoke-static {v3, v2, v4}, Llyiahf/vczjk/ix8;->OooOOO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, " instance"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v0, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_18
    invoke-static {v6}, Llyiahf/vczjk/rs;->Oooo000(Llyiahf/vczjk/x64;)Ljava/lang/Object;

    move-result-object v3

    const/4 v12, 0x1

    goto :goto_e

    :goto_10
    if-nez v11, :cond_19

    goto/16 :goto_7

    :cond_19
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Class;->isArray()Z

    move-result v3

    if-eqz v3, :cond_1a

    invoke-static {v11}, Llyiahf/vczjk/ex9;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/yw;

    move-result-object v11

    :cond_1a
    move/from16 v18, v12

    move-object v12, v11

    move/from16 v11, v18

    goto :goto_14

    :cond_1b
    :goto_11
    move-object v12, v15

    goto/16 :goto_8

    :cond_1c
    invoke-virtual {v6}, Llyiahf/vczjk/ok6;->OooOoO0()Z

    move-result v3

    if-eqz v3, :cond_1d

    goto :goto_11

    :cond_1d
    const/4 v11, 0x1

    :goto_12
    const/4 v12, 0x0

    goto :goto_14

    :cond_1e
    const/4 v3, 0x1

    :goto_13
    invoke-virtual {v6}, Llyiahf/vczjk/x64;->OooooOo()Z

    move-result v6

    if-eqz v6, :cond_1f

    sget-object v6, Llyiahf/vczjk/ig8;->OooOoo:Llyiahf/vczjk/ig8;

    invoke-virtual {v12, v6}, Llyiahf/vczjk/gg8;->Oooo0(Llyiahf/vczjk/ig8;)Z

    move-result v6

    if-nez v6, :cond_1f

    move v11, v3

    move-object v12, v15

    goto :goto_14

    :cond_1f
    move v11, v3

    goto :goto_12

    :goto_14
    invoke-virtual {v4}, Llyiahf/vczjk/eb0;->OooOO0()[Ljava/lang/Class;

    move-result-object v3

    if-nez v3, :cond_20

    invoke-virtual {v10}, Llyiahf/vczjk/h90;->OooO0OO()[Ljava/lang/Class;

    move-result-object v3

    :cond_20
    new-instance v6, Llyiahf/vczjk/gb0;

    iget-object v10, v10, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    iget-object v10, v10, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    move-object/from16 v18, v13

    move-object v13, v3

    move-object v3, v6

    move-object v6, v10

    move-object/from16 v10, v18

    invoke-direct/range {v3 .. v13}, Llyiahf/vczjk/gb0;-><init>(Llyiahf/vczjk/eb0;Llyiahf/vczjk/pm;Llyiahf/vczjk/lo;Llyiahf/vczjk/x64;Llyiahf/vczjk/zb4;Llyiahf/vczjk/e5a;Llyiahf/vczjk/x64;ZLjava/lang/Object;[Ljava/lang/Class;)V

    iget-object v0, v0, Llyiahf/vczjk/oO00O0o;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yn;

    invoke-virtual {v0, v5}, Llyiahf/vczjk/yn;->OooOo(Llyiahf/vczjk/pm;)Ljava/lang/Object;

    move-result-object v4

    if-eqz v4, :cond_21

    invoke-virtual {v2, v5, v4}, Llyiahf/vczjk/tg8;->o0000(Llyiahf/vczjk/u34;Ljava/lang/Object;)Llyiahf/vczjk/zb4;

    move-result-object v2

    invoke-virtual {v3, v2}, Llyiahf/vczjk/gb0;->OooO0oo(Llyiahf/vczjk/zb4;)V

    :cond_21
    invoke-virtual {v0, v5}, Llyiahf/vczjk/yn;->OoooOOo(Llyiahf/vczjk/pm;)Llyiahf/vczjk/wt5;

    move-result-object v0

    if-eqz v0, :cond_22

    new-instance v2, Llyiahf/vczjk/jaa;

    invoke-direct {v2, v3, v0}, Llyiahf/vczjk/jaa;-><init>(Llyiahf/vczjk/gb0;Llyiahf/vczjk/wt5;)V

    return-object v2

    :cond_22
    return-object v3

    :cond_23
    const-string v0, "could not determine property type"

    const/4 v3, 0x0

    new-array v3, v3, [Ljava/lang/Object;

    invoke-virtual {v2, v10, v4, v0, v3}, Llyiahf/vczjk/tg8;->o00000oO(Llyiahf/vczjk/h90;Llyiahf/vczjk/eb0;Ljava/lang/String;[Ljava/lang/Object;)V

    const/16 v16, 0x0

    throw v16

    :catch_2
    move-exception v0

    move-object/from16 v16, v11

    move v3, v12

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v0

    new-array v3, v3, [Ljava/lang/Object;

    invoke-virtual {v2, v10, v4, v0, v3}, Llyiahf/vczjk/tg8;->o00000oO(Llyiahf/vczjk/h90;Llyiahf/vczjk/eb0;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v16
.end method

.method public final OooO0oo(Llyiahf/vczjk/tg8;Llyiahf/vczjk/x64;Llyiahf/vczjk/h90;Z)Llyiahf/vczjk/zb4;
    .locals 38

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v0, p2

    move-object/from16 v7, p3

    invoke-virtual {v2}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object v3

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OooooOo()Z

    move-result v4

    sget-object v5, Llyiahf/vczjk/p94;->OooOOo0:Llyiahf/vczjk/p94;

    sget-object v6, Llyiahf/vczjk/ea4;->OooOOO0:Llyiahf/vczjk/ea4;

    sget-object v8, Llyiahf/vczjk/ea4;->OooOOo0:Llyiahf/vczjk/ea4;

    iget-object v9, v7, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    const-class v10, Ljava/util/Map;

    const/4 v13, 0x3

    const/4 v14, 0x2

    if-eqz v4, :cond_32

    if-nez p4, :cond_0

    invoke-static {v3, v7}, Llyiahf/vczjk/s90;->OooO0o(Llyiahf/vczjk/gg8;Llyiahf/vczjk/h90;)Z

    move-result v3

    goto :goto_0

    :cond_0
    move/from16 v3, p4

    :goto_0
    invoke-virtual {v2}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object v4

    if-nez v3, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->o00ooo()Z

    move-result v18

    if-eqz v18, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OooooOo()Z

    move-result v18

    if-eqz v18, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v18

    invoke-virtual/range {v18 .. v18}, Llyiahf/vczjk/x64;->o0OoOo0()Z

    move-result v18

    if-nez v18, :cond_2

    :cond_1
    const/16 v18, 0x1

    goto :goto_1

    :cond_2
    move/from16 v18, v3

    :goto_1
    invoke-virtual {v0}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v15

    invoke-virtual {v1, v4, v15}, Llyiahf/vczjk/s90;->OooO0O0(Llyiahf/vczjk/gg8;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e5a;

    move-result-object v23

    if-eqz v23, :cond_3

    const/16 v22, 0x0

    goto :goto_2

    :cond_3
    move/from16 v22, v18

    :goto_2
    invoke-virtual {v2}, Llyiahf/vczjk/tg8;->o0O0O00()Llyiahf/vczjk/yn;

    move-result-object v4

    invoke-virtual {v4, v9}, Llyiahf/vczjk/yn;->OooO0Oo(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v4

    if-eqz v4, :cond_4

    invoke-virtual {v2, v9, v4}, Llyiahf/vczjk/tg8;->o0000(Llyiahf/vczjk/u34;Ljava/lang/Object;)Llyiahf/vczjk/zb4;

    move-result-object v4

    move-object/from16 v25, v4

    goto :goto_3

    :cond_4
    const/16 v25, 0x0

    :goto_3
    invoke-virtual {v0}, Llyiahf/vczjk/x64;->ooOO()Z

    move-result v4

    if-eqz v4, :cond_1a

    move-object v4, v0

    check-cast v4, Llyiahf/vczjk/ub5;

    invoke-virtual {v2}, Llyiahf/vczjk/tg8;->o0O0O00()Llyiahf/vczjk/yn;

    move-result-object v15

    invoke-virtual {v15, v9}, Llyiahf/vczjk/yn;->OooOOoo(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v15

    if-eqz v15, :cond_5

    invoke-virtual {v2, v9, v15}, Llyiahf/vczjk/tg8;->o0000(Llyiahf/vczjk/u34;Ljava/lang/Object;)Llyiahf/vczjk/zb4;

    move-result-object v15

    move-object/from16 v24, v15

    goto :goto_4

    :cond_5
    const/16 v24, 0x0

    :goto_4
    instance-of v15, v4, Llyiahf/vczjk/wb5;

    if-eqz v15, :cond_17

    check-cast v4, Llyiahf/vczjk/wb5;

    invoke-virtual {v7}, Llyiahf/vczjk/h90;->OooO0Oo()Llyiahf/vczjk/q94;

    move-result-object v15

    if-eqz v15, :cond_6

    invoke-virtual {v15}, Llyiahf/vczjk/q94;->OooO0o()Llyiahf/vczjk/p94;

    move-result-object v15

    if-ne v15, v5, :cond_6

    :goto_5
    const/4 v11, 0x0

    goto/16 :goto_d

    :cond_6
    invoke-virtual {v2}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object v15

    iget-object v11, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v11}, Llyiahf/vczjk/sg8;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v11

    invoke-virtual {v11}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v20

    if-nez v20, :cond_16

    invoke-static {v2, v4, v7}, Llyiahf/vczjk/s90;->OooO0Oo(Llyiahf/vczjk/tg8;Llyiahf/vczjk/x64;Llyiahf/vczjk/h90;)Llyiahf/vczjk/b59;

    move-result-object v11

    if-nez v11, :cond_13

    invoke-virtual {v15}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v11

    invoke-virtual {v11, v9}, Llyiahf/vczjk/yn;->OooOOO0(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v26

    invoke-virtual {v15, v10, v9}, Llyiahf/vczjk/fc5;->OooOoO0(Ljava/lang/Class;Llyiahf/vczjk/hm;)Llyiahf/vczjk/ba4;

    move-result-object v11

    if-nez v11, :cond_7

    const/16 v20, 0x0

    :goto_6
    move-object/from16 v21, v4

    goto :goto_7

    :cond_7
    invoke-virtual {v11}, Llyiahf/vczjk/ba4;->OooO0OO()Ljava/util/Set;

    move-result-object v11

    move-object/from16 v20, v11

    goto :goto_6

    :goto_7
    invoke-static/range {v20 .. v26}, Llyiahf/vczjk/vb5;->OooOOOo(Ljava/util/Set;Llyiahf/vczjk/x64;ZLlyiahf/vczjk/e5a;Llyiahf/vczjk/zb4;Llyiahf/vczjk/zb4;Ljava/lang/Object;)Llyiahf/vczjk/vb5;

    move-result-object v4

    iget-object v11, v4, Llyiahf/vczjk/vb5;->_valueType:Llyiahf/vczjk/x64;

    invoke-static {v2, v7, v11, v10}, Llyiahf/vczjk/s90;->OooO0OO(Llyiahf/vczjk/tg8;Llyiahf/vczjk/h90;Llyiahf/vczjk/x64;Ljava/lang/Class;)Llyiahf/vczjk/fa4;

    move-result-object v15

    if-nez v15, :cond_8

    move-object v12, v8

    goto :goto_8

    :cond_8
    invoke-virtual {v15}, Llyiahf/vczjk/fa4;->OooO0O0()Llyiahf/vczjk/ea4;

    move-result-object v20

    move-object/from16 v12, v20

    :goto_8
    if-eq v12, v8, :cond_11

    if-ne v12, v6, :cond_9

    goto :goto_b

    :cond_9
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    move-result v12

    if-eq v12, v14, :cond_10

    if-eq v12, v13, :cond_f

    const/4 v13, 0x4

    if-eq v12, v13, :cond_e

    const/4 v13, 0x5

    if-eq v12, v13, :cond_c

    :cond_a
    const/4 v11, 0x0

    :cond_b
    :goto_9
    const/4 v12, 0x1

    goto :goto_a

    :cond_c
    invoke-virtual {v15}, Llyiahf/vczjk/fa4;->OooO00o()Ljava/lang/Class;

    move-result-object v11

    invoke-virtual {v2, v11}, Llyiahf/vczjk/tg8;->o00000OO(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v11

    if-nez v11, :cond_d

    goto :goto_9

    :cond_d
    invoke-virtual {v2, v11}, Llyiahf/vczjk/tg8;->o00000Oo(Ljava/lang/Object;)Z

    move-result v12

    goto :goto_a

    :cond_e
    invoke-static {v11}, Llyiahf/vczjk/rs;->Oooo000(Llyiahf/vczjk/x64;)Ljava/lang/Object;

    move-result-object v11

    if-eqz v11, :cond_b

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v12

    invoke-virtual {v12}, Ljava/lang/Class;->isArray()Z

    move-result v12

    if-eqz v12, :cond_b

    invoke-static {v11}, Llyiahf/vczjk/ex9;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/yw;

    move-result-object v11

    goto :goto_9

    :cond_f
    sget-object v11, Llyiahf/vczjk/vb5;->OooOOOO:Llyiahf/vczjk/ea4;

    goto :goto_9

    :cond_10
    invoke-virtual {v11}, Llyiahf/vczjk/ok6;->OooOoO0()Z

    move-result v11

    if-eqz v11, :cond_a

    sget-object v11, Llyiahf/vczjk/vb5;->OooOOOO:Llyiahf/vczjk/ea4;

    goto :goto_9

    :goto_a
    invoke-virtual {v4, v11, v12}, Llyiahf/vczjk/vb5;->OooOOoo(Ljava/lang/Object;Z)Llyiahf/vczjk/vb5;

    move-result-object v4

    goto :goto_c

    :cond_11
    :goto_b
    sget-object v11, Llyiahf/vczjk/ig8;->OooOoo0:Llyiahf/vczjk/ig8;

    invoke-virtual {v2, v11}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result v11

    if-nez v11, :cond_12

    const/4 v11, 0x1

    const/4 v12, 0x0

    invoke-virtual {v4, v12, v11}, Llyiahf/vczjk/vb5;->OooOOoo(Ljava/lang/Object;Z)Llyiahf/vczjk/vb5;

    move-result-object v4

    :cond_12
    :goto_c
    move-object v11, v4

    :cond_13
    iget-object v4, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v4}, Llyiahf/vczjk/sg8;->OooO00o()Z

    move-result v4

    if-eqz v4, :cond_15

    iget-object v4, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v4}, Llyiahf/vczjk/sg8;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v12

    if-nez v12, :cond_14

    goto :goto_d

    :cond_14
    invoke-static {v4}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_15
    :goto_d
    move-object v4, v11

    goto/16 :goto_13

    :cond_16
    invoke-static {v11}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_17
    iget-object v4, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v4}, Llyiahf/vczjk/sg8;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v11

    if-nez v11, :cond_19

    invoke-static/range {p1 .. p3}, Llyiahf/vczjk/s90;->OooO0Oo(Llyiahf/vczjk/tg8;Llyiahf/vczjk/x64;Llyiahf/vczjk/h90;)Llyiahf/vczjk/b59;

    move-result-object v4

    if-eqz v4, :cond_30

    iget-object v11, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v11}, Llyiahf/vczjk/sg8;->OooO00o()Z

    move-result v11

    if-eqz v11, :cond_30

    iget-object v11, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v11}, Llyiahf/vczjk/sg8;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v11

    invoke-virtual {v11}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v12

    if-nez v12, :cond_18

    goto/16 :goto_13

    :cond_18
    invoke-static {v11}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_19
    invoke-static {v4}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_1a
    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OooooO0()Z

    move-result v4

    if-eqz v4, :cond_28

    move-object v4, v0

    check-cast v4, Llyiahf/vczjk/w11;

    instance-of v11, v4, Llyiahf/vczjk/a21;

    if-eqz v11, :cond_25

    check-cast v4, Llyiahf/vczjk/a21;

    iget-object v11, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v11}, Llyiahf/vczjk/sg8;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v11

    invoke-virtual {v11}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v12

    if-nez v12, :cond_24

    invoke-static {v2, v4, v7}, Llyiahf/vczjk/s90;->OooO0Oo(Llyiahf/vczjk/tg8;Llyiahf/vczjk/x64;Llyiahf/vczjk/h90;)Llyiahf/vczjk/b59;

    move-result-object v11

    if-nez v11, :cond_22

    invoke-virtual {v7}, Llyiahf/vczjk/h90;->OooO0Oo()Llyiahf/vczjk/q94;

    move-result-object v12

    if-eqz v12, :cond_1b

    invoke-virtual {v12}, Llyiahf/vczjk/q94;->OooO0o()Llyiahf/vczjk/p94;

    move-result-object v12

    if-ne v12, v5, :cond_1b

    goto/16 :goto_5

    :cond_1b
    invoke-virtual {v4}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v12

    const-class v13, Ljava/util/EnumSet;

    invoke-virtual {v13, v12}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v13

    if-eqz v13, :cond_1d

    invoke-virtual {v4}, Llyiahf/vczjk/w11;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/x64;->Oooooo0()Z

    move-result v11

    if-nez v11, :cond_1c

    const/16 v29, 0x0

    goto :goto_e

    :cond_1c
    move-object/from16 v29, v4

    :goto_e
    new-instance v27, Llyiahf/vczjk/wp2;

    const-class v28, Ljava/util/EnumSet;

    const/16 v30, 0x1

    const/16 v31, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    invoke-direct/range {v27 .. v33}, Llyiahf/vczjk/wp2;-><init>(Ljava/lang/Class;Llyiahf/vczjk/x64;ZLlyiahf/vczjk/e5a;Llyiahf/vczjk/zb4;I)V

    move-object/from16 v11, v27

    goto :goto_10

    :cond_1d
    invoke-virtual {v4}, Llyiahf/vczjk/w11;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v13

    invoke-virtual {v13}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v13

    const-class v15, Ljava/util/RandomAccess;

    invoke-virtual {v15, v12}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v12

    const-class v15, Ljava/lang/String;

    if-eqz v12, :cond_20

    if-ne v13, v15, :cond_1f

    invoke-static/range {v25 .. v25}, Llyiahf/vczjk/vy0;->OooOOoo(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_1e

    sget-object v11, Llyiahf/vczjk/jx3;->OooOOO:Llyiahf/vczjk/jx3;

    :cond_1e
    move/from16 v14, v22

    move-object/from16 v12, v23

    goto :goto_f

    :cond_1f
    move-object/from16 v24, v23

    move/from16 v23, v22

    invoke-virtual {v4}, Llyiahf/vczjk/w11;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v22

    new-instance v20, Llyiahf/vczjk/hx3;

    const-class v21, Ljava/util/List;

    invoke-direct/range {v20 .. v25}, Llyiahf/vczjk/wy;-><init>(Ljava/lang/Class;Llyiahf/vczjk/x64;ZLlyiahf/vczjk/e5a;Llyiahf/vczjk/zb4;)V

    move/from16 v22, v23

    move-object/from16 v12, v24

    move-object/from16 v11, v20

    move/from16 v14, v22

    goto :goto_f

    :cond_20
    move/from16 v14, v22

    move-object/from16 v12, v23

    if-ne v13, v15, :cond_21

    invoke-static/range {v25 .. v25}, Llyiahf/vczjk/vy0;->OooOOoo(Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_21

    sget-object v11, Llyiahf/vczjk/n69;->OooOOO:Llyiahf/vczjk/n69;

    :cond_21
    :goto_f
    if-nez v11, :cond_22

    invoke-virtual {v4}, Llyiahf/vczjk/w11;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v4

    new-instance v11, Llyiahf/vczjk/y11;

    move-object/from16 v13, v25

    invoke-direct {v11, v4, v14, v12, v13}, Llyiahf/vczjk/y11;-><init>(Llyiahf/vczjk/x64;ZLlyiahf/vczjk/e5a;Llyiahf/vczjk/zb4;)V

    :cond_22
    :goto_10
    iget-object v4, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v4}, Llyiahf/vczjk/sg8;->OooO00o()Z

    move-result v4

    if-eqz v4, :cond_15

    iget-object v4, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v4}, Llyiahf/vczjk/sg8;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v12

    if-nez v12, :cond_23

    goto/16 :goto_d

    :cond_23
    invoke-static {v4}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_24
    invoke-static {v11}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_25
    iget-object v4, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v4}, Llyiahf/vczjk/sg8;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v11

    if-nez v11, :cond_27

    invoke-static/range {p1 .. p3}, Llyiahf/vczjk/s90;->OooO0Oo(Llyiahf/vczjk/tg8;Llyiahf/vczjk/x64;Llyiahf/vczjk/h90;)Llyiahf/vczjk/b59;

    move-result-object v4

    if-eqz v4, :cond_30

    iget-object v11, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v11}, Llyiahf/vczjk/sg8;->OooO00o()Z

    move-result v11

    if-eqz v11, :cond_30

    iget-object v11, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v11}, Llyiahf/vczjk/sg8;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v11

    invoke-virtual {v11}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v12

    if-nez v12, :cond_26

    goto/16 :goto_13

    :cond_26
    invoke-static {v11}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_27
    invoke-static {v4}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_28
    move/from16 v14, v22

    move-object/from16 v12, v23

    move-object/from16 v13, v25

    instance-of v4, v0, Llyiahf/vczjk/oy;

    if-eqz v4, :cond_2f

    move-object v4, v0

    check-cast v4, Llyiahf/vczjk/oy;

    iget-object v11, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v11}, Llyiahf/vczjk/sg8;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v11

    invoke-virtual {v11}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v15

    if-nez v15, :cond_2e

    invoke-virtual {v4}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v11

    if-eqz v13, :cond_2a

    invoke-static {v13}, Llyiahf/vczjk/vy0;->OooOOoo(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_29

    goto :goto_11

    :cond_29
    const/4 v11, 0x0

    goto :goto_12

    :cond_2a
    :goto_11
    const-class v15, [Ljava/lang/String;

    if-ne v15, v11, :cond_2b

    sget-object v11, Llyiahf/vczjk/k69;->OooOOO:Llyiahf/vczjk/k69;

    goto :goto_12

    :cond_2b
    sget-object v15, Llyiahf/vczjk/i49;->OooO00o:Ljava/util/HashMap;

    invoke-virtual {v11}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v11

    invoke-virtual {v15, v11}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/zb4;

    :goto_12
    if-nez v11, :cond_2c

    new-instance v11, Llyiahf/vczjk/k66;

    invoke-virtual {v4}, Llyiahf/vczjk/oy;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v4

    invoke-direct {v11, v4, v14, v12, v13}, Llyiahf/vczjk/k66;-><init>(Llyiahf/vczjk/x64;ZLlyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;)V

    :cond_2c
    iget-object v4, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v4}, Llyiahf/vczjk/sg8;->OooO00o()Z

    move-result v4

    if-eqz v4, :cond_15

    iget-object v4, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v4}, Llyiahf/vczjk/sg8;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v12

    if-nez v12, :cond_2d

    goto/16 :goto_d

    :cond_2d
    invoke-static {v4}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_2e
    invoke-static {v11}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_2f
    const/4 v4, 0x0

    :cond_30
    :goto_13
    if-eqz v4, :cond_31

    return-object v4

    :cond_31
    move/from16 v30, v3

    goto/16 :goto_19

    :cond_32
    invoke-virtual {v0}, Llyiahf/vczjk/ok6;->OooOoO0()Z

    move-result v3

    if-eqz v3, :cond_3f

    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/nl7;

    invoke-virtual {v3}, Llyiahf/vczjk/nl7;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/x64;->OoooOOO()Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/d5a;

    invoke-virtual {v2}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object v12

    if-nez v11, :cond_33

    invoke-virtual {v1, v12, v4}, Llyiahf/vczjk/s90;->OooO0O0(Llyiahf/vczjk/gg8;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e5a;

    move-result-object v11

    :cond_33
    invoke-virtual {v4}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/zb4;

    iget-object v12, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v12}, Llyiahf/vczjk/sg8;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v12

    invoke-virtual {v12}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v13

    if-nez v13, :cond_3e

    const-class v12, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v3, v12}, Llyiahf/vczjk/x64;->o00Oo0(Ljava/lang/Class;)Z

    move-result v13

    if-eqz v13, :cond_40

    invoke-virtual {v3}, Llyiahf/vczjk/nl7;->OoooOO0()Llyiahf/vczjk/x64;

    move-result-object v13

    invoke-static {v2, v7, v13, v12}, Llyiahf/vczjk/s90;->OooO0OO(Llyiahf/vczjk/tg8;Llyiahf/vczjk/h90;Llyiahf/vczjk/x64;Ljava/lang/Class;)Llyiahf/vczjk/fa4;

    move-result-object v12

    if-nez v12, :cond_34

    move-object v14, v8

    goto :goto_14

    :cond_34
    invoke-virtual {v12}, Llyiahf/vczjk/fa4;->OooO0O0()Llyiahf/vczjk/ea4;

    move-result-object v14

    :goto_14
    if-eq v14, v8, :cond_3d

    if-ne v14, v6, :cond_35

    goto :goto_16

    :cond_35
    invoke-virtual {v14}, Ljava/lang/Enum;->ordinal()I

    move-result v14

    const/4 v15, 0x2

    if-eq v14, v15, :cond_3c

    const/4 v15, 0x3

    if-eq v14, v15, :cond_3b

    const/4 v15, 0x4

    if-eq v14, v15, :cond_3a

    const/4 v15, 0x5

    if-eq v14, v15, :cond_38

    :cond_36
    const/4 v12, 0x0

    :cond_37
    :goto_15
    const/4 v13, 0x1

    goto :goto_17

    :cond_38
    invoke-virtual {v12}, Llyiahf/vczjk/fa4;->OooO00o()Ljava/lang/Class;

    move-result-object v12

    invoke-virtual {v2, v12}, Llyiahf/vczjk/tg8;->o00000OO(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v12

    if-nez v12, :cond_39

    goto :goto_15

    :cond_39
    invoke-virtual {v2, v12}, Llyiahf/vczjk/tg8;->o00000Oo(Ljava/lang/Object;)Z

    move-result v13

    goto :goto_17

    :cond_3a
    invoke-static {v13}, Llyiahf/vczjk/rs;->Oooo000(Llyiahf/vczjk/x64;)Ljava/lang/Object;

    move-result-object v12

    if-eqz v12, :cond_37

    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v13

    invoke-virtual {v13}, Ljava/lang/Class;->isArray()Z

    move-result v13

    if-eqz v13, :cond_37

    invoke-static {v12}, Llyiahf/vczjk/ex9;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/yw;

    move-result-object v12

    goto :goto_15

    :cond_3b
    sget-object v12, Llyiahf/vczjk/vb5;->OooOOOO:Llyiahf/vczjk/ea4;

    goto :goto_15

    :cond_3c
    invoke-virtual {v13}, Llyiahf/vczjk/ok6;->OooOoO0()Z

    move-result v12

    if-eqz v12, :cond_36

    sget-object v12, Llyiahf/vczjk/vb5;->OooOOOO:Llyiahf/vczjk/ea4;

    goto :goto_15

    :cond_3d
    :goto_16
    const/4 v12, 0x0

    const/4 v13, 0x0

    :goto_17
    new-instance v14, Llyiahf/vczjk/i10;

    invoke-direct {v14, v3, v11, v4}, Llyiahf/vczjk/pl7;-><init>(Llyiahf/vczjk/nl7;Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;)V

    invoke-virtual {v14, v12, v13}, Llyiahf/vczjk/i10;->OooOOOO(Ljava/lang/Object;Z)Llyiahf/vczjk/i10;

    move-result-object v3

    goto :goto_18

    :cond_3e
    invoke-static {v12}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_3f
    iget-object v3, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v3}, Llyiahf/vczjk/sg8;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v4

    if-nez v4, :cond_ad

    :cond_40
    const/4 v3, 0x0

    :goto_18
    if-nez v3, :cond_41

    invoke-static/range {p1 .. p3}, Llyiahf/vczjk/s90;->OooO0Oo(Llyiahf/vczjk/tg8;Llyiahf/vczjk/x64;Llyiahf/vczjk/h90;)Llyiahf/vczjk/b59;

    move-result-object v4

    move/from16 v30, p4

    goto :goto_19

    :cond_41
    move/from16 v30, p4

    move-object v4, v3

    :goto_19
    if-nez v4, :cond_aa

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/s90;->OooOOO0:Ljava/util/HashMap;

    invoke-virtual {v4, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/zb4;

    if-nez v4, :cond_42

    sget-object v11, Llyiahf/vczjk/s90;->OooOOO:Ljava/util/HashMap;

    invoke-virtual {v11, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Class;

    if-eqz v3, :cond_42

    const/4 v11, 0x0

    invoke-static {v3, v11}, Llyiahf/vczjk/vy0;->OooO0oO(Ljava/lang/Class;Z)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/zb4;

    move-object v4, v3

    :cond_42
    if-nez v4, :cond_aa

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->Oooooo()Z

    move-result v3

    sget-object v11, Llyiahf/vczjk/x56;->OooOOo0:Llyiahf/vczjk/x56;

    const-class v4, Ljava/lang/Object;

    if-eqz v3, :cond_48

    invoke-virtual {v2}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object v3

    invoke-virtual {v7}, Llyiahf/vczjk/h90;->OooO0Oo()Llyiahf/vczjk/q94;

    move-result-object v6

    if-eqz v6, :cond_45

    invoke-virtual {v6}, Llyiahf/vczjk/q94;->OooO0o()Llyiahf/vczjk/p94;

    move-result-object v8

    if-ne v8, v5, :cond_45

    invoke-virtual {v7}, Llyiahf/vczjk/h90;->OooO0O0()Ljava/util/List;

    move-result-object v3

    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_43
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_44

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/eb0;

    invoke-interface {v5}, Llyiahf/vczjk/yt5;->getName()Ljava/lang/String;

    move-result-object v5

    const-string v6, "declaringClass"

    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_43

    invoke-interface {v3}, Ljava/util/Iterator;->remove()V

    :cond_44
    :goto_1a
    const/4 v3, 0x0

    goto/16 :goto_24

    :cond_45
    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v5

    invoke-static {v3, v5}, Llyiahf/vczjk/aq2;->OooO00o(Llyiahf/vczjk/gg8;Ljava/lang/Class;)Llyiahf/vczjk/aq2;

    move-result-object v3

    const/4 v8, 0x1

    const/4 v12, 0x0

    invoke-static {v5, v6, v8, v12}, Llyiahf/vczjk/up2;->OooOOOO(Ljava/lang/Class;Llyiahf/vczjk/q94;ZLjava/lang/Boolean;)Ljava/lang/Boolean;

    move-result-object v5

    new-instance v6, Llyiahf/vczjk/up2;

    invoke-direct {v6, v3, v5}, Llyiahf/vczjk/up2;-><init>(Llyiahf/vczjk/aq2;Ljava/lang/Boolean;)V

    iget-object v3, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v3}, Llyiahf/vczjk/sg8;->OooO00o()Z

    move-result v3

    if-eqz v3, :cond_47

    iget-object v3, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v3}, Llyiahf/vczjk/sg8;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v5

    if-nez v5, :cond_46

    goto :goto_1b

    :cond_46
    invoke-static {v3}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_47
    :goto_1b
    move-object v3, v6

    goto/16 :goto_24

    :cond_48
    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v3

    sget-object v12, Llyiahf/vczjk/ff6;->OooOOOO:Llyiahf/vczjk/ff6;

    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v12

    sget-object v13, Llyiahf/vczjk/ff6;->OooOOO0:Ljava/lang/Class;

    if-eqz v13, :cond_49

    invoke-virtual {v13, v12}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v13

    if-eqz v13, :cond_49

    const-string v12, "com.fasterxml.jackson.databind.ext.DOMSerializer"

    invoke-static {v12}, Llyiahf/vczjk/ff6;->OooO00o(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/zb4;

    goto :goto_1d

    :cond_49
    invoke-virtual {v12}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v13

    const-string v14, "javax.xml."

    invoke-virtual {v13, v14}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v13

    if-nez v13, :cond_4c

    :cond_4a
    invoke-virtual {v12}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    move-result-object v12

    if-eqz v12, :cond_4d

    if-ne v12, v4, :cond_4b

    goto :goto_1c

    :cond_4b
    invoke-virtual {v12}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v13

    invoke-virtual {v13, v14}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v13

    if-eqz v13, :cond_4a

    :cond_4c
    const-string v12, "com.fasterxml.jackson.databind.ext.CoreXMLSerializers"

    invoke-static {v12}, Llyiahf/vczjk/ff6;->OooO00o(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v12

    if-nez v12, :cond_a9

    :cond_4d
    :goto_1c
    const/4 v12, 0x0

    :goto_1d
    if-eqz v12, :cond_4e

    move-object v3, v12

    goto/16 :goto_24

    :cond_4e
    const-class v12, Ljava/util/Calendar;

    invoke-virtual {v12, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v12

    if-eqz v12, :cond_4f

    sget-object v3, Llyiahf/vczjk/un0;->OooOOOO:Llyiahf/vczjk/un0;

    goto/16 :goto_24

    :cond_4f
    const-class v12, Ljava/util/Date;

    invoke-virtual {v12, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v12

    if-eqz v12, :cond_50

    sget-object v3, Llyiahf/vczjk/vz1;->OooOOOO:Llyiahf/vczjk/vz1;

    goto/16 :goto_24

    :cond_50
    const-class v12, Ljava/util/Map$Entry;

    invoke-virtual {v12, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v13

    if-eqz v13, :cond_5e

    invoke-virtual {v0, v12}, Llyiahf/vczjk/x64;->Oooo0o(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v3

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/x64;->Oooo0o0(I)Llyiahf/vczjk/x64;

    move-result-object v29

    const/4 v13, 0x1

    invoke-virtual {v3, v13}, Llyiahf/vczjk/x64;->Oooo0o0(I)Llyiahf/vczjk/x64;

    move-result-object v3

    invoke-virtual {v2, v12}, Llyiahf/vczjk/tg8;->o000000O(Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object v13

    invoke-virtual {v7}, Llyiahf/vczjk/h90;->OooO0Oo()Llyiahf/vczjk/q94;

    move-result-object v14

    sget-object v15, Llyiahf/vczjk/q94;->OooOOO:Llyiahf/vczjk/q94;

    if-nez v14, :cond_51

    goto :goto_1e

    :cond_51
    invoke-virtual {v14, v13}, Llyiahf/vczjk/q94;->OooOO0o(Llyiahf/vczjk/q94;)Llyiahf/vczjk/q94;

    move-result-object v13

    :goto_1e
    invoke-virtual {v13}, Llyiahf/vczjk/q94;->OooO0o()Llyiahf/vczjk/p94;

    move-result-object v13

    if-ne v13, v5, :cond_52

    goto/16 :goto_1a

    :cond_52
    new-instance v27, Llyiahf/vczjk/pb5;

    invoke-virtual {v2}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object v5

    invoke-virtual {v1, v5, v3}, Llyiahf/vczjk/s90;->OooO0O0(Llyiahf/vczjk/gg8;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e5a;

    move-result-object v32

    const/16 v33, 0x0

    move/from16 v31, v30

    move-object/from16 v30, v3

    move-object/from16 v28, v3

    invoke-direct/range {v27 .. v33}, Llyiahf/vczjk/pb5;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;ZLlyiahf/vczjk/e5a;Llyiahf/vczjk/db0;)V

    move-object/from16 v3, v27

    move/from16 v30, v31

    iget-object v5, v3, Llyiahf/vczjk/pb5;->_valueType:Llyiahf/vczjk/x64;

    invoke-static {v2, v7, v5, v12}, Llyiahf/vczjk/s90;->OooO0OO(Llyiahf/vczjk/tg8;Llyiahf/vczjk/h90;Llyiahf/vczjk/x64;Ljava/lang/Class;)Llyiahf/vczjk/fa4;

    move-result-object v12

    if-nez v12, :cond_53

    move-object v13, v8

    goto :goto_1f

    :cond_53
    invoke-virtual {v12}, Llyiahf/vczjk/fa4;->OooO0O0()Llyiahf/vczjk/ea4;

    move-result-object v13

    :goto_1f
    if-eq v13, v8, :cond_54

    if-ne v13, v6, :cond_55

    :cond_54
    move-object/from16 v27, v3

    goto/16 :goto_23

    :cond_55
    invoke-virtual {v13}, Ljava/lang/Enum;->ordinal()I

    move-result v6

    const/4 v15, 0x2

    if-eq v6, v15, :cond_5c

    const/4 v15, 0x3

    if-eq v6, v15, :cond_5b

    const/4 v13, 0x4

    if-eq v6, v13, :cond_5a

    const/4 v13, 0x5

    if-eq v6, v13, :cond_58

    :cond_56
    const/4 v5, 0x0

    :cond_57
    :goto_20
    const/4 v6, 0x1

    goto :goto_21

    :cond_58
    invoke-virtual {v12}, Llyiahf/vczjk/fa4;->OooO00o()Ljava/lang/Class;

    move-result-object v5

    invoke-virtual {v2, v5}, Llyiahf/vczjk/tg8;->o00000OO(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v5

    if-nez v5, :cond_59

    goto :goto_20

    :cond_59
    invoke-virtual {v2, v5}, Llyiahf/vczjk/tg8;->o00000Oo(Ljava/lang/Object;)Z

    move-result v6

    goto :goto_21

    :cond_5a
    invoke-static {v5}, Llyiahf/vczjk/rs;->Oooo000(Llyiahf/vczjk/x64;)Ljava/lang/Object;

    move-result-object v5

    if-eqz v5, :cond_57

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/Class;->isArray()Z

    move-result v6

    if-eqz v6, :cond_57

    invoke-static {v5}, Llyiahf/vczjk/ex9;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/yw;

    move-result-object v5

    goto :goto_20

    :cond_5b
    sget-object v5, Llyiahf/vczjk/vb5;->OooOOOO:Llyiahf/vczjk/ea4;

    goto :goto_20

    :cond_5c
    invoke-virtual {v5}, Llyiahf/vczjk/ok6;->OooOoO0()Z

    move-result v5

    if-eqz v5, :cond_56

    sget-object v5, Llyiahf/vczjk/vb5;->OooOOOO:Llyiahf/vczjk/ea4;

    goto :goto_20

    :goto_21
    iget-object v8, v3, Llyiahf/vczjk/pb5;->_suppressableValue:Ljava/lang/Object;

    if-ne v8, v5, :cond_5d

    iget-boolean v8, v3, Llyiahf/vczjk/pb5;->_suppressNulls:Z

    if-ne v8, v6, :cond_5d

    move-object/from16 v31, v3

    goto :goto_22

    :cond_5d
    new-instance v31, Llyiahf/vczjk/pb5;

    iget-object v8, v3, Llyiahf/vczjk/pb5;->_keySerializer:Llyiahf/vczjk/zb4;

    iget-object v12, v3, Llyiahf/vczjk/pb5;->_valueSerializer:Llyiahf/vczjk/zb4;

    move-object/from16 v32, v3

    move-object/from16 v35, v5

    move/from16 v36, v6

    move-object/from16 v33, v8

    move-object/from16 v34, v12

    invoke-direct/range {v31 .. v36}, Llyiahf/vczjk/pb5;-><init>(Llyiahf/vczjk/pb5;Llyiahf/vczjk/zb4;Llyiahf/vczjk/zb4;Ljava/lang/Object;Z)V

    :goto_22
    move-object/from16 v3, v31

    goto/16 :goto_24

    :goto_23
    move-object/from16 v3, v27

    goto/16 :goto_24

    :cond_5e
    const-class v5, Ljava/nio/ByteBuffer;

    invoke-virtual {v5, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_5f

    new-instance v3, Llyiahf/vczjk/vl0;

    const/4 v13, 0x0

    invoke-direct {v3, v13}, Llyiahf/vczjk/vl0;-><init>(I)V

    goto :goto_24

    :cond_5f
    const/4 v13, 0x0

    const-class v5, Ljava/net/InetAddress;

    invoke-virtual {v5, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_60

    new-instance v3, Llyiahf/vczjk/by3;

    invoke-direct {v3, v13}, Llyiahf/vczjk/by3;-><init>(Z)V

    goto :goto_24

    :cond_60
    const-class v5, Ljava/net/InetSocketAddress;

    invoke-virtual {v5, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_61

    new-instance v3, Llyiahf/vczjk/vl0;

    const/4 v13, 0x1

    invoke-direct {v3, v13}, Llyiahf/vczjk/vl0;-><init>(I)V

    goto :goto_24

    :cond_61
    const-class v5, Ljava/util/TimeZone;

    invoke-virtual {v5, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_62

    new-instance v3, Llyiahf/vczjk/vl0;

    const/4 v15, 0x2

    invoke-direct {v3, v15}, Llyiahf/vczjk/vl0;-><init>(I)V

    goto :goto_24

    :cond_62
    const-class v5, Ljava/nio/charset/Charset;

    invoke-virtual {v5, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_64

    :cond_63
    move-object v3, v11

    goto :goto_24

    :cond_64
    const-class v5, Ljava/lang/Number;

    invoke-virtual {v5, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v3

    if-eqz v3, :cond_44

    invoke-virtual {v7}, Llyiahf/vczjk/h90;->OooO0Oo()Llyiahf/vczjk/q94;

    move-result-object v3

    if-eqz v3, :cond_65

    invoke-virtual {v3}, Llyiahf/vczjk/q94;->OooO0o()Llyiahf/vczjk/p94;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    move-result v3

    const/4 v15, 0x3

    if-eq v3, v15, :cond_44

    const/4 v13, 0x4

    if-eq v3, v13, :cond_44

    const/16 v5, 0x8

    if-eq v3, v5, :cond_63

    :cond_65
    sget-object v3, Llyiahf/vczjk/y56;->OooOOOO:Llyiahf/vczjk/y56;

    :goto_24
    if-nez v3, :cond_a8

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/vy0;->OooO0OO(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v5

    if-nez v5, :cond_66

    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v3

    const-string v5, "net.sf.cglib.proxy."

    invoke-virtual {v3, v5}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v5

    if-nez v5, :cond_66

    const-string v5, "org.hibernate.proxy."

    invoke-virtual {v3, v5}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v3

    if-eqz v3, :cond_67

    :cond_66
    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v3

    const-class v5, Ljava/lang/Enum;

    invoke-virtual {v5, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v3

    if-nez v3, :cond_67

    const/4 v15, 0x0

    goto/16 :goto_46

    :cond_67
    invoke-virtual {v7}, Llyiahf/vczjk/h90;->OooO0oO()Ljava/lang/Class;

    move-result-object v3

    if-ne v3, v4, :cond_68

    invoke-virtual {v2, v4}, Llyiahf/vczjk/tg8;->o00000(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v15

    goto/16 :goto_46

    :cond_68
    invoke-virtual {v2}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object v8

    new-instance v12, Llyiahf/vczjk/jb0;

    invoke-direct {v12, v7}, Llyiahf/vczjk/jb0;-><init>(Llyiahf/vczjk/h90;)V

    iput-object v8, v12, Llyiahf/vczjk/jb0;->OooO0OO:Ljava/lang/Object;

    invoke-virtual {v7}, Llyiahf/vczjk/h90;->OooO0O0()Ljava/util/List;

    move-result-object v3

    invoke-virtual {v2}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object v4

    invoke-virtual {v4}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v5

    new-instance v6, Ljava/util/HashMap;

    invoke-direct {v6}, Ljava/util/HashMap;-><init>()V

    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v13

    :cond_69
    :goto_25
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    move-result v14

    if-eqz v14, :cond_6d

    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/eb0;

    invoke-virtual {v14}, Llyiahf/vczjk/eb0;->OooOO0O()Llyiahf/vczjk/pm;

    move-result-object v15

    if-nez v15, :cond_6a

    invoke-interface {v13}, Ljava/util/Iterator;->remove()V

    goto :goto_25

    :cond_6a
    invoke-virtual {v14}, Llyiahf/vczjk/eb0;->OooOOo0()Ljava/lang/Class;

    move-result-object v14

    invoke-virtual {v6, v14}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Ljava/lang/Boolean;

    if-nez v15, :cond_6c

    invoke-virtual {v4, v14}, Llyiahf/vczjk/fc5;->OooOo(Ljava/lang/Class;)Llyiahf/vczjk/uh1;

    invoke-virtual {v4, v14}, Llyiahf/vczjk/ec5;->OooOOOo(Ljava/lang/Class;)Llyiahf/vczjk/h90;

    move-result-object v15

    iget-object v15, v15, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {v5, v15}, Llyiahf/vczjk/yn;->Ooooooo(Llyiahf/vczjk/hm;)Ljava/lang/Boolean;

    move-result-object v15

    if-nez v15, :cond_6b

    sget-object v15, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    :cond_6b
    invoke-virtual {v6, v14, v15}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_6c
    invoke-virtual {v15}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v14

    if-eqz v14, :cond_69

    invoke-interface {v13}, Ljava/util/Iterator;->remove()V

    goto :goto_25

    :cond_6d
    sget-object v5, Llyiahf/vczjk/gc5;->OooOo0:Llyiahf/vczjk/gc5;

    invoke-virtual {v4, v5}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v5

    if-eqz v5, :cond_6f

    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :cond_6e
    :goto_26
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_6f

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/eb0;

    invoke-virtual {v6}, Llyiahf/vczjk/eb0;->OooO0o0()Z

    move-result v13

    if-nez v13, :cond_6e

    invoke-virtual {v6}, Llyiahf/vczjk/eb0;->OooOo()Z

    move-result v6

    if-nez v6, :cond_6e

    invoke-interface {v5}, Ljava/util/Iterator;->remove()V

    goto :goto_26

    :cond_6f
    invoke-interface {v3}, Ljava/util/List;->isEmpty()Z

    move-result v5

    if-eqz v5, :cond_71

    const/4 v13, 0x0

    :cond_70
    move-object/from16 p4, v11

    goto/16 :goto_29

    :cond_71
    invoke-static {v4, v7}, Llyiahf/vczjk/s90;->OooO0o(Llyiahf/vczjk/gg8;Llyiahf/vczjk/h90;)Z

    move-result v5

    new-instance v6, Llyiahf/vczjk/oO00O0o;

    invoke-direct {v6, v4, v7}, Llyiahf/vczjk/oO00O0o;-><init>(Llyiahf/vczjk/gg8;Llyiahf/vczjk/h90;)V

    new-instance v13, Ljava/util/ArrayList;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v4

    invoke-direct {v13, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v14

    :cond_72
    :goto_27
    invoke-interface {v14}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_70

    invoke-interface {v14}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/eb0;

    invoke-virtual {v3}, Llyiahf/vczjk/eb0;->OooOO0O()Llyiahf/vczjk/pm;

    move-result-object v4

    invoke-virtual {v3}, Llyiahf/vczjk/eb0;->OooOoO()Z

    move-result v15

    if-eqz v15, :cond_74

    if-eqz v4, :cond_72

    iget-object v3, v12, Llyiahf/vczjk/jb0;->OooO0oo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/pm;

    if-nez v3, :cond_73

    iput-object v4, v12, Llyiahf/vczjk/jb0;->OooO0oo:Ljava/lang/Object;

    goto :goto_27

    :cond_73
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Multiple type ids specified with "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v3, v12, Llyiahf/vczjk/jb0;->OooO0oo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/pm;

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v3, " and "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v0, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_74
    invoke-virtual {v3}, Llyiahf/vczjk/eb0;->OooO()Llyiahf/vczjk/xn;

    move-result-object v15

    if-eqz v15, :cond_75

    iget v15, v15, Llyiahf/vczjk/xn;->OooO00o:I

    move-object/from16 p4, v11

    const/4 v11, 0x2

    if-ne v15, v11, :cond_76

    move-object/from16 v11, p4

    goto :goto_27

    :cond_75
    move-object/from16 p4, v11

    const/4 v11, 0x2

    :cond_76
    instance-of v15, v4, Llyiahf/vczjk/rm;

    if-eqz v15, :cond_77

    check-cast v4, Llyiahf/vczjk/rm;

    move-object/from16 v37, v6

    move-object v6, v4

    move-object/from16 v4, v37

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/kb0;->OooO0oO(Llyiahf/vczjk/tg8;Llyiahf/vczjk/eb0;Llyiahf/vczjk/oO00O0o;ZLlyiahf/vczjk/pm;)Llyiahf/vczjk/gb0;

    move-result-object v3

    move-object v1, v4

    invoke-virtual {v13, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object/from16 v2, p1

    move-object/from16 v1, p0

    goto :goto_28

    :cond_77
    move-object v1, v6

    move-object v6, v4

    check-cast v6, Llyiahf/vczjk/mm;

    move-object/from16 v2, p1

    move-object v4, v1

    move-object/from16 v1, p0

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/kb0;->OooO0oO(Llyiahf/vczjk/tg8;Llyiahf/vczjk/eb0;Llyiahf/vczjk/oO00O0o;ZLlyiahf/vczjk/pm;)Llyiahf/vczjk/gb0;

    move-result-object v3

    invoke-virtual {v13, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_28
    move-object/from16 v11, p4

    move-object v6, v4

    goto :goto_27

    :goto_29
    if-nez v13, :cond_78

    new-instance v13, Ljava/util/ArrayList;

    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    goto :goto_2f

    :cond_78
    invoke-interface {v13}, Ljava/util/List;->size()I

    move-result v3

    const/4 v4, 0x0

    :goto_2a
    if-ge v4, v3, :cond_7f

    invoke-interface {v13, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/gb0;

    iget-object v6, v5, Llyiahf/vczjk/gb0;->_typeSerializer:Llyiahf/vczjk/d5a;

    if-eqz v6, :cond_79

    invoke-virtual {v6}, Llyiahf/vczjk/d5a;->OooO0OO()Llyiahf/vczjk/kc4;

    move-result-object v11

    sget-object v14, Llyiahf/vczjk/kc4;->OooOOOo:Llyiahf/vczjk/kc4;

    if-eq v11, v14, :cond_7a

    :cond_79
    :goto_2b
    const/16 v17, 0x1

    goto :goto_2e

    :cond_7a
    invoke-virtual {v6}, Llyiahf/vczjk/d5a;->OooO0O0()Ljava/lang/String;

    move-result-object v6

    invoke-static {v6}, Llyiahf/vczjk/xa7;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object v6

    invoke-interface {v13}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v11

    :cond_7b
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    move-result v14

    if-eqz v14, :cond_79

    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/gb0;

    if-eq v14, v5, :cond_7b

    iget-object v15, v14, Llyiahf/vczjk/gb0;->_wrapperName:Llyiahf/vczjk/xa7;

    if-eqz v15, :cond_7c

    invoke-virtual {v15, v6}, Llyiahf/vczjk/xa7;->equals(Ljava/lang/Object;)Z

    move-result v14

    goto :goto_2d

    :cond_7c
    iget-object v14, v14, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    invoke-virtual {v14}, Llyiahf/vczjk/ng8;->OooO0oO()Ljava/lang/String;

    move-result-object v14

    iget-object v15, v6, Llyiahf/vczjk/xa7;->_simpleName:Ljava/lang/String;

    invoke-virtual {v15, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_7e

    iget-object v14, v6, Llyiahf/vczjk/xa7;->_namespace:Ljava/lang/String;

    if-eqz v14, :cond_7d

    const/4 v14, 0x1

    goto :goto_2c

    :cond_7d
    const/4 v14, 0x0

    :goto_2c
    if-nez v14, :cond_7e

    const/4 v14, 0x1

    goto :goto_2d

    :cond_7e
    const/4 v14, 0x0

    :goto_2d
    if-eqz v14, :cond_7b

    const/4 v14, 0x0

    iput-object v14, v5, Llyiahf/vczjk/gb0;->_typeSerializer:Llyiahf/vczjk/d5a;

    goto :goto_2b

    :goto_2e
    add-int/lit8 v4, v4, 0x1

    goto :goto_2a

    :cond_7f
    :goto_2f
    invoke-virtual {v2}, Llyiahf/vczjk/tg8;->o0O0O00()Llyiahf/vczjk/yn;

    move-result-object v3

    invoke-virtual {v3, v8, v9, v13}, Llyiahf/vczjk/yn;->OooO00o(Llyiahf/vczjk/gg8;Llyiahf/vczjk/hm;Ljava/util/ArrayList;)V

    iget-object v3, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v3}, Llyiahf/vczjk/sg8;->OooO00o()Z

    move-result v3

    if-eqz v3, :cond_81

    iget-object v3, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v3}, Llyiahf/vczjk/sg8;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v4

    if-nez v4, :cond_80

    goto :goto_30

    :cond_80
    invoke-static {v3}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_81
    :goto_30
    invoke-virtual {v7}, Llyiahf/vczjk/h90;->OooO0oO()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v8, v3, v9}, Llyiahf/vczjk/fc5;->OooOoO0(Ljava/lang/Class;Llyiahf/vczjk/hm;)Llyiahf/vczjk/ba4;

    move-result-object v3

    if-eqz v3, :cond_83

    invoke-virtual {v3}, Llyiahf/vczjk/ba4;->OooO0OO()Ljava/util/Set;

    move-result-object v3

    invoke-interface {v3}, Ljava/util/Set;->isEmpty()Z

    move-result v4

    if-nez v4, :cond_83

    invoke-interface {v13}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :cond_82
    :goto_31
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_83

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/gb0;

    iget-object v5, v5, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    invoke-virtual {v5}, Llyiahf/vczjk/ng8;->OooO0oO()Ljava/lang/String;

    move-result-object v5

    invoke-interface {v3, v5}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_82

    invoke-interface {v4}, Ljava/util/Iterator;->remove()V

    goto :goto_31

    :cond_83
    iget-object v3, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v3}, Llyiahf/vczjk/sg8;->OooO00o()Z

    move-result v3

    if-eqz v3, :cond_85

    iget-object v3, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v3}, Llyiahf/vczjk/sg8;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v4

    if-nez v4, :cond_84

    goto :goto_32

    :cond_84
    invoke-static {v3}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_85
    :goto_32
    iget-object v3, v7, Llyiahf/vczjk/h90;->OooO:Llyiahf/vczjk/t66;

    if-nez v3, :cond_86

    const/4 v3, 0x0

    goto/16 :goto_35

    :cond_86
    iget-object v4, v3, Llyiahf/vczjk/t66;->OooO00o:Llyiahf/vczjk/xa7;

    const-class v5, Llyiahf/vczjk/s66;

    iget-boolean v6, v3, Llyiahf/vczjk/t66;->OooO0o0:Z

    iget-object v11, v3, Llyiahf/vczjk/t66;->OooO0O0:Ljava/lang/Class;

    if-ne v11, v5, :cond_8a

    invoke-virtual {v4}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v4

    invoke-interface {v13}, Ljava/util/List;->size()I

    move-result v5

    const/4 v11, 0x0

    :goto_33
    if-eq v11, v5, :cond_89

    invoke-interface {v13, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/gb0;

    iget-object v15, v14, Llyiahf/vczjk/gb0;->_name:Llyiahf/vczjk/ng8;

    invoke-virtual {v15}, Llyiahf/vczjk/ng8;->OooO0oO()Ljava/lang/String;

    move-result-object v15

    invoke-virtual {v4, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_88

    if-lez v11, :cond_87

    invoke-interface {v13, v11}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    const/4 v11, 0x0

    invoke-interface {v13, v11, v14}, Ljava/util/List;->add(ILjava/lang/Object;)V

    :cond_87
    iget-object v4, v14, Llyiahf/vczjk/gb0;->_declaredType:Llyiahf/vczjk/x64;

    new-instance v5, Llyiahf/vczjk/pa7;

    iget-object v3, v3, Llyiahf/vczjk/t66;->OooO0Oo:Ljava/lang/Class;

    invoke-direct {v5, v3, v14}, Llyiahf/vczjk/pa7;-><init>(Ljava/lang/Class;Llyiahf/vczjk/gb0;)V

    const/4 v14, 0x0

    invoke-static {v4, v14, v5, v6}, Llyiahf/vczjk/z66;->OooO00o(Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/p66;Z)Llyiahf/vczjk/z66;

    move-result-object v3

    goto :goto_35

    :cond_88
    const/16 v17, 0x1

    add-int/lit8 v11, v11, 0x1

    goto :goto_33

    :cond_89
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Invalid Object Id definition for "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v7}, Llyiahf/vczjk/h90;->OooO0oO()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, ": cannot find property with name \'"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, "\'"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v0, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_8a
    if-nez v11, :cond_8b

    const/4 v5, 0x0

    goto :goto_34

    :cond_8b
    invoke-virtual {v2}, Llyiahf/vczjk/tg8;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-result-object v5

    invoke-virtual {v5, v11}, Llyiahf/vczjk/a4a;->OooOO0O(Ljava/lang/reflect/Type;)Llyiahf/vczjk/x64;

    move-result-object v5

    :goto_34
    invoke-virtual {v2}, Llyiahf/vczjk/tg8;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-result-object v11

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-class v11, Llyiahf/vczjk/p66;

    invoke-static {v11, v5}, Llyiahf/vczjk/a4a;->OooOOO(Ljava/lang/Class;Llyiahf/vczjk/x64;)[Llyiahf/vczjk/x64;

    move-result-object v5

    const/16 v16, 0x0

    aget-object v5, v5, v16

    invoke-virtual {v2, v3}, Llyiahf/vczjk/mc4;->OoooO(Llyiahf/vczjk/t66;)Llyiahf/vczjk/p66;

    move-result-object v3

    invoke-static {v5, v4, v3, v6}, Llyiahf/vczjk/z66;->OooO00o(Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/p66;Z)Llyiahf/vczjk/z66;

    move-result-object v3

    :goto_35
    iput-object v3, v12, Llyiahf/vczjk/jb0;->OooO:Ljava/lang/Object;

    iput-object v13, v12, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    invoke-virtual {v8}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v3

    invoke-virtual {v3, v9}, Llyiahf/vczjk/yn;->OooOOO0(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v3

    iput-object v3, v12, Llyiahf/vczjk/jb0;->OooO0oO:Ljava/lang/Object;

    iget-object v3, v7, Llyiahf/vczjk/h90;->OooO0O0:Llyiahf/vczjk/yg6;

    if-nez v3, :cond_8d

    :cond_8c
    const/4 v3, 0x0

    goto :goto_36

    :cond_8d
    iget-boolean v4, v3, Llyiahf/vczjk/yg6;->OooOO0:Z

    if-nez v4, :cond_8e

    invoke-virtual {v3}, Llyiahf/vczjk/yg6;->OooO0o()V

    :cond_8e
    iget-object v4, v3, Llyiahf/vczjk/yg6;->OooOOO0:Ljava/util/LinkedList;

    if-eqz v4, :cond_8c

    invoke-virtual {v4}, Ljava/util/LinkedList;->size()I

    move-result v4

    const/4 v13, 0x1

    if-gt v4, v13, :cond_8f

    iget-object v3, v3, Llyiahf/vczjk/yg6;->OooOOO0:Ljava/util/LinkedList;

    invoke-virtual {v3}, Ljava/util/LinkedList;->getFirst()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/pm;

    goto :goto_36

    :cond_8f
    iget-object v0, v3, Llyiahf/vczjk/yg6;->OooOOO0:Ljava/util/LinkedList;

    const/4 v11, 0x0

    invoke-virtual {v0, v11}, Ljava/util/LinkedList;->get(I)Ljava/lang/Object;

    move-result-object v0

    iget-object v2, v3, Llyiahf/vczjk/yg6;->OooOOO0:Ljava/util/LinkedList;

    invoke-virtual {v2, v13}, Ljava/util/LinkedList;->get(I)Ljava/lang/Object;

    move-result-object v2

    filled-new-array {v0, v2}, [Ljava/lang/Object;

    move-result-object v0

    const-string v2, "Multiple \'any-getters\' defined (%s vs %s)"

    invoke-virtual {v3, v2, v0}, Llyiahf/vczjk/yg6;->OooO0oO(Ljava/lang/String;[Ljava/lang/Object;)V

    const/16 v19, 0x0

    throw v19

    :goto_36
    if-eqz v3, :cond_91

    invoke-virtual {v3}, Llyiahf/vczjk/u34;->OooOoOO()Ljava/lang/Class;

    move-result-object v4

    invoke-virtual {v10, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v4

    if-eqz v4, :cond_90

    goto :goto_37

    :cond_90
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v4, "Invalid \'any-getter\' annotation on method "

    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3}, Llyiahf/vczjk/u34;->getName()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, "(): return type is not instance of java.util.Map"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v0, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_91
    :goto_37
    if-eqz v3, :cond_93

    invoke-virtual {v3}, Llyiahf/vczjk/u34;->OooOoo()Llyiahf/vczjk/x64;

    move-result-object v21

    invoke-virtual/range {v21 .. v21}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v4

    invoke-virtual {v1, v8, v4}, Llyiahf/vczjk/s90;->OooO0O0(Llyiahf/vczjk/gg8;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e5a;

    move-result-object v23

    invoke-static {v2, v3}, Llyiahf/vczjk/s90;->OooO0o0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/u34;)Llyiahf/vczjk/zb4;

    move-result-object v5

    if-nez v5, :cond_92

    sget-object v5, Llyiahf/vczjk/gc5;->OooOoOO:Llyiahf/vczjk/gc5;

    invoke-virtual {v8, v5}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v22

    const/16 v20, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    invoke-static/range {v20 .. v26}, Llyiahf/vczjk/vb5;->OooOOOo(Ljava/util/Set;Llyiahf/vczjk/x64;ZLlyiahf/vczjk/e5a;Llyiahf/vczjk/zb4;Llyiahf/vczjk/zb4;Ljava/lang/Object;)Llyiahf/vczjk/vb5;

    move-result-object v5

    :cond_92
    invoke-virtual {v3}, Llyiahf/vczjk/u34;->getName()Ljava/lang/String;

    move-result-object v6

    invoke-static {v6}, Llyiahf/vczjk/xa7;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/xa7;

    move-result-object v21

    new-instance v20, Llyiahf/vczjk/cb0;

    const/16 v23, 0x0

    sget-object v25, Llyiahf/vczjk/wa7;->OooOOOO:Llyiahf/vczjk/wa7;

    move-object/from16 v24, v3

    move-object/from16 v22, v4

    invoke-direct/range {v20 .. v25}, Llyiahf/vczjk/cb0;-><init>(Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/pm;Llyiahf/vczjk/wa7;)V

    move-object/from16 v4, v20

    new-instance v6, Llyiahf/vczjk/to;

    invoke-direct {v6, v4, v3, v5}, Llyiahf/vczjk/to;-><init>(Llyiahf/vczjk/cb0;Llyiahf/vczjk/pm;Llyiahf/vczjk/zb4;)V

    iput-object v6, v12, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    :cond_93
    iget-object v3, v12, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v3, Ljava/util/List;

    sget-object v4, Llyiahf/vczjk/gc5;->OooOoo:Llyiahf/vczjk/gc5;

    invoke-virtual {v8, v4}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v4

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v5

    new-array v6, v5, [Llyiahf/vczjk/gb0;

    const/4 v10, 0x0

    const/4 v11, 0x0

    :goto_38
    if-ge v10, v5, :cond_98

    invoke-interface {v3, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/gb0;

    iget-object v14, v13, Llyiahf/vczjk/gb0;->_includeInViews:[Ljava/lang/Class;

    if-eqz v14, :cond_94

    array-length v15, v14

    if-nez v15, :cond_95

    :cond_94
    move-object/from16 v18, v3

    goto :goto_3b

    :cond_95
    const/4 v15, 0x1

    add-int/2addr v11, v15

    move-object/from16 v18, v3

    array-length v3, v14

    if-ne v3, v15, :cond_96

    new-instance v3, Llyiahf/vczjk/b13;

    const/16 v16, 0x0

    aget-object v14, v14, v16

    invoke-direct {v3, v14, v13}, Llyiahf/vczjk/b13;-><init>(Ljava/lang/Class;Llyiahf/vczjk/gb0;)V

    goto :goto_39

    :cond_96
    new-instance v3, Llyiahf/vczjk/a13;

    invoke-direct {v3, v13, v14}, Llyiahf/vczjk/a13;-><init>(Llyiahf/vczjk/gb0;[Ljava/lang/Class;)V

    :goto_39
    aput-object v3, v6, v10

    :cond_97
    :goto_3a
    const/16 v17, 0x1

    goto :goto_3c

    :goto_3b
    if-eqz v4, :cond_97

    aput-object v13, v6, v10

    goto :goto_3a

    :goto_3c
    add-int/lit8 v10, v10, 0x1

    move-object/from16 v3, v18

    goto :goto_38

    :cond_98
    if-eqz v4, :cond_99

    if-nez v11, :cond_99

    goto :goto_3d

    :cond_99
    iget-object v3, v12, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v3, Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ne v5, v3, :cond_a7

    iput-object v6, v12, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    :goto_3d
    iget-object v3, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v3}, Llyiahf/vczjk/sg8;->OooO00o()Z

    move-result v3

    if-eqz v3, :cond_9b

    iget-object v3, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v3}, Llyiahf/vczjk/sg8;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v4

    if-nez v4, :cond_9a

    goto :goto_3e

    :cond_9a
    invoke-static {v3}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_9b
    :goto_3e
    :try_start_0
    invoke-virtual {v12}, Llyiahf/vczjk/jb0;->OooO0O0()Llyiahf/vczjk/hb0;

    move-result-object v3
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    if-nez v3, :cond_a4

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v3

    const-class v4, Ljava/util/Iterator;

    invoke-virtual {v4, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_9e

    invoke-virtual {v8}, Llyiahf/vczjk/ec5;->OooOOOO()Llyiahf/vczjk/a4a;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4, v0}, Llyiahf/vczjk/a4a;->OooOOO(Ljava/lang/Class;Llyiahf/vczjk/x64;)[Llyiahf/vczjk/x64;

    move-result-object v0

    if-eqz v0, :cond_9d

    array-length v3, v0

    const/4 v13, 0x1

    if-eq v3, v13, :cond_9c

    goto :goto_3f

    :cond_9c
    const/16 v16, 0x0

    aget-object v0, v0, v16

    goto :goto_40

    :cond_9d
    :goto_3f
    invoke-static {}, Llyiahf/vczjk/a4a;->OooOOOo()Llyiahf/vczjk/ep8;

    move-result-object v0

    :goto_40
    new-instance v27, Llyiahf/vczjk/wp2;

    invoke-virtual {v1, v8, v0}, Llyiahf/vczjk/s90;->OooO0O0(Llyiahf/vczjk/gg8;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e5a;

    move-result-object v31

    const-class v28, Ljava/util/Iterator;

    const/16 v32, 0x0

    const/16 v33, 0x2

    move-object/from16 v29, v0

    invoke-direct/range {v27 .. v33}, Llyiahf/vczjk/wp2;-><init>(Ljava/lang/Class;Llyiahf/vczjk/x64;ZLlyiahf/vczjk/e5a;Llyiahf/vczjk/zb4;I)V

    const/4 v13, 0x1

    const/16 v16, 0x0

    goto :goto_44

    :cond_9e
    const-class v4, Ljava/lang/Iterable;

    invoke-virtual {v4, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v5

    if-eqz v5, :cond_a1

    invoke-virtual {v8}, Llyiahf/vczjk/ec5;->OooOOOO()Llyiahf/vczjk/a4a;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v4, v0}, Llyiahf/vczjk/a4a;->OooOOO(Ljava/lang/Class;Llyiahf/vczjk/x64;)[Llyiahf/vczjk/x64;

    move-result-object v0

    if-eqz v0, :cond_a0

    array-length v3, v0

    const/4 v13, 0x1

    if-eq v3, v13, :cond_9f

    :goto_41
    const/16 v16, 0x0

    goto :goto_42

    :cond_9f
    const/16 v16, 0x0

    aget-object v0, v0, v16

    goto :goto_43

    :cond_a0
    const/4 v13, 0x1

    goto :goto_41

    :goto_42
    invoke-static {}, Llyiahf/vczjk/a4a;->OooOOOo()Llyiahf/vczjk/ep8;

    move-result-object v0

    :goto_43
    new-instance v27, Llyiahf/vczjk/wp2;

    invoke-virtual {v1, v8, v0}, Llyiahf/vczjk/s90;->OooO0O0(Llyiahf/vczjk/gg8;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e5a;

    move-result-object v31

    const-class v28, Ljava/lang/Iterable;

    const/16 v32, 0x0

    const/16 v33, 0x1

    move-object/from16 v29, v0

    invoke-direct/range {v27 .. v33}, Llyiahf/vczjk/wp2;-><init>(Ljava/lang/Class;Llyiahf/vczjk/x64;ZLlyiahf/vczjk/e5a;Llyiahf/vczjk/zb4;I)V

    goto :goto_44

    :cond_a1
    const/4 v13, 0x1

    const/16 v16, 0x0

    const-class v0, Ljava/lang/CharSequence;

    invoke-virtual {v0, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_a2

    move-object/from16 v27, p4

    goto :goto_44

    :cond_a2
    const/16 v27, 0x0

    :goto_44
    if-nez v27, :cond_a5

    iget-object v0, v9, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    invoke-interface {v0}, Llyiahf/vczjk/lo;->size()I

    move-result v0

    if-lez v0, :cond_a3

    move v15, v13

    goto :goto_45

    :cond_a3
    move/from16 v15, v16

    :goto_45
    if-eqz v15, :cond_a5

    iget-object v0, v12, Llyiahf/vczjk/jb0;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/h90;

    iget-object v0, v0, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    new-instance v3, Llyiahf/vczjk/hb0;

    sget-object v4, Llyiahf/vczjk/ib0;->OooOOO:[Llyiahf/vczjk/gb0;

    const/4 v14, 0x0

    invoke-direct {v3, v0, v12, v4, v14}, Llyiahf/vczjk/ib0;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/jb0;[Llyiahf/vczjk/gb0;[Llyiahf/vczjk/gb0;)V

    :cond_a4
    move-object v15, v3

    goto :goto_46

    :cond_a5
    move-object/from16 v15, v27

    :goto_46
    if-nez v15, :cond_a6

    invoke-virtual {v7}, Llyiahf/vczjk/h90;->OooO0oO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v2, v0}, Llyiahf/vczjk/tg8;->o00000(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v4

    goto :goto_47

    :cond_a6
    move-object v4, v15

    goto :goto_47

    :catch_0
    move-exception v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v0

    iget-object v4, v7, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    filled-new-array {v4, v3, v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v3, "Failed to construct BeanSerializer for %s: (%s) %s"

    invoke-virtual {v2, v7, v3, v0}, Llyiahf/vczjk/tg8;->o00000oo(Llyiahf/vczjk/h90;Ljava/lang/String;[Ljava/lang/Object;)V

    const/16 v19, 0x0

    throw v19

    :cond_a7
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    iget-object v3, v12, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v3, Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    filled-new-array {v2, v3}, [Ljava/lang/Object;

    move-result-object v2

    const-string v3, "Trying to set %d filtered properties; must match length of non-filtered `properties` (%d)"

    invoke-static {v3, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v2

    invoke-direct {v0, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_a8
    move-object v4, v3

    goto :goto_47

    :cond_a9
    new-instance v0, Ljava/lang/ClassCastException;

    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    throw v0

    :cond_aa
    :goto_47
    if-eqz v4, :cond_ac

    iget-object v0, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v0}, Llyiahf/vczjk/sg8;->OooO00o()Z

    move-result v0

    if-eqz v0, :cond_ac

    iget-object v0, v1, Llyiahf/vczjk/s90;->_factoryConfig:Llyiahf/vczjk/sg8;

    invoke-virtual {v0}, Llyiahf/vczjk/sg8;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v2

    if-nez v2, :cond_ab

    return-object v4

    :cond_ab
    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0

    :cond_ac
    return-object v4

    :cond_ad
    invoke-static {v3}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object v0

    throw v0
.end method
