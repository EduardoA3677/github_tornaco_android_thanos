.class public final Llyiahf/vczjk/i76;
.super Llyiahf/vczjk/l66;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J = 0x2L


# instance fields
.field protected final _config:Llyiahf/vczjk/t72;

.field protected final _context:Llyiahf/vczjk/w12;

.field protected final _dataFormatReaders:Llyiahf/vczjk/nx1;

.field private final _filter:Llyiahf/vczjk/xt9;

.field protected final _injectableValues:Llyiahf/vczjk/mz3;

.field protected final _parserFactory:Llyiahf/vczjk/l94;

.field protected final _rootDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field

.field protected final _rootDeserializers:Ljava/util/concurrent/ConcurrentHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Llyiahf/vczjk/x64;",
            "Llyiahf/vczjk/e94;",
            ">;"
        }
    .end annotation
.end field

.field protected final _schema:Llyiahf/vczjk/zb3;

.field protected final _unwrapRoot:Z

.field protected final _valueToUpdate:Ljava/lang/Object;

.field protected final _valueType:Llyiahf/vczjk/x64;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/e76;Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;)V
    .locals 4

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/i76;->_config:Llyiahf/vczjk/t72;

    iget-object v0, p1, Llyiahf/vczjk/e76;->_deserializationContext:Llyiahf/vczjk/w12;

    iput-object v0, p0, Llyiahf/vczjk/i76;->_context:Llyiahf/vczjk/w12;

    iget-object v1, p1, Llyiahf/vczjk/e76;->_rootDeserializers:Ljava/util/concurrent/ConcurrentHashMap;

    iput-object v1, p0, Llyiahf/vczjk/i76;->_rootDeserializers:Ljava/util/concurrent/ConcurrentHashMap;

    iget-object p1, p1, Llyiahf/vczjk/e76;->_jsonFactory:Llyiahf/vczjk/l94;

    iput-object p1, p0, Llyiahf/vczjk/i76;->_parserFactory:Llyiahf/vczjk/l94;

    iput-object p3, p0, Llyiahf/vczjk/i76;->_valueType:Llyiahf/vczjk/x64;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/i76;->_valueToUpdate:Ljava/lang/Object;

    invoke-virtual {p2}, Llyiahf/vczjk/t72;->Oooo0O0()Z

    move-result v2

    iput-boolean v2, p0, Llyiahf/vczjk/i76;->_unwrapRoot:Z

    if-eqz p3, :cond_1

    sget-object v2, Llyiahf/vczjk/w72;->Oooo0o0:Llyiahf/vczjk/w72;

    invoke-virtual {p2, v2}, Llyiahf/vczjk/t72;->Oooo0(Llyiahf/vczjk/w72;)Z

    move-result v2

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v1, p3}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/e94;

    if-nez v2, :cond_2

    :try_start_0
    check-cast v0, Llyiahf/vczjk/v12;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v3, Llyiahf/vczjk/v12;

    invoke-direct {v3, v0, p2, p1}, Llyiahf/vczjk/v72;-><init>(Llyiahf/vczjk/v72;Llyiahf/vczjk/t72;Llyiahf/vczjk/eb4;)V

    invoke-virtual {v3, p3}, Llyiahf/vczjk/v72;->o00o0O(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v2

    if-eqz v2, :cond_2

    invoke-virtual {v1, p3, v2}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Llyiahf/vczjk/ib4; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :cond_1
    :goto_0
    move-object v2, p1

    :catch_0
    :cond_2
    :goto_1
    iput-object v2, p0, Llyiahf/vczjk/i76;->_rootDeserializer:Llyiahf/vczjk/e94;

    iput-object p1, p0, Llyiahf/vczjk/i76;->_filter:Llyiahf/vczjk/xt9;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/tt9;Ljava/lang/Object;)V
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "Not implemented for ObjectReader"

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/v12;)Llyiahf/vczjk/e94;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/i76;->_rootDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/i76;->_valueType:Llyiahf/vczjk/x64;

    const/4 v1, 0x0

    if-eqz v0, :cond_3

    iget-object v2, p0, Llyiahf/vczjk/i76;->_rootDeserializers:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v2, v0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/e94;

    if-eqz v2, :cond_1

    return-object v2

    :cond_1
    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o00o0O(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v2

    if-eqz v2, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/i76;->_rootDeserializers:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {p1, v0, v2}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object v2

    :cond_2
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Cannot find a deserializer for type "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1, v0, v2}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v1

    :cond_3
    const-string v0, "No value type configured for ObjectReader"

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v1
.end method

.method public final OooO0OO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v12;Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;)Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/i76;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v0, p3}, Llyiahf/vczjk/fc5;->OooOo0O(Llyiahf/vczjk/x64;)Llyiahf/vczjk/xa7;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/xa7;->_simpleName:Ljava/lang/String;

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOOO:Llyiahf/vczjk/gc4;

    const/4 v3, 0x0

    if-ne v1, v2, :cond_7

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-ne v1, v2, :cond_6

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_5

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    iget-object v1, p0, Llyiahf/vczjk/i76;->_valueToUpdate:Ljava/lang/Object;

    if-nez v1, :cond_0

    invoke-virtual {p4, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p4

    goto :goto_0

    :cond_0
    invoke-virtual {p4, p1, p2, v1}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object p4, p0, Llyiahf/vczjk/i76;->_valueToUpdate:Ljava/lang/Object;

    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    if-ne v1, v2, :cond_4

    iget-object p2, p0, Llyiahf/vczjk/i76;->_config:Llyiahf/vczjk/t72;

    sget-object p3, Llyiahf/vczjk/w72;->OooOoOO:Llyiahf/vczjk/w72;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/t72;->Oooo0(Llyiahf/vczjk/w72;)Z

    move-result p2

    if-eqz p2, :cond_3

    iget-object p2, p0, Llyiahf/vczjk/i76;->_valueType:Llyiahf/vczjk/x64;

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object p3

    if-eqz p3, :cond_3

    sget-object p4, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    if-nez p2, :cond_1

    move-object p2, v3

    goto :goto_1

    :cond_1
    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p2

    :goto_1
    if-nez p2, :cond_2

    iget-object p4, p0, Llyiahf/vczjk/i76;->_valueToUpdate:Ljava/lang/Object;

    if-eqz p4, :cond_2

    invoke-virtual {p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p2

    :cond_2
    invoke-static {p2, p1, p3}, Llyiahf/vczjk/v72;->o0000OOO(Ljava/lang/Class;Llyiahf/vczjk/eb4;Llyiahf/vczjk/gc4;)V

    throw v3

    :cond_3
    return-object p4

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object p1

    filled-new-array {v0, p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string p4, "Current token not END_OBJECT (to match wrapper object with root name \'%s\'), but %s"

    invoke-virtual {p2, p3, v2, p4, p1}, Llyiahf/vczjk/v72;->o0000OOo(Llyiahf/vczjk/x64;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v3

    :cond_5
    const-string p1, "Root name \'%s\' does not match expected (\'%s\') for type %s"

    filled-new-array {v1, v0, p3}, [Ljava/lang/Object;

    move-result-object p4

    invoke-virtual {p2, p3, v1, p1, p4}, Llyiahf/vczjk/v72;->o0000OO(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v3

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object p1

    filled-new-array {v0, p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string p4, "Current token not FIELD_NAME (to contain expected root name \'%s\'), but %s"

    invoke-virtual {p2, p3, v2, p4, p1}, Llyiahf/vczjk/v72;->o0000OOo(Llyiahf/vczjk/x64;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v3

    :cond_7
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object p1

    filled-new-array {v0, p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string p4, "Current token not START_OBJECT (needed to unwrap root name \'%s\'), but %s"

    invoke-virtual {p2, p3, v2, p4, p1}, Llyiahf/vczjk/v72;->o0000OOo(Llyiahf/vczjk/x64;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v3
.end method

.method public final OooO0Oo([B)Ljava/lang/Object;
    .locals 31

    move-object/from16 v1, p0

    move-object/from16 v4, p1

    const/16 v2, 0x10

    const/16 v3, 0x8

    const/4 v12, 0x1

    const/4 v13, 0x0

    if-eqz v4, :cond_26

    iget-object v8, v1, Llyiahf/vczjk/i76;->_parserFactory:Llyiahf/vczjk/l94;

    invoke-virtual {v8, v4, v12}, Llyiahf/vczjk/l94;->OooO00o(Ljava/lang/Object;Z)Llyiahf/vczjk/t01;

    move-result-object v15

    array-length v6, v4

    iget v4, v8, Llyiahf/vczjk/l94;->_parserFeatures:I

    iget-object v5, v8, Llyiahf/vczjk/l94;->_objectCodec:Llyiahf/vczjk/l66;

    iget v9, v8, Llyiahf/vczjk/l94;->_factoryFeatures:I

    add-int/lit8 v7, v6, 0x0

    const/4 v10, 0x4

    if-ge v7, v10, :cond_0

    move v7, v13

    goto :goto_0

    :cond_0
    move v7, v12

    :goto_0
    sget-object v11, Llyiahf/vczjk/i94;->OooOOO0:Llyiahf/vczjk/i94;

    const/4 v14, 0x2

    const v16, 0xff00

    const/16 v20, 0x0

    const-string v0, "Internal error"

    if-eqz v7, :cond_d

    aget-byte v7, p1, v13

    shl-int/lit8 v7, v7, 0x18

    add-int/lit8 v17, v13, 0x1

    move/from16 v21, v13

    aget-byte v13, p1, v17

    and-int/lit16 v13, v13, 0xff

    shl-int/2addr v13, v2

    or-int/2addr v7, v13

    add-int/lit8 v13, v21, 0x2

    move/from16 v17, v2

    aget-byte v2, p1, v13

    and-int/lit16 v2, v2, 0xff

    shl-int/2addr v2, v3

    or-int/2addr v2, v7

    add-int/lit8 v7, v21, 0x3

    move/from16 v18, v3

    aget-byte v3, p1, v7

    and-int/lit16 v3, v3, 0xff

    or-int/2addr v2, v3

    const/high16 v3, -0x1010000

    const-string v19, "3412"

    if-eq v2, v3, :cond_c

    const/high16 v3, -0x20000

    if-eq v2, v3, :cond_b

    const v3, 0xfeff

    if-eq v2, v3, :cond_a

    const-string v22, "2143"

    move/from16 v23, v10

    const v10, 0xfffe

    if-eq v2, v10, :cond_9

    move/from16 v24, v12

    ushr-int/lit8 v12, v2, 0x10

    if-ne v12, v3, :cond_1

    move v2, v14

    :goto_1
    move/from16 v3, v24

    goto :goto_4

    :cond_1
    if-ne v12, v10, :cond_2

    move v2, v14

    move/from16 v3, v21

    goto :goto_4

    :cond_2
    ushr-int/lit8 v3, v2, 0x8

    const v10, 0xefbbbf

    if-ne v3, v10, :cond_3

    move v13, v7

    move/from16 v2, v24

    move v3, v2

    goto :goto_4

    :cond_3
    shr-int/lit8 v3, v2, 0x8

    if-nez v3, :cond_4

    move/from16 v2, v24

    goto :goto_2

    :cond_4
    const v3, 0xffffff

    and-int/2addr v3, v2

    if-nez v3, :cond_5

    move/from16 v2, v21

    :goto_2
    move v3, v2

    move/from16 v13, v21

    :goto_3
    move/from16 v2, v23

    :goto_4
    move/from16 v7, v24

    goto/16 :goto_9

    :cond_5
    const v3, -0xff0001

    and-int/2addr v3, v2

    if-eqz v3, :cond_8

    const v3, -0xff01

    and-int/2addr v2, v3

    if-eqz v2, :cond_7

    and-int v2, v12, v16

    if-nez v2, :cond_6

    :goto_5
    move/from16 v2, v24

    goto :goto_7

    :cond_6
    and-int/lit16 v2, v12, 0xff

    if-nez v2, :cond_15

    :goto_6
    move/from16 v2, v21

    :goto_7
    move v3, v2

    move v2, v14

    move/from16 v13, v21

    goto :goto_4

    :cond_7
    invoke-static/range {v22 .. v22}, Llyiahf/vczjk/rs;->OoooOOO(Ljava/lang/String;)V

    throw v20

    :cond_8
    invoke-static/range {v19 .. v19}, Llyiahf/vczjk/rs;->OoooOOO(Ljava/lang/String;)V

    throw v20

    :cond_9
    invoke-static/range {v22 .. v22}, Llyiahf/vczjk/rs;->OoooOOO(Ljava/lang/String;)V

    throw v20

    :cond_a
    move/from16 v23, v10

    move/from16 v24, v12

    add-int/lit8 v13, v21, 0x4

    move/from16 v2, v23

    goto :goto_1

    :cond_b
    move/from16 v23, v10

    move/from16 v24, v12

    add-int/lit8 v13, v21, 0x4

    move/from16 v3, v21

    goto :goto_3

    :cond_c
    invoke-static/range {v19 .. v19}, Llyiahf/vczjk/rs;->OoooOOO(Ljava/lang/String;)V

    throw v20

    :cond_d
    move/from16 v17, v2

    move/from16 v18, v3

    move/from16 v23, v10

    move/from16 v24, v12

    move/from16 v21, v13

    add-int/lit8 v2, v6, 0x0

    if-ge v2, v14, :cond_e

    move/from16 v2, v21

    goto :goto_8

    :cond_e
    move/from16 v2, v24

    :goto_8
    if-eqz v2, :cond_15

    aget-byte v2, p1, v21

    and-int/lit16 v2, v2, 0xff

    shl-int/lit8 v2, v2, 0x8

    add-int/lit8 v13, v21, 0x1

    aget-byte v3, p1, v13

    and-int/lit16 v3, v3, 0xff

    or-int/2addr v2, v3

    and-int v3, v2, v16

    if-nez v3, :cond_f

    goto :goto_5

    :cond_f
    and-int/lit16 v2, v2, 0xff

    if-nez v2, :cond_15

    goto :goto_6

    :goto_9
    if-eq v2, v7, :cond_14

    if-eq v2, v14, :cond_12

    move/from16 v7, v23

    if-ne v2, v7, :cond_11

    if-eqz v3, :cond_10

    sget-object v2, Llyiahf/vczjk/i94;->OooOOOo:Llyiahf/vczjk/i94;

    goto :goto_a

    :cond_10
    sget-object v2, Llyiahf/vczjk/i94;->OooOOo0:Llyiahf/vczjk/i94;

    goto :goto_a

    :cond_11
    new-instance v2, Ljava/lang/RuntimeException;

    invoke-direct {v2, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw v2

    :cond_12
    if-eqz v3, :cond_13

    sget-object v2, Llyiahf/vczjk/i94;->OooOOO:Llyiahf/vczjk/i94;

    goto :goto_a

    :cond_13
    sget-object v2, Llyiahf/vczjk/i94;->OooOOOO:Llyiahf/vczjk/i94;

    goto :goto_a

    :cond_14
    move-object v2, v11

    goto :goto_a

    :cond_15
    move-object v2, v11

    move/from16 v13, v21

    :goto_a
    iput-object v2, v15, Llyiahf/vczjk/t01;->OooO0OO:Ljava/io/Serializable;

    if-ne v2, v11, :cond_16

    sget-object v2, Llyiahf/vczjk/k94;->OooOOO:Llyiahf/vczjk/k94;

    invoke-virtual {v2, v9}, Llyiahf/vczjk/k94;->OooO0O0(I)Z

    move-result v2

    if-eqz v2, :cond_16

    iget-object v0, v8, Llyiahf/vczjk/l94;->OooOOO:Llyiahf/vczjk/xl0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v25, Llyiahf/vczjk/xl0;

    sget-object v2, Llyiahf/vczjk/k94;->OooOOO0:Llyiahf/vczjk/k94;

    invoke-virtual {v2, v9}, Llyiahf/vczjk/k94;->OooO0O0(I)Z

    move-result v27

    sget-object v2, Llyiahf/vczjk/k94;->OooOOOO:Llyiahf/vczjk/k94;

    invoke-virtual {v2, v9}, Llyiahf/vczjk/k94;->OooO0O0(I)Z

    move-result v29

    iget-object v2, v0, Llyiahf/vczjk/xl0;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v2}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v2

    move-object/from16 v30, v2

    check-cast v30, Llyiahf/vczjk/wl0;

    iget v2, v0, Llyiahf/vczjk/xl0;->OooO0OO:I

    move-object/from16 v26, v0

    move/from16 v28, v2

    invoke-direct/range {v25 .. v30}, Llyiahf/vczjk/xl0;-><init>(Llyiahf/vczjk/xl0;ZIZLlyiahf/vczjk/wl0;)V

    new-instance v2, Llyiahf/vczjk/d7a;

    const/4 v11, 0x0

    move v10, v13

    move-object/from16 v7, p1

    move v9, v6

    move v8, v13

    move-object v3, v15

    move-object/from16 v6, v25

    invoke-direct/range {v2 .. v11}, Llyiahf/vczjk/d7a;-><init>(Llyiahf/vczjk/t01;ILlyiahf/vczjk/l66;Llyiahf/vczjk/xl0;[BIIIZ)V

    goto :goto_d

    :cond_16
    move/from16 v16, v4

    move-object v3, v15

    move/from16 v2, v18

    move-object/from16 v18, v5

    move v5, v13

    new-instance v14, Llyiahf/vczjk/ch7;

    iget-object v4, v3, Llyiahf/vczjk/t01;->OooO0OO:Ljava/io/Serializable;

    check-cast v4, Llyiahf/vczjk/i94;

    invoke-virtual {v4}, Llyiahf/vczjk/i94;->OooO00o()I

    move-result v7

    if-eq v7, v2, :cond_18

    move/from16 v2, v17

    if-eq v7, v2, :cond_18

    const/16 v2, 0x20

    if-ne v7, v2, :cond_17

    new-instance v2, Llyiahf/vczjk/b7a;

    iget-object v0, v3, Llyiahf/vczjk/t01;->OooO0OO:Ljava/io/Serializable;

    check-cast v0, Llyiahf/vczjk/i94;

    invoke-virtual {v0}, Llyiahf/vczjk/i94;->OooO0OO()Z

    move-result v7

    move-object/from16 v4, p1

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/b7a;-><init>(Llyiahf/vczjk/t01;[BIIZ)V

    :goto_b
    move-object/from16 v17, v2

    goto :goto_c

    :cond_17
    new-instance v2, Ljava/lang/RuntimeException;

    invoke-direct {v2, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw v2

    :cond_18
    move-object/from16 v7, p1

    new-instance v0, Ljava/io/ByteArrayInputStream;

    invoke-direct {v0, v7, v5, v6}, Ljava/io/ByteArrayInputStream;-><init>([BII)V

    new-instance v2, Ljava/io/InputStreamReader;

    invoke-virtual {v4}, Llyiahf/vczjk/i94;->OooO0O0()Ljava/lang/String;

    move-result-object v4

    invoke-direct {v2, v0, v4}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;Ljava/lang/String;)V

    goto :goto_b

    :goto_c
    new-instance v0, Llyiahf/vczjk/du0;

    iget-object v2, v8, Llyiahf/vczjk/l94;->OooOOO0:Llyiahf/vczjk/du0;

    iget-object v4, v2, Llyiahf/vczjk/du0;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/cu0;

    iget v5, v2, Llyiahf/vczjk/du0;->OooO0OO:I

    invoke-direct {v0, v2, v9, v5, v4}, Llyiahf/vczjk/du0;-><init>(Llyiahf/vczjk/du0;IILlyiahf/vczjk/cu0;)V

    move-object/from16 v19, v0

    move-object v15, v3

    invoke-direct/range {v14 .. v19}, Llyiahf/vczjk/ch7;-><init>(Llyiahf/vczjk/t01;ILjava/io/Reader;Llyiahf/vczjk/l66;Llyiahf/vczjk/du0;)V

    move-object v2, v14

    :goto_d
    iget-object v0, v1, Llyiahf/vczjk/i76;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/t72;->Oooo00O(Llyiahf/vczjk/eb4;)V

    iget-object v0, v1, Llyiahf/vczjk/i76;->_filter:Llyiahf/vczjk/xt9;

    if-eqz v0, :cond_1a

    const-class v0, Llyiahf/vczjk/c13;

    invoke-virtual {v0, v2}, Ljava/lang/Class;->isInstance(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_19

    goto :goto_e

    :cond_19
    new-instance v0, Llyiahf/vczjk/c13;

    iget-object v3, v1, Llyiahf/vczjk/i76;->_filter:Llyiahf/vczjk/xt9;

    invoke-direct {v0, v2}, Llyiahf/vczjk/fb4;-><init>(Llyiahf/vczjk/eb4;)V

    iput-object v3, v0, Llyiahf/vczjk/c13;->OooOOo:Llyiahf/vczjk/xt9;

    new-instance v2, Llyiahf/vczjk/yt9;

    move-object/from16 v5, v20

    move/from16 v4, v21

    const/4 v7, 0x1

    invoke-direct {v2, v4, v5, v3, v7}, Llyiahf/vczjk/yt9;-><init>(ILlyiahf/vczjk/yt9;Llyiahf/vczjk/xt9;Z)V

    iput-object v2, v0, Llyiahf/vczjk/c13;->OooOOOo:Llyiahf/vczjk/yt9;

    move-object v2, v0

    :cond_1a
    :goto_e
    :try_start_0
    iget-object v0, v1, Llyiahf/vczjk/i76;->_context:Llyiahf/vczjk/w12;

    iget-object v3, v1, Llyiahf/vczjk/i76;->_config:Llyiahf/vczjk/t72;

    check-cast v0, Llyiahf/vczjk/v12;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v4, Llyiahf/vczjk/v12;

    invoke-direct {v4, v0, v3, v2}, Llyiahf/vczjk/v72;-><init>(Llyiahf/vczjk/v72;Llyiahf/vczjk/t72;Llyiahf/vczjk/eb4;)V

    iget-object v0, v1, Llyiahf/vczjk/i76;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/t72;->Oooo00O(Llyiahf/vczjk/eb4;)V

    invoke-virtual {v2}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v0

    if-nez v0, :cond_1c

    invoke-virtual {v2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    if-eqz v0, :cond_1b

    goto :goto_f

    :cond_1b
    iget-object v0, v1, Llyiahf/vczjk/i76;->_valueType:Llyiahf/vczjk/x64;

    const-string v3, "No content to map due to end-of-input"

    new-instance v5, Llyiahf/vczjk/qj5;

    iget-object v4, v4, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {v5, v4, v3, v0}, Llyiahf/vczjk/qj5;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/x64;)V

    throw v5

    :cond_1c
    :goto_f
    sget-object v3, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v0, v3, :cond_1d

    iget-object v0, v1, Llyiahf/vczjk/i76;->_valueToUpdate:Ljava/lang/Object;

    if-nez v0, :cond_22

    invoke-virtual {v1, v4}, Llyiahf/vczjk/i76;->OooO0O0(Llyiahf/vczjk/v12;)Llyiahf/vczjk/e94;

    move-result-object v0

    invoke-virtual {v0, v4}, Llyiahf/vczjk/e94;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v0

    goto :goto_11

    :catchall_0
    move-exception v0

    move-object v3, v0

    goto :goto_13

    :cond_1d
    sget-object v3, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-eq v0, v3, :cond_21

    sget-object v3, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    if-ne v0, v3, :cond_1e

    goto :goto_10

    :cond_1e
    invoke-virtual {v1, v4}, Llyiahf/vczjk/i76;->OooO0O0(Llyiahf/vczjk/v12;)Llyiahf/vczjk/e94;

    move-result-object v0

    iget-boolean v3, v1, Llyiahf/vczjk/i76;->_unwrapRoot:Z

    if-eqz v3, :cond_1f

    iget-object v3, v1, Llyiahf/vczjk/i76;->_valueType:Llyiahf/vczjk/x64;

    invoke-virtual {v1, v2, v4, v3, v0}, Llyiahf/vczjk/i76;->OooO0OO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v12;Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;)Ljava/lang/Object;

    move-result-object v0

    goto :goto_11

    :cond_1f
    iget-object v3, v1, Llyiahf/vczjk/i76;->_valueToUpdate:Ljava/lang/Object;

    if-nez v3, :cond_20

    invoke-virtual {v0, v4, v2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v0

    goto :goto_11

    :cond_20
    invoke-virtual {v0, v2, v4, v3}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v0, v1, Llyiahf/vczjk/i76;->_valueToUpdate:Ljava/lang/Object;

    goto :goto_11

    :cond_21
    :goto_10
    iget-object v0, v1, Llyiahf/vczjk/i76;->_valueToUpdate:Ljava/lang/Object;

    :cond_22
    :goto_11
    iget-object v3, v1, Llyiahf/vczjk/i76;->_config:Llyiahf/vczjk/t72;

    sget-object v4, Llyiahf/vczjk/w72;->OooOoOO:Llyiahf/vczjk/w72;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/t72;->Oooo0(Llyiahf/vczjk/w72;)Z

    move-result v3

    if-eqz v3, :cond_25

    iget-object v3, v1, Llyiahf/vczjk/i76;->_valueType:Llyiahf/vczjk/x64;

    invoke-virtual {v2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v4

    if-eqz v4, :cond_25

    sget-object v0, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    if-nez v3, :cond_23

    const/4 v5, 0x0

    goto :goto_12

    :cond_23
    invoke-virtual {v3}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v5

    :goto_12
    if-nez v5, :cond_24

    iget-object v0, v1, Llyiahf/vczjk/i76;->_valueToUpdate:Ljava/lang/Object;

    if-eqz v0, :cond_24

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v5

    :cond_24
    invoke-static {v5, v2, v4}, Llyiahf/vczjk/v72;->o0000OOO(Ljava/lang/Class;Llyiahf/vczjk/eb4;Llyiahf/vczjk/gc4;)V

    const/16 v20, 0x0

    throw v20
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_25
    invoke-interface {v2}, Ljava/io/Closeable;->close()V

    return-object v0

    :goto_13
    :try_start_1
    throw v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception v0

    move-object v4, v0

    :try_start_2
    invoke-interface {v2}, Ljava/io/Closeable;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    goto :goto_14

    :catchall_2
    move-exception v0

    invoke-virtual {v3, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :goto_14
    throw v4

    :cond_26
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v2, "argument \"content\" is null"

    invoke-direct {v0, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
