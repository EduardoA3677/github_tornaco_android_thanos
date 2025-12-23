.class public abstract Llyiahf/vczjk/zl5;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/util/concurrent/ConcurrentHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    sput-object v0, Llyiahf/vczjk/zl5;->OooO00o:Ljava/util/concurrent/ConcurrentHashMap;

    return-void
.end method

.method public static final OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/gz7;
    .locals 36

    const/16 v3, 0x1d

    const/4 v4, 0x0

    const-string v5, "<this>"

    move-object/from16 v6, p0

    invoke-static {v6, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v6}, Llyiahf/vczjk/rl7;->OooO0Oo(Ljava/lang/Class;)Ljava/lang/ClassLoader;

    move-result-object v5

    new-instance v6, Llyiahf/vczjk/nla;

    invoke-direct {v6, v5}, Llyiahf/vczjk/nla;-><init>(Ljava/lang/ClassLoader;)V

    sget-object v7, Llyiahf/vczjk/zl5;->OooO00o:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v7, v6}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/lang/ref/WeakReference;

    if-eqz v8, :cond_1

    invoke-virtual {v8}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/gz7;

    if-eqz v9, :cond_0

    return-object v9

    :cond_0
    invoke-virtual {v7, v6, v8}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;Ljava/lang/Object;)Z

    :cond_1
    new-instance v13, Llyiahf/vczjk/tg7;

    invoke-direct {v13, v5, v3}, Llyiahf/vczjk/tg7;-><init>(Ljava/lang/Object;I)V

    new-instance v8, Llyiahf/vczjk/tg7;

    const-class v9, Llyiahf/vczjk/z8a;

    invoke-virtual {v9}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v9

    const-string v10, "getClassLoader(...)"

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v8, v9, v3}, Llyiahf/vczjk/tg7;-><init>(Ljava/lang/Object;I)V

    new-instance v12, Llyiahf/vczjk/bh6;

    invoke-direct {v12, v5}, Llyiahf/vczjk/bh6;-><init>(Ljava/lang/Object;)V

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v9, "runtime module for "

    invoke-direct {v3, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    sget-object v16, Llyiahf/vczjk/qp3;->OooOo00:Llyiahf/vczjk/qp3;

    sget-object v19, Llyiahf/vczjk/rp3;->OooOo0:Llyiahf/vczjk/rp3;

    const-string v5, "moduleName"

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v15, Llyiahf/vczjk/q45;

    const-string v5, "DeserializationComponentsForJava.ModuleData"

    invoke-direct {v15, v5}, Llyiahf/vczjk/q45;-><init>(Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/jd4;

    sget-object v9, Llyiahf/vczjk/hd4;->OooOOO0:[Llyiahf/vczjk/hd4;

    invoke-direct {v5, v15}, Llyiahf/vczjk/jd4;-><init>(Llyiahf/vczjk/q45;)V

    new-instance v9, Llyiahf/vczjk/dm5;

    new-instance v10, Ljava/lang/StringBuilder;

    const-string v11, "<"

    invoke-direct {v10, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v10, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v3, 0x3e

    invoke-virtual {v10, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/qt5;->OooO0oO(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v3

    const/16 v10, 0x38

    invoke-direct {v9, v3, v15, v5, v10}, Llyiahf/vczjk/dm5;-><init>(Llyiahf/vczjk/qt5;Llyiahf/vczjk/q45;Llyiahf/vczjk/hk4;I)V

    iget-object v3, v15, Llyiahf/vczjk/q45;->OooO00o:Llyiahf/vczjk/qo8;

    invoke-interface {v3}, Llyiahf/vczjk/qo8;->lock()V

    :try_start_0
    iget-object v10, v5, Llyiahf/vczjk/hk4;->OooO00o:Llyiahf/vczjk/dm5;

    if-nez v10, :cond_7

    iput-object v9, v5, Llyiahf/vczjk/hk4;->OooO00o:Llyiahf/vczjk/dm5;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-interface {v3}, Llyiahf/vczjk/qo8;->unlock()V

    new-instance v3, Llyiahf/vczjk/gd4;

    invoke-direct {v3, v9, v4}, Llyiahf/vczjk/gd4;-><init>(Llyiahf/vczjk/dm5;I)V

    iput-object v3, v5, Llyiahf/vczjk/jd4;->OooO0o:Llyiahf/vczjk/gd4;

    new-instance v14, Llyiahf/vczjk/l82;

    invoke-direct {v14}, Ljava/lang/Object;-><init>()V

    new-instance v20, Llyiahf/vczjk/as7;

    invoke-direct/range {v20 .. v20}, Ljava/lang/Object;-><init>()V

    new-instance v3, Llyiahf/vczjk/ld9;

    invoke-direct {v3, v15, v9}, Llyiahf/vczjk/ld9;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/cm5;)V

    sget-object v21, Llyiahf/vczjk/pp3;->OooOOoo:Llyiahf/vczjk/pp3;

    new-instance v10, Llyiahf/vczjk/s64;

    sget-object v11, Llyiahf/vczjk/xj0;->OooOo0O:Llyiahf/vczjk/xj0;

    sget-object v17, Llyiahf/vczjk/up3;->OooOOo0:Llyiahf/vczjk/up3;

    const/16 v34, 0x1

    new-instance v0, Llyiahf/vczjk/ws7;

    sget-object v33, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-direct {v0, v15}, Llyiahf/vczjk/ws7;-><init>(Llyiahf/vczjk/q45;)V

    sget-object v22, Llyiahf/vczjk/sp3;->OooOo00:Llyiahf/vczjk/sp3;

    sget-object v23, Llyiahf/vczjk/sp3;->OooOOo0:Llyiahf/vczjk/sp3;

    new-instance v1, Llyiahf/vczjk/fn7;

    invoke-direct {v1, v9, v3}, Llyiahf/vczjk/fn7;-><init>(Llyiahf/vczjk/dm5;Llyiahf/vczjk/ld9;)V

    new-instance v4, Llyiahf/vczjk/eo;

    sget-object v2, Llyiahf/vczjk/c74;->OooO0OO:Llyiahf/vczjk/c74;

    invoke-direct {v4, v2}, Llyiahf/vczjk/eo;-><init>(Llyiahf/vczjk/c74;)V

    move-object/from16 v18, v0

    new-instance v0, Llyiahf/vczjk/tp3;

    move-object/from16 v25, v1

    new-instance v1, Llyiahf/vczjk/tp3;

    sget-object v29, Llyiahf/vczjk/wp3;->OooOOo0:Llyiahf/vczjk/wp3;

    move-object/from16 v31, v2

    const/16 v2, 0x12

    invoke-direct {v1, v2}, Llyiahf/vczjk/tp3;-><init>(I)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/tp3;-><init>(Llyiahf/vczjk/tp3;)V

    sget-object v28, Llyiahf/vczjk/sp3;->OooOOOo:Llyiahf/vczjk/sp3;

    sget-object v1, Llyiahf/vczjk/u06;->OooO0O0:Llyiahf/vczjk/t06;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v27, Llyiahf/vczjk/t06;->OooO0O0:Llyiahf/vczjk/v06;

    new-instance v1, Llyiahf/vczjk/e86;

    const/16 v2, 0xf

    invoke-direct {v1, v2}, Llyiahf/vczjk/e86;-><init>(I)V

    move-object/from16 v24, v15

    move-object v15, v11

    move-object/from16 v11, v24

    move-object/from16 v32, v1

    move-object/from16 v26, v4

    move-object/from16 v24, v9

    move-object/from16 v30, v27

    move-object/from16 v27, v0

    invoke-direct/range {v10 .. v32}, Llyiahf/vczjk/s64;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/bh6;Llyiahf/vczjk/tg7;Llyiahf/vczjk/l82;Llyiahf/vczjk/xj0;Llyiahf/vczjk/qp3;Llyiahf/vczjk/up3;Llyiahf/vczjk/ws7;Llyiahf/vczjk/rp3;Llyiahf/vczjk/as7;Llyiahf/vczjk/pp3;Llyiahf/vczjk/sp3;Llyiahf/vczjk/sp3;Llyiahf/vczjk/dm5;Llyiahf/vczjk/fn7;Llyiahf/vczjk/eo;Llyiahf/vczjk/tp3;Llyiahf/vczjk/sp3;Llyiahf/vczjk/wp3;Llyiahf/vczjk/v06;Llyiahf/vczjk/c74;Llyiahf/vczjk/e86;)V

    move-object v15, v11

    move-object v1, v14

    move-object/from16 v2, v20

    move-object/from16 v0, v24

    move-object/from16 v31, v30

    new-instance v4, Llyiahf/vczjk/ur4;

    invoke-direct {v4, v10}, Llyiahf/vczjk/ur4;-><init>(Llyiahf/vczjk/s64;)V

    sget-object v9, Llyiahf/vczjk/yi5;->OooO0oO:Llyiahf/vczjk/yi5;

    const-string v10, "metadataVersion"

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v10, Llyiahf/vczjk/n62;

    const/4 v11, 0x0

    const/16 v12, 0x12

    invoke-direct {v10, v12, v13, v1, v11}, Llyiahf/vczjk/n62;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    new-instance v11, Llyiahf/vczjk/lr;

    invoke-direct {v11, v0, v3, v15, v13}, Llyiahf/vczjk/lr;-><init>(Llyiahf/vczjk/dm5;Llyiahf/vczjk/ld9;Llyiahf/vczjk/q45;Llyiahf/vczjk/tg7;)V

    iput-object v9, v11, Llyiahf/vczjk/lr;->OooOOoo:Ljava/lang/Object;

    sget-object v9, Llyiahf/vczjk/q42;->OooO00o:Llyiahf/vczjk/q42;

    invoke-static {v9}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v29

    iget-object v9, v0, Llyiahf/vczjk/dm5;->OooOOoo:Llyiahf/vczjk/hk4;

    instance-of v12, v9, Llyiahf/vczjk/jd4;

    if-eqz v12, :cond_2

    check-cast v9, Llyiahf/vczjk/jd4;

    goto :goto_0

    :cond_2
    const/4 v9, 0x0

    :goto_0
    new-instance v14, Llyiahf/vczjk/s72;

    sget-object v21, Llyiahf/vczjk/tp3;->OooOOo0:Llyiahf/vczjk/tp3;

    if-eqz v9, :cond_3

    invoke-virtual {v9}, Llyiahf/vczjk/jd4;->Oooo0OO()Llyiahf/vczjk/nd4;

    move-result-object v12

    if-eqz v12, :cond_3

    :goto_1
    move-object/from16 v24, v12

    goto :goto_2

    :cond_3
    sget-object v12, Llyiahf/vczjk/uk2;->OooOOO:Llyiahf/vczjk/uk2;

    goto :goto_1

    :goto_2
    if-eqz v9, :cond_4

    invoke-virtual {v9}, Llyiahf/vczjk/jd4;->Oooo0OO()Llyiahf/vczjk/nd4;

    move-result-object v9

    if-eqz v9, :cond_4

    :goto_3
    move-object/from16 v25, v9

    goto :goto_4

    :cond_4
    sget-object v9, Llyiahf/vczjk/up3;->OooOOoo:Llyiahf/vczjk/up3;

    goto :goto_3

    :goto_4
    sget-object v26, Llyiahf/vczjk/ve4;->OooO00o:Llyiahf/vczjk/iu2;

    new-instance v9, Llyiahf/vczjk/ws7;

    invoke-direct {v9, v15}, Llyiahf/vczjk/ws7;-><init>(Llyiahf/vczjk/q45;)V

    sget-object v30, Llyiahf/vczjk/uk2;->OooOOo:Llyiahf/vczjk/uk2;

    move-object/from16 v23, v3

    move-object/from16 v19, v4

    move-object/from16 v28, v9

    move-object/from16 v17, v10

    move-object/from16 v18, v11

    move-object/from16 v20, v16

    move-object/from16 v27, v31

    move-object/from16 v22, v33

    move-object/from16 v16, v0

    invoke-direct/range {v14 .. v30}, Llyiahf/vczjk/s72;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/cm5;Llyiahf/vczjk/wx0;Llyiahf/vczjk/hn;Llyiahf/vczjk/lh6;Llyiahf/vczjk/kq2;Llyiahf/vczjk/l23;Ljava/lang/Iterable;Llyiahf/vczjk/ld9;Llyiahf/vczjk/n1;Llyiahf/vczjk/cx6;Llyiahf/vczjk/iu2;Llyiahf/vczjk/u06;Llyiahf/vczjk/ws7;Ljava/util/List;Llyiahf/vczjk/mp2;)V

    iput-object v14, v1, Llyiahf/vczjk/l82;->OooO00o:Llyiahf/vczjk/s72;

    new-instance v9, Llyiahf/vczjk/uz5;

    const/16 v10, 0x15

    invoke-direct {v9, v4, v10}, Llyiahf/vczjk/uz5;-><init>(Ljava/lang/Object;I)V

    iput-object v9, v2, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    new-instance v2, Llyiahf/vczjk/pd4;

    invoke-virtual {v5}, Llyiahf/vczjk/jd4;->Oooo0OO()Llyiahf/vczjk/nd4;

    move-result-object v9

    invoke-virtual {v5}, Llyiahf/vczjk/jd4;->Oooo0OO()Llyiahf/vczjk/nd4;

    move-result-object v5

    new-instance v10, Llyiahf/vczjk/ws7;

    invoke-direct {v10, v15}, Llyiahf/vczjk/ws7;-><init>(Llyiahf/vczjk/q45;)V

    const-string v11, "additionalClassPartsProvider"

    invoke-static {v9, v11}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v11, "platformDependentDeclarationFilter"

    invoke-static {v5, v11}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v2, v15, v8, v0}, Llyiahf/vczjk/pd4;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/tg7;Llyiahf/vczjk/dm5;)V

    new-instance v20, Llyiahf/vczjk/s72;

    new-instance v8, Llyiahf/vczjk/vz5;

    const/16 v11, 0x10

    invoke-direct {v8, v2, v11}, Llyiahf/vczjk/vz5;-><init>(Ljava/lang/Object;I)V

    new-instance v11, Llyiahf/vczjk/era;

    sget-object v12, Llyiahf/vczjk/bk0;->OooOOO0:Llyiahf/vczjk/bk0;

    invoke-direct {v11, v0, v3, v12}, Llyiahf/vczjk/era;-><init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/ld9;Llyiahf/vczjk/bk0;)V

    move-object/from16 v25, v2

    new-instance v2, Llyiahf/vczjk/ak0;

    invoke-direct {v2, v15, v0}, Llyiahf/vczjk/ak0;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/dm5;)V

    move-object/from16 p0, v2

    new-instance v2, Llyiahf/vczjk/fd4;

    invoke-direct {v2, v15, v0}, Llyiahf/vczjk/fd4;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/dm5;)V

    move-object/from16 v24, v0

    move-object/from16 v16, v2

    const/4 v0, 0x2

    new-array v2, v0, [Llyiahf/vczjk/dy0;

    const/16 v35, 0x0

    aput-object p0, v2, v35

    aput-object v16, v2, v34

    invoke-static {v2}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v26

    iget-object v0, v12, Llyiahf/vczjk/qg8;->OooO00o:Llyiahf/vczjk/iu2;

    const/high16 v33, 0x40000

    move-object/from16 v30, v0

    move-object/from16 v27, v3

    move-object/from16 v29, v5

    move-object/from16 v23, v8

    move-object/from16 v28, v9

    move-object/from16 v32, v10

    move-object/from16 v21, v15

    move-object/from16 v22, v24

    move-object/from16 v24, v11

    invoke-direct/range {v20 .. v33}, Llyiahf/vczjk/s72;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/cm5;Llyiahf/vczjk/vz5;Llyiahf/vczjk/era;Llyiahf/vczjk/lh6;Ljava/lang/Iterable;Llyiahf/vczjk/ld9;Llyiahf/vczjk/n1;Llyiahf/vczjk/cx6;Llyiahf/vczjk/iu2;Llyiahf/vczjk/v06;Llyiahf/vczjk/ws7;I)V

    move-object/from16 v3, v20

    move-object/from16 v0, v22

    move-object/from16 v2, v25

    iput-object v3, v2, Llyiahf/vczjk/pd4;->OooO0OO:Llyiahf/vczjk/s72;

    filled-new-array {v0}, [Llyiahf/vczjk/dm5;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/sy;->o0000oO([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    new-instance v5, Llyiahf/vczjk/tg7;

    const/16 v8, 0x16

    invoke-direct {v5, v3, v8}, Llyiahf/vczjk/tg7;-><init>(Ljava/lang/Object;I)V

    iput-object v5, v0, Llyiahf/vczjk/dm5;->OooOo0O:Llyiahf/vczjk/tg7;

    new-instance v3, Llyiahf/vczjk/ig1;

    const/4 v5, 0x2

    new-array v5, v5, [Llyiahf/vczjk/lh6;

    const/16 v35, 0x0

    aput-object v4, v5, v35

    aput-object v2, v5, v34

    invoke-static {v5}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    new-instance v4, Ljava/lang/StringBuilder;

    const-string v5, "CompositeProvider@RuntimeModuleData for "

    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-direct {v3, v2, v4}, Llyiahf/vczjk/ig1;-><init>(Ljava/util/List;Ljava/lang/String;)V

    iput-object v3, v0, Llyiahf/vczjk/dm5;->OooOo0o:Llyiahf/vczjk/lh6;

    new-instance v0, Llyiahf/vczjk/gz7;

    new-instance v2, Llyiahf/vczjk/ed5;

    invoke-direct {v2, v1, v13}, Llyiahf/vczjk/ed5;-><init>(Llyiahf/vczjk/l82;Llyiahf/vczjk/tg7;)V

    invoke-direct {v0, v14, v2}, Llyiahf/vczjk/gz7;-><init>(Llyiahf/vczjk/s72;Llyiahf/vczjk/ed5;)V

    :goto_5
    new-instance v1, Ljava/lang/ref/WeakReference;

    invoke-direct {v1, v0}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    invoke-virtual {v7, v6, v1}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/ref/WeakReference;

    if-nez v1, :cond_5

    return-object v0

    :cond_5
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/gz7;

    if-eqz v2, :cond_6

    return-object v2

    :cond_6
    invoke-virtual {v7, v6, v1}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;Ljava/lang/Object;)Z

    goto :goto_5

    :cond_7
    move-object v0, v9

    :try_start_1
    new-instance v1, Ljava/lang/AssertionError;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v4, "Built-ins module is already set: "

    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v4, v5, Llyiahf/vczjk/hk4;->OooO00o:Llyiahf/vczjk/dm5;

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v4, " (attempting to reset to "

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, ")"

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v1, v0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :catchall_0
    move-exception v0

    :try_start_2
    iget-object v1, v15, Llyiahf/vczjk/q45;->OooO0O0:Llyiahf/vczjk/rp3;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    throw v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :catchall_1
    move-exception v0

    invoke-interface {v3}, Llyiahf/vczjk/qo8;->unlock()V

    throw v0
.end method
