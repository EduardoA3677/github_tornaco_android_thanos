.class public Llyiahf/vczjk/e76;
.super Llyiahf/vczjk/l66;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/w80;

.field private static final serialVersionUID:J = 0x2L


# instance fields
.field protected final _configOverrides:Llyiahf/vczjk/vh1;

.field protected _deserializationConfig:Llyiahf/vczjk/t72;

.field protected _deserializationContext:Llyiahf/vczjk/w12;

.field protected _injectableValues:Llyiahf/vczjk/mz3;

.field protected final _jsonFactory:Llyiahf/vczjk/l94;

.field protected _mixIns:Llyiahf/vczjk/ro8;

.field protected _registeredModuleTypes:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/Object;",
            ">;"
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

.field protected _serializationConfig:Llyiahf/vczjk/gg8;

.field protected _serializerFactory:Llyiahf/vczjk/rg8;

.field protected _serializerProvider:Llyiahf/vczjk/w32;

.field protected _subtypeResolver:Llyiahf/vczjk/k99;

.field protected _typeFactory:Llyiahf/vczjk/a4a;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    new-instance v2, Llyiahf/vczjk/r54;

    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/kl4;

    const/16 v1, 0x30

    invoke-direct {v0, v1, v1}, Llyiahf/vczjk/kl4;-><init>(II)V

    iput-object v0, v2, Llyiahf/vczjk/r54;->OooOOO0:Llyiahf/vczjk/kl4;

    const/4 v0, 0x1

    iput-boolean v0, v2, Llyiahf/vczjk/r54;->_cfgConstructorPropertiesImpliesCreator:Z

    new-instance v0, Llyiahf/vczjk/w80;

    sget-object v3, Llyiahf/vczjk/a4a;->OooOOO:Llyiahf/vczjk/a4a;

    sget-object v5, Llyiahf/vczjk/j49;->OooOo0O:Llyiahf/vczjk/j49;

    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    move-result-object v6

    sget-object v8, Llyiahf/vczjk/a60;->OooO0O0:Llyiahf/vczjk/z50;

    sget-object v9, Llyiahf/vczjk/qm4;->OooOOO0:Llyiahf/vczjk/qm4;

    const/4 v4, 0x0

    const/4 v7, 0x0

    const/4 v1, 0x0

    invoke-direct/range {v0 .. v9}, Llyiahf/vczjk/w80;-><init>(Llyiahf/vczjk/l90;Llyiahf/vczjk/yn;Llyiahf/vczjk/a4a;Llyiahf/vczjk/b5a;Ljava/text/DateFormat;Ljava/util/Locale;Ljava/util/TimeZone;Llyiahf/vczjk/z50;Llyiahf/vczjk/zy6;)V

    sput-object v0, Llyiahf/vczjk/e76;->OooOOO0:Llyiahf/vczjk/w80;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/l94;)V
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    new-instance v2, Ljava/util/concurrent/ConcurrentHashMap;

    const/4 v3, 0x2

    const/16 v4, 0x40

    const v5, 0x3f19999a    # 0.6f

    invoke-direct {v2, v4, v5, v3}, Ljava/util/concurrent/ConcurrentHashMap;-><init>(IFI)V

    iput-object v2, v0, Llyiahf/vczjk/e76;->_rootDeserializers:Ljava/util/concurrent/ConcurrentHashMap;

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/ic5;

    invoke-direct {v1, v0}, Llyiahf/vczjk/l94;-><init>(Llyiahf/vczjk/e76;)V

    iput-object v1, v0, Llyiahf/vczjk/e76;->_jsonFactory:Llyiahf/vczjk/l94;

    goto :goto_0

    :cond_0
    iput-object v1, v0, Llyiahf/vczjk/e76;->_jsonFactory:Llyiahf/vczjk/l94;

    invoke-virtual {v1}, Llyiahf/vczjk/l94;->OooO0Oo()Llyiahf/vczjk/l66;

    move-result-object v2

    if-nez v2, :cond_1

    iput-object v0, v1, Llyiahf/vczjk/l94;->_objectCodec:Llyiahf/vczjk/l66;

    :cond_1
    :goto_0
    new-instance v1, Llyiahf/vczjk/c59;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    iput-object v1, v0, Llyiahf/vczjk/e76;->_subtypeResolver:Llyiahf/vczjk/k99;

    new-instance v6, Llyiahf/vczjk/cv7;

    invoke-direct {v6}, Llyiahf/vczjk/cv7;-><init>()V

    sget-object v1, Llyiahf/vczjk/a4a;->OooOOO:Llyiahf/vczjk/a4a;

    iput-object v1, v0, Llyiahf/vczjk/e76;->_typeFactory:Llyiahf/vczjk/a4a;

    new-instance v5, Llyiahf/vczjk/ro8;

    invoke-direct {v5}, Llyiahf/vczjk/ro8;-><init>()V

    iput-object v5, v0, Llyiahf/vczjk/e76;->_mixIns:Llyiahf/vczjk/ro8;

    new-instance v8, Llyiahf/vczjk/l90;

    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    sget-object v1, Llyiahf/vczjk/e76;->OooOOO0:Llyiahf/vczjk/w80;

    iget-object v2, v1, Llyiahf/vczjk/w80;->_classIntrospector:Llyiahf/vczjk/jy0;

    if-ne v2, v8, :cond_2

    move-object v3, v1

    goto :goto_1

    :cond_2
    new-instance v7, Llyiahf/vczjk/w80;

    iget-object v9, v1, Llyiahf/vczjk/w80;->_annotationIntrospector:Llyiahf/vczjk/yn;

    iget-object v10, v1, Llyiahf/vczjk/w80;->_typeFactory:Llyiahf/vczjk/a4a;

    iget-object v11, v1, Llyiahf/vczjk/w80;->_typeResolverBuilder:Llyiahf/vczjk/b5a;

    iget-object v12, v1, Llyiahf/vczjk/w80;->_dateFormat:Ljava/text/DateFormat;

    iget-object v13, v1, Llyiahf/vczjk/w80;->_locale:Ljava/util/Locale;

    iget-object v14, v1, Llyiahf/vczjk/w80;->_timeZone:Ljava/util/TimeZone;

    iget-object v15, v1, Llyiahf/vczjk/w80;->_defaultBase64:Llyiahf/vczjk/z50;

    iget-object v1, v1, Llyiahf/vczjk/w80;->_typeValidator:Llyiahf/vczjk/zy6;

    move-object/from16 v16, v1

    invoke-direct/range {v7 .. v16}, Llyiahf/vczjk/w80;-><init>(Llyiahf/vczjk/l90;Llyiahf/vczjk/yn;Llyiahf/vczjk/a4a;Llyiahf/vczjk/b5a;Ljava/text/DateFormat;Ljava/util/Locale;Ljava/util/TimeZone;Llyiahf/vczjk/z50;Llyiahf/vczjk/zy6;)V

    move-object v3, v7

    :goto_1
    new-instance v7, Llyiahf/vczjk/vh1;

    sget-object v1, Llyiahf/vczjk/fa4;->OooOOO0:Llyiahf/vczjk/fa4;

    sget-object v2, Llyiahf/vczjk/ac4;->OooOOO0:Llyiahf/vczjk/ac4;

    sget-object v4, Llyiahf/vczjk/fka;->OooOOO0:Llyiahf/vczjk/fka;

    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    const/4 v8, 0x0

    iput-object v8, v7, Llyiahf/vczjk/vh1;->_overrides:Ljava/util/Map;

    iput-object v1, v7, Llyiahf/vczjk/vh1;->_defaultInclusion:Llyiahf/vczjk/fa4;

    iput-object v2, v7, Llyiahf/vczjk/vh1;->_defaultSetterInfo:Llyiahf/vczjk/ac4;

    iput-object v4, v7, Llyiahf/vczjk/vh1;->_visibilityChecker:Llyiahf/vczjk/gka;

    iput-object v8, v7, Llyiahf/vczjk/vh1;->_defaultMergeable:Ljava/lang/Boolean;

    iput-object v8, v7, Llyiahf/vczjk/vh1;->_defaultLeniency:Ljava/lang/Boolean;

    iput-object v7, v0, Llyiahf/vczjk/e76;->_configOverrides:Llyiahf/vczjk/vh1;

    new-instance v2, Llyiahf/vczjk/gg8;

    iget-object v4, v0, Llyiahf/vczjk/e76;->_subtypeResolver:Llyiahf/vczjk/k99;

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/gg8;-><init>(Llyiahf/vczjk/w80;Llyiahf/vczjk/k99;Llyiahf/vczjk/ro8;Llyiahf/vczjk/cv7;Llyiahf/vczjk/vh1;)V

    iput-object v2, v0, Llyiahf/vczjk/e76;->_serializationConfig:Llyiahf/vczjk/gg8;

    new-instance v2, Llyiahf/vczjk/t72;

    iget-object v4, v0, Llyiahf/vczjk/e76;->_subtypeResolver:Llyiahf/vczjk/k99;

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/t72;-><init>(Llyiahf/vczjk/w80;Llyiahf/vczjk/k99;Llyiahf/vczjk/ro8;Llyiahf/vczjk/cv7;Llyiahf/vczjk/vh1;)V

    iput-object v2, v0, Llyiahf/vczjk/e76;->_deserializationConfig:Llyiahf/vczjk/t72;

    iget-object v1, v0, Llyiahf/vczjk/e76;->_jsonFactory:Llyiahf/vczjk/l94;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, v0, Llyiahf/vczjk/e76;->_serializationConfig:Llyiahf/vczjk/gg8;

    sget-object v2, Llyiahf/vczjk/gc5;->OooOooO:Llyiahf/vczjk/gc5;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v1

    if-eqz v1, :cond_3

    iget-object v1, v0, Llyiahf/vczjk/e76;->_serializationConfig:Llyiahf/vczjk/gg8;

    filled-new-array {v2}, [Llyiahf/vczjk/gc5;

    move-result-object v3

    invoke-virtual {v1, v3}, Llyiahf/vczjk/fc5;->Oooo000([Llyiahf/vczjk/gc5;)Llyiahf/vczjk/fc5;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/gg8;

    iput-object v1, v0, Llyiahf/vczjk/e76;->_serializationConfig:Llyiahf/vczjk/gg8;

    iget-object v1, v0, Llyiahf/vczjk/e76;->_deserializationConfig:Llyiahf/vczjk/t72;

    filled-new-array {v2}, [Llyiahf/vczjk/gc5;

    move-result-object v2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/fc5;->Oooo000([Llyiahf/vczjk/gc5;)Llyiahf/vczjk/fc5;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/t72;

    iput-object v1, v0, Llyiahf/vczjk/e76;->_deserializationConfig:Llyiahf/vczjk/t72;

    :cond_3
    new-instance v1, Llyiahf/vczjk/v32;

    invoke-direct {v1}, Llyiahf/vczjk/tg8;-><init>()V

    iput-object v1, v0, Llyiahf/vczjk/e76;->_serializerProvider:Llyiahf/vczjk/w32;

    new-instance v1, Llyiahf/vczjk/v12;

    sget-object v2, Llyiahf/vczjk/ab0;->OooOOO0:[Ljava/lang/Class;

    invoke-direct {v1}, Llyiahf/vczjk/v72;-><init>()V

    iput-object v1, v0, Llyiahf/vczjk/e76;->_deserializationContext:Llyiahf/vczjk/w12;

    sget-object v1, Llyiahf/vczjk/kb0;->OooOOOO:Llyiahf/vczjk/kb0;

    iput-object v1, v0, Llyiahf/vczjk/e76;->_serializerFactory:Llyiahf/vczjk/rg8;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/tt9;Ljava/lang/Object;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/e76;->_serializationConfig:Llyiahf/vczjk/gg8;

    sget-object v1, Llyiahf/vczjk/ig8;->OooOOO:Llyiahf/vczjk/ig8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/gg8;->Oooo0(Llyiahf/vczjk/ig8;)Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, p1, Llyiahf/vczjk/u94;->OooOOO0:Llyiahf/vczjk/u37;

    if-nez v1, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/gg8;->_defaultPrettyPrinter:Llyiahf/vczjk/u37;

    instance-of v2, v1, Llyiahf/vczjk/l14;

    if-eqz v2, :cond_0

    check-cast v1, Llyiahf/vczjk/l14;

    check-cast v1, Llyiahf/vczjk/j32;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/j32;

    invoke-direct {v2, v1}, Llyiahf/vczjk/j32;-><init>(Llyiahf/vczjk/j32;)V

    move-object v1, v2

    :cond_0
    iput-object v1, p1, Llyiahf/vczjk/u94;->OooOOO0:Llyiahf/vczjk/u37;

    :cond_1
    sget-object v1, Llyiahf/vczjk/ig8;->OooOo00:Llyiahf/vczjk/ig8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/gg8;->Oooo0(Llyiahf/vczjk/ig8;)Z

    move-result v1

    if-eqz v1, :cond_2

    instance-of v1, p2, Ljava/io/Closeable;

    if-eqz v1, :cond_2

    move-object v1, p2

    check-cast v1, Ljava/io/Closeable;

    :try_start_0
    invoke-virtual {p0, v0}, Llyiahf/vczjk/e76;->OooO0OO(Llyiahf/vczjk/gg8;)Llyiahf/vczjk/v32;

    move-result-object v2

    invoke-virtual {v2, p1, p2}, Llyiahf/vczjk/w32;->o0000oO(Llyiahf/vczjk/u94;Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/ig8;->OooOo0:Llyiahf/vczjk/ig8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/gg8;->Oooo0(Llyiahf/vczjk/ig8;)Z
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    invoke-interface {v1}, Ljava/io/Closeable;->close()V

    return-void

    :catch_0
    move-exception p1

    const/4 p2, 0x0

    invoke-static {p2, v1, p1}, Llyiahf/vczjk/vy0;->OooO0o(Llyiahf/vczjk/u94;Ljava/io/Closeable;Ljava/lang/Exception;)V

    throw p2

    :cond_2
    invoke-virtual {p0, v0}, Llyiahf/vczjk/e76;->OooO0OO(Llyiahf/vczjk/gg8;)Llyiahf/vczjk/v32;

    move-result-object v1

    invoke-virtual {v1, p1, p2}, Llyiahf/vczjk/w32;->o0000oO(Llyiahf/vczjk/u94;Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/ig8;->OooOo0:Llyiahf/vczjk/ig8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/gg8;->Oooo0(Llyiahf/vczjk/ig8;)Z

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/v12;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/e76;->_rootDeserializers:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v0, p2}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/e94;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    invoke-virtual {p1, p2}, Llyiahf/vczjk/v72;->o00o0O(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v0

    if-eqz v0, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/e76;->_rootDeserializers:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {p1, p2, v0}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object v0

    :cond_1
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Cannot find a deserializer for type "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/gg8;)Llyiahf/vczjk/v32;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/e76;->_serializerProvider:Llyiahf/vczjk/w32;

    iget-object v1, p0, Llyiahf/vczjk/e76;->_serializerFactory:Llyiahf/vczjk/rg8;

    check-cast v0, Llyiahf/vczjk/v32;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/v32;

    invoke-direct {v2, v0, p1, v1}, Llyiahf/vczjk/tg8;-><init>(Llyiahf/vczjk/tg8;Llyiahf/vczjk/gg8;Llyiahf/vczjk/rg8;)V

    return-object v2
.end method

.method public final OooO0Oo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v12;Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;)Ljava/lang/Object;
    .locals 4

    invoke-virtual {p3, p4}, Llyiahf/vczjk/fc5;->OooOo0O(Llyiahf/vczjk/x64;)Llyiahf/vczjk/xa7;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/xa7;->_simpleName:Ljava/lang/String;

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOOO:Llyiahf/vczjk/gc4;

    const/4 v3, 0x0

    if-ne v1, v2, :cond_6

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-ne v1, v2, :cond_5

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    invoke-virtual {p5, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p5

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    if-ne v1, v2, :cond_3

    sget-object p2, Llyiahf/vczjk/w72;->OooOoOO:Llyiahf/vczjk/w72;

    invoke-virtual {p3, p2}, Llyiahf/vczjk/t72;->Oooo0(Llyiahf/vczjk/w72;)Z

    move-result p2

    if-eqz p2, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object p2

    if-nez p2, :cond_0

    goto :goto_1

    :cond_0
    sget-object p3, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    if-nez p4, :cond_1

    move-object p3, v3

    goto :goto_0

    :cond_1
    invoke-virtual {p4}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p3

    :goto_0
    invoke-static {p3, p1, p2}, Llyiahf/vczjk/v72;->o0000OOO(Ljava/lang/Class;Llyiahf/vczjk/eb4;Llyiahf/vczjk/gc4;)V

    throw v3

    :cond_2
    :goto_1
    return-object p5

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object p1

    filled-new-array {v0, p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string p3, "Current token not END_OBJECT (to match wrapper object with root name \'%s\'), but %s"

    invoke-virtual {p2, p4, v2, p3, p1}, Llyiahf/vczjk/v72;->o0000OOo(Llyiahf/vczjk/x64;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v3

    :cond_4
    const-string p1, "Root name \'%s\' does not match expected (\'%s\') for type %s"

    filled-new-array {v1, v0, p4}, [Ljava/lang/Object;

    move-result-object p3

    invoke-virtual {p2, p4, v1, p1, p3}, Llyiahf/vczjk/v72;->o0000OO(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v3

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object p1

    filled-new-array {v0, p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string p3, "Current token not FIELD_NAME (to contain expected root name \'%s\'), but %s"

    invoke-virtual {p2, p4, v2, p3, p1}, Llyiahf/vczjk/v72;->o0000OOo(Llyiahf/vczjk/x64;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v3

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object p1

    filled-new-array {v0, p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string p3, "Current token not START_OBJECT (needed to unwrap root name \'%s\'), but %s"

    invoke-virtual {p2, p4, v2, p3, p1}, Llyiahf/vczjk/v72;->o0000OOo(Llyiahf/vczjk/x64;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v3
.end method

.method public final OooO0o(Llyiahf/vczjk/y70;)[B
    .locals 4

    new-instance v0, Llyiahf/vczjk/pl0;

    iget-object v1, p0, Llyiahf/vczjk/e76;->_jsonFactory:Llyiahf/vczjk/l94;

    invoke-virtual {v1}, Llyiahf/vczjk/l94;->OooO0O0()Llyiahf/vczjk/bj0;

    move-result-object v1

    invoke-direct {v0, v1}, Llyiahf/vczjk/pl0;-><init>(Llyiahf/vczjk/bj0;)V

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/e76;->_jsonFactory:Llyiahf/vczjk/l94;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/l94;->OooO0OO(Llyiahf/vczjk/pl0;)Llyiahf/vczjk/u94;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/e76;->_serializationConfig:Llyiahf/vczjk/gg8;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/gg8;->Oooo00O(Llyiahf/vczjk/u94;)V

    invoke-virtual {p0, v1, p1}, Llyiahf/vczjk/e76;->OooO0o0(Llyiahf/vczjk/u94;Llyiahf/vczjk/y70;)V
    :try_end_0
    .catch Llyiahf/vczjk/ib4; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    invoke-virtual {v0}, Llyiahf/vczjk/pl0;->OooOoO()[B

    move-result-object p1

    invoke-virtual {v0}, Llyiahf/vczjk/pl0;->reset()V

    iget-object v1, v0, Llyiahf/vczjk/pl0;->OooOOO0:Llyiahf/vczjk/bj0;

    if-eqz v1, :cond_0

    iget-object v2, v0, Llyiahf/vczjk/pl0;->OooOOOo:[B

    if-eqz v2, :cond_0

    iget-object v1, v1, Llyiahf/vczjk/bj0;->OooO00o:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    const/4 v3, 0x2

    invoke-virtual {v1, v3, v2}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->set(ILjava/lang/Object;)V

    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/pl0;->OooOOOo:[B

    :cond_0
    return-object p1

    :catch_0
    move-exception p1

    goto :goto_0

    :catch_1
    move-exception p1

    goto :goto_1

    :goto_0
    invoke-static {p1}, Llyiahf/vczjk/na4;->OooO0o0(Ljava/io/IOException;)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1

    :goto_1
    throw p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/u94;Llyiahf/vczjk/y70;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/e76;->_serializationConfig:Llyiahf/vczjk/gg8;

    sget-object v1, Llyiahf/vczjk/ig8;->OooOo00:Llyiahf/vczjk/ig8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/gg8;->Oooo0(Llyiahf/vczjk/ig8;)Z

    move-result v1

    if-eqz v1, :cond_0

    instance-of v1, p2, Ljava/io/Closeable;

    if-eqz v1, :cond_0

    move-object v1, p2

    check-cast v1, Ljava/io/Closeable;

    const/4 v2, 0x0

    :try_start_0
    invoke-virtual {p0, v0}, Llyiahf/vczjk/e76;->OooO0OO(Llyiahf/vczjk/gg8;)Llyiahf/vczjk/v32;

    move-result-object v0

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/w32;->o0000oO(Llyiahf/vczjk/u94;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    :try_start_1
    invoke-interface {v1}, Ljava/io/Closeable;->close()V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    invoke-virtual {p1}, Llyiahf/vczjk/u94;->close()V

    return-void

    :catch_0
    move-exception p2

    move-object v1, v2

    goto :goto_0

    :catch_1
    move-exception p2

    :goto_0
    invoke-static {p1, v1, p2}, Llyiahf/vczjk/vy0;->OooO0o(Llyiahf/vczjk/u94;Ljava/io/Closeable;Ljava/lang/Exception;)V

    throw v2

    :cond_0
    :try_start_2
    invoke-virtual {p0, v0}, Llyiahf/vczjk/e76;->OooO0OO(Llyiahf/vczjk/gg8;)Llyiahf/vczjk/v32;

    move-result-object v0

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/w32;->o0000oO(Llyiahf/vczjk/u94;Ljava/lang/Object;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    invoke-virtual {p1}, Llyiahf/vczjk/u94;->close()V

    return-void

    :catch_2
    move-exception p2

    sget-object v0, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    sget-object v0, Llyiahf/vczjk/t94;->OooOOO:Llyiahf/vczjk/t94;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u94;->OooOoO(Llyiahf/vczjk/t94;)Llyiahf/vczjk/u94;

    :try_start_3
    invoke-virtual {p1}, Llyiahf/vczjk/u94;->close()V
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_3

    goto :goto_1

    :catch_3
    move-exception p1

    invoke-virtual {p2, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :goto_1
    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOoO0(Ljava/lang/Throwable;)V

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    new-instance p1, Ljava/lang/RuntimeException;

    invoke-direct {p1, p2}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw p1
.end method

.method public final OooO0oO()Llyiahf/vczjk/m76;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/e76;->_serializationConfig:Llyiahf/vczjk/gg8;

    new-instance v1, Llyiahf/vczjk/m76;

    invoke-direct {v1, p0, v0}, Llyiahf/vczjk/m76;-><init>(Llyiahf/vczjk/e76;Llyiahf/vczjk/gg8;)V

    return-object v1
.end method
