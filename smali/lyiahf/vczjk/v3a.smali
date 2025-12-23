.class public abstract Llyiahf/vczjk/v3a;
.super Llyiahf/vczjk/u3a;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _baseType:Llyiahf/vczjk/x64;

.field protected final _defaultImpl:Llyiahf/vczjk/x64;

.field protected _defaultImplDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field

.field protected final _deserializers:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Llyiahf/vczjk/e94;",
            ">;"
        }
    .end annotation
.end field

.field protected final _idResolver:Llyiahf/vczjk/d4a;

.field protected final _property:Llyiahf/vczjk/db0;

.field protected final _typeIdVisible:Z

.field protected final _typePropertyName:Ljava/lang/String;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v3a;Llyiahf/vczjk/db0;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iget-object v0, p1, Llyiahf/vczjk/v3a;->_baseType:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/v3a;->_baseType:Llyiahf/vczjk/x64;

    iget-object v0, p1, Llyiahf/vczjk/v3a;->_idResolver:Llyiahf/vczjk/d4a;

    iput-object v0, p0, Llyiahf/vczjk/v3a;->_idResolver:Llyiahf/vczjk/d4a;

    iget-object v0, p1, Llyiahf/vczjk/v3a;->_typePropertyName:Ljava/lang/String;

    iput-object v0, p0, Llyiahf/vczjk/v3a;->_typePropertyName:Ljava/lang/String;

    iget-boolean v0, p1, Llyiahf/vczjk/v3a;->_typeIdVisible:Z

    iput-boolean v0, p0, Llyiahf/vczjk/v3a;->_typeIdVisible:Z

    iget-object v0, p1, Llyiahf/vczjk/v3a;->_deserializers:Ljava/util/Map;

    iput-object v0, p0, Llyiahf/vczjk/v3a;->_deserializers:Ljava/util/Map;

    iget-object v0, p1, Llyiahf/vczjk/v3a;->_defaultImpl:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/v3a;->_defaultImpl:Llyiahf/vczjk/x64;

    iget-object p1, p1, Llyiahf/vczjk/v3a;->_defaultImplDeserializer:Llyiahf/vczjk/e94;

    iput-object p1, p0, Llyiahf/vczjk/v3a;->_defaultImplDeserializer:Llyiahf/vczjk/e94;

    iput-object p2, p0, Llyiahf/vczjk/v3a;->_property:Llyiahf/vczjk/db0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/d4a;Ljava/lang/String;ZLlyiahf/vczjk/x64;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/v3a;->_baseType:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/v3a;->_idResolver:Llyiahf/vczjk/d4a;

    sget-object p1, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    if-nez p3, :cond_0

    const-string p3, ""

    :cond_0
    iput-object p3, p0, Llyiahf/vczjk/v3a;->_typePropertyName:Ljava/lang/String;

    iput-boolean p4, p0, Llyiahf/vczjk/v3a;->_typeIdVisible:Z

    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    const/high16 p2, 0x3f400000    # 0.75f

    const/4 p3, 0x2

    const/16 p4, 0x10

    invoke-direct {p1, p4, p2, p3}, Ljava/util/concurrent/ConcurrentHashMap;-><init>(IFI)V

    iput-object p1, p0, Llyiahf/vczjk/v3a;->_deserializers:Ljava/util/Map;

    iput-object p5, p0, Llyiahf/vczjk/v3a;->_defaultImpl:Llyiahf/vczjk/x64;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/v3a;->_property:Llyiahf/vczjk/db0;

    return-void
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/d4a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v3a;->_idResolver:Llyiahf/vczjk/d4a;

    return-object v0
.end method

.method public final OooO0oO()Ljava/lang/Class;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/v3a;->_defaultImpl:Llyiahf/vczjk/x64;

    sget-object v1, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0oo()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v3a;->_typePropertyName:Ljava/lang/String;

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    instance-of v0, p3, Ljava/lang/String;

    if-eqz v0, :cond_0

    check-cast p3, Ljava/lang/String;

    goto :goto_0

    :cond_0
    invoke-static {p3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p3

    :goto_0
    invoke-virtual {p0, p3, p2}, Llyiahf/vczjk/v3a;->OooOOO0(Ljava/lang/String;Llyiahf/vczjk/v72;)Llyiahf/vczjk/e94;

    move-result-object p3

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0o(Llyiahf/vczjk/v72;)Llyiahf/vczjk/e94;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/v3a;->_defaultImpl:Llyiahf/vczjk/x64;

    if-nez v0, :cond_1

    sget-object v0, Llyiahf/vczjk/w72;->OooOo00:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p1

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/c56;->OooOOOO:Llyiahf/vczjk/c56;

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooOOo(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_2

    sget-object p1, Llyiahf/vczjk/c56;->OooOOOO:Llyiahf/vczjk/c56;

    return-object p1

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/v3a;->_defaultImpl:Llyiahf/vczjk/x64;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/v3a;->_defaultImplDeserializer:Llyiahf/vczjk/e94;

    if-nez v1, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/v3a;->_defaultImpl:Llyiahf/vczjk/x64;

    iget-object v2, p0, Llyiahf/vczjk/v3a;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/v3a;->_defaultImplDeserializer:Llyiahf/vczjk/e94;

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_3
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/v3a;->_defaultImplDeserializer:Llyiahf/vczjk/e94;

    monitor-exit v0

    return-object p1

    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p1
.end method

.method public final OooOOO0(Ljava/lang/String;Llyiahf/vczjk/v72;)Llyiahf/vczjk/e94;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/v3a;->_deserializers:Ljava/util/Map;

    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/e94;

    if-nez v0, :cond_6

    iget-object v0, p0, Llyiahf/vczjk/v3a;->_idResolver:Llyiahf/vczjk/d4a;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/d4a;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/v72;)Llyiahf/vczjk/x64;

    move-result-object v0

    if-nez v0, :cond_2

    invoke-virtual {p0, p2}, Llyiahf/vczjk/v3a;->OooOO0o(Llyiahf/vczjk/v72;)Llyiahf/vczjk/e94;

    move-result-object v0

    if-nez v0, :cond_5

    iget-object v0, p0, Llyiahf/vczjk/v3a;->_idResolver:Llyiahf/vczjk/d4a;

    invoke-interface {v0}, Llyiahf/vczjk/d4a;->OooO0OO()Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_0

    const-string v0, "type ids are not statically known"

    goto :goto_0

    :cond_0
    const-string v1, "known type ids = "

    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/v3a;->_property:Llyiahf/vczjk/db0;

    if-eqz v1, :cond_1

    invoke-interface {v1}, Llyiahf/vczjk/yt5;->getName()Ljava/lang/String;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, " (for POJO property \'"

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, "\')"

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/v3a;->_baseType:Llyiahf/vczjk/x64;

    invoke-virtual {p2, v1, p1, v0}, Llyiahf/vczjk/v72;->o00000OO(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;)V

    sget-object p1, Llyiahf/vczjk/c56;->OooOOOO:Llyiahf/vczjk/c56;

    return-object p1

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/v3a;->_baseType:Llyiahf/vczjk/x64;

    if-eqz v1, :cond_4

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    if-ne v1, v2, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooOoO()Z

    move-result v1

    if-nez v1, :cond_4

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/v3a;->_baseType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v2

    if-eqz v2, :cond_3

    move-object v0, v1

    goto :goto_1

    :cond_3
    iget-object v2, p2, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v2}, Llyiahf/vczjk/ec5;->OooOOOO()Llyiahf/vczjk/a4a;

    move-result-object v2

    const/4 v3, 0x0

    invoke-virtual {v2, v1, v0, v3}, Llyiahf/vczjk/a4a;->OooOO0(Llyiahf/vczjk/x64;Ljava/lang/Class;Z)Llyiahf/vczjk/x64;

    move-result-object v0
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :catch_0
    move-exception v0

    iget-object v1, p0, Llyiahf/vczjk/v3a;->_baseType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2, v1, p1, v0}, Llyiahf/vczjk/v72;->Oooo(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/k44;

    move-result-object p1

    throw p1

    :cond_4
    :goto_1
    iget-object v1, p0, Llyiahf/vczjk/v3a;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {p2, v0, v1}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object v0

    :cond_5
    iget-object p2, p0, Llyiahf/vczjk/v3a;->_deserializers:Ljava/util/Map;

    invoke-interface {p2, p1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_6
    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "["

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "; base-type:"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/v3a;->_baseType:Llyiahf/vczjk/x64;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "; id-resolver: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/v3a;->_idResolver:Llyiahf/vczjk/d4a;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x5d

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
