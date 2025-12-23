.class public abstract Llyiahf/vczjk/tg8;
.super Llyiahf/vczjk/mc4;
.source "SourceFile"


# static fields
.field public static final OooOoO:Llyiahf/vczjk/s46;

.field public static final OooOoO0:Llyiahf/vczjk/sv2;


# instance fields
.field public transient OooOo:Llyiahf/vczjk/jn1;

.field protected final _config:Llyiahf/vczjk/gg8;

.field protected _dateFormat:Ljava/text/DateFormat;

.field protected _keySerializer:Llyiahf/vczjk/zb4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zb4;"
        }
    .end annotation
.end field

.field protected final _knownSerializers:Llyiahf/vczjk/zg7;

.field protected _nullKeySerializer:Llyiahf/vczjk/zb4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zb4;"
        }
    .end annotation
.end field

.field protected _nullValueSerializer:Llyiahf/vczjk/zb4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zb4;"
        }
    .end annotation
.end field

.field protected final _serializationView:Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation
.end field

.field protected final _serializerCache:Llyiahf/vczjk/pg8;

.field protected final _serializerFactory:Llyiahf/vczjk/rg8;

.field protected final _stdNullValueSerializer:Z

.field protected _unknownTypeSerializer:Llyiahf/vczjk/zb4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zb4;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/sv2;

    invoke-direct {v0}, Llyiahf/vczjk/sv2;-><init>()V

    sput-object v0, Llyiahf/vczjk/tg8;->OooOoO0:Llyiahf/vczjk/sv2;

    new-instance v0, Llyiahf/vczjk/s46;

    const/4 v1, 0x5

    invoke-direct {v0, v1}, Llyiahf/vczjk/s46;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/tg8;->OooOoO:Llyiahf/vczjk/s46;

    return-void
.end method

.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v0, Llyiahf/vczjk/tg8;->OooOoO:Llyiahf/vczjk/s46;

    iput-object v0, p0, Llyiahf/vczjk/tg8;->_unknownTypeSerializer:Llyiahf/vczjk/zb4;

    sget-object v0, Llyiahf/vczjk/s46;->OooOOOO:Llyiahf/vczjk/s46;

    iput-object v0, p0, Llyiahf/vczjk/tg8;->_nullValueSerializer:Llyiahf/vczjk/zb4;

    sget-object v0, Llyiahf/vczjk/tg8;->OooOoO0:Llyiahf/vczjk/sv2;

    iput-object v0, p0, Llyiahf/vczjk/tg8;->_nullKeySerializer:Llyiahf/vczjk/zb4;

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    iput-object v0, p0, Llyiahf/vczjk/tg8;->_serializerFactory:Llyiahf/vczjk/rg8;

    new-instance v1, Llyiahf/vczjk/pg8;

    invoke-direct {v1}, Llyiahf/vczjk/pg8;-><init>()V

    iput-object v1, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    iput-object v0, p0, Llyiahf/vczjk/tg8;->_knownSerializers:Llyiahf/vczjk/zg7;

    iput-object v0, p0, Llyiahf/vczjk/tg8;->_serializationView:Ljava/lang/Class;

    iput-object v0, p0, Llyiahf/vczjk/tg8;->OooOo:Llyiahf/vczjk/jn1;

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/tg8;->_stdNullValueSerializer:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/tg8;Llyiahf/vczjk/gg8;Llyiahf/vczjk/rg8;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v0, Llyiahf/vczjk/tg8;->OooOoO:Llyiahf/vczjk/s46;

    iput-object v0, p0, Llyiahf/vczjk/tg8;->_unknownTypeSerializer:Llyiahf/vczjk/zb4;

    sget-object v0, Llyiahf/vczjk/s46;->OooOOOO:Llyiahf/vczjk/s46;

    iput-object v0, p0, Llyiahf/vczjk/tg8;->_nullValueSerializer:Llyiahf/vczjk/zb4;

    sget-object v0, Llyiahf/vczjk/tg8;->OooOoO0:Llyiahf/vczjk/sv2;

    iput-object v0, p0, Llyiahf/vczjk/tg8;->_nullKeySerializer:Llyiahf/vczjk/zb4;

    iput-object p3, p0, Llyiahf/vczjk/tg8;->_serializerFactory:Llyiahf/vczjk/rg8;

    iput-object p2, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    iget-object p3, p1, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    iput-object p3, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    iget-object v1, p1, Llyiahf/vczjk/tg8;->_unknownTypeSerializer:Llyiahf/vczjk/zb4;

    iput-object v1, p0, Llyiahf/vczjk/tg8;->_unknownTypeSerializer:Llyiahf/vczjk/zb4;

    iget-object v1, p1, Llyiahf/vczjk/tg8;->_keySerializer:Llyiahf/vczjk/zb4;

    iput-object v1, p0, Llyiahf/vczjk/tg8;->_keySerializer:Llyiahf/vczjk/zb4;

    iget-object v1, p1, Llyiahf/vczjk/tg8;->_nullValueSerializer:Llyiahf/vczjk/zb4;

    iput-object v1, p0, Llyiahf/vczjk/tg8;->_nullValueSerializer:Llyiahf/vczjk/zb4;

    iget-object p1, p1, Llyiahf/vczjk/tg8;->_nullKeySerializer:Llyiahf/vczjk/zb4;

    iput-object p1, p0, Llyiahf/vczjk/tg8;->_nullKeySerializer:Llyiahf/vczjk/zb4;

    if-ne v1, v0, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    iput-boolean p1, p0, Llyiahf/vczjk/tg8;->_stdNullValueSerializer:Z

    invoke-virtual {p2}, Llyiahf/vczjk/fc5;->OooOo0o()Ljava/lang/Class;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/tg8;->_serializationView:Ljava/lang/Class;

    iget-object p1, p2, Llyiahf/vczjk/fc5;->_attributes:Llyiahf/vczjk/jn1;

    iput-object p1, p0, Llyiahf/vczjk/tg8;->OooOo:Llyiahf/vczjk/jn1;

    iget-object p1, p3, Llyiahf/vczjk/pg8;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/zg7;

    if-eqz p1, :cond_1

    goto :goto_2

    :cond_1
    monitor-enter p3

    :try_start_0
    iget-object p1, p3, Llyiahf/vczjk/pg8;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/zg7;

    if-nez p1, :cond_2

    iget-object p1, p3, Llyiahf/vczjk/pg8;->OooO00o:Ljava/util/HashMap;

    new-instance p2, Llyiahf/vczjk/zg7;

    invoke-direct {p2, p1}, Llyiahf/vczjk/zg7;-><init>(Ljava/util/HashMap;)V

    iget-object p1, p3, Llyiahf/vczjk/pg8;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {p1, p2}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    move-object p1, p2

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_3

    :cond_2
    :goto_1
    monitor-exit p3

    :goto_2
    iput-object p1, p0, Llyiahf/vczjk/tg8;->_knownSerializers:Llyiahf/vczjk/zg7;

    return-void

    :goto_3
    :try_start_1
    monitor-exit p3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1
.end method


# virtual methods
.method public final Oooo(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/k44;
    .locals 3

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOOOo(Llyiahf/vczjk/x64;)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Could not resolve type id \'"

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "\' as a subtype of "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0, p3}, Llyiahf/vczjk/mc4;->OooOO0o(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p3

    new-instance v0, Llyiahf/vczjk/k44;

    const/4 v1, 0x0

    invoke-direct {v0, v1, p3, p1, p2}, Llyiahf/vczjk/k44;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/x64;Ljava/lang/String;)V

    return-object v0
.end method

.method public final Oooo00O()Llyiahf/vczjk/ec5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    return-object v0
.end method

.method public final Oooo0o0()Llyiahf/vczjk/a4a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooOOOO()Llyiahf/vczjk/a4a;

    move-result-object v0

    return-object v0
.end method

.method public final OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;
    .locals 2

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/w32;

    iget-object v0, v0, Llyiahf/vczjk/w32;->OooOoo:Llyiahf/vczjk/u94;

    new-instance v1, Llyiahf/vczjk/d44;

    invoke-direct {v1, v0, p2, p1}, Llyiahf/vczjk/d44;-><init>(Llyiahf/vczjk/u94;Ljava/lang/String;Llyiahf/vczjk/x64;)V

    throw v1
.end method

.method public final Oooooo(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;
    .locals 5

    :try_start_0
    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->OoooooO(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    if-eqz v0, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    monitor-enter v1

    :try_start_1
    iget-object v2, v1, Llyiahf/vczjk/pg8;->OooO00o:Ljava/util/HashMap;

    new-instance v3, Llyiahf/vczjk/m4a;

    const/4 v4, 0x0

    invoke-direct {v3, p1, v4}, Llyiahf/vczjk/m4a;-><init>(Llyiahf/vczjk/x64;Z)V

    invoke-virtual {v2, v3, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_0

    iget-object p1, v1, Llyiahf/vczjk/pg8;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    const/4 v2, 0x0

    invoke-virtual {p1, v2}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    :goto_0
    instance-of p1, v0, Llyiahf/vczjk/pr7;

    if-eqz p1, :cond_1

    move-object p1, v0

    check-cast p1, Llyiahf/vczjk/pr7;

    invoke-interface {p1, p0}, Llyiahf/vczjk/pr7;->OooO00o(Llyiahf/vczjk/tg8;)V

    :cond_1
    monitor-exit v1

    return-object v0

    :goto_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1

    :cond_2
    return-object v0

    :catch_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v0

    move-object v1, p0

    check-cast v1, Llyiahf/vczjk/w32;

    iget-object v1, v1, Llyiahf/vczjk/w32;->OooOoo:Llyiahf/vczjk/u94;

    new-instance v2, Llyiahf/vczjk/na4;

    invoke-direct {v2, v1, v0, p1}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v2
.end method

.method public final Oooooo0(Ljava/lang/Class;)Llyiahf/vczjk/zb4;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ec5;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v0

    :try_start_0
    invoke-virtual {p0, v0}, Llyiahf/vczjk/tg8;->OoooooO(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v1
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    if-eqz v1, :cond_3

    iget-object v2, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    monitor-enter v2

    :try_start_1
    iget-object v3, v2, Llyiahf/vczjk/pg8;->OooO00o:Ljava/util/HashMap;

    new-instance v4, Llyiahf/vczjk/m4a;

    const/4 v5, 0x0

    invoke-direct {v4, p1, v5}, Llyiahf/vczjk/m4a;-><init>(Ljava/lang/Class;Z)V

    invoke-virtual {v3, v4, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    iget-object v3, v2, Llyiahf/vczjk/pg8;->OooO00o:Ljava/util/HashMap;

    new-instance v4, Llyiahf/vczjk/m4a;

    invoke-direct {v4, v0, v5}, Llyiahf/vczjk/m4a;-><init>(Llyiahf/vczjk/x64;Z)V

    invoke-virtual {v3, v4, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    if-eqz p1, :cond_0

    if-nez v0, :cond_1

    :cond_0
    iget-object p1, v2, Llyiahf/vczjk/pg8;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    :cond_1
    instance-of p1, v1, Llyiahf/vczjk/pr7;

    if-eqz p1, :cond_2

    move-object p1, v1

    check-cast p1, Llyiahf/vczjk/pr7;

    invoke-interface {p1, p0}, Llyiahf/vczjk/pr7;->OooO00o(Llyiahf/vczjk/tg8;)V

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_2
    :goto_0
    monitor-exit v2

    return-object v1

    :goto_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1

    :cond_3
    return-object v1

    :catch_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v0

    move-object v1, p0

    check-cast v1, Llyiahf/vczjk/w32;

    iget-object v1, v1, Llyiahf/vczjk/w32;->OooOoo:Llyiahf/vczjk/u94;

    new-instance v2, Llyiahf/vczjk/na4;

    invoke-direct {v2, v1, v0, p1}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v2
.end method

.method public final OoooooO(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerFactory:Llyiahf/vczjk/rg8;

    check-cast v0, Llyiahf/vczjk/kb0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/gg8;->Oooo00o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v2

    iget-object v3, v2, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-static {p0, v3}, Llyiahf/vczjk/s90;->OooO0o0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/u34;)Llyiahf/vczjk/zb4;

    move-result-object v4

    if-eqz v4, :cond_0

    return-object v4

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v5

    const/4 v6, 0x0

    const/4 v7, 0x0

    if-nez v5, :cond_1

    move-object v3, p1

    goto :goto_0

    :cond_1
    :try_start_0
    invoke-virtual {v5, v1, v3, p1}, Llyiahf/vczjk/yn;->o00O0O(Llyiahf/vczjk/ec5;Llyiahf/vczjk/u34;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object v3
    :try_end_0
    .catch Llyiahf/vczjk/na4; {:try_start_0 .. :try_end_0} :catch_0

    :goto_0
    const/4 v5, 0x1

    if-ne v3, p1, :cond_2

    goto :goto_1

    :cond_2
    iget-object p1, p1, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {v3, p1}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result p1

    if-nez p1, :cond_3

    invoke-virtual {v1, v3}, Llyiahf/vczjk/gg8;->Oooo00o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v2

    :cond_3
    move v7, v5

    :goto_1
    iget-object p1, v2, Llyiahf/vczjk/h90;->OooO0Oo:Llyiahf/vczjk/yn;

    if-nez p1, :cond_4

    goto :goto_2

    :cond_4
    iget-object v6, v2, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {p1, v6}, Llyiahf/vczjk/yn;->Oooo0oo(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v2, p1}, Llyiahf/vczjk/h90;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/gp1;

    move-result-object v6

    :goto_2
    if-nez v6, :cond_5

    invoke-virtual {v0, p0, v3, v2, v7}, Llyiahf/vczjk/kb0;->OooO0oo(Llyiahf/vczjk/tg8;Llyiahf/vczjk/x64;Llyiahf/vczjk/h90;Z)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1

    :cond_5
    invoke-virtual {p0}, Llyiahf/vczjk/tg8;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-object p1, v6

    check-cast p1, Llyiahf/vczjk/j74;

    iget-object v3, v3, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    iget-object p1, p1, Llyiahf/vczjk/j74;->OooO00o:Llyiahf/vczjk/x64;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v3

    if-nez v3, :cond_6

    invoke-virtual {v1, p1}, Llyiahf/vczjk/gg8;->Oooo00o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v2

    iget-object v1, v2, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-static {p0, v1}, Llyiahf/vczjk/s90;->OooO0o0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/u34;)Llyiahf/vczjk/zb4;

    move-result-object v4

    :cond_6
    if-nez v4, :cond_7

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->o0OoOo0()Z

    move-result v1

    if-nez v1, :cond_7

    invoke-virtual {v0, p0, p1, v2, v5}, Llyiahf/vczjk/kb0;->OooO0oo(Llyiahf/vczjk/tg8;Llyiahf/vczjk/x64;Llyiahf/vczjk/h90;Z)Llyiahf/vczjk/zb4;

    move-result-object v4

    :cond_7
    new-instance v0, Llyiahf/vczjk/l49;

    invoke-direct {v0, v6, p1, v4}, Llyiahf/vczjk/l49;-><init>(Llyiahf/vczjk/gp1;Llyiahf/vczjk/x64;Llyiahf/vczjk/zb4;)V

    return-object v0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Llyiahf/vczjk/na4;->getMessage()Ljava/lang/String;

    move-result-object p1

    new-array v0, v7, [Ljava/lang/Object;

    invoke-virtual {p0, v2, p1, v0}, Llyiahf/vczjk/tg8;->o00000oo(Llyiahf/vczjk/h90;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v6
.end method

.method public final Ooooooo()Ljava/text/DateFormat;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_dateFormat:Ljava/text/DateFormat;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0oo()Ljava/text/DateFormat;

    move-result-object v0

    invoke-virtual {v0}, Ljava/text/DateFormat;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/text/DateFormat;

    iput-object v0, p0, Llyiahf/vczjk/tg8;->_dateFormat:Ljava/text/DateFormat;

    return-object v0
.end method

.method public abstract o0000(Llyiahf/vczjk/u34;Ljava/lang/Object;)Llyiahf/vczjk/zb4;
.end method

.method public final o00000(Ljava/lang/Class;)Llyiahf/vczjk/zb4;
    .locals 3

    const-class v0, Ljava/lang/Object;

    if-ne p1, v0, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/tg8;->_unknownTypeSerializer:Llyiahf/vczjk/zb4;

    return-object p1

    :cond_0
    new-instance v0, Llyiahf/vczjk/s46;

    const/4 v1, 0x0

    const/4 v2, 0x5

    invoke-direct {v0, v1, v2, p1}, Llyiahf/vczjk/s46;-><init>(IILjava/lang/Class;)V

    return-object v0
.end method

.method public final o000000()Llyiahf/vczjk/zb4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_nullValueSerializer:Llyiahf/vczjk/zb4;

    return-object v0
.end method

.method public final o000000O(Ljava/lang/Class;)Llyiahf/vczjk/q94;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fc5;->OooO(Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object p1

    return-object p1
.end method

.method public final o000000o()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-void
.end method

.method public final o00000O(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 1

    if-eqz p1, :cond_0

    instance-of v0, p1, Llyiahf/vczjk/xo1;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/xo1;

    invoke-interface {p1, p0, p2}, Llyiahf/vczjk/xo1;->OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    :cond_0
    return-object p1
.end method

.method public final o00000O0(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 1

    if-eqz p1, :cond_0

    instance-of v0, p1, Llyiahf/vczjk/xo1;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/xo1;

    invoke-interface {p1, p0, p2}, Llyiahf/vczjk/xo1;->OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    :cond_0
    return-object p1
.end method

.method public abstract o00000OO(Ljava/lang/Class;)Ljava/lang/Object;
.end method

.method public abstract o00000Oo(Ljava/lang/Object;)Z
.end method

.method public final o00000o0(Llyiahf/vczjk/gc5;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result p1

    return p1
.end method

.method public final varargs o00000oO(Llyiahf/vczjk/h90;Llyiahf/vczjk/eb0;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 3

    array-length v0, p4

    if-lez v0, :cond_0

    invoke-static {p3, p4}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p3

    :cond_0
    invoke-interface {p2}, Llyiahf/vczjk/yt5;->getName()Ljava/lang/String;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/mc4;->OooOOO0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    iget-object p4, p1, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    iget-object p4, p4, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-static {p4}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object p4

    const-string v0, "Invalid definition for property "

    const-string v1, " (of type "

    const-string v2, "): "

    invoke-static {v0, p2, v1, p4, v2}, Llyiahf/vczjk/q99;->OooO0oo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p2

    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    move-object p3, p0

    check-cast p3, Llyiahf/vczjk/w32;

    iget-object p3, p3, Llyiahf/vczjk/w32;->OooOoo:Llyiahf/vczjk/u94;

    new-instance p4, Llyiahf/vczjk/d44;

    invoke-direct {p4, p3, p2, p1}, Llyiahf/vczjk/d44;-><init>(Llyiahf/vczjk/u94;Ljava/lang/String;Llyiahf/vczjk/h90;)V

    throw p4
.end method

.method public final varargs o00000oo(Llyiahf/vczjk/h90;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 2

    iget-object v0, p1, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    iget-object v0, v0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v0

    array-length v1, p3

    if-lez v1, :cond_0

    invoke-static {p2, p3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    :cond_0
    const-string p3, "Invalid type definition for type "

    const-string v1, ": "

    invoke-static {p3, v0, v1, p2}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    move-object p3, p0

    check-cast p3, Llyiahf/vczjk/w32;

    iget-object p3, p3, Llyiahf/vczjk/w32;->OooOoo:Llyiahf/vczjk/u94;

    new-instance v0, Llyiahf/vczjk/d44;

    invoke-direct {v0, p3, p2, p1}, Llyiahf/vczjk/d44;-><init>(Llyiahf/vczjk/u94;Ljava/lang/String;Llyiahf/vczjk/h90;)V

    throw v0
.end method

.method public final o0000Ooo(Llyiahf/vczjk/ig8;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/gg8;->Oooo0(Llyiahf/vczjk/ig8;)Z

    move-result p1

    return p1
.end method

.method public final o000OOo()Llyiahf/vczjk/gg8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    return-object v0
.end method

.method public final o00O0O(Llyiahf/vczjk/u94;)V
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/tg8;->_stdNullValueSerializer:Z

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/u94;->o00000oo()V

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/tg8;->_nullValueSerializer:Llyiahf/vczjk/zb4;

    const/4 v1, 0x0

    invoke-virtual {v0, v1, p1, p0}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void
.end method

.method public final o00Oo0(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_knownSerializers:Llyiahf/vczjk/zg7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zg7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pg8;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    iget-object v1, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ec5;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/pg8;->OooO0O0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->Oooooo0(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->o00000(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p0, v0, p2}, Llyiahf/vczjk/tg8;->o00000O(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1
.end method

.method public final o00Ooo(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_knownSerializers:Llyiahf/vczjk/zg7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zg7;->OooO0O0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pg8;->OooO0O0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->Oooooo(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->o00000(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p0, v0, p2}, Llyiahf/vczjk/tg8;->o00000O(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1
.end method

.method public final o00o0O(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerFactory:Llyiahf/vczjk/rg8;

    iget-object v1, p0, Llyiahf/vczjk/tg8;->_keySerializer:Llyiahf/vczjk/zb4;

    invoke-virtual {v0, p0, p1, v1}, Llyiahf/vczjk/rg8;->OooO00o(Llyiahf/vczjk/tg8;Llyiahf/vczjk/x64;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/zb4;

    move-result-object p1

    instance-of v0, p1, Llyiahf/vczjk/pr7;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/pr7;

    invoke-interface {v0, p0}, Llyiahf/vczjk/pr7;->OooO00o(Llyiahf/vczjk/tg8;)V

    :cond_0
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/tg8;->o00000O(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1
.end method

.method public final o00oO0O(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_knownSerializers:Llyiahf/vczjk/zg7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zg7;->OooO0O0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pg8;->OooO0O0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->Oooooo(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->o00000(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p0, v0, p2}, Llyiahf/vczjk/tg8;->o00000O0(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1
.end method

.method public final o00oO0o(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_knownSerializers:Llyiahf/vczjk/zg7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zg7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pg8;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    iget-object v1, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ec5;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/pg8;->OooO0O0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->Oooooo0(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->o00000(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p0, v0, p2}, Llyiahf/vczjk/tg8;->o00000O0(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1
.end method

.method public final o00ooo()Llyiahf/vczjk/zb4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_nullKeySerializer:Llyiahf/vczjk/zb4;

    return-object v0
.end method

.method public final o0O0O00()Llyiahf/vczjk/yn;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v0

    return-object v0
.end method

.method public final o0OO00O(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 2

    if-eqz p1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_knownSerializers:Llyiahf/vczjk/zg7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zg7;->OooO0O0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pg8;->OooO0O0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->Oooooo(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->o00000(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p0, v0, p2}, Llyiahf/vczjk/tg8;->o00000O(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1

    :cond_1
    move-object p1, p0

    check-cast p1, Llyiahf/vczjk/w32;

    iget-object p1, p1, Llyiahf/vczjk/w32;->OooOoo:Llyiahf/vczjk/u94;

    new-instance p2, Llyiahf/vczjk/na4;

    const/4 v0, 0x0

    const-string v1, "Null passed for `valueType` of `findValueSerializer()`"

    invoke-direct {p2, p1, v1, v0}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    throw p2
.end method

.method public final o0OOO0o(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_knownSerializers:Llyiahf/vczjk/zg7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zg7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pg8;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    iget-object v1, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ec5;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/pg8;->OooO0O0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->Oooooo0(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->o00000(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p0, v0, p2}, Llyiahf/vczjk/tg8;->o00000O(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1
.end method

.method public final o0Oo0oo(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_knownSerializers:Llyiahf/vczjk/zg7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zg7;->OooO0O0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pg8;->OooO0O0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->Oooooo(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->o00000(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1

    :cond_0
    return-object v0
.end method

.method public final o0OoOo0(Llyiahf/vczjk/y70;Llyiahf/vczjk/x64;)V
    .locals 2

    iget-object v0, p2, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->isPrimitive()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p2, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooOoo0(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_0

    return-void

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooO0o0(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    filled-new-array {p2, p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v0, "Incompatible types: declared root type (%s) vs %s"

    invoke-static {v0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/tg8;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    const/4 p1, 0x0

    throw p1
.end method

.method public final o0ooOO0(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_knownSerializers:Llyiahf/vczjk/zg7;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    move-result v1

    const/4 v2, 0x1

    add-int/2addr v1, v2

    iget v3, v0, Llyiahf/vczjk/zg7;->OooO0O0:I

    and-int/2addr v1, v3

    iget-object v0, v0, Llyiahf/vczjk/zg7;->OooO00o:[Llyiahf/vczjk/qv0;

    aget-object v0, v0, v1

    const/4 v1, 0x0

    if-nez v0, :cond_1

    :cond_0
    move-object v0, v1

    goto :goto_0

    :cond_1
    iget-object v3, v0, Llyiahf/vczjk/qv0;->OooO0Oo:Ljava/lang/Object;

    check-cast v3, Ljava/lang/Class;

    if-ne v3, p1, :cond_2

    iget-boolean v3, v0, Llyiahf/vczjk/qv0;->OooO00o:Z

    if-eqz v3, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/qv0;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/zb4;

    goto :goto_0

    :cond_2
    iget-object v0, v0, Llyiahf/vczjk/qv0;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/qv0;

    if-eqz v0, :cond_0

    iget-object v3, v0, Llyiahf/vczjk/qv0;->OooO0Oo:Ljava/lang/Object;

    check-cast v3, Ljava/lang/Class;

    if-ne v3, p1, :cond_2

    iget-boolean v3, v0, Llyiahf/vczjk/qv0;->OooO00o:Z

    if-eqz v3, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/qv0;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/zb4;

    :goto_0
    if-eqz v0, :cond_3

    return-object v0

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    monitor-enter v0

    :try_start_0
    iget-object v3, v0, Llyiahf/vczjk/pg8;->OooO00o:Ljava/util/HashMap;

    new-instance v4, Llyiahf/vczjk/m4a;

    invoke-direct {v4, p1, v2}, Llyiahf/vczjk/m4a;-><init>(Ljava/lang/Class;Z)V

    invoke-virtual {v3, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/zb4;

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    if-eqz v3, :cond_4

    return-object v3

    :cond_4
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/tg8;->o0OOO0o(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v0

    iget-object v3, p0, Llyiahf/vczjk/tg8;->_serializerFactory:Llyiahf/vczjk/rg8;

    iget-object v4, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v4, p1}, Llyiahf/vczjk/ec5;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v5

    invoke-virtual {v3, v4, v5}, Llyiahf/vczjk/rg8;->OooO0O0(Llyiahf/vczjk/gg8;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e5a;

    move-result-object v3

    if-eqz v3, :cond_5

    invoke-virtual {v3, p2}, Llyiahf/vczjk/d5a;->OooO00o(Llyiahf/vczjk/db0;)Llyiahf/vczjk/d5a;

    move-result-object p2

    new-instance v3, Llyiahf/vczjk/r5a;

    invoke-direct {v3, p2, v0}, Llyiahf/vczjk/r5a;-><init>(Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;)V

    move-object v0, v3

    :cond_5
    iget-object p2, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    monitor-enter p2

    :try_start_1
    iget-object v3, p2, Llyiahf/vczjk/pg8;->OooO00o:Ljava/util/HashMap;

    new-instance v4, Llyiahf/vczjk/m4a;

    invoke-direct {v4, p1, v2}, Llyiahf/vczjk/m4a;-><init>(Ljava/lang/Class;Z)V

    invoke-virtual {v3, v4, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_6

    iget-object p1, p2, Llyiahf/vczjk/pg8;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {p1, v1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_6
    :goto_1
    monitor-exit p2

    return-object v0

    :goto_2
    monitor-exit p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1

    :catchall_1
    move-exception p1

    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    throw p1
.end method

.method public final o0ooOOo(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_knownSerializers:Llyiahf/vczjk/zg7;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->hashCode()I

    move-result v1

    add-int/lit8 v1, v1, -0x2

    iget v2, v0, Llyiahf/vczjk/zg7;->OooO0O0:I

    and-int/2addr v1, v2

    iget-object v0, v0, Llyiahf/vczjk/zg7;->OooO00o:[Llyiahf/vczjk/qv0;

    aget-object v0, v0, v1

    const/4 v1, 0x0

    if-nez v0, :cond_1

    :cond_0
    move-object v0, v1

    goto :goto_0

    :cond_1
    iget-boolean v2, v0, Llyiahf/vczjk/qv0;->OooO00o:Z

    if-eqz v2, :cond_2

    iget-object v2, v0, Llyiahf/vczjk/qv0;->OooO0o0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/x64;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/x64;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/qv0;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/zb4;

    goto :goto_0

    :cond_2
    iget-object v0, v0, Llyiahf/vczjk/qv0;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/qv0;

    if-eqz v0, :cond_0

    iget-boolean v2, v0, Llyiahf/vczjk/qv0;->OooO00o:Z

    if-eqz v2, :cond_2

    iget-object v2, v0, Llyiahf/vczjk/qv0;->OooO0o0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/x64;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/x64;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/qv0;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/zb4;

    :goto_0
    if-eqz v0, :cond_3

    return-object v0

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    monitor-enter v0

    :try_start_0
    iget-object v2, v0, Llyiahf/vczjk/pg8;->OooO00o:Ljava/util/HashMap;

    new-instance v3, Llyiahf/vczjk/m4a;

    const/4 v4, 0x1

    invoke-direct {v3, p1, v4}, Llyiahf/vczjk/m4a;-><init>(Llyiahf/vczjk/x64;Z)V

    invoke-virtual {v2, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/zb4;

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    if-eqz v2, :cond_4

    return-object v2

    :cond_4
    invoke-virtual {p0, p1, v1}, Llyiahf/vczjk/tg8;->o0OO00O(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v0

    iget-object v2, p0, Llyiahf/vczjk/tg8;->_serializerFactory:Llyiahf/vczjk/rg8;

    iget-object v3, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v2, v3, p1}, Llyiahf/vczjk/rg8;->OooO0O0(Llyiahf/vczjk/gg8;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e5a;

    move-result-object v2

    if-eqz v2, :cond_5

    invoke-virtual {v2, v1}, Llyiahf/vczjk/d5a;->OooO00o(Llyiahf/vczjk/db0;)Llyiahf/vczjk/d5a;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/r5a;

    invoke-direct {v3, v2, v0}, Llyiahf/vczjk/r5a;-><init>(Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;)V

    move-object v0, v3

    :cond_5
    iget-object v2, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    monitor-enter v2

    :try_start_1
    iget-object v3, v2, Llyiahf/vczjk/pg8;->OooO00o:Ljava/util/HashMap;

    new-instance v5, Llyiahf/vczjk/m4a;

    invoke-direct {v5, p1, v4}, Llyiahf/vczjk/m4a;-><init>(Llyiahf/vczjk/x64;Z)V

    invoke-virtual {v3, v5, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_6

    iget-object p1, v2, Llyiahf/vczjk/pg8;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {p1, v1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_6
    :goto_1
    monitor-exit v2

    return-object v0

    :goto_2
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1

    :catchall_1
    move-exception p1

    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    throw p1
.end method

.method public final o0ooOoO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_knownSerializers:Llyiahf/vczjk/zg7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zg7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pg8;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializerCache:Llyiahf/vczjk/pg8;

    iget-object v1, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ec5;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/pg8;->OooO0O0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->Oooooo0(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tg8;->o00000(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1

    :cond_0
    return-object v0
.end method

.method public abstract oo000o(Ljava/lang/Object;Llyiahf/vczjk/p66;)Llyiahf/vczjk/qsa;
.end method

.method public final oo0o0Oo()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_serializationView:Ljava/lang/Class;

    return-object v0
.end method

.method public final ooOO(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;
    .locals 2

    invoke-virtual {p2, p1}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_0

    return-object p2

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooOOOO()Llyiahf/vczjk/a4a;

    move-result-object v0

    const/4 v1, 0x1

    invoke-virtual {v0, p2, p1, v1}, Llyiahf/vczjk/a4a;->OooOO0(Llyiahf/vczjk/x64;Ljava/lang/Class;Z)Llyiahf/vczjk/x64;

    move-result-object p1

    return-object p1
.end method
