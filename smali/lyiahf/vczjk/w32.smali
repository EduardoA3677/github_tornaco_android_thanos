.class public abstract Llyiahf/vczjk/w32;
.super Llyiahf/vczjk/tg8;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field public transient OooOoOO:Ljava/util/AbstractMap;

.field public transient OooOoo:Llyiahf/vczjk/u94;

.field public transient OooOoo0:Ljava/util/ArrayList;


# direct methods
.method public static o0000oo(Llyiahf/vczjk/u94;Ljava/lang/Exception;)Ljava/io/IOException;
    .locals 2

    instance-of v0, p1, Ljava/io/IOException;

    if-eqz v0, :cond_0

    check-cast p1, Ljava/io/IOException;

    return-object p1

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_1

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "[no message for "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "]"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    :cond_1
    new-instance v1, Llyiahf/vczjk/na4;

    invoke-direct {v1, p0, v0, p1}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-object v1
.end method


# virtual methods
.method public final o0000(Llyiahf/vczjk/u34;Ljava/lang/Object;)Llyiahf/vczjk/zb4;
    .locals 3

    instance-of v0, p2, Llyiahf/vczjk/zb4;

    if-eqz v0, :cond_0

    check-cast p2, Llyiahf/vczjk/zb4;

    goto :goto_0

    :cond_0
    instance-of v0, p2, Ljava/lang/Class;

    const/4 v1, 0x0

    if-eqz v0, :cond_5

    check-cast p2, Ljava/lang/Class;

    const-class v0, Llyiahf/vczjk/yb4;

    if-eq p2, v0, :cond_4

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOOo(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_1

    goto :goto_1

    :cond_1
    const-class v0, Llyiahf/vczjk/zb4;

    invoke-virtual {v0, p2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooOO0O()V

    iget-object p1, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result p1

    invoke-static {p2, p1}, Llyiahf/vczjk/vy0;->OooO0oO(Ljava/lang/Class;Z)Ljava/lang/Object;

    move-result-object p1

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zb4;

    :goto_0
    instance-of p1, p2, Llyiahf/vczjk/pr7;

    if-eqz p1, :cond_2

    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/pr7;

    invoke-interface {p1, p0}, Llyiahf/vczjk/pr7;->OooO00o(Llyiahf/vczjk/tg8;)V

    :cond_2
    return-object p2

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/u34;->OooOoo()Llyiahf/vczjk/x64;

    move-result-object p1

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "AnnotationIntrospector returned Class "

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p2, "; expected Class<JsonSerializer>"

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/tg8;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v1

    :cond_4
    :goto_1
    return-object v1

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/u34;->OooOoo()Llyiahf/vczjk/x64;

    move-result-object p1

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "AnnotationIntrospector returned serializer definition of type "

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p2, "; expected type JsonSerializer or Class<JsonSerializer> instead"

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/tg8;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v1
.end method

.method public final o00000OO(Ljava/lang/Class;)Ljava/lang/Object;
    .locals 1

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooOO0O()V

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v0

    invoke-static {p1, v0}, Llyiahf/vczjk/vy0;->OooO0oO(Ljava/lang/Class;Z)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final o00000Oo(Ljava/lang/Object;)Z
    .locals 7

    const/4 v0, 0x0

    :try_start_0
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return p1

    :catchall_0
    move-exception v0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v3

    const-string v4, "Problem determining whether filter of type \'"

    const-string v5, "\' should filter out `null` values: ("

    const-string v6, ") "

    invoke-static {v4, v1, v5, v2, v6}, Llyiahf/vczjk/q99;->OooO0oo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    iget-object v2, p0, Llyiahf/vczjk/w32;->OooOoo:Llyiahf/vczjk/u94;

    invoke-virtual {p0}, Llyiahf/vczjk/tg8;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-result-object v3

    invoke-virtual {v3, p1}, Llyiahf/vczjk/a4a;->OooOO0O(Ljava/lang/reflect/Type;)Llyiahf/vczjk/x64;

    move-result-object p1

    new-instance v3, Llyiahf/vczjk/d44;

    invoke-direct {v3, v2, v1, p1}, Llyiahf/vczjk/d44;-><init>(Llyiahf/vczjk/u94;Ljava/lang/String;Llyiahf/vczjk/x64;)V

    invoke-virtual {v3, v0}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    throw v3
.end method

.method public final o0000O00(Llyiahf/vczjk/u94;Ljava/lang/Object;Llyiahf/vczjk/zb4;Llyiahf/vczjk/xa7;)V
    .locals 1

    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/u94;->o0000oO0()V

    iget-object v0, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {p4, v0}, Llyiahf/vczjk/xa7;->OooO0o(Llyiahf/vczjk/ec5;)Llyiahf/vczjk/fg8;

    move-result-object p4

    invoke-virtual {p1, p4}, Llyiahf/vczjk/u94;->o00000oO(Llyiahf/vczjk/fg8;)V

    invoke-virtual {p3, p2, p1, p0}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    invoke-virtual {p1}, Llyiahf/vczjk/u94;->o00000o0()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p2

    invoke-static {p1, p2}, Llyiahf/vczjk/w32;->o0000oo(Llyiahf/vczjk/u94;Ljava/lang/Exception;)Ljava/io/IOException;

    move-result-object p1

    throw p1
.end method

.method public final o0000oO(Llyiahf/vczjk/u94;Ljava/lang/Object;)V
    .locals 4

    iput-object p1, p0, Llyiahf/vczjk/w32;->OooOoo:Llyiahf/vczjk/u94;

    if-nez p2, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/tg8;->o000000()Llyiahf/vczjk/zb4;

    move-result-object p2

    const/4 v0, 0x0

    :try_start_0
    invoke-virtual {p2, v0, p1, p0}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p2

    invoke-static {p1, p2}, Llyiahf/vczjk/w32;->o0000oo(Llyiahf/vczjk/u94;Ljava/lang/Exception;)Ljava/io/IOException;

    move-result-object p1

    throw p1

    :cond_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {p0, v0, v1}, Llyiahf/vczjk/tg8;->o0ooOO0(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v2}, Llyiahf/vczjk/fc5;->OooOooO()Llyiahf/vczjk/xa7;

    move-result-object v2

    if-nez v2, :cond_1

    iget-object v2, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    sget-object v3, Llyiahf/vczjk/ig8;->OooOOO0:Llyiahf/vczjk/ig8;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/gg8;->Oooo0(Llyiahf/vczjk/ig8;)Z

    move-result v2

    if-eqz v2, :cond_2

    iget-object v2, p0, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/fc5;->OooOo0(Ljava/lang/Class;)Llyiahf/vczjk/xa7;

    move-result-object v0

    invoke-virtual {p0, p1, p2, v1, v0}, Llyiahf/vczjk/w32;->o0000O00(Llyiahf/vczjk/u94;Ljava/lang/Object;Llyiahf/vczjk/zb4;Llyiahf/vczjk/xa7;)V

    return-void

    :cond_1
    invoke-virtual {v2}, Llyiahf/vczjk/xa7;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_2

    invoke-virtual {p0, p1, p2, v1, v2}, Llyiahf/vczjk/w32;->o0000O00(Llyiahf/vczjk/u94;Ljava/lang/Object;Llyiahf/vczjk/zb4;Llyiahf/vczjk/xa7;)V

    return-void

    :cond_2
    :try_start_1
    invoke-virtual {v1, p2, p1, p0}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    return-void

    :catch_1
    move-exception p2

    invoke-static {p1, p2}, Llyiahf/vczjk/w32;->o0000oo(Llyiahf/vczjk/u94;Ljava/lang/Exception;)Ljava/io/IOException;

    move-result-object p1

    throw p1
.end method

.method public final oo000o(Ljava/lang/Object;Llyiahf/vczjk/p66;)Llyiahf/vczjk/qsa;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/w32;->OooOoOO:Ljava/util/AbstractMap;

    if-nez v0, :cond_1

    sget-object v0, Llyiahf/vczjk/ig8;->Oooo00O:Llyiahf/vczjk/ig8;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result v0

    if-eqz v0, :cond_0

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/util/IdentityHashMap;

    invoke-direct {v0}, Ljava/util/IdentityHashMap;-><init>()V

    :goto_0
    iput-object v0, p0, Llyiahf/vczjk/w32;->OooOoOO:Ljava/util/AbstractMap;

    goto :goto_1

    :cond_1
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/qsa;

    if-eqz v0, :cond_2

    return-object v0

    :cond_2
    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/w32;->OooOoo0:Ljava/util/ArrayList;

    if-nez v0, :cond_3

    new-instance v0, Ljava/util/ArrayList;

    const/16 v1, 0x8

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/w32;->OooOoo0:Ljava/util/ArrayList;

    goto :goto_3

    :cond_3
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    const/4 v1, 0x0

    :goto_2
    if-ge v1, v0, :cond_5

    iget-object v2, p0, Llyiahf/vczjk/w32;->OooOoo0:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/p66;

    invoke-virtual {v2, p2}, Llyiahf/vczjk/p66;->OooO00o(Llyiahf/vczjk/p66;)Z

    move-result v3

    if-eqz v3, :cond_4

    goto :goto_4

    :cond_4
    add-int/lit8 v1, v1, 0x1

    goto :goto_2

    :cond_5
    :goto_3
    const/4 v2, 0x0

    :goto_4
    if-nez v2, :cond_6

    invoke-virtual {p2}, Llyiahf/vczjk/p66;->OooO0o0()Llyiahf/vczjk/p66;

    move-result-object v2

    iget-object p2, p0, Llyiahf/vczjk/w32;->OooOoo0:Ljava/util/ArrayList;

    invoke-virtual {p2, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_6
    new-instance p2, Llyiahf/vczjk/qsa;

    invoke-direct {p2, v2}, Llyiahf/vczjk/qsa;-><init>(Llyiahf/vczjk/p66;)V

    iget-object v0, p0, Llyiahf/vczjk/w32;->OooOoOO:Ljava/util/AbstractMap;

    invoke-interface {v0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method
