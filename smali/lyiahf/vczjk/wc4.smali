.class public final Llyiahf/vczjk/wc4;
.super Llyiahf/vczjk/b59;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xo1;


# instance fields
.field protected final _accessor:Llyiahf/vczjk/pm;

.field protected final _forceTypeInformation:Z

.field protected final _property:Llyiahf/vczjk/db0;

.field protected final _valueSerializer:Llyiahf/vczjk/zb4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zb4;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/pm;Llyiahf/vczjk/zb4;)V
    .locals 1

    invoke-virtual {p1}, Llyiahf/vczjk/u34;->OooOoo()Llyiahf/vczjk/x64;

    move-result-object v0

    invoke-direct {p0, v0}, Llyiahf/vczjk/b59;-><init>(Llyiahf/vczjk/x64;)V

    iput-object p1, p0, Llyiahf/vczjk/wc4;->_accessor:Llyiahf/vczjk/pm;

    iput-object p2, p0, Llyiahf/vczjk/wc4;->_valueSerializer:Llyiahf/vczjk/zb4;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/wc4;->_property:Llyiahf/vczjk/db0;

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/wc4;->_forceTypeInformation:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/wc4;Llyiahf/vczjk/db0;Llyiahf/vczjk/zb4;Z)V
    .locals 1

    iget-object v0, p1, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    if-nez v0, :cond_0

    const-class v0, Ljava/lang/Object;

    :cond_0
    invoke-direct {p0, v0}, Llyiahf/vczjk/b59;-><init>(Ljava/lang/Class;)V

    iget-object p1, p1, Llyiahf/vczjk/wc4;->_accessor:Llyiahf/vczjk/pm;

    iput-object p1, p0, Llyiahf/vczjk/wc4;->_accessor:Llyiahf/vczjk/pm;

    iput-object p3, p0, Llyiahf/vczjk/wc4;->_valueSerializer:Llyiahf/vczjk/zb4;

    iput-object p2, p0, Llyiahf/vczjk/wc4;->_property:Llyiahf/vczjk/db0;

    iput-boolean p4, p0, Llyiahf/vczjk/wc4;->_forceTypeInformation:Z

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/wc4;->_valueSerializer:Llyiahf/vczjk/zb4;

    if-nez v0, :cond_5

    iget-object v1, p0, Llyiahf/vczjk/wc4;->_accessor:Llyiahf/vczjk/pm;

    invoke-virtual {v1}, Llyiahf/vczjk/u34;->OooOoo()Llyiahf/vczjk/x64;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc5;->OooOoOO:Llyiahf/vczjk/gc5;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/tg8;->o00000o0(Llyiahf/vczjk/gc5;)Z

    move-result v2

    if-nez v2, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooooO()Z

    move-result v2

    if-eqz v2, :cond_0

    goto :goto_0

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/wc4;->_property:Llyiahf/vczjk/db0;

    if-eq p2, p1, :cond_1

    iget-boolean p1, p0, Llyiahf/vczjk/wc4;->_forceTypeInformation:Z

    invoke-virtual {p0, p2, v0, p1}, Llyiahf/vczjk/wc4;->OooOOO(Llyiahf/vczjk/db0;Llyiahf/vczjk/zb4;Z)Llyiahf/vczjk/wc4;

    move-result-object p1

    return-object p1

    :cond_1
    return-object p0

    :cond_2
    :goto_0
    invoke-virtual {p1, v1, p2}, Llyiahf/vczjk/tg8;->o00oO0O(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->isPrimitive()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_3

    sget-object v1, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    if-eq v0, v1, :cond_4

    sget-object v1, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    if-eq v0, v1, :cond_4

    sget-object v1, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    if-eq v0, v1, :cond_4

    goto :goto_1

    :cond_3
    const-class v1, Ljava/lang/String;

    if-eq v0, v1, :cond_4

    const-class v1, Ljava/lang/Integer;

    if-eq v0, v1, :cond_4

    const-class v1, Ljava/lang/Boolean;

    if-eq v0, v1, :cond_4

    const-class v1, Ljava/lang/Double;

    if-eq v0, v1, :cond_4

    goto :goto_1

    :cond_4
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOOoo(Ljava/lang/Object;)Z

    move-result v2

    :goto_1
    invoke-virtual {p0, p2, p1, v2}, Llyiahf/vczjk/wc4;->OooOOO(Llyiahf/vczjk/db0;Llyiahf/vczjk/zb4;Z)Llyiahf/vczjk/wc4;

    move-result-object p1

    return-object p1

    :cond_5
    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/tg8;->o00000O0(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    iget-boolean v0, p0, Llyiahf/vczjk/wc4;->_forceTypeInformation:Z

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/wc4;->OooOOO(Llyiahf/vczjk/db0;Llyiahf/vczjk/zb4;Z)Llyiahf/vczjk/wc4;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 3

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/wc4;->_accessor:Llyiahf/vczjk/pm;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pm;->o0ooOOo(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p3, p2}, Llyiahf/vczjk/tg8;->o00O0O(Llyiahf/vczjk/u94;)V

    return-void

    :catch_0
    move-exception p2

    goto :goto_0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/wc4;->_valueSerializer:Llyiahf/vczjk/zb4;

    if-nez v1, :cond_1

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/wc4;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {p3, v1, v2}, Llyiahf/vczjk/tg8;->o0ooOO0(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v1

    :cond_1
    invoke-virtual {v1, v0, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :goto_0
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/wc4;->_accessor:Llyiahf/vczjk/pm;

    invoke-virtual {v1}, Llyiahf/vczjk/u34;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "()"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {p3, p2, p1, v0}, Llyiahf/vczjk/b59;->OooOOO0(Llyiahf/vczjk/tg8;Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    .locals 3

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/wc4;->_accessor:Llyiahf/vczjk/pm;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pm;->o0ooOOo(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p3, p2}, Llyiahf/vczjk/tg8;->o00O0O(Llyiahf/vczjk/u94;)V

    return-void

    :catch_0
    move-exception p2

    goto :goto_1

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/wc4;->_valueSerializer:Llyiahf/vczjk/zb4;

    if-nez v1, :cond_1

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/wc4;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {p3, v1, v2}, Llyiahf/vczjk/tg8;->o0OOO0o(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v1

    goto :goto_0

    :cond_1
    iget-boolean v2, p0, Llyiahf/vczjk/wc4;->_forceTypeInformation:Z

    if-eqz v2, :cond_2

    sget-object v2, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    invoke-virtual {p4, p1, v2}, Llyiahf/vczjk/d5a;->OooO0Oo(Ljava/lang/Object;Llyiahf/vczjk/gc4;)Llyiahf/vczjk/rsa;

    move-result-object v2

    invoke-virtual {p4, p2, v2}, Llyiahf/vczjk/d5a;->OooO0o0(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    move-result-object v2

    invoke-virtual {v1, v0, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    invoke-virtual {p4, p2, v2}, Llyiahf/vczjk/d5a;->OooO0o(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    return-void

    :cond_2
    :goto_0
    new-instance v2, Llyiahf/vczjk/vc4;

    invoke-direct {v2, p4, p1}, Llyiahf/vczjk/vc4;-><init>(Llyiahf/vczjk/d5a;Ljava/lang/Object;)V

    invoke-virtual {v1, v0, p2, p3, v2}, Llyiahf/vczjk/zb4;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :goto_1
    new-instance p4, Ljava/lang/StringBuilder;

    invoke-direct {p4}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v0, p0, Llyiahf/vczjk/wc4;->_accessor:Llyiahf/vczjk/pm;

    invoke-virtual {v0}, Llyiahf/vczjk/u34;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, "()"

    invoke-virtual {p4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p4

    invoke-static {p3, p2, p1, p4}, Llyiahf/vczjk/b59;->OooOOO0(Llyiahf/vczjk/tg8;Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooOOO(Llyiahf/vczjk/db0;Llyiahf/vczjk/zb4;Z)Llyiahf/vczjk/wc4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wc4;->_property:Llyiahf/vczjk/db0;

    if-ne v0, p1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/wc4;->_valueSerializer:Llyiahf/vczjk/zb4;

    if-ne v0, p2, :cond_0

    iget-boolean v0, p0, Llyiahf/vczjk/wc4;->_forceTypeInformation:Z

    if-ne p3, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/wc4;

    invoke-direct {v0, p0, p1, p2, p3}, Llyiahf/vczjk/wc4;-><init>(Llyiahf/vczjk/wc4;Llyiahf/vczjk/db0;Llyiahf/vczjk/zb4;Z)V

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "(@JsonValue serializer for method "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/wc4;->_accessor:Llyiahf/vczjk/pm;

    invoke-virtual {v1}, Llyiahf/vczjk/pm;->o00oO0o()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "#"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/wc4;->_accessor:Llyiahf/vczjk/pm;

    invoke-virtual {v1}, Llyiahf/vczjk/u34;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ")"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
