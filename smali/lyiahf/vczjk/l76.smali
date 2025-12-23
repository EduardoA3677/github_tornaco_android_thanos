.class public final Llyiahf/vczjk/l76;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/l76;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field private final rootType:Llyiahf/vczjk/x64;

.field private final typeSerializer:Llyiahf/vczjk/d5a;

.field private final valueSerializer:Llyiahf/vczjk/zb4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zb4;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/l76;

    invoke-direct {v0}, Llyiahf/vczjk/l76;-><init>()V

    sput-object v0, Llyiahf/vczjk/l76;->OooOOO0:Llyiahf/vczjk/l76;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/l76;->rootType:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/l76;->valueSerializer:Llyiahf/vczjk/zb4;

    iput-object v0, p0, Llyiahf/vczjk/l76;->typeSerializer:Llyiahf/vczjk/d5a;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/u94;Llyiahf/vczjk/y70;Llyiahf/vczjk/v32;)V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/l76;->typeSerializer:Llyiahf/vczjk/d5a;

    if-eqz v0, :cond_7

    iget-object v1, p0, Llyiahf/vczjk/l76;->rootType:Llyiahf/vczjk/x64;

    iget-object v2, p0, Llyiahf/vczjk/l76;->valueSerializer:Llyiahf/vczjk/zb4;

    iput-object p1, p3, Llyiahf/vczjk/w32;->OooOoo:Llyiahf/vczjk/u94;

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v3

    if-nez v3, :cond_0

    invoke-virtual {p3, p2, v1}, Llyiahf/vczjk/tg8;->o0OoOo0(Llyiahf/vczjk/y70;Llyiahf/vczjk/x64;)V

    :cond_0
    if-nez v2, :cond_2

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OooooOo()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-virtual {p3, v1, v2}, Llyiahf/vczjk/tg8;->o0OO00O(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v2

    goto :goto_0

    :cond_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {p3, v1, v2}, Llyiahf/vczjk/tg8;->o0OOO0o(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v2

    :cond_2
    :goto_0
    iget-object v1, p3, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v1}, Llyiahf/vczjk/fc5;->OooOooO()Llyiahf/vczjk/xa7;

    move-result-object v1

    if-nez v1, :cond_3

    iget-object v1, p3, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    sget-object v3, Llyiahf/vczjk/ig8;->OooOOO0:Llyiahf/vczjk/ig8;

    invoke-virtual {v1, v3}, Llyiahf/vczjk/gg8;->Oooo0(Llyiahf/vczjk/ig8;)Z

    move-result v1

    if-eqz v1, :cond_5

    invoke-virtual {p1}, Llyiahf/vczjk/u94;->o0000oO0()V

    iget-object v3, p3, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v4

    invoke-virtual {v3, v4}, Llyiahf/vczjk/fc5;->OooOo0(Ljava/lang/Class;)Llyiahf/vczjk/xa7;

    move-result-object v3

    iget-object v4, p3, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/xa7;->OooO0o(Llyiahf/vczjk/ec5;)Llyiahf/vczjk/fg8;

    move-result-object v3

    invoke-virtual {p1, v3}, Llyiahf/vczjk/u94;->o00000oO(Llyiahf/vczjk/fg8;)V

    goto :goto_1

    :cond_3
    invoke-virtual {v1}, Llyiahf/vczjk/xa7;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_4

    const/4 v1, 0x0

    goto :goto_1

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/u94;->o0000oO0()V

    invoke-virtual {v1}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Llyiahf/vczjk/u94;->o0000Ooo(Ljava/lang/String;)V

    const/4 v1, 0x1

    :cond_5
    :goto_1
    :try_start_0
    invoke-virtual {v2, p2, p1, p3, v0}, Llyiahf/vczjk/zb4;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V

    if-eqz v1, :cond_6

    invoke-virtual {p1}, Llyiahf/vczjk/u94;->o00000o0()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_2

    :catch_0
    move-exception p2

    goto :goto_3

    :cond_6
    :goto_2
    return-void

    :goto_3
    invoke-static {p1, p2}, Llyiahf/vczjk/w32;->o0000oo(Llyiahf/vczjk/u94;Ljava/lang/Exception;)Ljava/io/IOException;

    move-result-object p1

    throw p1

    :cond_7
    iget-object v0, p0, Llyiahf/vczjk/l76;->valueSerializer:Llyiahf/vczjk/zb4;

    if-eqz v0, :cond_d

    iget-object v1, p0, Llyiahf/vczjk/l76;->rootType:Llyiahf/vczjk/x64;

    iput-object p1, p3, Llyiahf/vczjk/w32;->OooOoo:Llyiahf/vczjk/u94;

    if-eqz v1, :cond_8

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v2

    if-nez v2, :cond_8

    invoke-virtual {p3, p2, v1}, Llyiahf/vczjk/tg8;->o0OoOo0(Llyiahf/vczjk/y70;Llyiahf/vczjk/x64;)V

    :cond_8
    if-nez v0, :cond_9

    invoke-virtual {p3, v1}, Llyiahf/vczjk/tg8;->o0ooOOo(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    :cond_9
    iget-object v2, p3, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v2}, Llyiahf/vczjk/fc5;->OooOooO()Llyiahf/vczjk/xa7;

    move-result-object v2

    if-nez v2, :cond_b

    iget-object v2, p3, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    sget-object v3, Llyiahf/vczjk/ig8;->OooOOO0:Llyiahf/vczjk/ig8;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/gg8;->Oooo0(Llyiahf/vczjk/ig8;)Z

    move-result v2

    if-eqz v2, :cond_c

    if-nez v1, :cond_a

    iget-object v1, p3, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/fc5;->OooOo0(Ljava/lang/Class;)Llyiahf/vczjk/xa7;

    move-result-object v1

    goto :goto_4

    :cond_a
    iget-object v2, p3, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/fc5;->OooOo0O(Llyiahf/vczjk/x64;)Llyiahf/vczjk/xa7;

    move-result-object v1

    :goto_4
    invoke-virtual {p3, p1, p2, v0, v1}, Llyiahf/vczjk/w32;->o0000O00(Llyiahf/vczjk/u94;Ljava/lang/Object;Llyiahf/vczjk/zb4;Llyiahf/vczjk/xa7;)V

    goto :goto_5

    :cond_b
    invoke-virtual {v2}, Llyiahf/vczjk/xa7;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_c

    invoke-virtual {p3, p1, p2, v0, v2}, Llyiahf/vczjk/w32;->o0000O00(Llyiahf/vczjk/u94;Ljava/lang/Object;Llyiahf/vczjk/zb4;Llyiahf/vczjk/xa7;)V

    goto :goto_5

    :cond_c
    :try_start_1
    invoke-virtual {v0, p2, p1, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    :goto_5
    return-void

    :catch_1
    move-exception p2

    invoke-static {p1, p2}, Llyiahf/vczjk/w32;->o0000oo(Llyiahf/vczjk/u94;Ljava/lang/Exception;)Ljava/io/IOException;

    move-result-object p1

    throw p1

    :cond_d
    iget-object v0, p0, Llyiahf/vczjk/l76;->rootType:Llyiahf/vczjk/x64;

    if-eqz v0, :cond_11

    iput-object p1, p3, Llyiahf/vczjk/w32;->OooOoo:Llyiahf/vczjk/u94;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v1

    if-nez v1, :cond_e

    invoke-virtual {p3, p2, v0}, Llyiahf/vczjk/tg8;->o0OoOo0(Llyiahf/vczjk/y70;Llyiahf/vczjk/x64;)V

    :cond_e
    invoke-virtual {p3, v0}, Llyiahf/vczjk/tg8;->o0ooOOo(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v1

    iget-object v2, p3, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v2}, Llyiahf/vczjk/fc5;->OooOooO()Llyiahf/vczjk/xa7;

    move-result-object v2

    if-nez v2, :cond_f

    iget-object v2, p3, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    sget-object v3, Llyiahf/vczjk/ig8;->OooOOO0:Llyiahf/vczjk/ig8;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/gg8;->Oooo0(Llyiahf/vczjk/ig8;)Z

    move-result v2

    if-eqz v2, :cond_10

    iget-object v2, p3, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/fc5;->OooOo0O(Llyiahf/vczjk/x64;)Llyiahf/vczjk/xa7;

    move-result-object v0

    invoke-virtual {p3, p1, p2, v1, v0}, Llyiahf/vczjk/w32;->o0000O00(Llyiahf/vczjk/u94;Ljava/lang/Object;Llyiahf/vczjk/zb4;Llyiahf/vczjk/xa7;)V

    goto :goto_6

    :cond_f
    invoke-virtual {v2}, Llyiahf/vczjk/xa7;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_10

    invoke-virtual {p3, p1, p2, v1, v2}, Llyiahf/vczjk/w32;->o0000O00(Llyiahf/vczjk/u94;Ljava/lang/Object;Llyiahf/vczjk/zb4;Llyiahf/vczjk/xa7;)V

    goto :goto_6

    :cond_10
    :try_start_2
    invoke-virtual {v1, p2, p1, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    :goto_6
    return-void

    :catch_2
    move-exception p2

    invoke-static {p1, p2}, Llyiahf/vczjk/w32;->o0000oo(Llyiahf/vczjk/u94;Ljava/lang/Exception;)Ljava/io/IOException;

    move-result-object p1

    throw p1

    :cond_11
    invoke-virtual {p3, p1, p2}, Llyiahf/vczjk/w32;->o0000oO(Llyiahf/vczjk/u94;Ljava/lang/Object;)V

    return-void
.end method
