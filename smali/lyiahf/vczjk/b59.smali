.class public abstract Llyiahf/vczjk/b59;
.super Llyiahf/vczjk/zb4;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO0:Ljava/lang/Object;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _handledType:Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Class<",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/b59;->OooOOO0:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(ILjava/lang/Class;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Class;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/b59;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iget-object p1, p1, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    iput-object p1, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/x64;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    return-void
.end method

.method public static OooOO0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/zb4;
    .locals 5

    sget-object v0, Llyiahf/vczjk/b59;->OooOOO0:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/tg8;->OooOo:Llyiahf/vczjk/jn1;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/jn1;->OooO00o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Map;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_1

    return-object p2

    :cond_0
    new-instance v0, Ljava/util/IdentityHashMap;

    invoke-direct {v0}, Ljava/util/IdentityHashMap;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/tg8;->OooOo:Llyiahf/vczjk/jn1;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/jn1;->OooO0O0(Ljava/util/IdentityHashMap;)Llyiahf/vczjk/in1;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/tg8;->OooOo:Llyiahf/vczjk/jn1;

    :cond_1
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-interface {v0, p1, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :try_start_0
    invoke-virtual {p0}, Llyiahf/vczjk/tg8;->o0O0O00()Llyiahf/vczjk/yn;

    move-result-object v1

    if-eqz v1, :cond_2

    if-eqz p1, :cond_2

    const/4 v2, 0x1

    goto :goto_0

    :cond_2
    const/4 v2, 0x0

    :goto_0
    if-eqz v2, :cond_4

    invoke-interface {p1}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v2

    if-eqz v2, :cond_4

    invoke-virtual {v1, v2}, Llyiahf/vczjk/yn;->Oooo0oO(Llyiahf/vczjk/pm;)Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_4

    invoke-interface {p1}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    invoke-virtual {p0, v1}, Llyiahf/vczjk/mc4;->OooOo0(Ljava/lang/Object;)Llyiahf/vczjk/gp1;

    move-result-object v1

    invoke-virtual {p0}, Llyiahf/vczjk/tg8;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/j74;

    iget-object v2, v2, Llyiahf/vczjk/j74;->OooO00o:Llyiahf/vczjk/x64;

    if-nez p2, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->o0OoOo0()Z

    move-result v3

    if-nez v3, :cond_3

    invoke-virtual {p0, v2}, Llyiahf/vczjk/tg8;->o0Oo0oo(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v3

    goto :goto_1

    :cond_3
    move-object v3, p2

    :goto_1
    new-instance v4, Llyiahf/vczjk/l49;

    invoke-direct {v4, v1, v2, v3}, Llyiahf/vczjk/l49;-><init>(Llyiahf/vczjk/gp1;Llyiahf/vczjk/x64;Llyiahf/vczjk/zb4;)V

    goto :goto_2

    :cond_4
    move-object v4, p2

    :goto_2
    if-eqz v4, :cond_5

    invoke-virtual {p0, v4, p1}, Llyiahf/vczjk/tg8;->o00000O(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-interface {v0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p0

    :catchall_0
    move-exception p0

    goto :goto_3

    :cond_5
    invoke-interface {v0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2

    :goto_3
    invoke-interface {v0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    throw p0
.end method

.method public static OooOO0O(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Ljava/lang/Class;)Llyiahf/vczjk/q94;
    .locals 0

    if-eqz p1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object p0

    invoke-interface {p1, p2, p0}, Llyiahf/vczjk/db0;->OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/fc5;)Llyiahf/vczjk/q94;

    move-result-object p0

    return-object p0

    :cond_0
    invoke-virtual {p0, p2}, Llyiahf/vczjk/tg8;->o000000O(Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object p0

    return-object p0
.end method

.method public static OooOO0o(Llyiahf/vczjk/tg8;Ljava/lang/Exception;Ljava/lang/Object;I)V
    .locals 1

    :goto_0
    instance-of v0, p1, Ljava/lang/reflect/InvocationTargetException;

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object p1

    goto :goto_0

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo(Ljava/lang/Throwable;)V

    if-eqz p0, :cond_2

    sget-object v0, Llyiahf/vczjk/ig8;->OooOOo0:Llyiahf/vczjk/ig8;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result p0

    if-eqz p0, :cond_1

    goto :goto_1

    :cond_1
    const/4 p0, 0x0

    goto :goto_2

    :cond_2
    :goto_1
    const/4 p0, 0x1

    :goto_2
    instance-of v0, p1, Ljava/io/IOException;

    if-eqz v0, :cond_4

    if-eqz p0, :cond_3

    instance-of p0, p1, Llyiahf/vczjk/na4;

    if-nez p0, :cond_5

    :cond_3
    check-cast p1, Ljava/io/IOException;

    throw p1

    :cond_4
    if-nez p0, :cond_5

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    :cond_5
    invoke-static {p1, p2, p3}, Llyiahf/vczjk/na4;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Object;I)Llyiahf/vczjk/na4;

    move-result-object p0

    throw p0
.end method

.method public static OooOOO0(Llyiahf/vczjk/tg8;Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;)V
    .locals 1

    :goto_0
    instance-of v0, p1, Ljava/lang/reflect/InvocationTargetException;

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object p1

    goto :goto_0

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo(Ljava/lang/Throwable;)V

    if-eqz p0, :cond_2

    sget-object v0, Llyiahf/vczjk/ig8;->OooOOo0:Llyiahf/vczjk/ig8;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result p0

    if-eqz p0, :cond_1

    goto :goto_1

    :cond_1
    const/4 p0, 0x0

    goto :goto_2

    :cond_2
    :goto_1
    const/4 p0, 0x1

    :goto_2
    instance-of v0, p1, Ljava/io/IOException;

    if-eqz v0, :cond_4

    if-eqz p0, :cond_3

    instance-of p0, p1, Llyiahf/vczjk/na4;

    if-nez p0, :cond_5

    :cond_3
    check-cast p1, Ljava/io/IOException;

    throw p1

    :cond_4
    if-nez p0, :cond_5

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    :cond_5
    sget p0, Llyiahf/vczjk/na4;->OooOOO:I

    new-instance p0, Llyiahf/vczjk/ma4;

    invoke-direct {p0, p2, p3}, Llyiahf/vczjk/ma4;-><init>(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1, p0}, Llyiahf/vczjk/na4;->OooO0oo(Ljava/lang/Throwable;Llyiahf/vczjk/ma4;)Llyiahf/vczjk/na4;

    move-result-object p0

    throw p0
.end method


# virtual methods
.method public final OooO0OO()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    return-object v0
.end method
