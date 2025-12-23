.class public final Llyiahf/vczjk/r49;
.super Llyiahf/vczjk/v49;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _byNameResolver:Llyiahf/vczjk/tp2;

.field protected _byToStringResolver:Llyiahf/vczjk/tp2;

.field protected final _enumDefaultValue:Ljava/lang/Enum;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Enum<",
            "*>;"
        }
    .end annotation
.end field

.field protected final _factory:Llyiahf/vczjk/rm;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tp2;Llyiahf/vczjk/rm;)V
    .locals 3

    invoke-virtual {p1}, Llyiahf/vczjk/tp2;->OooO0Oo()Ljava/lang/Class;

    move-result-object v0

    const/4 v1, 0x0

    const/4 v2, -0x1

    invoke-direct {p0, v2, v0, v1}, Llyiahf/vczjk/v49;-><init>(ILjava/lang/Class;Llyiahf/vczjk/ie3;)V

    iput-object p1, p0, Llyiahf/vczjk/r49;->_byNameResolver:Llyiahf/vczjk/tp2;

    iput-object p2, p0, Llyiahf/vczjk/r49;->_factory:Llyiahf/vczjk/rm;

    invoke-virtual {p1}, Llyiahf/vczjk/tp2;->OooO0OO()Ljava/lang/Enum;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/r49;->_enumDefaultValue:Ljava/lang/Enum;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Ljava/lang/String;Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/r49;->_factory:Llyiahf/vczjk/rm;

    if-eqz v0, :cond_0

    :try_start_0
    invoke-virtual {v0, p1}, Llyiahf/vczjk/rm;->o0O0O00(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOOOO(Ljava/lang/Exception;)Ljava/lang/Throwable;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p2

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo(Ljava/lang/Throwable;)V

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0, p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0

    :cond_0
    sget-object v0, Llyiahf/vczjk/w72;->Oooo0:Llyiahf/vczjk/w72;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/r49;->_byToStringResolver:Llyiahf/vczjk/tp2;

    if-nez v0, :cond_2

    monitor-enter p0

    :try_start_1
    iget-object v0, p0, Llyiahf/vczjk/r49;->_byNameResolver:Llyiahf/vczjk/tp2;

    invoke-virtual {v0}, Llyiahf/vczjk/tp2;->OooO0Oo()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/tp2;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/yn;)Llyiahf/vczjk/tp2;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/r49;->_byToStringResolver:Llyiahf/vczjk/tp2;

    monitor-exit p0

    goto :goto_0

    :catchall_0
    move-exception p1

    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/r49;->_byNameResolver:Llyiahf/vczjk/tp2;

    :cond_2
    :goto_0
    iget-object v1, v0, Llyiahf/vczjk/tp2;->_enumsById:Ljava/util/HashMap;

    invoke-virtual {v1, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Enum;

    if-nez v1, :cond_5

    iget-object v2, p0, Llyiahf/vczjk/r49;->_enumDefaultValue:Ljava/lang/Enum;

    if-eqz v2, :cond_3

    sget-object v2, Llyiahf/vczjk/w72;->Oooo0OO:Llyiahf/vczjk/w72;

    invoke-virtual {p2, v2}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v2

    if-eqz v2, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/r49;->_enumDefaultValue:Ljava/lang/Enum;

    return-object p1

    :cond_3
    sget-object v2, Llyiahf/vczjk/w72;->Oooo0O0:Llyiahf/vczjk/w72;

    invoke-virtual {p2, v2}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v2

    if-eqz v2, :cond_4

    goto :goto_1

    :cond_4
    iget-object v1, p0, Llyiahf/vczjk/v49;->_keyClass:Ljava/lang/Class;

    const-string v2, "not one of the values accepted for Enum class: %s"

    iget-object v0, v0, Llyiahf/vczjk/tp2;->_enumsById:Ljava/util/HashMap;

    invoke-virtual {v0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    move-result-object v0

    check-cast v0, Ljava/util/Set;

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p2, v1, p1, v2, v0}, Llyiahf/vczjk/v72;->o00000Oo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p1, 0x0

    throw p1

    :cond_5
    :goto_1
    return-object v1
.end method
