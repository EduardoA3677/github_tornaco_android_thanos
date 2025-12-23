.class public abstract Llyiahf/vczjk/v72;
.super Llyiahf/vczjk/mc4;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field public final transient OooOo:Llyiahf/vczjk/eb4;

.field public transient OooOoO:Llyiahf/vczjk/ie;

.field public transient OooOoO0:Llyiahf/vczjk/ex9;

.field public transient OooOoOO:Ljava/text/DateFormat;

.field protected final _cache:Llyiahf/vczjk/x82;

.field protected final _config:Llyiahf/vczjk/t72;

.field protected _currentType:Llyiahf/vczjk/j05;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/j05;"
        }
    .end annotation
.end field

.field protected final _factory:Llyiahf/vczjk/y82;

.field protected final _featureFlags:I

.field protected final _injectableValues:Llyiahf/vczjk/mz3;

.field protected final _view:Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/ab0;->OooOOO:Llyiahf/vczjk/ab0;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/v72;->_factory:Llyiahf/vczjk/y82;

    new-instance v0, Llyiahf/vczjk/x82;

    invoke-direct {v0}, Llyiahf/vczjk/x82;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/v72;->_cache:Llyiahf/vczjk/x82;

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/v72;->_featureFlags:I

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    iput-object v0, p0, Llyiahf/vczjk/v72;->_view:Ljava/lang/Class;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/v72;Llyiahf/vczjk/t72;Llyiahf/vczjk/eb4;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iget-object v0, p1, Llyiahf/vczjk/v72;->_cache:Llyiahf/vczjk/x82;

    iput-object v0, p0, Llyiahf/vczjk/v72;->_cache:Llyiahf/vczjk/x82;

    iget-object p1, p1, Llyiahf/vczjk/v72;->_factory:Llyiahf/vczjk/y82;

    iput-object p1, p0, Llyiahf/vczjk/v72;->_factory:Llyiahf/vczjk/y82;

    iput-object p2, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    iget p1, p2, Llyiahf/vczjk/t72;->_deserFeatures:I

    iput p1, p0, Llyiahf/vczjk/v72;->_featureFlags:I

    invoke-virtual {p2}, Llyiahf/vczjk/fc5;->OooOo0o()Ljava/lang/Class;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/v72;->_view:Ljava/lang/Class;

    iput-object p3, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    return-void
.end method

.method public static o0000OOO(Ljava/lang/Class;Llyiahf/vczjk/eb4;Llyiahf/vczjk/gc4;)V
    .locals 3

    invoke-static {p0}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Trailing token (of type "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p2, ") found after value (bound as "

    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p2, "): not allowed as per `DeserializationFeature.FAIL_ON_TRAILING_TOKENS`"

    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    new-instance v0, Llyiahf/vczjk/qj5;

    invoke-direct {v0, p1, p2, p0}, Llyiahf/vczjk/qj5;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Ljava/lang/Class;)V

    throw v0
.end method

.method public static o0000o0(Ljava/lang/Class;Ljava/lang/String;Llyiahf/vczjk/eb4;Llyiahf/vczjk/gc4;)Llyiahf/vczjk/qj5;
    .locals 3

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Unexpected token ("

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, "), expected "

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p3

    invoke-static {p3, p1}, Llyiahf/vczjk/mc4;->OooOO0o(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    new-instance p3, Llyiahf/vczjk/qj5;

    invoke-direct {p3, p2, p1, p0}, Llyiahf/vczjk/qj5;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Ljava/lang/Class;)V

    return-object p3
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

    iget-object v1, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {v0, v1, p3, p1, p2}, Llyiahf/vczjk/k44;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/x64;Ljava/lang/String;)V

    return-object v0
.end method

.method public final Oooo00O()Llyiahf/vczjk/ec5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    return-object v0
.end method

.method public final Oooo0o0()Llyiahf/vczjk/a4a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooOOOO()Llyiahf/vczjk/a4a;

    move-result-object v0

    return-object v0
.end method

.method public final OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/d44;

    iget-object v1, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {v0, v1, p2, p1}, Llyiahf/vczjk/d44;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/x64;)V

    throw v0
.end method

.method public final Oooooo(Ljava/lang/Class;)Llyiahf/vczjk/x64;
    .locals 1

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ec5;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object p1

    return-object p1
.end method

.method public final Oooooo0(Ljava/util/Date;)Ljava/util/Calendar;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooOOO()Ljava/util/TimeZone;

    move-result-object v0

    invoke-static {v0}, Ljava/util/Calendar;->getInstance(Ljava/util/TimeZone;)Ljava/util/Calendar;

    move-result-object v0

    invoke-virtual {v0, p1}, Ljava/util/Calendar;->setTime(Ljava/util/Date;)V

    return-object v0
.end method

.method public abstract OoooooO(Ljava/lang/Object;)Llyiahf/vczjk/e94;
.end method

.method public final Ooooooo(Ljava/lang/String;)Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooOOOO()Llyiahf/vczjk/a4a;

    move-result-object v0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a4a;->OooOOO0(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object p1

    return-object p1
.end method

.method public final o0000(Llyiahf/vczjk/w72;)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/v72;->_featureFlags:I

    invoke-virtual {p1}, Llyiahf/vczjk/w72;->OooO0O0()I

    move-result p1

    and-int/2addr p1, v0

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final o00000(Llyiahf/vczjk/x64;Llyiahf/vczjk/eb4;)V
    .locals 6

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v2

    const/4 v0, 0x0

    new-array v5, v0, [Ljava/lang/Object;

    const/4 v4, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v3, p2

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/v72;->o00000O0(Llyiahf/vczjk/x64;Llyiahf/vczjk/gc4;Llyiahf/vczjk/eb4;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final o000000(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;
    .locals 2

    instance-of v0, p1, Llyiahf/vczjk/wo1;

    if-eqz v0, :cond_0

    new-instance v0, Llyiahf/vczjk/j05;

    iget-object v1, p0, Llyiahf/vczjk/v72;->_currentType:Llyiahf/vczjk/j05;

    invoke-direct {v0, p3, v1}, Llyiahf/vczjk/j05;-><init>(Ljava/lang/Object;Llyiahf/vczjk/j05;)V

    iput-object v0, p0, Llyiahf/vczjk/v72;->_currentType:Llyiahf/vczjk/j05;

    :try_start_0
    check-cast p1, Llyiahf/vczjk/wo1;

    invoke-interface {p1, p0, p2}, Llyiahf/vczjk/wo1;->OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iget-object p2, p0, Llyiahf/vczjk/v72;->_currentType:Llyiahf/vczjk/j05;

    iget-object p2, p2, Llyiahf/vczjk/j05;->OooO0O0:Llyiahf/vczjk/j05;

    iput-object p2, p0, Llyiahf/vczjk/v72;->_currentType:Llyiahf/vczjk/j05;

    return-object p1

    :catchall_0
    move-exception p1

    iget-object p2, p0, Llyiahf/vczjk/v72;->_currentType:Llyiahf/vczjk/j05;

    iget-object p2, p2, Llyiahf/vczjk/j05;->OooO0O0:Llyiahf/vczjk/j05;

    iput-object p2, p0, Llyiahf/vczjk/v72;->_currentType:Llyiahf/vczjk/j05;

    throw p1

    :cond_0
    return-object p1
.end method

.method public final o000000O(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;
    .locals 2

    instance-of v0, p1, Llyiahf/vczjk/wo1;

    if-eqz v0, :cond_0

    new-instance v0, Llyiahf/vczjk/j05;

    iget-object v1, p0, Llyiahf/vczjk/v72;->_currentType:Llyiahf/vczjk/j05;

    invoke-direct {v0, p3, v1}, Llyiahf/vczjk/j05;-><init>(Ljava/lang/Object;Llyiahf/vczjk/j05;)V

    iput-object v0, p0, Llyiahf/vczjk/v72;->_currentType:Llyiahf/vczjk/j05;

    :try_start_0
    check-cast p1, Llyiahf/vczjk/wo1;

    invoke-interface {p1, p0, p2}, Llyiahf/vczjk/wo1;->OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iget-object p2, p0, Llyiahf/vczjk/v72;->_currentType:Llyiahf/vczjk/j05;

    iget-object p2, p2, Llyiahf/vczjk/j05;->OooO0O0:Llyiahf/vczjk/j05;

    iput-object p2, p0, Llyiahf/vczjk/v72;->_currentType:Llyiahf/vczjk/j05;

    return-object p1

    :catchall_0
    move-exception p1

    iget-object p2, p0, Llyiahf/vczjk/v72;->_currentType:Llyiahf/vczjk/j05;

    iget-object p2, p2, Llyiahf/vczjk/j05;->OooO0O0:Llyiahf/vczjk/j05;

    iput-object p2, p0, Llyiahf/vczjk/v72;->_currentType:Llyiahf/vczjk/j05;

    throw p1

    :cond_0
    return-object p1
.end method

.method public final o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V
    .locals 6

    invoke-virtual {p0, p1}, Llyiahf/vczjk/v72;->Oooooo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v1

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v2

    const/4 p1, 0x0

    new-array v5, p1, [Ljava/lang/Object;

    const/4 v4, 0x0

    move-object v0, p0

    move-object v3, p2

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/v72;->o00000O0(Llyiahf/vczjk/x64;Llyiahf/vczjk/gc4;Llyiahf/vczjk/eb4;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final o00000O(Llyiahf/vczjk/eb4;Llyiahf/vczjk/m49;Ljava/lang/Object;Ljava/lang/String;)V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    iget-object v0, v0, Llyiahf/vczjk/t72;->_problemHandlers:Llyiahf/vczjk/j05;

    if-nez v0, :cond_2

    sget-object v0, Llyiahf/vczjk/w72;->OooOOo0:Llyiahf/vczjk/w72;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    return-void

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/e94;->OooOO0O()Ljava/util/Collection;

    move-result-object v7

    sget p1, Llyiahf/vczjk/k9a;->OooOOOo:I

    instance-of p1, p3, Ljava/lang/Class;

    if-eqz p1, :cond_1

    move-object p1, p3

    check-cast p1, Ljava/lang/Class;

    :goto_0
    move-object v5, p1

    goto :goto_1

    :cond_1
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    goto :goto_0

    :goto_1
    invoke-virtual {v5}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    const-string p2, "Unrecognized field \""

    const-string v0, "\" (class "

    const-string v1, "), not marked as ignorable"

    invoke-static {p2, p4, v0, p1, v1}, Llyiahf/vczjk/ii5;->OooOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    new-instance v1, Llyiahf/vczjk/k9a;

    iget-object v2, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-virtual {v2}, Llyiahf/vczjk/eb4;->OoooOO0()Llyiahf/vczjk/ia4;

    move-result-object v4

    move-object v6, p4

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/ra7;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/ia4;Ljava/lang/Class;Ljava/lang/String;Ljava/util/Collection;)V

    new-instance p1, Llyiahf/vczjk/ma4;

    invoke-direct {p1, p3, v6}, Llyiahf/vczjk/ma4;-><init>(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Llyiahf/vczjk/na4;->OooO0o(Llyiahf/vczjk/ma4;)V

    throw v1

    :cond_2
    iget-object p1, v0, Llyiahf/vczjk/j05;->OooO00o:Ljava/lang/Object;

    invoke-static {p1}, Llyiahf/vczjk/ix8;->OooO0O0(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1
.end method

.method public final varargs o00000O0(Llyiahf/vczjk/x64;Llyiahf/vczjk/gc4;Llyiahf/vczjk/eb4;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    array-length v0, p5

    if-lez v0, :cond_0

    invoke-static {p4, p5}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p4

    :cond_0
    iget-object p5, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    iget-object p5, p5, Llyiahf/vczjk/t72;->_problemHandlers:Llyiahf/vczjk/j05;

    if-nez p5, :cond_4

    if-nez p4, :cond_2

    if-nez p2, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOOOo(Llyiahf/vczjk/x64;)Ljava/lang/String;

    move-result-object p4

    const-string p5, "Unexpected end-of-input when binding data into "

    invoke-static {p5, p4}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p4

    goto :goto_0

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOOOo(Llyiahf/vczjk/x64;)Ljava/lang/String;

    move-result-object p4

    new-instance p5, Ljava/lang/StringBuilder;

    const-string v0, "Cannot deserialize instance of "

    invoke-direct {p5, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p5, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p4, " out of "

    invoke-virtual {p5, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p5, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p4, " token"

    invoke-virtual {p5, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p4

    :cond_2
    :goto_0
    if-eqz p2, :cond_3

    invoke-virtual {p2}, Llyiahf/vczjk/gc4;->OooO0o0()Z

    move-result p2

    if-eqz p2, :cond_3

    invoke-virtual {p3}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    :cond_3
    new-instance p2, Llyiahf/vczjk/qj5;

    iget-object p3, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {p2, p3, p4, p1}, Llyiahf/vczjk/qj5;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/x64;)V

    throw p2

    :cond_4
    iget-object p1, p5, Llyiahf/vczjk/j05;->OooO00o:Ljava/lang/Object;

    invoke-static {p1}, Llyiahf/vczjk/ix8;->OooO0O0(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1
.end method

.method public final o00000OO(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    iget-object v0, v0, Llyiahf/vczjk/t72;->_problemHandlers:Llyiahf/vczjk/j05;

    if-nez v0, :cond_1

    sget-object v0, Llyiahf/vczjk/w72;->OooOo00:Llyiahf/vczjk/w72;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-nez v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/v72;->Oooo(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/k44;

    move-result-object p1

    throw p1

    :cond_1
    iget-object p1, v0, Llyiahf/vczjk/j05;->OooO00o:Ljava/lang/Object;

    invoke-static {p1}, Llyiahf/vczjk/ix8;->OooO0O0(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1
.end method

.method public final varargs o00000Oo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 4

    array-length v0, p4

    if-lez v0, :cond_0

    invoke-static {p3, p4}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p3

    :cond_0
    iget-object p4, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    iget-object p4, p4, Llyiahf/vczjk/t72;->_problemHandlers:Llyiahf/vczjk/j05;

    if-eqz p4, :cond_1

    iget-object p1, p4, Llyiahf/vczjk/j05;->OooO00o:Ljava/lang/Object;

    invoke-static {p1}, Llyiahf/vczjk/ix8;->OooO0O0(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object p4

    invoke-static {p2}, Llyiahf/vczjk/mc4;->OooOOO0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "Cannot deserialize Map key of type "

    const-string v2, " from String "

    const-string v3, ": "

    invoke-static {v1, p4, v2, v0, v3}, Llyiahf/vczjk/q99;->OooO0oo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p4

    invoke-virtual {p4, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p3

    new-instance p4, Llyiahf/vczjk/e44;

    iget-object v0, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {p4, v0, p3, p2, p1}, Llyiahf/vczjk/e44;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Class;)V

    throw p4
.end method

.method public final varargs o00000o0(Ljava/lang/Class;Ljava/lang/Number;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 4

    array-length v0, p4

    if-lez v0, :cond_0

    invoke-static {p3, p4}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p3

    :cond_0
    iget-object p4, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    iget-object p4, p4, Llyiahf/vczjk/t72;->_problemHandlers:Llyiahf/vczjk/j05;

    if-eqz p4, :cond_1

    iget-object p1, p4, Llyiahf/vczjk/j05;->OooO00o:Ljava/lang/Object;

    invoke-static {p1}, Llyiahf/vczjk/ix8;->OooO0O0(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object p4

    invoke-static {p2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "Cannot deserialize value of type "

    const-string v2, " from number "

    const-string v3, ": "

    invoke-static {v1, p4, v2, v0, v3}, Llyiahf/vczjk/q99;->OooO0oo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p4

    invoke-virtual {p4, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p3

    new-instance p4, Llyiahf/vczjk/e44;

    iget-object v0, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {p4, v0, p3, p2, p1}, Llyiahf/vczjk/e44;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Class;)V

    throw p4
.end method

.method public final o00000oO(I)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/v72;->_featureFlags:I

    and-int/2addr p1, v0

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final o00000oo(Ljava/lang/Class;Ljava/lang/Throwable;)Llyiahf/vczjk/lca;
    .locals 4

    if-nez p2, :cond_0

    const-string v0, "N/A"

    goto :goto_0

    :cond_0
    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_1

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v0

    :cond_1
    :goto_0
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v1

    const-string v2, "Cannot construct instance of "

    const-string v3, ", problem: "

    invoke-static {v2, v1, v3, v0}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/v72;->Oooooo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/lca;

    iget-object v2, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {v1, v2, v0, p1, p2}, Llyiahf/vczjk/lca;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/x64;Ljava/lang/Throwable;)V

    return-object v1
.end method

.method public final varargs o0000O(Llyiahf/vczjk/db0;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 2

    array-length v0, p3

    if-lez v0, :cond_0

    invoke-static {p2, p3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    :cond_0
    if-nez p1, :cond_1

    const/4 p3, 0x0

    goto :goto_0

    :cond_1
    invoke-interface {p1}, Llyiahf/vczjk/db0;->getType()Llyiahf/vczjk/x64;

    move-result-object p3

    :goto_0
    new-instance v0, Llyiahf/vczjk/qj5;

    iget-object v1, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {v0, v1, p2, p3}, Llyiahf/vczjk/qj5;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/x64;)V

    if-eqz p1, :cond_2

    invoke-interface {p1}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object p2

    if-eqz p2, :cond_2

    invoke-virtual {p2}, Llyiahf/vczjk/pm;->o00oO0o()Ljava/lang/Class;

    move-result-object p2

    invoke-interface {p1}, Llyiahf/vczjk/yt5;->getName()Ljava/lang/String;

    move-result-object p1

    new-instance p3, Llyiahf/vczjk/ma4;

    invoke-direct {p3, p2, p1}, Llyiahf/vczjk/ma4;-><init>(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0, p3}, Llyiahf/vczjk/na4;->OooO0o(Llyiahf/vczjk/ma4;)V

    :cond_2
    throw v0
.end method

.method public final o0000O0(Ljava/lang/String;)Ljava/util/Date;
    .locals 4

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/v72;->OooOoOO:Ljava/text/DateFormat;

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0oo()Ljava/text/DateFormat;

    move-result-object v0

    invoke-virtual {v0}, Ljava/text/DateFormat;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/text/DateFormat;

    iput-object v0, p0, Llyiahf/vczjk/v72;->OooOoOO:Ljava/text/DateFormat;

    :goto_0
    invoke-virtual {v0, p1}, Ljava/text/DateFormat;->parse(Ljava/lang/String;)Ljava/util/Date;

    move-result-object p1
    :try_end_0
    .catch Ljava/text/ParseException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception v0

    new-instance v1, Ljava/lang/IllegalArgumentException;

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v0

    const-string v2, "Failed to parse Date value \'"

    const-string v3, "\': "

    invoke-static {v2, p1, v3, v0}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {v1, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v1
.end method

.method public final o0000O00(Llyiahf/vczjk/gc5;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result p1

    return p1
.end method

.method public final varargs o0000O0O(Llyiahf/vczjk/h90;Llyiahf/vczjk/eb0;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 3

    array-length v0, p4

    if-lez v0, :cond_0

    invoke-static {p3, p4}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p3

    :cond_0
    sget-object p4, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    invoke-interface {p2}, Llyiahf/vczjk/yt5;->getName()Ljava/lang/String;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooO0O0(Ljava/lang/String;)Ljava/lang/String;

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

    new-instance p3, Llyiahf/vczjk/d44;

    iget-object p4, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {p3, p4, p2, p1}, Llyiahf/vczjk/d44;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/h90;)V

    throw p3
.end method

.method public final varargs o0000OO(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    iget-object p1, p1, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    array-length v0, p4

    if-lez v0, :cond_0

    invoke-static {p3, p4}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p3

    :cond_0
    new-instance p4, Llyiahf/vczjk/qj5;

    iget-object v0, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {p4, v0, p3, p1}, Llyiahf/vczjk/qj5;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Ljava/lang/Class;)V

    if-eqz p2, :cond_1

    new-instance p3, Llyiahf/vczjk/ma4;

    invoke-direct {p3, p1, p2}, Llyiahf/vczjk/ma4;-><init>(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p4, p3}, Llyiahf/vczjk/na4;->OooO0o(Llyiahf/vczjk/ma4;)V

    :cond_1
    throw p4
.end method

.method public final varargs o0000OO0(Llyiahf/vczjk/e94;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    array-length v0, p3

    if-lez v0, :cond_0

    invoke-static {p2, p3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/e94;->OooOOO0()Ljava/lang/Class;

    move-result-object p1

    new-instance p3, Llyiahf/vczjk/qj5;

    iget-object v0, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {p3, v0, p2, p1}, Llyiahf/vczjk/qj5;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Ljava/lang/Class;)V

    throw p3
.end method

.method public final varargs o0000OOo(Llyiahf/vczjk/x64;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 3

    array-length v0, p4

    if-lez v0, :cond_0

    invoke-static {p3, p4}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p3

    :cond_0
    iget-object p4, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-virtual {p4}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Unexpected token ("

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, "), expected "

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-static {p2, p3}, Llyiahf/vczjk/mc4;->OooOO0o(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    new-instance p3, Llyiahf/vczjk/qj5;

    invoke-direct {p3, p4, p2, p1}, Llyiahf/vczjk/qj5;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/x64;)V

    throw p3
.end method

.method public final o0000Oo(Llyiahf/vczjk/ie;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/v72;->OooOoO:Llyiahf/vczjk/ie;

    if-eqz v0, :cond_3

    iget-object v1, p1, Llyiahf/vczjk/ie;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, [Ljava/lang/Object;

    const/4 v2, 0x0

    if-nez v1, :cond_0

    move v1, v2

    goto :goto_0

    :cond_0
    array-length v1, v1

    :goto_0
    iget-object v0, v0, Llyiahf/vczjk/ie;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, [Ljava/lang/Object;

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    array-length v2, v0

    :goto_1
    if-lt v1, v2, :cond_2

    goto :goto_2

    :cond_2
    return-void

    :cond_3
    :goto_2
    iput-object p1, p0, Llyiahf/vczjk/v72;->OooOoO:Llyiahf/vczjk/ie;

    return-void
.end method

.method public final varargs o0000Oo0(Llyiahf/vczjk/e94;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    array-length v0, p4

    if-lez v0, :cond_0

    invoke-static {p3, p4}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p3

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/e94;->OooOOO0()Ljava/lang/Class;

    move-result-object p1

    iget-object p4, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-static {p1, p3, p4, p2}, Llyiahf/vczjk/v72;->o0000o0(Ljava/lang/Class;Ljava/lang/String;Llyiahf/vczjk/eb4;Llyiahf/vczjk/gc4;)Llyiahf/vczjk/qj5;

    move-result-object p1

    throw p1
.end method

.method public final o0000OoO(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/e44;
    .locals 5

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v0

    invoke-static {p2}, Llyiahf/vczjk/mc4;->OooOOO0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const-string v2, "Cannot deserialize value of type "

    const-string v3, " from String "

    const-string v4, ": "

    invoke-static {v2, v0, v3, v1, v4}, Llyiahf/vczjk/q99;->OooO0oo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p3

    new-instance v0, Llyiahf/vczjk/e44;

    iget-object v1, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {v0, v1, p3, p2, p1}, Llyiahf/vczjk/e44;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Class;)V

    return-object v0
.end method

.method public final varargs o0000Ooo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    array-length v0, p4

    if-lez v0, :cond_0

    invoke-static {p3, p4}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p3

    :cond_0
    iget-object p4, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    iget-object p4, p4, Llyiahf/vczjk/t72;->_problemHandlers:Llyiahf/vczjk/j05;

    if-eqz p4, :cond_1

    iget-object p1, p4, Llyiahf/vczjk/j05;->OooO00o:Ljava/lang/Object;

    invoke-static {p1}, Llyiahf/vczjk/ix8;->OooO0O0(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1

    :cond_1
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/v72;->o0000OoO(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/e44;

    move-result-object p1

    throw p1
.end method

.method public final o0000oO()Llyiahf/vczjk/ie;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/v72;->OooOoO:Llyiahf/vczjk/ie;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/ie;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    return-object v0

    :cond_0
    const/4 v1, 0x0

    iput-object v1, p0, Llyiahf/vczjk/v72;->OooOoO:Llyiahf/vczjk/ie;

    return-object v0
.end method

.method public abstract o0000oo(Ljava/lang/Object;)Llyiahf/vczjk/ti4;
.end method

.method public final varargs o000OO(Llyiahf/vczjk/h90;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 2

    array-length v0, p3

    if-lez v0, :cond_0

    invoke-static {p2, p3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p2

    :cond_0
    iget-object p3, p1, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    iget-object p3, p3, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-static {p3}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object p3

    const-string v0, "Invalid type definition for type "

    const-string v1, ": "

    invoke-static {v0, p3, v1, p2}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    new-instance p3, Llyiahf/vczjk/d44;

    iget-object v0, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {p3, v0, p2, p1}, Llyiahf/vczjk/d44;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/h90;)V

    throw p3
.end method

.method public final varargs o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    array-length v0, p4

    if-lez v0, :cond_0

    invoke-static {p3, p4}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p3

    :cond_0
    iget-object p4, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    iget-object p4, p4, Llyiahf/vczjk/t72;->_problemHandlers:Llyiahf/vczjk/j05;

    if-nez p4, :cond_3

    const/4 p4, 0x0

    const-string v0, "Cannot construct instance of "

    if-eqz p2, :cond_2

    invoke-virtual {p2}, Llyiahf/vczjk/nca;->OooOO0O()Z

    move-result p2

    if-eqz p2, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object p2

    const-string p4, " (although at least one Creator exists): "

    invoke-static {v0, p2, p4, p3}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    new-instance p3, Llyiahf/vczjk/qj5;

    iget-object p4, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {p3, p4, p2, p1}, Llyiahf/vczjk/qj5;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Ljava/lang/Class;)V

    throw p3

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object p2

    const-string v1, " (no Creators, like default constructor, exist): "

    invoke-static {v0, p2, v1, p3}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/mc4;->o000oOoO(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;

    throw p4

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object p2

    const-string v1, ": "

    invoke-static {v0, p2, v1, p3}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/mc4;->o000oOoO(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;

    throw p4

    :cond_3
    iget-object p1, p4, Llyiahf/vczjk/j05;->OooO00o:Ljava/lang/Object;

    invoke-static {p1}, Llyiahf/vczjk/ix8;->OooO0O0(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1
.end method

.method public final o00O0O(Llyiahf/vczjk/x64;)Llyiahf/vczjk/ti4;
    .locals 13

    iget-object v0, p0, Llyiahf/vczjk/v72;->_cache:Llyiahf/vczjk/x82;

    iget-object v1, p0, Llyiahf/vczjk/v72;->_factory:Llyiahf/vczjk/y82;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    check-cast v1, Llyiahf/vczjk/n90;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p0}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v0

    iget-object v2, v1, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    iget-object v2, v2, Llyiahf/vczjk/z82;->_additionalKeyDeserializers:[Llyiahf/vczjk/ui4;

    array-length v2, v2

    if-lez v2, :cond_0

    const/4 v2, 0x1

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    :goto_0
    const/4 v3, 0x0

    const/4 v4, 0x1

    const-class v5, Ljava/lang/String;

    if-eqz v2, :cond_18

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ec5;->OooOOo0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v2

    iget-object v6, v1, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    new-instance v7, Llyiahf/vczjk/yx;

    iget-object v6, v6, Llyiahf/vczjk/z82;->_additionalKeyDeserializers:[Llyiahf/vczjk/ui4;

    invoke-direct {v7, v6}, Llyiahf/vczjk/yx;-><init>([Ljava/lang/Object;)V

    move-object v6, v3

    :cond_1
    invoke-virtual {v7}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_19

    invoke-virtual {v7}, Llyiahf/vczjk/yx;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/ui4;

    check-cast v6, Llyiahf/vczjk/w49;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/Class;->isPrimitive()Z

    move-result v8

    if-eqz v8, :cond_2

    invoke-static {v6}, Llyiahf/vczjk/vy0;->OooOoo0(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object v6

    :cond_2
    const-class v8, Ljava/lang/Object;

    if-eq v6, v5, :cond_15

    if-eq v6, v8, :cond_15

    const-class v9, Ljava/lang/CharSequence;

    if-eq v6, v9, :cond_15

    const-class v9, Ljava/io/Serializable;

    if-ne v6, v9, :cond_3

    goto/16 :goto_3

    :cond_3
    const-class v8, Ljava/util/UUID;

    if-ne v6, v8, :cond_4

    const/16 v8, 0xc

    goto/16 :goto_2

    :cond_4
    const-class v8, Ljava/lang/Integer;

    if-ne v6, v8, :cond_5

    const/4 v8, 0x5

    goto/16 :goto_2

    :cond_5
    const-class v8, Ljava/lang/Long;

    if-ne v6, v8, :cond_6

    const/4 v8, 0x6

    goto/16 :goto_2

    :cond_6
    const-class v8, Ljava/util/Date;

    if-ne v6, v8, :cond_7

    const/16 v8, 0xa

    goto/16 :goto_2

    :cond_7
    const-class v8, Ljava/util/Calendar;

    if-ne v6, v8, :cond_8

    const/16 v8, 0xb

    goto/16 :goto_2

    :cond_8
    const-class v8, Ljava/lang/Boolean;

    if-ne v6, v8, :cond_9

    move v8, v4

    goto :goto_2

    :cond_9
    const-class v8, Ljava/lang/Byte;

    if-ne v6, v8, :cond_a

    const/4 v8, 0x2

    goto :goto_2

    :cond_a
    const-class v8, Ljava/lang/Character;

    if-ne v6, v8, :cond_b

    const/4 v8, 0x4

    goto :goto_2

    :cond_b
    const-class v8, Ljava/lang/Short;

    if-ne v6, v8, :cond_c

    const/4 v8, 0x3

    goto :goto_2

    :cond_c
    const-class v8, Ljava/lang/Float;

    if-ne v6, v8, :cond_d

    const/4 v8, 0x7

    goto :goto_2

    :cond_d
    const-class v8, Ljava/lang/Double;

    if-ne v6, v8, :cond_e

    const/16 v8, 0x8

    goto :goto_2

    :cond_e
    const-class v8, Ljava/net/URI;

    if-ne v6, v8, :cond_f

    const/16 v8, 0xd

    goto :goto_2

    :cond_f
    const-class v8, Ljava/net/URL;

    if-ne v6, v8, :cond_10

    const/16 v8, 0xe

    goto :goto_2

    :cond_10
    const-class v8, Ljava/lang/Class;

    if-ne v6, v8, :cond_11

    const/16 v8, 0xf

    goto :goto_2

    :cond_11
    const-class v8, Ljava/util/Locale;

    if-ne v6, v8, :cond_12

    invoke-static {v8}, Llyiahf/vczjk/je3;->OoooOoO(Ljava/lang/Class;)Llyiahf/vczjk/ie3;

    move-result-object v8

    new-instance v9, Llyiahf/vczjk/v49;

    const/16 v10, 0x9

    invoke-direct {v9, v10, v6, v8}, Llyiahf/vczjk/v49;-><init>(ILjava/lang/Class;Llyiahf/vczjk/ie3;)V

    :goto_1
    move-object v6, v9

    goto :goto_4

    :cond_12
    const-class v8, Ljava/util/Currency;

    if-ne v6, v8, :cond_13

    invoke-static {v8}, Llyiahf/vczjk/je3;->OoooOoO(Ljava/lang/Class;)Llyiahf/vczjk/ie3;

    move-result-object v8

    new-instance v9, Llyiahf/vczjk/v49;

    const/16 v10, 0x10

    invoke-direct {v9, v10, v6, v8}, Llyiahf/vczjk/v49;-><init>(ILjava/lang/Class;Llyiahf/vczjk/ie3;)V

    goto :goto_1

    :cond_13
    const-class v8, [B

    if-ne v6, v8, :cond_14

    const/16 v8, 0x11

    :goto_2
    new-instance v9, Llyiahf/vczjk/v49;

    invoke-direct {v9, v8, v6, v3}, Llyiahf/vczjk/v49;-><init>(ILjava/lang/Class;Llyiahf/vczjk/ie3;)V

    goto :goto_1

    :cond_14
    move-object v6, v3

    goto :goto_4

    :cond_15
    :goto_3
    if-ne v6, v5, :cond_16

    sget-object v6, Llyiahf/vczjk/u49;->OooOOO0:Llyiahf/vczjk/u49;

    goto :goto_4

    :cond_16
    if-ne v6, v8, :cond_17

    sget-object v6, Llyiahf/vczjk/u49;->OooOOO:Llyiahf/vczjk/u49;

    goto :goto_4

    :cond_17
    new-instance v8, Llyiahf/vczjk/u49;

    invoke-direct {v8, v6}, Llyiahf/vczjk/u49;-><init>(Ljava/lang/Class;)V

    move-object v6, v8

    :goto_4
    if-eqz v6, :cond_1

    goto :goto_5

    :cond_18
    move-object v2, v3

    move-object v6, v2

    :cond_19
    :goto_5
    if-nez v6, :cond_2f

    if-nez v2, :cond_1a

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/ec5;->OooOOOo(Ljava/lang/Class;)Llyiahf/vczjk/h90;

    move-result-object v2

    :cond_1a
    invoke-virtual {p0}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v6

    if-eqz v6, :cond_1b

    iget-object v2, v2, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {v6, v2}, Llyiahf/vczjk/yn;->OooOOo(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_1b

    invoke-virtual {p0, v2}, Llyiahf/vczjk/v72;->o0000oo(Ljava/lang/Object;)Llyiahf/vczjk/ti4;

    move-result-object v2

    move-object v6, v2

    goto :goto_6

    :cond_1b
    move-object v6, v3

    :goto_6
    if-nez v6, :cond_2f

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->Oooooo()Z

    move-result v2

    if-eqz v2, :cond_25

    invoke-virtual {p0}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v0, p1}, Llyiahf/vczjk/t72;->Oooo00o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v6

    invoke-virtual {p0}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v7

    iget-object v8, v6, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    if-eqz v7, :cond_1c

    invoke-virtual {v7, v8}, Llyiahf/vczjk/yn;->OooOOo(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v7

    if-eqz v7, :cond_1c

    invoke-virtual {p0, v7}, Llyiahf/vczjk/v72;->o0000oo(Ljava/lang/Object;)Llyiahf/vczjk/ti4;

    move-result-object v7

    goto :goto_7

    :cond_1c
    move-object v7, v3

    :goto_7
    if-eqz v7, :cond_1d

    move-object v6, v7

    goto/16 :goto_d

    :cond_1d
    iget-object v7, v1, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v7}, Llyiahf/vczjk/z82;->OooO0OO()Llyiahf/vczjk/yx;

    move-result-object v7

    invoke-virtual {v7}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v9

    if-nez v9, :cond_24

    invoke-static {p0, v8}, Llyiahf/vczjk/n90;->OooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/u34;)Llyiahf/vczjk/e94;

    move-result-object v7

    if-eqz v7, :cond_1e

    new-instance v0, Llyiahf/vczjk/q49;

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v2

    invoke-direct {v0, v2, v7}, Llyiahf/vczjk/q49;-><init>(Ljava/lang/Class;Llyiahf/vczjk/e94;)V

    :goto_8
    move-object v6, v0

    goto/16 :goto_d

    :cond_1e
    invoke-virtual {v6}, Llyiahf/vczjk/h90;->OooO0o0()Llyiahf/vczjk/pm;

    move-result-object v7

    invoke-static {v2, v0, v7}, Llyiahf/vczjk/n90;->OooOOO0(Ljava/lang/Class;Llyiahf/vczjk/t72;Llyiahf/vczjk/pm;)Llyiahf/vczjk/tp2;

    move-result-object v7

    invoke-virtual {v6}, Llyiahf/vczjk/h90;->OooO0oo()Ljava/util/List;

    move-result-object v6

    invoke-interface {v6}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :cond_1f
    :goto_9
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_23

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/rm;

    invoke-static {p0, v8}, Llyiahf/vczjk/n90;->OooOO0(Llyiahf/vczjk/v72;Llyiahf/vczjk/gn;)Z

    move-result v9

    if-eqz v9, :cond_1f

    invoke-virtual {v8}, Llyiahf/vczjk/rm;->o00000()[Ljava/lang/Class;

    move-result-object v9

    array-length v9, v9

    if-ne v9, v4, :cond_22

    iget-object v9, v8, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    invoke-virtual {v9}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    move-result-object v10

    invoke-virtual {v10, v2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v10

    if-eqz v10, :cond_22

    invoke-virtual {v8}, Llyiahf/vczjk/rm;->o000000o()Ljava/lang/Class;

    move-result-object v10

    if-eq v10, v5, :cond_20

    goto :goto_9

    :cond_20
    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v0

    if-eqz v0, :cond_21

    sget-object v0, Llyiahf/vczjk/gc5;->OooOoO:Llyiahf/vczjk/gc5;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/v72;->o0000O00(Llyiahf/vczjk/gc5;)Z

    move-result v0

    invoke-static {v9, v0}, Llyiahf/vczjk/vy0;->OooO0Oo(Ljava/lang/reflect/Member;Z)V

    :cond_21
    new-instance v0, Llyiahf/vczjk/r49;

    invoke-direct {v0, v7, v8}, Llyiahf/vczjk/r49;-><init>(Llyiahf/vczjk/tp2;Llyiahf/vczjk/rm;)V

    goto :goto_8

    :cond_22
    new-instance p1, Ljava/lang/IllegalArgumentException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Unsuitable method ("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ") decorated with @JsonCreator (for Enum type "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ")"

    invoke-static {v2, v0, v1}, Llyiahf/vczjk/ii5;->OooO0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_23
    new-instance v0, Llyiahf/vczjk/r49;

    invoke-direct {v0, v7, v3}, Llyiahf/vczjk/r49;-><init>(Llyiahf/vczjk/tp2;Llyiahf/vczjk/rm;)V

    goto :goto_8

    :cond_24
    invoke-static {v7}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1

    :cond_25
    invoke-virtual {v0, p1}, Llyiahf/vczjk/t72;->Oooo00o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/h90;

    move-result-object v2

    filled-new-array {v5}, [Ljava/lang/Class;

    move-result-object v6

    iget-object v7, v2, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {v7}, Llyiahf/vczjk/hm;->oo000o()Llyiahf/vczjk/uqa;

    move-result-object v7

    iget-object v7, v7, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v7, Ljava/util/List;

    invoke-interface {v7}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v7

    :cond_26
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_28

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/jm;

    invoke-virtual {v8}, Llyiahf/vczjk/jm;->o000000()I

    move-result v9

    const/4 v10, 0x1

    if-ne v9, v10, :cond_26

    invoke-virtual {v8}, Llyiahf/vczjk/jm;->o000000o()Ljava/lang/Class;

    move-result-object v9

    array-length v10, v6

    const/4 v11, 0x0

    :goto_a
    if-ge v11, v10, :cond_26

    aget-object v12, v6, v11

    if-ne v12, v9, :cond_27

    iget-object v6, v8, Llyiahf/vczjk/jm;->_constructor:Ljava/lang/reflect/Constructor;

    goto :goto_b

    :cond_27
    add-int/lit8 v11, v11, 0x1

    goto :goto_a

    :cond_28
    const/4 v6, 0x0

    :goto_b
    if-eqz v6, :cond_2a

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v2

    if-eqz v2, :cond_29

    sget-object v2, Llyiahf/vczjk/gc5;->OooOoO:Llyiahf/vczjk/gc5;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v0

    invoke-static {v6, v0}, Llyiahf/vczjk/vy0;->OooO0Oo(Ljava/lang/reflect/Member;Z)V

    :cond_29
    new-instance v0, Llyiahf/vczjk/s49;

    invoke-direct {v0, v6}, Llyiahf/vczjk/s49;-><init>(Ljava/lang/reflect/Constructor;)V

    goto/16 :goto_8

    :cond_2a
    filled-new-array {v5}, [Ljava/lang/Class;

    move-result-object v5

    iget-object v6, v2, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {v6}, Llyiahf/vczjk/hm;->oo000o()Llyiahf/vczjk/uqa;

    move-result-object v6

    iget-object v6, v6, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v6, Ljava/util/List;

    invoke-interface {v6}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :cond_2b
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_2c

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/rm;

    invoke-virtual {v2, v7}, Llyiahf/vczjk/h90;->OooOO0(Llyiahf/vczjk/rm;)Z

    move-result v8

    if-eqz v8, :cond_2b

    invoke-virtual {v7}, Llyiahf/vczjk/rm;->o00000()[Ljava/lang/Class;

    move-result-object v8

    array-length v8, v8

    if-ne v8, v4, :cond_2b

    invoke-virtual {v7}, Llyiahf/vczjk/rm;->o000000o()Ljava/lang/Class;

    move-result-object v8

    const/4 v9, 0x0

    aget-object v9, v5, v9

    invoke-virtual {v8, v9}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v8

    if-eqz v8, :cond_2b

    iget-object v2, v7, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    goto :goto_c

    :cond_2c
    move-object v2, v3

    :goto_c
    if-eqz v2, :cond_2e

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v4

    if-eqz v4, :cond_2d

    sget-object v4, Llyiahf/vczjk/gc5;->OooOoO:Llyiahf/vczjk/gc5;

    invoke-virtual {v0, v4}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v0

    invoke-static {v2, v0}, Llyiahf/vczjk/vy0;->OooO0Oo(Ljava/lang/reflect/Member;Z)V

    :cond_2d
    new-instance v0, Llyiahf/vczjk/t49;

    invoke-direct {v0, v2}, Llyiahf/vczjk/t49;-><init>(Ljava/lang/reflect/Method;)V

    goto/16 :goto_8

    :cond_2e
    move-object v6, v3

    :cond_2f
    :goto_d
    if-eqz v6, :cond_31

    iget-object v0, v1, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v0}, Llyiahf/vczjk/z82;->OooO0o0()Z

    move-result v0

    if-eqz v0, :cond_31

    iget-object v0, v1, Llyiahf/vczjk/n90;->_factoryConfig:Llyiahf/vczjk/z82;

    invoke-virtual {v0}, Llyiahf/vczjk/z82;->OooO0O0()Llyiahf/vczjk/yx;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/yx;->hasNext()Z

    move-result v1

    if-nez v1, :cond_30

    goto :goto_e

    :cond_30
    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooO0OO(Llyiahf/vczjk/yx;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1

    :cond_31
    :goto_e
    if-eqz v6, :cond_33

    instance-of p1, v6, Llyiahf/vczjk/nr7;

    if-eqz p1, :cond_32

    move-object p1, v6

    check-cast p1, Llyiahf/vczjk/nr7;

    invoke-interface {p1, p0}, Llyiahf/vczjk/nr7;->OooO00o(Llyiahf/vczjk/v72;)V

    :cond_32
    return-object v6

    :cond_33
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Cannot find a (Map) Key deserializer for type "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v3
.end method

.method public final o00Oo0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/v72;->_cache:Llyiahf/vczjk/x82;

    iget-object v1, p0, Llyiahf/vczjk/v72;->_factory:Llyiahf/vczjk/y82;

    invoke-virtual {v0, p0, v1, p1}, Llyiahf/vczjk/x82;->OooO0o0(Llyiahf/vczjk/v72;Llyiahf/vczjk/y82;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object p1

    return-object p1
.end method

.method public abstract o00Ooo(Ljava/lang/Object;Llyiahf/vczjk/p66;)Llyiahf/vczjk/bh7;
.end method

.method public final o00o0O(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/v72;->_cache:Llyiahf/vczjk/x82;

    iget-object v1, p0, Llyiahf/vczjk/v72;->_factory:Llyiahf/vczjk/y82;

    invoke-virtual {v0, p0, v1, p1}, Llyiahf/vczjk/x82;->OooO0o0(Llyiahf/vczjk/v72;Llyiahf/vczjk/y82;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {p0, v0, v1, p1}, Llyiahf/vczjk/v72;->o000000O(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v0

    iget-object v2, p0, Llyiahf/vczjk/v72;->_factory:Llyiahf/vczjk/y82;

    iget-object v3, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v2, v3, p1}, Llyiahf/vczjk/y82;->OooO0O0(Llyiahf/vczjk/t72;Llyiahf/vczjk/x64;)Llyiahf/vczjk/v3a;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-virtual {p1, v1}, Llyiahf/vczjk/u3a;->OooO0o(Llyiahf/vczjk/db0;)Llyiahf/vczjk/u3a;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/q5a;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/q5a;-><init>(Llyiahf/vczjk/u3a;Llyiahf/vczjk/e94;)V

    return-object v1

    :cond_0
    return-object v0
.end method

.method public final o00oO0O()Llyiahf/vczjk/z50;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0o()Llyiahf/vczjk/z50;

    move-result-object v0

    return-object v0
.end method

.method public final o00oO0o()Llyiahf/vczjk/ex9;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/v72;->OooOoO0:Llyiahf/vczjk/ex9;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/ex9;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/ex9;->OooOOO0:Ljava/lang/Object;

    iput-object v1, v0, Llyiahf/vczjk/ex9;->OooOOO:Ljava/lang/Object;

    iput-object v1, v0, Llyiahf/vczjk/ex9;->OooOOOO:Ljava/lang/Object;

    iput-object v1, v0, Llyiahf/vczjk/ex9;->OooOOOo:Ljava/lang/Object;

    iput-object v1, v0, Llyiahf/vczjk/ex9;->OooOOo0:Ljava/lang/Object;

    iput-object v1, v0, Llyiahf/vczjk/ex9;->OooOOo:Ljava/lang/Object;

    iput-object v1, v0, Llyiahf/vczjk/ex9;->OooOOoo:Ljava/lang/Object;

    iput-object v0, p0, Llyiahf/vczjk/v72;->OooOoO0:Llyiahf/vczjk/ex9;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/v72;->OooOoO0:Llyiahf/vczjk/ex9;

    return-object v0
.end method

.method public final o00ooo()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v72;->_view:Ljava/lang/Class;

    return-object v0
.end method

.method public final o0O0O00(Ljava/lang/Class;Ljava/lang/Throwable;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    iget-object v0, v0, Llyiahf/vczjk/t72;->_problemHandlers:Llyiahf/vczjk/j05;

    if-nez v0, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOoO0(Ljava/lang/Throwable;)V

    sget-object v0, Llyiahf/vczjk/w72;->OooOoo0:Llyiahf/vczjk/w72;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-nez v0, :cond_0

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    :cond_0
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/v72;->o00000oo(Ljava/lang/Class;Ljava/lang/Throwable;)Llyiahf/vczjk/lca;

    move-result-object p1

    throw p1

    :cond_1
    iget-object p1, v0, Llyiahf/vczjk/j05;->OooO00o:Ljava/lang/Object;

    invoke-static {p1}, Llyiahf/vczjk/ix8;->OooO0O0(Ljava/lang/Object;)Ljava/lang/ClassCastException;

    move-result-object p1

    throw p1
.end method

.method public final o0OO00O()Ljava/util/TimeZone;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooOOO()Ljava/util/TimeZone;

    move-result-object v0

    return-object v0
.end method

.method public final o0OOO0o()Ljava/util/Locale;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooOO0o()Ljava/util/Locale;

    move-result-object v0

    return-object v0
.end method

.method public final o0Oo0oo()Llyiahf/vczjk/ua4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    iget-object v0, v0, Llyiahf/vczjk/t72;->_nodeFactory:Llyiahf/vczjk/ua4;

    return-object v0
.end method

.method public final o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/v72;->_cache:Llyiahf/vczjk/x82;

    iget-object v1, p0, Llyiahf/vczjk/v72;->_factory:Llyiahf/vczjk/y82;

    invoke-virtual {v0, p0, v1, p1}, Llyiahf/vczjk/x82;->OooO0o0(Llyiahf/vczjk/v72;Llyiahf/vczjk/y82;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v0

    invoke-virtual {p0, v0, p2, p1}, Llyiahf/vczjk/v72;->o000000O(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object p1

    return-object p1
.end method

.method public final o0ooOO0()Llyiahf/vczjk/t72;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    return-object v0
.end method

.method public final o0ooOOo(Ljava/lang/Class;)Llyiahf/vczjk/q94;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fc5;->OooO(Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object p1

    return-object p1
.end method

.method public final o0ooOoO()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/v72;->_featureFlags:I

    return v0
.end method

.method public final oo000o()Llyiahf/vczjk/yn;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v0

    return-object v0
.end method

.method public final oo0o0Oo(Llyiahf/vczjk/e94;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/gc5;->Oooo0OO:Llyiahf/vczjk/gc5;

    iget-object v1, p0, Llyiahf/vczjk/v72;->_config:Llyiahf/vczjk/t72;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v0

    if-eqz v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/e94;->OooOOO0()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/v72;->Oooooo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOOOo(Llyiahf/vczjk/x64;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "Invalid configuration: values of type "

    const-string v2, " cannot be merged"

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/d44;

    iget-object v2, p0, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    invoke-direct {v1, v2, v0, p1}, Llyiahf/vczjk/d44;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;Llyiahf/vczjk/x64;)V

    throw v1
.end method

.method public final ooOO(Ljava/lang/Object;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    const/4 v0, 0x0

    if-nez p1, :cond_0

    move-object v1, v0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    :goto_0
    const-string v2, "No \'injectableValues\' configured, cannot inject value with id [%s]"

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-static {v2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, v1, p1}, Llyiahf/vczjk/mc4;->o000oOoO(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;

    throw v0
.end method
