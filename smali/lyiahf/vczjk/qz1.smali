.class public abstract Llyiahf/vczjk/qz1;
.super Llyiahf/vczjk/a59;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wo1;


# instance fields
.field protected final _customFormat:Ljava/text/DateFormat;

.field protected final _formatString:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/Class;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/qz1;->_customFormat:Ljava/text/DateFormat;

    iput-object p1, p0, Llyiahf/vczjk/qz1;->_formatString:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/qz1;Ljava/text/DateFormat;Ljava/lang/String;)V
    .locals 0

    iget-object p1, p1, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-direct {p0, p1}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    iput-object p2, p0, Llyiahf/vczjk/qz1;->_customFormat:Ljava/text/DateFormat;

    iput-object p3, p0, Llyiahf/vczjk/qz1;->_formatString:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    if-eqz p2, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v1

    invoke-interface {p2, v0, v1}, Llyiahf/vczjk/db0;->OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/fc5;)Llyiahf/vczjk/q94;

    move-result-object p2

    goto :goto_0

    :cond_0
    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o0ooOOo(Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object p2

    :goto_0
    if-eqz p2, :cond_d

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0oO()Ljava/util/TimeZone;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0OO()Ljava/lang/Boolean;

    move-result-object v1

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO()Z

    move-result v2

    if-eqz v2, :cond_4

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0o0()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0oo()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0Oo()Ljava/util/Locale;

    move-result-object p2

    goto :goto_1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0OOO0o()Ljava/util/Locale;

    move-result-object p2

    :goto_1
    new-instance v3, Ljava/text/SimpleDateFormat;

    invoke-direct {v3, v2, p2}, Ljava/text/SimpleDateFormat;-><init>(Ljava/lang/String;Ljava/util/Locale;)V

    if-nez v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0OO00O()Ljava/util/TimeZone;

    move-result-object v0

    :cond_2
    invoke-virtual {v3, v0}, Ljava/text/DateFormat;->setTimeZone(Ljava/util/TimeZone;)V

    if-eqz v1, :cond_3

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    invoke-virtual {v3, p1}, Ljava/text/DateFormat;->setLenient(Z)V

    :cond_3
    invoke-virtual {p0, v3, v2}, Llyiahf/vczjk/qz1;->OoooOOO(Ljava/text/DateFormat;Ljava/lang/String;)Llyiahf/vczjk/qz1;

    move-result-object p1

    return-object p1

    :cond_4
    const-class v2, Llyiahf/vczjk/j49;

    if-eqz v0, :cond_8

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/ec5;->OooO0oo()Ljava/text/DateFormat;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v4

    if-ne v4, v2, :cond_6

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0oo()Z

    move-result v2

    if-eqz v2, :cond_5

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0Oo()Ljava/util/Locale;

    move-result-object p1

    goto :goto_2

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0OOO0o()Ljava/util/Locale;

    move-result-object p1

    :goto_2
    check-cast v3, Llyiahf/vczjk/j49;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/j49;->OooOO0O(Ljava/util/TimeZone;)Llyiahf/vczjk/j49;

    move-result-object p2

    invoke-virtual {p2, p1}, Llyiahf/vczjk/j49;->OooOO0(Ljava/util/Locale;)Llyiahf/vczjk/j49;

    move-result-object p1

    if-eqz v1, :cond_7

    invoke-virtual {p1, v1}, Llyiahf/vczjk/j49;->OooO(Ljava/lang/Boolean;)Llyiahf/vczjk/j49;

    move-result-object p1

    goto :goto_3

    :cond_6
    invoke-virtual {v3}, Ljava/text/DateFormat;->clone()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/text/DateFormat;

    invoke-virtual {p1, v0}, Ljava/text/DateFormat;->setTimeZone(Ljava/util/TimeZone;)V

    if-eqz v1, :cond_7

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    invoke-virtual {p1, p2}, Ljava/text/DateFormat;->setLenient(Z)V

    :cond_7
    :goto_3
    iget-object p2, p0, Llyiahf/vczjk/qz1;->_formatString:Ljava/lang/String;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/qz1;->OoooOOO(Ljava/text/DateFormat;Ljava/lang/String;)Llyiahf/vczjk/qz1;

    move-result-object p1

    return-object p1

    :cond_8
    if-eqz v1, :cond_d

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooO0oo()Ljava/text/DateFormat;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/qz1;->_formatString:Ljava/lang/String;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    if-ne v0, v2, :cond_a

    check-cast p1, Llyiahf/vczjk/j49;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/j49;->OooO(Ljava/lang/Boolean;)Llyiahf/vczjk/j49;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p2, 0x64

    const-string v0, "[one of: \'yyyy-MM-dd\'T\'HH:mm:ss.SSSX\', \'EEE, dd MMM yyyy HH:mm:ss zzz\' ("

    invoke-static {p2, v0}, Llyiahf/vczjk/ix8;->OooOOO0(ILjava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p2

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    iget-object v1, p1, Llyiahf/vczjk/j49;->_lenient:Ljava/lang/Boolean;

    invoke-virtual {v0, v1}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_9

    const-string v0, "strict"

    goto :goto_4

    :cond_9
    const-string v0, "lenient"

    :goto_4
    const-string v1, ")]"

    invoke-static {p2, v0, v1}, Llyiahf/vczjk/ix8;->OooOO0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    goto :goto_5

    :cond_a
    invoke-virtual {p1}, Ljava/text/DateFormat;->clone()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/text/DateFormat;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    invoke-virtual {p1, v0}, Ljava/text/DateFormat;->setLenient(Z)V

    instance-of v0, p1, Ljava/text/SimpleDateFormat;

    if-eqz v0, :cond_b

    move-object v0, p1

    check-cast v0, Ljava/text/SimpleDateFormat;

    invoke-virtual {v0}, Ljava/text/SimpleDateFormat;->toPattern()Ljava/lang/String;

    :cond_b
    :goto_5
    if-nez p2, :cond_c

    const-string p2, "[unknown]"

    :cond_c
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/qz1;->OoooOOO(Ljava/text/DateFormat;Ljava/lang/String;)Llyiahf/vczjk/qz1;

    move-result-object p1

    return-object p1

    :cond_d
    return-object p0
.end method

.method public OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/qz1;->OooOooO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/util/Date;

    move-result-object p1

    return-object p1
.end method

.method public final OooOooO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/util/Date;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/qz1;->_customFormat:Ljava/text/DateFormat;

    if-eqz v0, :cond_1

    sget-object v0, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/String;->length()I

    move-result v0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    return-object v1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/qz1;->_customFormat:Ljava/text/DateFormat;

    monitor-enter v0

    :try_start_0
    iget-object v2, p0, Llyiahf/vczjk/qz1;->_customFormat:Ljava/text/DateFormat;

    invoke-virtual {v2, p2}, Ljava/text/DateFormat;->parse(Ljava/lang/String;)Ljava/util/Date;

    move-result-object p1
    :try_end_0
    .catch Ljava/text/ParseException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :try_start_1
    monitor-exit v0

    return-object p1

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    iget-object v2, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    const-string v3, "expected format \"%s\""

    iget-object v4, p0, Llyiahf/vczjk/qz1;->_formatString:Ljava/lang/String;

    filled-new-array {v4}, [Ljava/lang/Object;

    move-result-object v4

    invoke-virtual {p1, v2, p2, v3, v4}, Llyiahf/vczjk/v72;->o0000Ooo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v1

    :goto_0
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1

    :cond_1
    invoke-super {p0, p1, p2}, Llyiahf/vczjk/m49;->OooOooO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/util/Date;

    move-result-object p1

    return-object p1
.end method

.method public abstract OoooOOO(Ljava/text/DateFormat;Ljava/lang/String;)Llyiahf/vczjk/qz1;
.end method
