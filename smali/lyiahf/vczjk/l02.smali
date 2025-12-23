.class public abstract Llyiahf/vczjk/l02;
.super Llyiahf/vczjk/wt9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xo1;


# instance fields
.field protected final _customFormat:Ljava/text/DateFormat;

.field protected final _reusedCustomFormat:Ljava/util/concurrent/atomic/AtomicReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/atomic/AtomicReference<",
            "Ljava/text/DateFormat;",
            ">;"
        }
    .end annotation
.end field

.field protected final _useTimestamp:Ljava/lang/Boolean;


# direct methods
.method public constructor <init>(Ljava/lang/Class;Ljava/lang/Boolean;Ljava/text/DateFormat;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/wt9;-><init>(Ljava/lang/Class;)V

    iput-object p2, p0, Llyiahf/vczjk/l02;->_useTimestamp:Ljava/lang/Boolean;

    iput-object p3, p0, Llyiahf/vczjk/l02;->_customFormat:Ljava/text/DateFormat;

    if-nez p3, :cond_0

    const/4 p1, 0x0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-direct {p1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/l02;->_reusedCustomFormat:Ljava/util/concurrent/atomic/AtomicReference;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    invoke-static {p1, p2, v0}, Llyiahf/vczjk/b59;->OooOO0O(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object p2

    if-nez p2, :cond_0

    goto :goto_3

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0o()Llyiahf/vczjk/p94;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/p94;->OooO00o()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-virtual {p0, p1, v2}, Llyiahf/vczjk/l02;->OooOOo0(Ljava/lang/Boolean;Ljava/text/DateFormat;)Llyiahf/vczjk/l02;

    move-result-object p1

    return-object p1

    :cond_1
    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO()Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0oo()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0Oo()Ljava/util/Locale;

    move-result-object v0

    goto :goto_0

    :cond_2
    iget-object v0, p1, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooOO0o()Ljava/util/Locale;

    move-result-object v0

    :goto_0
    new-instance v1, Ljava/text/SimpleDateFormat;

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0o0()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2, v0}, Ljava/text/SimpleDateFormat;-><init>(Ljava/lang/String;Ljava/util/Locale;)V

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooOO0O()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0oO()Ljava/util/TimeZone;

    move-result-object p1

    goto :goto_1

    :cond_3
    iget-object p1, p1, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooOOO()Ljava/util/TimeZone;

    move-result-object p1

    :goto_1
    invoke-virtual {v1, p1}, Ljava/text/DateFormat;->setTimeZone(Ljava/util/TimeZone;)V

    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-virtual {p0, p1, v1}, Llyiahf/vczjk/l02;->OooOOo0(Ljava/lang/Boolean;Ljava/text/DateFormat;)Llyiahf/vczjk/l02;

    move-result-object p1

    return-object p1

    :cond_4
    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0oo()Z

    move-result v1

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooOO0O()Z

    move-result v3

    sget-object v4, Llyiahf/vczjk/p94;->OooOo0:Llyiahf/vczjk/p94;

    if-ne v0, v4, :cond_5

    const/4 v0, 0x1

    goto :goto_2

    :cond_5
    const/4 v0, 0x0

    :goto_2
    if-nez v1, :cond_6

    if-nez v3, :cond_6

    if-nez v0, :cond_6

    :goto_3
    return-object p0

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0oo()Ljava/text/DateFormat;

    move-result-object v0

    instance-of v3, v0, Llyiahf/vczjk/j49;

    if-eqz v3, :cond_9

    check-cast v0, Llyiahf/vczjk/j49;

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0oo()Z

    move-result p1

    if-eqz p1, :cond_7

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0Oo()Ljava/util/Locale;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/j49;->OooOO0(Ljava/util/Locale;)Llyiahf/vczjk/j49;

    move-result-object v0

    :cond_7
    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooOO0O()Z

    move-result p1

    if-eqz p1, :cond_8

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0oO()Ljava/util/TimeZone;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/j49;->OooOO0O(Ljava/util/TimeZone;)Llyiahf/vczjk/j49;

    move-result-object v0

    :cond_8
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/l02;->OooOOo0(Ljava/lang/Boolean;Ljava/text/DateFormat;)Llyiahf/vczjk/l02;

    move-result-object p1

    return-object p1

    :cond_9
    instance-of v3, v0, Ljava/text/SimpleDateFormat;

    if-eqz v3, :cond_c

    check-cast v0, Ljava/text/SimpleDateFormat;

    if-eqz v1, :cond_a

    new-instance p1, Ljava/text/SimpleDateFormat;

    invoke-virtual {v0}, Ljava/text/SimpleDateFormat;->toPattern()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0Oo()Ljava/util/Locale;

    move-result-object v1

    invoke-direct {p1, v0, v1}, Ljava/text/SimpleDateFormat;-><init>(Ljava/lang/String;Ljava/util/Locale;)V

    goto :goto_4

    :cond_a
    invoke-virtual {v0}, Ljava/text/SimpleDateFormat;->clone()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/text/SimpleDateFormat;

    :goto_4
    invoke-virtual {p2}, Llyiahf/vczjk/q94;->OooO0oO()Ljava/util/TimeZone;

    move-result-object p2

    if-eqz p2, :cond_b

    invoke-virtual {p1}, Ljava/text/DateFormat;->getTimeZone()Ljava/util/TimeZone;

    move-result-object v0

    invoke-virtual {p2, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_b

    invoke-virtual {p1, p2}, Ljava/text/DateFormat;->setTimeZone(Ljava/util/TimeZone;)V

    :cond_b
    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/l02;->OooOOo0(Ljava/lang/Boolean;Ljava/text/DateFormat;)Llyiahf/vczjk/l02;

    move-result-object p1

    return-object p1

    :cond_c
    iget-object p2, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v3, "Configured `DateFormat` ("

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, ") not a `SimpleDateFormat`; cannot configure `Locale` or `TimeZone`"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/mc4;->o000oOoO(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;

    throw v2
.end method

.method public final OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method

.method public final OooOOOO(Llyiahf/vczjk/tg8;)Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/l02;->_useTimestamp:Ljava/lang/Boolean;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    return p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/l02;->_customFormat:Ljava/text/DateFormat;

    if-nez v0, :cond_2

    if-eqz p1, :cond_1

    sget-object v0, Llyiahf/vczjk/ig8;->OooOo0O:Llyiahf/vczjk/ig8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result p1

    return p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    iget-object v0, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    const-string v1, "Null SerializerProvider passed for "

    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    const/4 p1, 0x0

    return p1
.end method

.method public final OooOOOo(Ljava/util/Date;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/l02;->_customFormat:Ljava/text/DateFormat;

    if-nez v0, :cond_1

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/ig8;->OooOo0O:Llyiahf/vczjk/ig8;

    iget-object v1, p3, Llyiahf/vczjk/tg8;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/gg8;->Oooo0(Llyiahf/vczjk/ig8;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Ljava/util/Date;->getTime()J

    move-result-wide v0

    invoke-virtual {p2, v0, v1}, Llyiahf/vczjk/u94;->o0000oO(J)V

    goto :goto_0

    :cond_0
    invoke-virtual {p3}, Llyiahf/vczjk/tg8;->Ooooooo()Ljava/text/DateFormat;

    move-result-object p3

    invoke-virtual {p3, p1}, Ljava/text/DateFormat;->format(Ljava/util/Date;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o0000ooO(Ljava/lang/String;)V

    :goto_0
    return-void

    :cond_1
    iget-object p3, p0, Llyiahf/vczjk/l02;->_reusedCustomFormat:Ljava/util/concurrent/atomic/AtomicReference;

    const/4 v0, 0x0

    invoke-virtual {p3, v0}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Ljava/text/DateFormat;

    if-nez p3, :cond_2

    iget-object p3, p0, Llyiahf/vczjk/l02;->_customFormat:Ljava/text/DateFormat;

    invoke-virtual {p3}, Ljava/text/DateFormat;->clone()Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Ljava/text/DateFormat;

    :cond_2
    invoke-virtual {p3, p1}, Ljava/text/DateFormat;->format(Ljava/util/Date;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o0000ooO(Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/l02;->_reusedCustomFormat:Ljava/util/concurrent/atomic/AtomicReference;

    :cond_3
    invoke-virtual {p1, v0, p3}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_4

    goto :goto_1

    :cond_4
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object p2

    if-eqz p2, :cond_3

    :goto_1
    return-void
.end method

.method public abstract OooOOo0(Ljava/lang/Boolean;Ljava/text/DateFormat;)Llyiahf/vczjk/l02;
.end method
