.class public final Llyiahf/vczjk/pz1;
.super Llyiahf/vczjk/qz1;
.source "SourceFile"


# instance fields
.field protected final _defaultCtor:Ljava/lang/reflect/Constructor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/reflect/Constructor<",
            "Ljava/util/Calendar;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    const-class v0, Ljava/util/Calendar;

    invoke-direct {p0, v0}, Llyiahf/vczjk/qz1;-><init>(Ljava/lang/Class;)V

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/pz1;->_defaultCtor:Ljava/lang/reflect/Constructor;

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    const-class p1, Ljava/util/GregorianCalendar;

    invoke-direct {p0, p1}, Llyiahf/vczjk/qz1;-><init>(Ljava/lang/Class;)V

    const/4 v0, 0x0

    invoke-static {p1, v0}, Llyiahf/vczjk/vy0;->OooOO0(Ljava/lang/Class;Z)Ljava/lang/reflect/Constructor;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/pz1;->_defaultCtor:Ljava/lang/reflect/Constructor;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/pz1;Ljava/text/DateFormat;Ljava/lang/String;)V
    .locals 0

    invoke-direct {p0, p1, p2, p3}, Llyiahf/vczjk/qz1;-><init>(Llyiahf/vczjk/qz1;Ljava/text/DateFormat;Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/pz1;->_defaultCtor:Ljava/lang/reflect/Constructor;

    iput-object p1, p0, Llyiahf/vczjk/pz1;->_defaultCtor:Ljava/lang/reflect/Constructor;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 4

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/qz1;->OooOooO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/util/Date;

    move-result-object p2

    const/4 v0, 0x0

    if-nez p2, :cond_0

    return-object v0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/pz1;->_defaultCtor:Ljava/lang/reflect/Constructor;

    if-nez v1, :cond_1

    invoke-virtual {p1, p2}, Llyiahf/vczjk/v72;->Oooooo0(Ljava/util/Date;)Ljava/util/Calendar;

    move-result-object p1

    return-object p1

    :cond_1
    :try_start_0
    invoke-virtual {v1, v0}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Calendar;

    invoke-virtual {p2}, Ljava/util/Date;->getTime()J

    move-result-wide v2

    invoke-virtual {v1, v2, v3}, Ljava/util/Calendar;->setTimeInMillis(J)V

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0OO00O()Ljava/util/TimeZone;

    move-result-object p2

    if-eqz p2, :cond_2

    invoke-virtual {v1, p2}, Ljava/util/Calendar;->setTimeZone(Ljava/util/TimeZone;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object v1

    :catch_0
    move-exception p2

    goto :goto_0

    :cond_2
    return-object v1

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/m49;->_valueClass:Ljava/lang/Class;

    invoke-virtual {p1, v1, p2}, Llyiahf/vczjk/v72;->o0O0O00(Ljava/lang/Class;Ljava/lang/Throwable;)V

    throw v0
.end method

.method public final OoooOOO(Ljava/text/DateFormat;Ljava/lang/String;)Llyiahf/vczjk/qz1;
    .locals 1

    new-instance v0, Llyiahf/vczjk/pz1;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/pz1;-><init>(Llyiahf/vczjk/pz1;Ljava/text/DateFormat;Ljava/lang/String;)V

    return-object v0
.end method
