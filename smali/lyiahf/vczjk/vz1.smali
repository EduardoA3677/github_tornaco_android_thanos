.class public final Llyiahf/vczjk/vz1;
.super Llyiahf/vczjk/l02;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/vz1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/vz1;

    const/4 v1, 0x0

    invoke-direct {v0, v1, v1}, Llyiahf/vczjk/vz1;-><init>(Ljava/lang/Boolean;Ljava/text/DateFormat;)V

    sput-object v0, Llyiahf/vczjk/vz1;->OooOOOO:Llyiahf/vczjk/vz1;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Boolean;Ljava/text/DateFormat;)V
    .locals 1

    const-class v0, Ljava/util/Date;

    invoke-direct {p0, v0, p1, p2}, Llyiahf/vczjk/l02;-><init>(Ljava/lang/Class;Ljava/lang/Boolean;Ljava/text/DateFormat;)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 2

    check-cast p1, Ljava/util/Date;

    invoke-virtual {p0, p3}, Llyiahf/vczjk/l02;->OooOOOO(Llyiahf/vczjk/tg8;)Z

    move-result v0

    if-eqz v0, :cond_1

    if-nez p1, :cond_0

    const-wide/16 v0, 0x0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Ljava/util/Date;->getTime()J

    move-result-wide v0

    :goto_0
    invoke-virtual {p2, v0, v1}, Llyiahf/vczjk/u94;->o0000oO(J)V

    return-void

    :cond_1
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/l02;->OooOOOo(Ljava/util/Date;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void
.end method

.method public final OooOOo0(Ljava/lang/Boolean;Ljava/text/DateFormat;)Llyiahf/vczjk/l02;
    .locals 1

    new-instance v0, Llyiahf/vczjk/vz1;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/vz1;-><init>(Ljava/lang/Boolean;Ljava/text/DateFormat;)V

    return-object v0
.end method
