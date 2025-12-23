.class public final Llyiahf/vczjk/u02;
.super Llyiahf/vczjk/g66;
.source "SourceFile"


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/u02;


# instance fields
.field protected final _value:Ljava/math/BigDecimal;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/u02;

    sget-object v1, Ljava/math/BigDecimal;->ZERO:Ljava/math/BigDecimal;

    invoke-direct {v0, v1}, Llyiahf/vczjk/u02;-><init>(Ljava/math/BigDecimal;)V

    sput-object v0, Llyiahf/vczjk/u02;->OooOOO0:Llyiahf/vczjk/u02;

    const-wide/32 v0, -0x80000000

    invoke-static {v0, v1}, Ljava/math/BigDecimal;->valueOf(J)Ljava/math/BigDecimal;

    const-wide/32 v0, 0x7fffffff

    invoke-static {v0, v1}, Ljava/math/BigDecimal;->valueOf(J)Ljava/math/BigDecimal;

    const-wide/high16 v0, -0x8000000000000000L

    invoke-static {v0, v1}, Ljava/math/BigDecimal;->valueOf(J)Ljava/math/BigDecimal;

    const-wide v0, 0x7fffffffffffffffL

    invoke-static {v0, v1}, Ljava/math/BigDecimal;->valueOf(J)Ljava/math/BigDecimal;

    return-void
.end method

.method public constructor <init>(Ljava/math/BigDecimal;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/u02;->_value:Ljava/math/BigDecimal;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 0

    iget-object p2, p0, Llyiahf/vczjk/u02;->_value:Ljava/math/BigDecimal;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/u94;->o0000O0O(Ljava/math/BigDecimal;)V

    return-void
.end method

.method public final OooO0o()Llyiahf/vczjk/gc4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/gc4;->OooOo0O:Llyiahf/vczjk/gc4;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    const/4 v0, 0x1

    if-ne p1, p0, :cond_0

    return v0

    :cond_0
    const/4 v1, 0x0

    if-nez p1, :cond_1

    return v1

    :cond_1
    instance-of v2, p1, Llyiahf/vczjk/u02;

    if-eqz v2, :cond_2

    check-cast p1, Llyiahf/vczjk/u02;

    iget-object p1, p1, Llyiahf/vczjk/u02;->_value:Ljava/math/BigDecimal;

    iget-object v2, p0, Llyiahf/vczjk/u02;->_value:Ljava/math/BigDecimal;

    invoke-virtual {p1, v2}, Ljava/math/BigDecimal;->compareTo(Ljava/math/BigDecimal;)I

    move-result p1

    if-nez p1, :cond_2

    return v0

    :cond_2
    return v1
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/u02;->_value:Ljava/math/BigDecimal;

    invoke-virtual {v0}, Ljava/math/BigDecimal;->doubleValue()D

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Double;->hashCode()I

    move-result v0

    return v0
.end method
