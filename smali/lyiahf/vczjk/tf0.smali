.class public final synthetic Llyiahf/vczjk/tf0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:F

.field public final synthetic OooOOO0:Llyiahf/vczjk/zl8;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/zl8;F)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/tf0;->OooOOO0:Llyiahf/vczjk/zl8;

    iput p2, p0, Llyiahf/vczjk/tf0;->OooOOO:F

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/b24;

    check-cast p2, Llyiahf/vczjk/rk1;

    iget-wide v0, p2, Llyiahf/vczjk/rk1;->OooO00o:J

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p2

    int-to-float p2, p2

    iget-wide v0, p1, Llyiahf/vczjk/b24;->OooO00o:J

    const-wide v2, 0xffffffffL

    and-long/2addr v0, v2

    long-to-int p1, v0

    int-to-float p1, p1

    new-instance v0, Llyiahf/vczjk/kb5;

    new-instance v1, Ljava/util/LinkedHashMap;

    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    iget-object v2, p0, Llyiahf/vczjk/tf0;->OooOOO0:Llyiahf/vczjk/zl8;

    iget-boolean v3, v2, Llyiahf/vczjk/zl8;->OooO00o:Z

    iget v4, p0, Llyiahf/vczjk/tf0;->OooOOO:F

    if-nez v3, :cond_0

    sget-object v3, Llyiahf/vczjk/am8;->OooOOOO:Llyiahf/vczjk/am8;

    sub-float v5, p2, v4

    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v5

    invoke-interface {v1, v3, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    cmpg-float v3, p1, v4

    if-nez v3, :cond_1

    goto :goto_0

    :cond_1
    sget-object v3, Llyiahf/vczjk/am8;->OooOOO:Llyiahf/vczjk/am8;

    sub-float p1, p2, p1

    const/4 v4, 0x0

    invoke-static {p1, v4}, Ljava/lang/Math;->max(FF)F

    move-result p1

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p1

    invoke-interface {v1, v3, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :goto_0
    iget-boolean p1, v2, Llyiahf/vczjk/zl8;->OooO0OO:Z

    if-nez p1, :cond_2

    sget-object p1, Llyiahf/vczjk/am8;->OooOOO0:Llyiahf/vczjk/am8;

    invoke-static {p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p2

    invoke-interface {v1, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_2
    invoke-direct {v0, v1}, Llyiahf/vczjk/kb5;-><init>(Ljava/util/Map;)V

    iget-object p1, v2, Llyiahf/vczjk/zl8;->OooO0o0:Llyiahf/vczjk/c9;

    iget-object p1, p1, Llyiahf/vczjk/c9;->OooO0oo:Llyiahf/vczjk/w62;

    invoke-virtual {p1}, Llyiahf/vczjk/w62;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/am8;

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    if-eqz p2, :cond_9

    const/4 v2, 0x1

    if-eq p2, v2, :cond_6

    const/4 v2, 0x2

    if-ne p2, v2, :cond_5

    sget-object p2, Llyiahf/vczjk/am8;->OooOOOO:Llyiahf/vczjk/am8;

    invoke-interface {v1, p2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_3

    :goto_1
    move-object p1, p2

    goto :goto_2

    :cond_3
    sget-object p2, Llyiahf/vczjk/am8;->OooOOO:Llyiahf/vczjk/am8;

    invoke-interface {v1, p2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_4

    goto :goto_1

    :cond_4
    sget-object p2, Llyiahf/vczjk/am8;->OooOOO0:Llyiahf/vczjk/am8;

    invoke-interface {v1, p2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_a

    goto :goto_1

    :cond_5
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_6
    sget-object p2, Llyiahf/vczjk/am8;->OooOOO:Llyiahf/vczjk/am8;

    invoke-interface {v1, p2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_7

    goto :goto_1

    :cond_7
    sget-object p2, Llyiahf/vczjk/am8;->OooOOOO:Llyiahf/vczjk/am8;

    invoke-interface {v1, p2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_8

    goto :goto_1

    :cond_8
    sget-object p2, Llyiahf/vczjk/am8;->OooOOO0:Llyiahf/vczjk/am8;

    invoke-interface {v1, p2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_a

    goto :goto_1

    :cond_9
    sget-object p2, Llyiahf/vczjk/am8;->OooOOO0:Llyiahf/vczjk/am8;

    invoke-interface {v1, p2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_a

    goto :goto_1

    :cond_a
    :goto_2
    new-instance p2, Llyiahf/vczjk/xn6;

    invoke-direct {p2, v0, p1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    return-object p2
.end method
