.class public abstract Llyiahf/vczjk/v4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO:Ljava/util/HashMap;

.field public final OooO00o:Llyiahf/vczjk/ow6;

.field public OooO0O0:Z

.field public OooO0OO:Z

.field public OooO0Oo:Z

.field public OooO0o:Z

.field public OooO0o0:Z

.field public OooO0oO:Z

.field public OooO0oo:Llyiahf/vczjk/w4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/w4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    check-cast p1, Llyiahf/vczjk/ow6;

    iput-object p1, p0, Llyiahf/vczjk/v4;->OooO00o:Llyiahf/vczjk/ow6;

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/v4;->OooO0O0:Z

    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/v4;->OooO:Ljava/util/HashMap;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/v4;Llyiahf/vczjk/p4;ILlyiahf/vczjk/v16;)V
    .locals 8

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    int-to-float p2, p2

    invoke-static {p2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v0

    int-to-long v0, v0

    invoke-static {p2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p2

    int-to-long v2, p2

    const/16 p2, 0x20

    shl-long/2addr v0, p2

    const-wide v4, 0xffffffffL

    and-long/2addr v2, v4

    :goto_0
    or-long/2addr v0, v2

    :cond_0
    invoke-virtual {p0, p3, v0, v1}, Llyiahf/vczjk/v4;->OooO0O0(Llyiahf/vczjk/v16;J)J

    move-result-wide v0

    iget-object p3, p3, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    invoke-static {p3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v2, p0, Llyiahf/vczjk/v4;->OooO00o:Llyiahf/vczjk/ow6;

    invoke-interface {v2}, Llyiahf/vczjk/w4;->OooO0oO()Llyiahf/vczjk/b04;

    move-result-object v2

    invoke-virtual {p3, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_1

    invoke-virtual {p0, p3}, Llyiahf/vczjk/v4;->OooO0OO(Llyiahf/vczjk/v16;)Ljava/util/Map;

    move-result-object v2

    invoke-interface {v2, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-virtual {p0, p3, p1}, Llyiahf/vczjk/v4;->OooO0Oo(Llyiahf/vczjk/v16;Llyiahf/vczjk/p4;)I

    move-result v0

    int-to-float v0, v0

    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v1, v1

    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v0

    int-to-long v6, v0

    shl-long v0, v1, p2

    and-long v2, v6, v4

    goto :goto_0

    :cond_1
    instance-of p3, p1, Llyiahf/vczjk/go3;

    if-eqz p3, :cond_2

    and-long p2, v0, v4

    long-to-int p2, p2

    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p2

    goto :goto_1

    :cond_2
    shr-long p2, v0, p2

    long-to-int p2, p2

    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p2

    :goto_1
    invoke-static {p2}, Ljava/lang/Math;->round(F)I

    move-result p2

    iget-object p0, p0, Llyiahf/vczjk/v4;->OooO:Ljava/util/HashMap;

    invoke-virtual {p0, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result p3

    if-eqz p3, :cond_3

    invoke-static {p1, p0}, Llyiahf/vczjk/lc5;->oo000o(Ljava/lang/Object;Ljava/util/Map;)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    move-result p3

    sget-object v0, Llyiahf/vczjk/s4;->OooO00o:Llyiahf/vczjk/go3;

    iget-object v0, p1, Llyiahf/vczjk/p4;->OooO00o:Llyiahf/vczjk/wf3;

    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p3

    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    invoke-interface {v0, p3, p2}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    :cond_3
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    invoke-virtual {p0, p1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO()V
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/v4;->OooO0o0()Z

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/v4;->OooO00o:Llyiahf/vczjk/ow6;

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-interface {v1}, Llyiahf/vczjk/w4;->OooOO0O()Llyiahf/vczjk/w4;

    move-result-object v0

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-interface {v0}, Llyiahf/vczjk/w4;->OooO00o()Llyiahf/vczjk/v4;

    move-result-object v0

    iget-object v1, v0, Llyiahf/vczjk/v4;->OooO0oo:Llyiahf/vczjk/w4;

    if-eqz v1, :cond_2

    invoke-interface {v1}, Llyiahf/vczjk/w4;->OooO00o()Llyiahf/vczjk/v4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/v4;->OooO0o0()Z

    move-result v0

    if-eqz v0, :cond_2

    goto :goto_0

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/v4;->OooO0oo:Llyiahf/vczjk/w4;

    if-eqz v0, :cond_6

    invoke-interface {v0}, Llyiahf/vczjk/w4;->OooO00o()Llyiahf/vczjk/v4;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/v4;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_3

    goto :goto_1

    :cond_3
    invoke-interface {v0}, Llyiahf/vczjk/w4;->OooOO0O()Llyiahf/vczjk/w4;

    move-result-object v1

    if-eqz v1, :cond_4

    invoke-interface {v1}, Llyiahf/vczjk/w4;->OooO00o()Llyiahf/vczjk/v4;

    move-result-object v1

    if-eqz v1, :cond_4

    invoke-virtual {v1}, Llyiahf/vczjk/v4;->OooO()V

    :cond_4
    invoke-interface {v0}, Llyiahf/vczjk/w4;->OooOO0O()Llyiahf/vczjk/w4;

    move-result-object v0

    if-eqz v0, :cond_5

    invoke-interface {v0}, Llyiahf/vczjk/w4;->OooO00o()Llyiahf/vczjk/v4;

    move-result-object v0

    if-eqz v0, :cond_5

    iget-object v1, v0, Llyiahf/vczjk/v4;->OooO0oo:Llyiahf/vczjk/w4;

    goto :goto_0

    :cond_5
    const/4 v1, 0x0

    :goto_0
    iput-object v1, p0, Llyiahf/vczjk/v4;->OooO0oo:Llyiahf/vczjk/w4;

    :cond_6
    :goto_1
    return-void
.end method

.method public abstract OooO0O0(Llyiahf/vczjk/v16;J)J
.end method

.method public abstract OooO0OO(Llyiahf/vczjk/v16;)Ljava/util/Map;
.end method

.method public abstract OooO0Oo(Llyiahf/vczjk/v16;Llyiahf/vczjk/p4;)I
.end method

.method public final OooO0o()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/v4;->OooO()V

    iget-object v0, p0, Llyiahf/vczjk/v4;->OooO0oo:Llyiahf/vczjk/w4;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0o0()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/v4;->OooO0OO:Z

    if-nez v0, :cond_1

    iget-boolean v0, p0, Llyiahf/vczjk/v4;->OooO0o0:Z

    if-nez v0, :cond_1

    iget-boolean v0, p0, Llyiahf/vczjk/v4;->OooO0o:Z

    if-nez v0, :cond_1

    iget-boolean v0, p0, Llyiahf/vczjk/v4;->OooO0oO:Z

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    return v0

    :cond_1
    :goto_0
    const/4 v0, 0x1

    return v0
.end method

.method public final OooO0oO()V
    .locals 3

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/v4;->OooO0O0:Z

    iget-object v0, p0, Llyiahf/vczjk/v4;->OooO00o:Llyiahf/vczjk/ow6;

    invoke-interface {v0}, Llyiahf/vczjk/w4;->OooOO0O()Llyiahf/vczjk/w4;

    move-result-object v1

    if-nez v1, :cond_0

    return-void

    :cond_0
    iget-boolean v2, p0, Llyiahf/vczjk/v4;->OooO0OO:Z

    if-eqz v2, :cond_1

    invoke-interface {v1}, Llyiahf/vczjk/w4;->OoooOOo()V

    goto :goto_0

    :cond_1
    iget-boolean v2, p0, Llyiahf/vczjk/v4;->OooO0o0:Z

    if-nez v2, :cond_2

    iget-boolean v2, p0, Llyiahf/vczjk/v4;->OooO0Oo:Z

    if-eqz v2, :cond_3

    :cond_2
    invoke-interface {v1}, Llyiahf/vczjk/w4;->requestLayout()V

    :cond_3
    :goto_0
    iget-boolean v2, p0, Llyiahf/vczjk/v4;->OooO0o:Z

    if-eqz v2, :cond_4

    invoke-interface {v0}, Llyiahf/vczjk/w4;->OoooOOo()V

    :cond_4
    iget-boolean v2, p0, Llyiahf/vczjk/v4;->OooO0oO:Z

    if-eqz v2, :cond_5

    invoke-interface {v0}, Llyiahf/vczjk/w4;->requestLayout()V

    :cond_5
    invoke-interface {v1}, Llyiahf/vczjk/w4;->OooO00o()Llyiahf/vczjk/v4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/v4;->OooO0oO()V

    return-void
.end method

.method public final OooO0oo()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/v4;->OooO:Ljava/util/HashMap;

    invoke-virtual {v0}, Ljava/util/HashMap;->clear()V

    new-instance v1, Llyiahf/vczjk/u4;

    invoke-direct {v1, p0}, Llyiahf/vczjk/u4;-><init>(Llyiahf/vczjk/v4;)V

    iget-object v2, p0, Llyiahf/vczjk/v4;->OooO00o:Llyiahf/vczjk/ow6;

    invoke-interface {v2, v1}, Llyiahf/vczjk/w4;->OooOoO0(Llyiahf/vczjk/u4;)V

    invoke-interface {v2}, Llyiahf/vczjk/w4;->OooO0oO()Llyiahf/vczjk/b04;

    move-result-object v1

    invoke-virtual {p0, v1}, Llyiahf/vczjk/v4;->OooO0OO(Llyiahf/vczjk/v16;)Ljava/util/Map;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/HashMap;->putAll(Ljava/util/Map;)V

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/v4;->OooO0O0:Z

    return-void
.end method
