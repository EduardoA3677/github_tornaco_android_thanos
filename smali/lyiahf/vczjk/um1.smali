.class public final Llyiahf/vczjk/um1;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/vn4;
.implements Llyiahf/vczjk/ug1;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/nf6;

.field public OooOoo:Z

.field public final OooOoo0:Llyiahf/vczjk/db8;

.field public OooOooO:Llyiahf/vczjk/rk6;

.field public final OooOooo:Llyiahf/vczjk/sh0;

.field public Oooo0:J

.field public Oooo000:Llyiahf/vczjk/xn4;

.field public Oooo00O:Z

.field public Oooo00o:Z

.field public Oooo0O0:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nf6;Llyiahf/vczjk/db8;ZLlyiahf/vczjk/rk6;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/um1;->OooOoOO:Llyiahf/vczjk/nf6;

    iput-object p2, p0, Llyiahf/vczjk/um1;->OooOoo0:Llyiahf/vczjk/db8;

    iput-boolean p3, p0, Llyiahf/vczjk/um1;->OooOoo:Z

    iput-object p4, p0, Llyiahf/vczjk/um1;->OooOooO:Llyiahf/vczjk/rk6;

    new-instance p1, Llyiahf/vczjk/sh0;

    invoke-direct {p1}, Llyiahf/vczjk/sh0;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/um1;->OooOooo:Llyiahf/vczjk/sh0;

    const-wide/16 p1, 0x0

    iput-wide p1, p0, Llyiahf/vczjk/um1;->Oooo0:J

    return-void
.end method

.method public static final o00000OO(Llyiahf/vczjk/um1;Llyiahf/vczjk/gi0;)F
    .locals 14

    iget-wide v0, p0, Llyiahf/vczjk/um1;->Oooo0:J

    const-wide/16 v2, 0x0

    invoke-static {v0, v1, v2, v3}, Llyiahf/vczjk/b24;->OooO00o(JJ)Z

    move-result v0

    if-eqz v0, :cond_0

    goto/16 :goto_4

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/um1;->OooOooo:Llyiahf/vczjk/sh0;

    iget-object v0, v0, Llyiahf/vczjk/sh0;->OooO00o:Llyiahf/vczjk/ws5;

    iget v1, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v2, 0x1

    sub-int/2addr v1, v2

    iget-object v0, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    array-length v3, v0

    const-wide v4, 0xffffffffL

    const/16 v6, 0x20

    const/4 v7, 0x0

    if-ge v1, v3, :cond_5

    move-object v3, v7

    :goto_0
    if-ltz v1, :cond_6

    aget-object v8, v0, v1

    check-cast v8, Llyiahf/vczjk/pm1;

    iget-object v8, v8, Llyiahf/vczjk/pm1;->OooO00o:Llyiahf/vczjk/yh0;

    invoke-virtual {v8}, Llyiahf/vczjk/yh0;->OooO00o()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/wj7;

    if-eqz v8, :cond_4

    invoke-virtual {v8}, Llyiahf/vczjk/wj7;->OooO0OO()J

    move-result-wide v9

    iget-wide v11, p0, Llyiahf/vczjk/um1;->Oooo0:J

    invoke-static {v11, v12}, Llyiahf/vczjk/e16;->Oooo0oO(J)J

    move-result-wide v11

    iget-object v13, p0, Llyiahf/vczjk/um1;->OooOoOO:Llyiahf/vczjk/nf6;

    invoke-virtual {v13}, Ljava/lang/Enum;->ordinal()I

    move-result v13

    if-eqz v13, :cond_2

    if-ne v13, v2, :cond_1

    shr-long/2addr v9, v6

    long-to-int v9, v9

    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v9

    shr-long v10, v11, v6

    long-to-int v10, v10

    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v10

    invoke-static {v9, v10}, Ljava/lang/Float;->compare(FF)I

    move-result v9

    goto :goto_1

    :cond_1
    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_2
    and-long/2addr v9, v4

    long-to-int v9, v9

    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v9

    and-long v10, v11, v4

    long-to-int v10, v10

    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v10

    invoke-static {v9, v10}, Ljava/lang/Float;->compare(FF)I

    move-result v9

    :goto_1
    if-gtz v9, :cond_3

    move-object v3, v8

    goto :goto_2

    :cond_3
    if-nez v3, :cond_6

    move-object v3, v8

    goto :goto_3

    :cond_4
    :goto_2
    add-int/lit8 v1, v1, -0x1

    goto :goto_0

    :cond_5
    move-object v3, v7

    :cond_6
    :goto_3
    if-nez v3, :cond_9

    iget-boolean v0, p0, Llyiahf/vczjk/um1;->Oooo00O:Z

    if-eqz v0, :cond_7

    invoke-virtual {p0}, Llyiahf/vczjk/um1;->o00000Oo()Llyiahf/vczjk/wj7;

    move-result-object v7

    :cond_7
    if-nez v7, :cond_8

    :goto_4
    const/4 p0, 0x0

    return p0

    :cond_8
    move-object v3, v7

    :cond_9
    iget-wide v0, p0, Llyiahf/vczjk/um1;->Oooo0:J

    invoke-static {v0, v1}, Llyiahf/vczjk/e16;->Oooo0oO(J)J

    move-result-wide v0

    iget-object p0, p0, Llyiahf/vczjk/um1;->OooOoOO:Llyiahf/vczjk/nf6;

    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    move-result p0

    if-eqz p0, :cond_b

    if-ne p0, v2, :cond_a

    iget p0, v3, Llyiahf/vczjk/wj7;->OooO0OO:F

    iget v2, v3, Llyiahf/vczjk/wj7;->OooO00o:F

    sub-float/2addr p0, v2

    shr-long/2addr v0, v6

    long-to-int v0, v0

    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    invoke-interface {p1, v2, p0, v0}, Llyiahf/vczjk/gi0;->OooO00o(FFF)F

    move-result p0

    return p0

    :cond_a
    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_b
    iget p0, v3, Llyiahf/vczjk/wj7;->OooO0Oo:F

    iget v2, v3, Llyiahf/vczjk/wj7;->OooO0O0:F

    sub-float/2addr p0, v2

    and-long/2addr v0, v4

    long-to-int v0, v0

    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    invoke-interface {p1, v2, p0, v0}, Llyiahf/vczjk/gi0;->OooO00o(FFF)F

    move-result p0

    return p0
.end method


# virtual methods
.method public final OooOOO0(J)V
    .locals 6

    iget-wide v0, p0, Llyiahf/vczjk/um1;->Oooo0:J

    iput-wide p1, p0, Llyiahf/vczjk/um1;->Oooo0:J

    iget-object v2, p0, Llyiahf/vczjk/um1;->OooOoOO:Llyiahf/vczjk/nf6;

    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    move-result v2

    const/4 v3, 0x1

    if-eqz v2, :cond_1

    if-ne v2, v3, :cond_0

    const/16 v2, 0x20

    shr-long/2addr p1, v2

    long-to-int p1, p1

    shr-long v4, v0, v2

    long-to-int p2, v4

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result p1

    goto :goto_0

    :cond_0
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_1
    const-wide v4, 0xffffffffL

    and-long/2addr p1, v4

    long-to-int p1, p1

    and-long/2addr v4, v0

    long-to-int p2, v4

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoo(II)I

    move-result p1

    :goto_0
    if-ltz p1, :cond_2

    goto :goto_1

    :cond_2
    iget-boolean p1, p0, Llyiahf/vczjk/um1;->Oooo0O0:Z

    if-nez p1, :cond_5

    iget-boolean p1, p0, Llyiahf/vczjk/um1;->Oooo00O:Z

    if-eqz p1, :cond_3

    goto :goto_1

    :cond_3
    invoke-virtual {p0}, Llyiahf/vczjk/um1;->o00000Oo()Llyiahf/vczjk/wj7;

    move-result-object p1

    if-nez p1, :cond_4

    goto :goto_1

    :cond_4
    invoke-virtual {p0, p1, v0, v1}, Llyiahf/vczjk/um1;->o00000o0(Llyiahf/vczjk/wj7;J)Z

    move-result p1

    if-eqz p1, :cond_5

    iput-boolean v3, p0, Llyiahf/vczjk/um1;->Oooo00o:Z

    :cond_5
    :goto_1
    return-void
.end method

.method public final o00000Oo()Llyiahf/vczjk/wj7;
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    const/4 v1, 0x0

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/yi4;->oo000o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/v16;

    move-result-object v0

    iget-object v2, p0, Llyiahf/vczjk/um1;->Oooo000:Llyiahf/vczjk/xn4;

    if-eqz v2, :cond_3

    invoke-interface {v2}, Llyiahf/vczjk/xn4;->OooOO0o()Z

    move-result v3

    if-eqz v3, :cond_1

    goto :goto_0

    :cond_1
    move-object v2, v1

    :goto_0
    if-nez v2, :cond_2

    goto :goto_1

    :cond_2
    const/4 v1, 0x0

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/v16;->OooOOO0(Llyiahf/vczjk/xn4;Z)Llyiahf/vczjk/wj7;

    move-result-object v0

    return-object v0

    :cond_3
    :goto_1
    return-object v1
.end method

.method public final o00000o0(Llyiahf/vczjk/wj7;J)Z
    .locals 3

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/um1;->o00000oO(Llyiahf/vczjk/wj7;J)J

    move-result-wide p1

    const/16 p3, 0x20

    shr-long v0, p1, p3

    long-to-int p3, v0

    invoke-static {p3}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p3

    invoke-static {p3}, Ljava/lang/Math;->abs(F)F

    move-result p3

    const/high16 v0, 0x3f000000    # 0.5f

    cmpg-float p3, p3, v0

    if-gtz p3, :cond_0

    const-wide v1, 0xffffffffL

    and-long/2addr p1, v1

    long-to-int p1, p1

    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p1

    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    move-result p1

    cmpg-float p1, p1, v0

    if-gtz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final o00000oO(Llyiahf/vczjk/wj7;J)J
    .locals 6

    invoke-static {p2, p3}, Llyiahf/vczjk/e16;->Oooo0oO(J)J

    move-result-wide p2

    iget-object v0, p0, Llyiahf/vczjk/um1;->OooOoOO:Llyiahf/vczjk/nf6;

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    const/4 v1, 0x0

    const-wide v2, 0xffffffffL

    const/16 v4, 0x20

    if-eqz v0, :cond_2

    const/4 v5, 0x1

    if-ne v0, v5, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/um1;->OooOooO:Llyiahf/vczjk/rk6;

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/ii0;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-static {p0, v0}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/gi0;

    :cond_0
    iget v5, p1, Llyiahf/vczjk/wj7;->OooO0OO:F

    iget p1, p1, Llyiahf/vczjk/wj7;->OooO00o:F

    sub-float/2addr v5, p1

    shr-long/2addr p2, v4

    long-to-int p2, p2

    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p2

    invoke-interface {v0, p1, v5, p2}, Llyiahf/vczjk/gi0;->OooO00o(FFF)F

    move-result p1

    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long p1, p1

    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p3

    int-to-long v0, p3

    shl-long/2addr p1, v4

    :goto_0
    and-long/2addr v0, v2

    or-long/2addr p1, v0

    return-wide p1

    :cond_1
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/um1;->OooOooO:Llyiahf/vczjk/rk6;

    if-nez v0, :cond_3

    sget-object v0, Llyiahf/vczjk/ii0;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-static {p0, v0}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/gi0;

    :cond_3
    iget v5, p1, Llyiahf/vczjk/wj7;->OooO0Oo:F

    iget p1, p1, Llyiahf/vczjk/wj7;->OooO0O0:F

    sub-float/2addr v5, p1

    and-long/2addr p2, v2

    long-to-int p2, p2

    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p2

    invoke-interface {v0, p1, v5, p2}, Llyiahf/vczjk/gi0;->OooO00o(FFF)F

    move-result p1

    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p2

    int-to-long p2, p2

    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long v0, p1

    shl-long p1, p2, v4

    goto :goto_0
.end method

.method public final o0000Ooo()V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/um1;->OooOooO:Llyiahf/vczjk/rk6;

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/ii0;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-static {p0, v0}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/gi0;

    :cond_0
    iget-boolean v1, p0, Llyiahf/vczjk/um1;->Oooo0O0:Z

    if-eqz v1, :cond_1

    const-string v1, "launchAnimation called when previous animation was running"

    invoke-static {v1}, Llyiahf/vczjk/sz3;->OooO0OO(Ljava/lang/String;)V

    :cond_1
    new-instance v1, Llyiahf/vczjk/oaa;

    sget-object v2, Llyiahf/vczjk/gi0;->OooO00o:Llyiahf/vczjk/fi0;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/fi0;->OooO0O0:Llyiahf/vczjk/wz8;

    invoke-direct {v1, v2}, Llyiahf/vczjk/oaa;-><init>(Llyiahf/vczjk/wz8;)V

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v4, Llyiahf/vczjk/tm1;

    const/4 v5, 0x0

    invoke-direct {v4, p0, v1, v0, v5}, Llyiahf/vczjk/tm1;-><init>(Llyiahf/vczjk/um1;Llyiahf/vczjk/oaa;Llyiahf/vczjk/gi0;Llyiahf/vczjk/yo1;)V

    const/4 v0, 0x1

    invoke-static {v2, v5, v3, v4, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method

.method public final o0Oo0oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method
