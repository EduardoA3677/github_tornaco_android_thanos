.class public final Llyiahf/vczjk/mj2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/c07;


# instance fields
.field public final OooO:Llyiahf/vczjk/f7;

.field public final OooO00o:J

.field public final OooO0O0:Llyiahf/vczjk/f62;

.field public final OooO0OO:I

.field public final OooO0Oo:Llyiahf/vczjk/xd;

.field public final OooO0o:Llyiahf/vczjk/e7;

.field public final OooO0o0:Llyiahf/vczjk/e7;

.field public final OooO0oO:Llyiahf/vczjk/sma;

.field public final OooO0oo:Llyiahf/vczjk/sma;

.field public final OooOO0:Llyiahf/vczjk/f7;

.field public final OooOO0O:Llyiahf/vczjk/f7;

.field public final OooOO0o:Llyiahf/vczjk/tma;

.field public final OooOOO0:Llyiahf/vczjk/tma;


# direct methods
.method public constructor <init>(JLlyiahf/vczjk/f62;Llyiahf/vczjk/xd;)V
    .locals 3

    sget v0, Llyiahf/vczjk/sh5;->OooO00o:F

    invoke-interface {p3, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Llyiahf/vczjk/mj2;->OooO00o:J

    iput-object p3, p0, Llyiahf/vczjk/mj2;->OooO0O0:Llyiahf/vczjk/f62;

    iput v0, p0, Llyiahf/vczjk/mj2;->OooO0OO:I

    iput-object p4, p0, Llyiahf/vczjk/mj2;->OooO0Oo:Llyiahf/vczjk/xd;

    const/16 p4, 0x20

    shr-long v1, p1, p4

    long-to-int p4, v1

    invoke-static {p4}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p4

    invoke-interface {p3, p4}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p4

    new-instance v1, Llyiahf/vczjk/e7;

    sget-object v2, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-direct {v1, v2, v2, p4}, Llyiahf/vczjk/e7;-><init>(Llyiahf/vczjk/sb0;Llyiahf/vczjk/sb0;I)V

    iput-object v1, p0, Llyiahf/vczjk/mj2;->OooO0o0:Llyiahf/vczjk/e7;

    new-instance v1, Llyiahf/vczjk/e7;

    sget-object v2, Llyiahf/vczjk/op3;->OooOoo0:Llyiahf/vczjk/sb0;

    invoke-direct {v1, v2, v2, p4}, Llyiahf/vczjk/e7;-><init>(Llyiahf/vczjk/sb0;Llyiahf/vczjk/sb0;I)V

    iput-object v1, p0, Llyiahf/vczjk/mj2;->OooO0o:Llyiahf/vczjk/e7;

    new-instance p4, Llyiahf/vczjk/sma;

    sget-object v1, Llyiahf/vczjk/ng0;->OooO0OO:Llyiahf/vczjk/qb0;

    invoke-direct {p4, v1}, Llyiahf/vczjk/sma;-><init>(Llyiahf/vczjk/qb0;)V

    iput-object p4, p0, Llyiahf/vczjk/mj2;->OooO0oO:Llyiahf/vczjk/sma;

    new-instance p4, Llyiahf/vczjk/sma;

    sget-object v1, Llyiahf/vczjk/ng0;->OooO0Oo:Llyiahf/vczjk/qb0;

    invoke-direct {p4, v1}, Llyiahf/vczjk/sma;-><init>(Llyiahf/vczjk/qb0;)V

    iput-object p4, p0, Llyiahf/vczjk/mj2;->OooO0oo:Llyiahf/vczjk/sma;

    const-wide v1, 0xffffffffL

    and-long/2addr p1, v1

    long-to-int p1, p1

    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p1

    invoke-interface {p3, p1}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p1

    new-instance p2, Llyiahf/vczjk/f7;

    sget-object p3, Llyiahf/vczjk/op3;->OooOo0o:Llyiahf/vczjk/tb0;

    sget-object p4, Llyiahf/vczjk/op3;->OooOoO0:Llyiahf/vczjk/tb0;

    invoke-direct {p2, p3, p4, p1}, Llyiahf/vczjk/f7;-><init>(Llyiahf/vczjk/tb0;Llyiahf/vczjk/tb0;I)V

    iput-object p2, p0, Llyiahf/vczjk/mj2;->OooO:Llyiahf/vczjk/f7;

    new-instance p2, Llyiahf/vczjk/f7;

    invoke-direct {p2, p4, p3, p1}, Llyiahf/vczjk/f7;-><init>(Llyiahf/vczjk/tb0;Llyiahf/vczjk/tb0;I)V

    iput-object p2, p0, Llyiahf/vczjk/mj2;->OooOO0:Llyiahf/vczjk/f7;

    new-instance p2, Llyiahf/vczjk/f7;

    sget-object v1, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    invoke-direct {p2, v1, p3, p1}, Llyiahf/vczjk/f7;-><init>(Llyiahf/vczjk/tb0;Llyiahf/vczjk/tb0;I)V

    iput-object p2, p0, Llyiahf/vczjk/mj2;->OooOO0O:Llyiahf/vczjk/f7;

    new-instance p1, Llyiahf/vczjk/tma;

    invoke-direct {p1, p3, v0}, Llyiahf/vczjk/tma;-><init>(Llyiahf/vczjk/tb0;I)V

    iput-object p1, p0, Llyiahf/vczjk/mj2;->OooOO0o:Llyiahf/vczjk/tma;

    new-instance p1, Llyiahf/vczjk/tma;

    invoke-direct {p1, p4, v0}, Llyiahf/vczjk/tma;-><init>(Llyiahf/vczjk/tb0;I)V

    iput-object p1, p0, Llyiahf/vczjk/mj2;->OooOOO0:Llyiahf/vczjk/tma;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/y14;JLlyiahf/vczjk/yn4;J)J
    .locals 18

    move-object/from16 v0, p0

    const/4 v7, 0x3

    const/4 v8, 0x0

    const/4 v9, 0x1

    const/4 v10, 0x2

    invoke-virtual/range {p1 .. p1}, Llyiahf/vczjk/y14;->OooO00o()J

    move-result-wide v1

    const/16 v11, 0x20

    shr-long/2addr v1, v11

    long-to-int v1, v1

    shr-long v2, p2, v11

    long-to-int v12, v2

    div-int/lit8 v2, v12, 0x2

    if-ge v1, v2, :cond_0

    iget-object v1, v0, Llyiahf/vczjk/mj2;->OooO0oO:Llyiahf/vczjk/sma;

    goto :goto_0

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/mj2;->OooO0oo:Llyiahf/vczjk/sma;

    :goto_0
    iget-object v2, v0, Llyiahf/vczjk/mj2;->OooO0o0:Llyiahf/vczjk/e7;

    iget-object v3, v0, Llyiahf/vczjk/mj2;->OooO0o:Llyiahf/vczjk/e7;

    new-array v4, v7, [Llyiahf/vczjk/ai5;

    aput-object v2, v4, v8

    aput-object v3, v4, v9

    aput-object v1, v4, v10

    invoke-static {v4}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v13

    invoke-interface {v13}, Ljava/util/Collection;->size()I

    move-result v14

    move v15, v8

    :goto_1
    if-ge v15, v14, :cond_2

    invoke-interface {v13, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ai5;

    shr-long v2, p5, v11

    long-to-int v5, v2

    move-object/from16 v2, p1

    move-wide/from16 v3, p2

    move-object/from16 v6, p4

    invoke-interface/range {v1 .. v6}, Llyiahf/vczjk/ai5;->OooO00o(Llyiahf/vczjk/y14;JILlyiahf/vczjk/yn4;)I

    move-result v1

    invoke-static {v13}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v6

    if-eq v15, v6, :cond_3

    if-ltz v1, :cond_1

    add-int/2addr v5, v1

    if-gt v5, v12, :cond_1

    goto :goto_2

    :cond_1
    add-int/2addr v15, v9

    goto :goto_1

    :cond_2
    move-object/from16 v2, p1

    move-wide/from16 v3, p2

    move v1, v8

    :cond_3
    :goto_2
    invoke-virtual {v2}, Llyiahf/vczjk/y14;->OooO00o()J

    move-result-wide v5

    const-wide v12, 0xffffffffL

    and-long/2addr v5, v12

    long-to-int v5, v5

    and-long v14, v3, v12

    long-to-int v6, v14

    div-int/lit8 v14, v6, 0x2

    if-ge v5, v14, :cond_4

    iget-object v5, v0, Llyiahf/vczjk/mj2;->OooOO0o:Llyiahf/vczjk/tma;

    goto :goto_3

    :cond_4
    iget-object v5, v0, Llyiahf/vczjk/mj2;->OooOOO0:Llyiahf/vczjk/tma;

    :goto_3
    iget-object v14, v0, Llyiahf/vczjk/mj2;->OooO:Llyiahf/vczjk/f7;

    iget-object v15, v0, Llyiahf/vczjk/mj2;->OooOO0:Llyiahf/vczjk/f7;

    move/from16 v16, v7

    iget-object v7, v0, Llyiahf/vczjk/mj2;->OooOO0O:Llyiahf/vczjk/f7;

    move/from16 v17, v8

    const/4 v8, 0x4

    new-array v8, v8, [Llyiahf/vczjk/bi5;

    aput-object v14, v8, v17

    aput-object v15, v8, v9

    aput-object v7, v8, v10

    aput-object v5, v8, v16

    invoke-static {v8}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v5

    invoke-interface {v5}, Ljava/util/Collection;->size()I

    move-result v7

    move/from16 v8, v17

    :goto_4
    if-ge v8, v7, :cond_7

    invoke-interface {v5, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/bi5;

    and-long v14, p5, v12

    long-to-int v14, v14

    invoke-interface {v10, v2, v3, v4, v14}, Llyiahf/vczjk/bi5;->OooO00o(Llyiahf/vczjk/y14;JI)I

    move-result v10

    invoke-static {v5}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v15

    if-eq v8, v15, :cond_6

    iget v15, v0, Llyiahf/vczjk/mj2;->OooO0OO:I

    if-lt v10, v15, :cond_5

    add-int/2addr v14, v10

    sub-int v15, v6, v15

    if-gt v14, v15, :cond_5

    goto :goto_5

    :cond_5
    add-int/2addr v8, v9

    goto :goto_4

    :cond_6
    :goto_5
    move v8, v10

    goto :goto_6

    :cond_7
    move/from16 v8, v17

    :goto_6
    int-to-long v3, v1

    shl-long/2addr v3, v11

    int-to-long v5, v8

    and-long/2addr v5, v12

    or-long/2addr v3, v5

    new-instance v1, Llyiahf/vczjk/y14;

    shr-long v5, v3, v11

    long-to-int v5, v5

    and-long v6, v3, v12

    long-to-int v6, v6

    shr-long v7, p5, v11

    long-to-int v7, v7

    add-int/2addr v7, v5

    and-long v8, p5, v12

    long-to-int v8, v8

    add-int/2addr v8, v6

    invoke-direct {v1, v5, v6, v7, v8}, Llyiahf/vczjk/y14;-><init>(IIII)V

    iget-object v5, v0, Llyiahf/vczjk/mj2;->OooO0Oo:Llyiahf/vczjk/xd;

    invoke-virtual {v5, v2, v1}, Llyiahf/vczjk/xd;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-wide v3
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 6

    if-ne p0, p1, :cond_0

    goto :goto_1

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/mj2;

    const/4 v1, 0x0

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    check-cast p1, Llyiahf/vczjk/mj2;

    iget-wide v2, p1, Llyiahf/vczjk/mj2;->OooO00o:J

    iget-wide v4, p0, Llyiahf/vczjk/mj2;->OooO00o:J

    cmp-long v0, v4, v2

    if-nez v0, :cond_5

    iget-object v0, p0, Llyiahf/vczjk/mj2;->OooO0O0:Llyiahf/vczjk/f62;

    iget-object v2, p1, Llyiahf/vczjk/mj2;->OooO0O0:Llyiahf/vczjk/f62;

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_0

    :cond_2
    iget v0, p0, Llyiahf/vczjk/mj2;->OooO0OO:I

    iget v2, p1, Llyiahf/vczjk/mj2;->OooO0OO:I

    if-eq v0, v2, :cond_3

    goto :goto_0

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/mj2;->OooO0Oo:Llyiahf/vczjk/xd;

    iget-object p1, p1, Llyiahf/vczjk/mj2;->OooO0Oo:Llyiahf/vczjk/xd;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_4

    :goto_0
    return v1

    :cond_4
    :goto_1
    const/4 p1, 0x1

    return p1

    :cond_5
    return v1
.end method

.method public final hashCode()I
    .locals 3

    iget-wide v0, p0, Llyiahf/vczjk/mj2;->OooO00o:J

    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    move-result v0

    const/16 v1, 0x1f

    mul-int/2addr v0, v1

    iget-object v2, p0, Llyiahf/vczjk/mj2;->OooO0O0:Llyiahf/vczjk/f62;

    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    move-result v2

    add-int/2addr v2, v0

    mul-int/2addr v2, v1

    iget v0, p0, Llyiahf/vczjk/mj2;->OooO0OO:I

    invoke-static {v0, v2, v1}, Llyiahf/vczjk/u81;->OooO0Oo(III)I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/mj2;->OooO0Oo:Llyiahf/vczjk/xd;

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "DropdownMenuPositionProvider(contentOffset="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-wide v1, p0, Llyiahf/vczjk/mj2;->OooO00o:J

    invoke-static {v1, v2}, Llyiahf/vczjk/zd2;->OooO00o(J)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", density="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/mj2;->OooO0O0:Llyiahf/vczjk/f62;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", verticalMargin="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget v1, p0, Llyiahf/vczjk/mj2;->OooO0OO:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ", onPositionCalculated="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/mj2;->OooO0Oo:Llyiahf/vczjk/xd;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
