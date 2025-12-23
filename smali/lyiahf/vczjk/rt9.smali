.class public final Llyiahf/vczjk/rt9;
.super Llyiahf/vczjk/sp6;
.source "SourceFile"


# instance fields
.field public final OooOo:Llyiahf/vczjk/l66;

.field public final OooOoO:Z

.field public final OooOoO0:Z

.field public OooOoOO:Llyiahf/vczjk/st9;

.field public OooOoo:Llyiahf/vczjk/vt9;

.field public OooOoo0:I

.field public OooOooO:Z

.field public transient OooOooo:Llyiahf/vczjk/pl0;

.field public Oooo000:Llyiahf/vczjk/ia4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/st9;Llyiahf/vczjk/l66;ZZLlyiahf/vczjk/b23;)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, v0}, Llyiahf/vczjk/sp6;-><init>(I)V

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/rt9;->Oooo000:Llyiahf/vczjk/ia4;

    iput-object p1, p0, Llyiahf/vczjk/rt9;->OooOoOO:Llyiahf/vczjk/st9;

    const/4 p1, -0x1

    iput p1, p0, Llyiahf/vczjk/rt9;->OooOoo0:I

    iput-object p2, p0, Llyiahf/vczjk/rt9;->OooOo:Llyiahf/vczjk/l66;

    if-nez p5, :cond_0

    new-instance p1, Llyiahf/vczjk/vt9;

    invoke-direct {p1}, Llyiahf/vczjk/vt9;-><init>()V

    goto :goto_0

    :cond_0
    new-instance p1, Llyiahf/vczjk/vt9;

    invoke-direct {p1, p5, v0}, Llyiahf/vczjk/vt9;-><init>(Llyiahf/vczjk/b23;Llyiahf/vczjk/ia4;)V

    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/rt9;->OooOoo:Llyiahf/vczjk/vt9;

    iput-boolean p3, p0, Llyiahf/vczjk/rt9;->OooOoO0:Z

    iput-boolean p4, p0, Llyiahf/vczjk/rt9;->OooOoO:Z

    return-void
.end method


# virtual methods
.method public final OooO0Oo()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/rt9;->OooOoO:Z

    return v0
.end method

.method public final OooO0oO()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/rt9;->OooOoO0:Z

    return v0
.end method

.method public final OooOoOO()Ljava/math/BigInteger;
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o00000oo()Ljava/lang/Number;

    move-result-object v0

    instance-of v1, v0, Ljava/math/BigInteger;

    if-eqz v1, :cond_0

    check-cast v0, Ljava/math/BigInteger;

    return-object v0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o00000oO()Llyiahf/vczjk/db4;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/db4;->OooOOo:Llyiahf/vczjk/db4;

    if-ne v1, v2, :cond_1

    check-cast v0, Ljava/math/BigDecimal;

    invoke-virtual {v0}, Ljava/math/BigDecimal;->toBigInteger()Ljava/math/BigInteger;

    move-result-object v0

    return-object v0

    :cond_1
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/math/BigInteger;->valueOf(J)Ljava/math/BigInteger;

    move-result-object v0

    return-object v0
.end method

.method public final OooOooo(Llyiahf/vczjk/z50;)[B
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/sp6;->OooOOO:Llyiahf/vczjk/gc4;

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOoo:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o000OOoO()Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, [B

    if-eqz v1, :cond_0

    check-cast v0, [B

    return-object v0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/sp6;->OooOOO:Llyiahf/vczjk/gc4;

    sget-object v1, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o0000oO()Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x0

    if-nez v0, :cond_1

    return-object v1

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/rt9;->OooOooo:Llyiahf/vczjk/pl0;

    if-nez v2, :cond_2

    new-instance v2, Llyiahf/vczjk/pl0;

    const/16 v3, 0x64

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/pl0;-><init>(Llyiahf/vczjk/bj0;I)V

    iput-object v2, p0, Llyiahf/vczjk/rt9;->OooOooo:Llyiahf/vczjk/pl0;

    goto :goto_0

    :cond_2
    invoke-virtual {v2}, Llyiahf/vczjk/pl0;->reset()V

    :goto_0
    invoke-virtual {p0, v0, v2, p1}, Llyiahf/vczjk/sp6;->o000O0O(Ljava/lang/String;Llyiahf/vczjk/pl0;Llyiahf/vczjk/z50;)V

    invoke-virtual {v2}, Llyiahf/vczjk/pl0;->OooOoO()[B

    move-result-object p1

    return-object p1

    :cond_3
    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "Current token ("

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/sp6;->OooOOO:Llyiahf/vczjk/gc4;

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, ") not VALUE_STRING (or VALUE_EMBEDDED_OBJECT with byte[]), cannot access as binary"

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/bb4;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/a69;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;)V

    throw v0
.end method

.method public final OoooO00()Llyiahf/vczjk/l66;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rt9;->OooOo:Llyiahf/vczjk/l66;

    return-object v0
.end method

.method public final OoooOO0()Llyiahf/vczjk/ia4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rt9;->Oooo000:Llyiahf/vczjk/ia4;

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/ia4;->OooOOO:Llyiahf/vczjk/ia4;

    :cond_0
    return-object v0
.end method

.method public final OoooOoo()Ljava/lang/String;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/sp6;->OooOOO:Llyiahf/vczjk/gc4;

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOO:Llyiahf/vczjk/gc4;

    if-eq v0, v1, :cond_1

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOOo:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/rt9;->OooOoo:Llyiahf/vczjk/vt9;

    iget-object v0, v0, Llyiahf/vczjk/vt9;->OooO0o:Ljava/lang/String;

    return-object v0

    :cond_1
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/rt9;->OooOoo:Llyiahf/vczjk/vt9;

    iget-object v0, v0, Llyiahf/vczjk/vt9;->OooO0Oo:Llyiahf/vczjk/b23;

    invoke-virtual {v0}, Llyiahf/vczjk/b23;->OooO0Oo()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final close()V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/rt9;->OooOooO:Z

    if-nez v0, :cond_0

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/rt9;->OooOooO:Z

    :cond_0
    return-void
.end method

.method public final o000(Llyiahf/vczjk/z50;Llyiahf/vczjk/tl0;)I
    .locals 2

    invoke-virtual {p0, p1}, Llyiahf/vczjk/rt9;->OooOooo(Llyiahf/vczjk/z50;)[B

    move-result-object p1

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    array-length v1, p1

    invoke-virtual {p2, p1, v0, v1}, Llyiahf/vczjk/tl0;->write([BII)V

    array-length p1, p1

    return p1

    :cond_0
    return v0
.end method

.method public final o0000()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/rt9;->OooOoOO:Llyiahf/vczjk/st9;

    iget v1, p0, Llyiahf/vczjk/rt9;->OooOoo0:I

    iget-object v0, v0, Llyiahf/vczjk/st9;->OooO0Oo:Ljava/util/TreeMap;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    add-int/2addr v1, v1

    add-int/lit8 v1, v1, 0x1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final o00000O()F
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o00000oo()Ljava/lang/Number;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    return v0
.end method

.method public final o00000o0()I
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/sp6;->OooOOO:Llyiahf/vczjk/gc4;

    sget-object v1, Llyiahf/vczjk/gc4;->OooOo0:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o000OOoO()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o00000oo()Ljava/lang/Number;

    move-result-object v0

    :goto_0
    instance-of v1, v0, Ljava/lang/Integer;

    if-nez v1, :cond_b

    instance-of v1, v0, Ljava/lang/Short;

    if-nez v1, :cond_b

    instance-of v1, v0, Ljava/lang/Byte;

    if-eqz v1, :cond_1

    goto/16 :goto_3

    :cond_1
    instance-of v1, v0, Ljava/lang/Long;

    const/4 v2, 0x0

    if-eqz v1, :cond_3

    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    move-result-wide v0

    long-to-int v3, v0

    int-to-long v4, v3

    cmp-long v0, v4, v0

    if-nez v0, :cond_2

    return v3

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/sp6;->o0OoO0o()V

    throw v2

    :cond_3
    instance-of v1, v0, Ljava/math/BigInteger;

    if-eqz v1, :cond_5

    move-object v1, v0

    check-cast v1, Ljava/math/BigInteger;

    sget-object v3, Llyiahf/vczjk/sp6;->OooOOOo:Ljava/math/BigInteger;

    invoke-virtual {v3, v1}, Ljava/math/BigInteger;->compareTo(Ljava/math/BigInteger;)I

    move-result v3

    if-gtz v3, :cond_4

    sget-object v3, Llyiahf/vczjk/sp6;->OooOOo0:Ljava/math/BigInteger;

    invoke-virtual {v3, v1}, Ljava/math/BigInteger;->compareTo(Ljava/math/BigInteger;)I

    move-result v1

    if-ltz v1, :cond_4

    goto :goto_1

    :cond_4
    invoke-virtual {p0}, Llyiahf/vczjk/sp6;->o0OoO0o()V

    throw v2

    :cond_5
    instance-of v1, v0, Ljava/lang/Double;

    if-nez v1, :cond_9

    instance-of v1, v0, Ljava/lang/Float;

    if-eqz v1, :cond_6

    goto :goto_2

    :cond_6
    instance-of v1, v0, Ljava/math/BigDecimal;

    if-eqz v1, :cond_8

    move-object v1, v0

    check-cast v1, Ljava/math/BigDecimal;

    sget-object v3, Llyiahf/vczjk/sp6;->OooOo0O:Ljava/math/BigDecimal;

    invoke-virtual {v3, v1}, Ljava/math/BigDecimal;->compareTo(Ljava/math/BigDecimal;)I

    move-result v3

    if-gtz v3, :cond_7

    sget-object v3, Llyiahf/vczjk/sp6;->OooOo0o:Ljava/math/BigDecimal;

    invoke-virtual {v3, v1}, Ljava/math/BigDecimal;->compareTo(Ljava/math/BigDecimal;)I

    move-result v1

    if-ltz v1, :cond_7

    :goto_1
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    move-result v0

    return v0

    :cond_7
    invoke-virtual {p0}, Llyiahf/vczjk/sp6;->o0OoO0o()V

    throw v2

    :cond_8
    invoke-static {}, Llyiahf/vczjk/yea;->OooO00o()V

    throw v2

    :cond_9
    :goto_2
    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    move-result-wide v0

    const-wide/high16 v3, -0x3e20000000000000L    # -2.147483648E9

    cmpg-double v3, v0, v3

    if-ltz v3, :cond_a

    const-wide v3, 0x41dfffffffc00000L    # 2.147483647E9

    cmpl-double v3, v0, v3

    if-gtz v3, :cond_a

    double-to-int v0, v0

    return v0

    :cond_a
    invoke-virtual {p0}, Llyiahf/vczjk/sp6;->o0OoO0o()V

    throw v2

    :cond_b
    :goto_3
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    move-result v0

    return v0
.end method

.method public final o00000oO()Llyiahf/vczjk/db4;
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o00000oo()Ljava/lang/Number;

    move-result-object v0

    instance-of v1, v0, Ljava/lang/Integer;

    sget-object v2, Llyiahf/vczjk/db4;->OooOOO0:Llyiahf/vczjk/db4;

    if-eqz v1, :cond_0

    return-object v2

    :cond_0
    instance-of v1, v0, Ljava/lang/Long;

    if-eqz v1, :cond_1

    sget-object v0, Llyiahf/vczjk/db4;->OooOOO:Llyiahf/vczjk/db4;

    return-object v0

    :cond_1
    instance-of v1, v0, Ljava/lang/Double;

    if-eqz v1, :cond_2

    sget-object v0, Llyiahf/vczjk/db4;->OooOOo0:Llyiahf/vczjk/db4;

    return-object v0

    :cond_2
    instance-of v1, v0, Ljava/math/BigDecimal;

    if-eqz v1, :cond_3

    sget-object v0, Llyiahf/vczjk/db4;->OooOOo:Llyiahf/vczjk/db4;

    return-object v0

    :cond_3
    instance-of v1, v0, Ljava/math/BigInteger;

    if-eqz v1, :cond_4

    sget-object v0, Llyiahf/vczjk/db4;->OooOOOO:Llyiahf/vczjk/db4;

    return-object v0

    :cond_4
    instance-of v1, v0, Ljava/lang/Float;

    if-eqz v1, :cond_5

    sget-object v0, Llyiahf/vczjk/db4;->OooOOOo:Llyiahf/vczjk/db4;

    return-object v0

    :cond_5
    instance-of v0, v0, Ljava/lang/Short;

    if-eqz v0, :cond_6

    return-object v2

    :cond_6
    const/4 v0, 0x0

    return-object v0
.end method

.method public final o00000oo()Ljava/lang/Number;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/sp6;->OooOOO:Llyiahf/vczjk/gc4;

    if-eqz v0, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/gc4;->OooO0Oo()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o000OOoO()Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Ljava/lang/Number;

    if-eqz v1, :cond_0

    check-cast v0, Ljava/lang/Number;

    return-object v0

    :cond_0
    instance-of v1, v0, Ljava/lang/String;

    if-eqz v1, :cond_2

    check-cast v0, Ljava/lang/String;

    const/16 v1, 0x2e

    invoke-virtual {v0, v1}, Ljava/lang/String;->indexOf(I)I

    move-result v1

    if-ltz v1, :cond_1

    invoke-static {v0}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v0

    return-object v0

    :cond_1
    invoke-static {v0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v0

    return-object v0

    :cond_2
    if-nez v0, :cond_3

    const/4 v0, 0x0

    return-object v0

    :cond_3
    new-instance v1, Ljava/lang/IllegalStateException;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    const-string v2, "Internal error: entry should be a Number, but is of type "

    invoke-virtual {v2, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_4
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Current token ("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/sp6;->OooOOO:Llyiahf/vczjk/gc4;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ") not numeric, cannot use numeric value accessors"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/bb4;

    invoke-direct {v1, p0, v0}, Llyiahf/vczjk/a69;-><init>(Llyiahf/vczjk/eb4;Ljava/lang/String;)V

    throw v1
.end method

.method public final o0000O0()[C
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o0000oO()Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    invoke-virtual {v0}, Ljava/lang/String;->toCharArray()[C

    move-result-object v0

    return-object v0
.end method

.method public final o0000O00()Llyiahf/vczjk/b23;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rt9;->OooOoo:Llyiahf/vczjk/vt9;

    return-object v0
.end method

.method public final o0000O0O()I
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o0000oO()Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return v0

    :cond_0
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    return v0
.end method

.method public final o0000OO0()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/rt9;->OooOoOO:Llyiahf/vczjk/st9;

    iget v1, p0, Llyiahf/vczjk/rt9;->OooOoo0:I

    iget-object v0, v0, Llyiahf/vczjk/st9;->OooO0Oo:Ljava/util/TreeMap;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    add-int/2addr v1, v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final o0000Oo0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final o0000Ooo()J
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/sp6;->OooOOO:Llyiahf/vczjk/gc4;

    sget-object v1, Llyiahf/vczjk/gc4;->OooOo0:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o000OOoO()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o00000oo()Ljava/lang/Number;

    move-result-object v0

    :goto_0
    instance-of v1, v0, Ljava/lang/Long;

    if-nez v1, :cond_9

    instance-of v1, v0, Ljava/lang/Integer;

    if-nez v1, :cond_9

    instance-of v1, v0, Ljava/lang/Short;

    if-nez v1, :cond_9

    instance-of v1, v0, Ljava/lang/Byte;

    if-eqz v1, :cond_1

    goto :goto_3

    :cond_1
    instance-of v1, v0, Ljava/math/BigInteger;

    const/4 v2, 0x0

    if-eqz v1, :cond_3

    move-object v1, v0

    check-cast v1, Ljava/math/BigInteger;

    sget-object v3, Llyiahf/vczjk/sp6;->OooOOo:Ljava/math/BigInteger;

    invoke-virtual {v3, v1}, Ljava/math/BigInteger;->compareTo(Ljava/math/BigInteger;)I

    move-result v3

    if-gtz v3, :cond_2

    sget-object v3, Llyiahf/vczjk/sp6;->OooOOoo:Ljava/math/BigInteger;

    invoke-virtual {v3, v1}, Ljava/math/BigInteger;->compareTo(Ljava/math/BigInteger;)I

    move-result v1

    if-ltz v1, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/sp6;->o000OO0o()V

    throw v2

    :cond_3
    instance-of v1, v0, Ljava/lang/Double;

    if-nez v1, :cond_7

    instance-of v1, v0, Ljava/lang/Float;

    if-eqz v1, :cond_4

    goto :goto_2

    :cond_4
    instance-of v1, v0, Ljava/math/BigDecimal;

    if-eqz v1, :cond_6

    move-object v1, v0

    check-cast v1, Ljava/math/BigDecimal;

    sget-object v3, Llyiahf/vczjk/sp6;->OooOo00:Ljava/math/BigDecimal;

    invoke-virtual {v3, v1}, Ljava/math/BigDecimal;->compareTo(Ljava/math/BigDecimal;)I

    move-result v3

    if-gtz v3, :cond_5

    sget-object v3, Llyiahf/vczjk/sp6;->OooOo0:Ljava/math/BigDecimal;

    invoke-virtual {v3, v1}, Ljava/math/BigDecimal;->compareTo(Ljava/math/BigDecimal;)I

    move-result v1

    if-ltz v1, :cond_5

    :goto_1
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    move-result-wide v0

    return-wide v0

    :cond_5
    invoke-virtual {p0}, Llyiahf/vczjk/sp6;->o000OO0o()V

    throw v2

    :cond_6
    invoke-static {}, Llyiahf/vczjk/yea;->OooO00o()V

    throw v2

    :cond_7
    :goto_2
    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    move-result-wide v0

    const-wide/high16 v3, -0x3c20000000000000L    # -9.223372036854776E18

    cmpg-double v3, v0, v3

    if-ltz v3, :cond_8

    const-wide/high16 v3, 0x43e0000000000000L    # 9.223372036854776E18

    cmpl-double v3, v0, v3

    if-gtz v3, :cond_8

    double-to-long v0, v0

    return-wide v0

    :cond_8
    invoke-virtual {p0}, Llyiahf/vczjk/sp6;->o000OO0o()V

    throw v2

    :cond_9
    :goto_3
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    move-result-wide v0

    return-wide v0
.end method

.method public final o0000o()Ljava/lang/String;
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/rt9;->OooOooO:Z

    if-nez v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/rt9;->OooOoOO:Llyiahf/vczjk/st9;

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    iget v1, p0, Llyiahf/vczjk/rt9;->OooOoo0:I

    add-int/lit8 v1, v1, 0x1

    const/16 v2, 0x10

    if-ge v1, v2, :cond_2

    invoke-virtual {v0, v1}, Llyiahf/vczjk/st9;->OooO0OO(I)Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-ne v0, v2, :cond_2

    iput v1, p0, Llyiahf/vczjk/rt9;->OooOoo0:I

    iput-object v2, p0, Llyiahf/vczjk/sp6;->OooOOO:Llyiahf/vczjk/gc4;

    iget-object v0, p0, Llyiahf/vczjk/rt9;->OooOoOO:Llyiahf/vczjk/st9;

    iget-object v0, v0, Llyiahf/vczjk/st9;->OooO0OO:[Ljava/lang/Object;

    aget-object v0, v0, v1

    instance-of v1, v0, Ljava/lang/String;

    if-eqz v1, :cond_1

    check-cast v0, Ljava/lang/String;

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/rt9;->OooOoo:Llyiahf/vczjk/vt9;

    iput-object v0, v1, Llyiahf/vczjk/vt9;->OooO0o:Ljava/lang/String;

    return-object v0

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->OoooOoo()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :cond_3
    :goto_1
    const/4 v0, 0x0

    return-object v0
.end method

.method public final o0000o0o()Z
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/sp6;->OooOOO:Llyiahf/vczjk/gc4;

    sget-object v1, Llyiahf/vczjk/gc4;->OooOo0O:Llyiahf/vczjk/gc4;

    const/4 v2, 0x0

    if-ne v0, v1, :cond_5

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o000OOoO()Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Ljava/lang/Double;

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    check-cast v0, Ljava/lang/Double;

    invoke-virtual {v0}, Ljava/lang/Double;->isNaN()Z

    move-result v1

    if-nez v1, :cond_1

    invoke-virtual {v0}, Ljava/lang/Double;->isInfinite()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    return v2

    :cond_1
    :goto_0
    return v3

    :cond_2
    instance-of v1, v0, Ljava/lang/Float;

    if-eqz v1, :cond_5

    check-cast v0, Ljava/lang/Float;

    invoke-virtual {v0}, Ljava/lang/Float;->isNaN()Z

    move-result v1

    if-nez v1, :cond_4

    invoke-virtual {v0}, Ljava/lang/Float;->isInfinite()Z

    move-result v0

    if-eqz v0, :cond_3

    goto :goto_1

    :cond_3
    return v2

    :cond_4
    :goto_1
    return v3

    :cond_5
    return v2
.end method

.method public final o0000oO()Ljava/lang/String;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/sp6;->OooOOO:Llyiahf/vczjk/gc4;

    sget-object v1, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    const/4 v2, 0x0

    if-eq v0, v1, :cond_4

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    if-nez v0, :cond_1

    return-object v2

    :cond_1
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    const/16 v1, 0x8

    if-eq v0, v1, :cond_2

    const/16 v1, 0x9

    if-eq v0, v1, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/sp6;->OooOOO:Llyiahf/vczjk/gc4;

    invoke-virtual {v0}, Llyiahf/vczjk/gc4;->OooO0O0()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o000OOoO()Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    if-nez v0, :cond_3

    return-object v2

    :cond_3
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :cond_4
    :goto_0
    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o000OOoO()Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Ljava/lang/String;

    if-eqz v1, :cond_5

    check-cast v0, Ljava/lang/String;

    return-object v0

    :cond_5
    sget-object v1, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    if-nez v0, :cond_6

    return-object v2

    :cond_6
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final o0000oOO()Llyiahf/vczjk/gc4;
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/rt9;->OooOooO:Z

    if-nez v0, :cond_a

    iget-object v0, p0, Llyiahf/vczjk/rt9;->OooOoOO:Llyiahf/vczjk/st9;

    if-nez v0, :cond_0

    goto/16 :goto_4

    :cond_0
    iget v1, p0, Llyiahf/vczjk/rt9;->OooOoo0:I

    const/4 v2, 0x1

    add-int/2addr v1, v2

    iput v1, p0, Llyiahf/vczjk/rt9;->OooOoo0:I

    const/16 v3, 0x10

    if-lt v1, v3, :cond_1

    const/4 v1, 0x0

    iput v1, p0, Llyiahf/vczjk/rt9;->OooOoo0:I

    iget-object v0, v0, Llyiahf/vczjk/st9;->OooO00o:Llyiahf/vczjk/st9;

    iput-object v0, p0, Llyiahf/vczjk/rt9;->OooOoOO:Llyiahf/vczjk/st9;

    if-nez v0, :cond_1

    goto/16 :goto_4

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/rt9;->OooOoOO:Llyiahf/vczjk/st9;

    iget v1, p0, Llyiahf/vczjk/rt9;->OooOoo0:I

    invoke-virtual {v0, v1}, Llyiahf/vczjk/st9;->OooO0OO(I)Llyiahf/vczjk/gc4;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/sp6;->OooOOO:Llyiahf/vczjk/gc4;

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o000OOoO()Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Ljava/lang/String;

    if-eqz v1, :cond_2

    check-cast v0, Ljava/lang/String;

    goto :goto_0

    :cond_2
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/rt9;->OooOoo:Llyiahf/vczjk/vt9;

    iput-object v0, v1, Llyiahf/vczjk/vt9;->OooO0o:Ljava/lang/String;

    goto :goto_3

    :cond_3
    sget-object v1, Llyiahf/vczjk/gc4;->OooOOO:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/rt9;->OooOoo:Llyiahf/vczjk/vt9;

    iget v1, v0, Llyiahf/vczjk/b23;->OooO0OO:I

    add-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/b23;->OooO0OO:I

    new-instance v1, Llyiahf/vczjk/vt9;

    const/4 v2, 0x2

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/vt9;-><init>(Llyiahf/vczjk/vt9;I)V

    iput-object v1, p0, Llyiahf/vczjk/rt9;->OooOoo:Llyiahf/vczjk/vt9;

    goto :goto_3

    :cond_4
    sget-object v1, Llyiahf/vczjk/gc4;->OooOOOo:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_5

    iget-object v0, p0, Llyiahf/vczjk/rt9;->OooOoo:Llyiahf/vczjk/vt9;

    iget v1, v0, Llyiahf/vczjk/b23;->OooO0OO:I

    add-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/b23;->OooO0OO:I

    new-instance v1, Llyiahf/vczjk/vt9;

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/vt9;-><init>(Llyiahf/vczjk/vt9;I)V

    iput-object v1, p0, Llyiahf/vczjk/rt9;->OooOoo:Llyiahf/vczjk/vt9;

    goto :goto_3

    :cond_5
    sget-object v1, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    if-eq v0, v1, :cond_7

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_6

    goto :goto_1

    :cond_6
    iget-object v0, p0, Llyiahf/vczjk/rt9;->OooOoo:Llyiahf/vczjk/vt9;

    iget v1, v0, Llyiahf/vczjk/b23;->OooO0OO:I

    add-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/b23;->OooO0OO:I

    goto :goto_3

    :cond_7
    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/rt9;->OooOoo:Llyiahf/vczjk/vt9;

    iget-object v1, v0, Llyiahf/vczjk/vt9;->OooO0Oo:Llyiahf/vczjk/b23;

    instance-of v2, v1, Llyiahf/vczjk/vt9;

    if-eqz v2, :cond_8

    check-cast v1, Llyiahf/vczjk/vt9;

    goto :goto_2

    :cond_8
    if-nez v1, :cond_9

    new-instance v1, Llyiahf/vczjk/vt9;

    invoke-direct {v1}, Llyiahf/vczjk/vt9;-><init>()V

    goto :goto_2

    :cond_9
    new-instance v2, Llyiahf/vczjk/vt9;

    iget-object v0, v0, Llyiahf/vczjk/vt9;->OooO0o0:Llyiahf/vczjk/ia4;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/vt9;-><init>(Llyiahf/vczjk/b23;Llyiahf/vczjk/ia4;)V

    move-object v1, v2

    :goto_2
    iput-object v1, p0, Llyiahf/vczjk/rt9;->OooOoo:Llyiahf/vczjk/vt9;

    :goto_3
    iget-object v0, p0, Llyiahf/vczjk/sp6;->OooOOO:Llyiahf/vczjk/gc4;

    return-object v0

    :cond_a
    :goto_4
    const/4 v0, 0x0

    return-object v0
.end method

.method public final o000O00()V
    .locals 1

    invoke-static {}, Llyiahf/vczjk/yea;->OooO00o()V

    const/4 v0, 0x0

    throw v0
.end method

.method public final o000OO()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final o000OOo()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/sp6;->OooOOO:Llyiahf/vczjk/gc4;

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOoo:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o000OOoO()Ljava/lang/Object;

    move-result-object v0

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final o000OOoO()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/rt9;->OooOoOO:Llyiahf/vczjk/st9;

    iget v1, p0, Llyiahf/vczjk/rt9;->OooOoo0:I

    iget-object v0, v0, Llyiahf/vczjk/st9;->OooO0OO:[Ljava/lang/Object;

    aget-object v0, v0, v1

    return-object v0
.end method

.method public final o00oO0o()Ljava/math/BigDecimal;
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o00000oo()Ljava/lang/Number;

    move-result-object v0

    instance-of v1, v0, Ljava/math/BigDecimal;

    if-eqz v1, :cond_0

    check-cast v0, Ljava/math/BigDecimal;

    return-object v0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o00000oO()Llyiahf/vczjk/db4;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    if-eqz v1, :cond_2

    const/4 v2, 0x1

    if-eq v1, v2, :cond_2

    const/4 v2, 0x2

    if-eq v1, v2, :cond_1

    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/math/BigDecimal;->valueOf(D)Ljava/math/BigDecimal;

    move-result-object v0

    return-object v0

    :cond_1
    new-instance v1, Ljava/math/BigDecimal;

    check-cast v0, Ljava/math/BigInteger;

    invoke-direct {v1, v0}, Ljava/math/BigDecimal;-><init>(Ljava/math/BigInteger;)V

    return-object v1

    :cond_2
    invoke-virtual {v0}, Ljava/lang/Number;->longValue()J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/math/BigDecimal;->valueOf(J)Ljava/math/BigDecimal;

    move-result-object v0

    return-object v0
.end method

.method public final o0ooOO0()D
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/rt9;->o00000oo()Ljava/lang/Number;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Number;->doubleValue()D

    move-result-wide v0

    return-wide v0
.end method
