.class public abstract Llyiahf/vczjk/eb4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Closeable;
.implements Ljava/lang/AutoCloseable;


# instance fields
.field public OooOOO0:I


# virtual methods
.method public OooO0Oo()Z
    .locals 1

    instance-of v0, p0, Llyiahf/vczjk/nta;

    return v0
.end method

.method public OooO0oO()Z
    .locals 1

    instance-of v0, p0, Llyiahf/vczjk/nta;

    return v0
.end method

.method public abstract OooOOOO()V
.end method

.method public abstract OooOo()Llyiahf/vczjk/gc4;
.end method

.method public abstract OooOoO()I
.end method

.method public abstract OooOoOO()Ljava/math/BigInteger;
.end method

.method public abstract OooOooo(Llyiahf/vczjk/z50;)[B
.end method

.method public Oooo0oO()B
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/eb4;->o00000o0()I

    move-result v0

    const/16 v1, -0x80

    if-lt v0, v1, :cond_0

    const/16 v1, 0xff

    if-gt v0, v1, :cond_0

    int-to-byte v0, v0

    return v0

    :cond_0
    new-instance v0, Llyiahf/vczjk/c04;

    invoke-virtual {p0}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v1

    const-string v2, "Numeric value ("

    const-string v3, ") out of range of Java byte"

    invoke-static {v2, v1, v3}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOo0:Llyiahf/vczjk/gc4;

    sget-object v3, Ljava/lang/Byte;->TYPE:Ljava/lang/Class;

    invoke-direct {v0, v3, v1, p0, v2}, Llyiahf/vczjk/c04;-><init>(Ljava/lang/Class;Ljava/lang/String;Llyiahf/vczjk/eb4;Llyiahf/vczjk/gc4;)V

    throw v0
.end method

.method public abstract OoooO00()Llyiahf/vczjk/l66;
.end method

.method public abstract OoooOO0()Llyiahf/vczjk/ia4;
.end method

.method public abstract OoooOoo()Ljava/lang/String;
.end method

.method public abstract Oooooo0()Llyiahf/vczjk/gc4;
.end method

.method public abstract o000(Llyiahf/vczjk/z50;Llyiahf/vczjk/tl0;)I
.end method

.method public o0000()Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public abstract o00000O()F
.end method

.method public abstract o00000o0()I
.end method

.method public abstract o00000oO()Llyiahf/vczjk/db4;
.end method

.method public abstract o00000oo()Ljava/lang/Number;
.end method

.method public abstract o0000O()Llyiahf/vczjk/ia4;
.end method

.method public abstract o0000O0()[C
.end method

.method public abstract o0000O00()Llyiahf/vczjk/b23;
.end method

.method public abstract o0000O0O()I
.end method

.method public abstract o0000OO()I
.end method

.method public o0000OO0()Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public abstract o0000OOO()J
.end method

.method public abstract o0000OOo()Ljava/lang/String;
.end method

.method public abstract o0000Oo(Llyiahf/vczjk/gc4;)Z
.end method

.method public abstract o0000Oo0()Z
.end method

.method public abstract o0000OoO()Z
.end method

.method public abstract o0000Ooo()J
.end method

.method public o0000o()Ljava/lang/String;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public abstract o0000o0()Z
.end method

.method public abstract o0000o0O()Z
.end method

.method public abstract o0000o0o()Z
.end method

.method public abstract o0000oO()Ljava/lang/String;
.end method

.method public o0000oO0()Ljava/lang/String;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public abstract o0000oOO()Llyiahf/vczjk/gc4;
.end method

.method public abstract o0000oOo()Llyiahf/vczjk/gc4;
.end method

.method public o0000oo()S
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/eb4;->o00000o0()I

    move-result v0

    const/16 v1, -0x8000

    if-lt v0, v1, :cond_0

    const/16 v1, 0x7fff

    if-gt v0, v1, :cond_0

    int-to-short v0, v0

    return v0

    :cond_0
    new-instance v0, Llyiahf/vczjk/c04;

    invoke-virtual {p0}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v1

    const-string v2, "Numeric value ("

    const-string v3, ") out of range of Java short"

    invoke-static {v2, v1, v3}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOo0:Llyiahf/vczjk/gc4;

    sget-object v3, Ljava/lang/Short;->TYPE:Ljava/lang/Class;

    invoke-direct {v0, v3, v1, p0, v2}, Llyiahf/vczjk/c04;-><init>(Ljava/lang/Class;Ljava/lang/String;Llyiahf/vczjk/eb4;Llyiahf/vczjk/gc4;)V

    throw v0
.end method

.method public o0000oo0(II)V
    .locals 0

    return-void
.end method

.method public o0000ooO(II)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/eb4;->OooOOO0:I

    not-int v1, p2

    and-int/2addr v0, v1

    and-int/2addr p1, p2

    or-int/2addr p1, v0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/eb4;->o000O0o(I)Llyiahf/vczjk/eb4;

    return-void
.end method

.method public o000O000()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public o000O0o(I)Llyiahf/vczjk/eb4;
    .locals 0

    iput p1, p0, Llyiahf/vczjk/eb4;->OooOOO0:I

    return-object p0
.end method

.method public abstract o000OO()I
.end method

.method public o000OOo()Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public o000OoO(Ljava/lang/Object;)V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/eb4;->o0000O00()Llyiahf/vczjk/b23;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/b23;->OooOO0(Ljava/lang/Object;)V

    :cond_0
    return-void
.end method

.method public abstract o000Ooo()Llyiahf/vczjk/eb4;
.end method

.method public abstract o00oO0o()Ljava/math/BigDecimal;
.end method

.method public abstract o0OoOo0()I
.end method

.method public abstract o0ooOO0()D
.end method
