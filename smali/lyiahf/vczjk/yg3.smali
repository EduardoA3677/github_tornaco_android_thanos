.class public abstract Llyiahf/vczjk/yg3;
.super Llyiahf/vczjk/u94;
.source "SourceFile"


# static fields
.field public static final OooOOo0:I


# instance fields
.field public OooOOO:I

.field public OooOOOO:Z

.field public OooOOOo:Llyiahf/vczjk/yc4;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/t94;->OooOOoo:Llyiahf/vczjk/t94;

    invoke-virtual {v0}, Llyiahf/vczjk/t94;->OooO0OO()I

    move-result v0

    sget-object v1, Llyiahf/vczjk/t94;->OooOOo:Llyiahf/vczjk/t94;

    invoke-virtual {v1}, Llyiahf/vczjk/t94;->OooO0OO()I

    move-result v1

    or-int/2addr v0, v1

    sget-object v1, Llyiahf/vczjk/t94;->OooOo0:Llyiahf/vczjk/t94;

    invoke-virtual {v1}, Llyiahf/vczjk/t94;->OooO0OO()I

    move-result v1

    or-int/2addr v0, v1

    sput v0, Llyiahf/vczjk/yg3;->OooOOo0:I

    return-void
.end method


# virtual methods
.method public OooOoO(Llyiahf/vczjk/t94;)Llyiahf/vczjk/u94;
    .locals 3

    invoke-virtual {p1}, Llyiahf/vczjk/t94;->OooO0OO()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/yg3;->OooOOO:I

    not-int v2, v0

    and-int/2addr v1, v2

    iput v1, p0, Llyiahf/vczjk/yg3;->OooOOO:I

    sget v1, Llyiahf/vczjk/yg3;->OooOOo0:I

    and-int/2addr v0, v1

    if-eqz v0, :cond_2

    sget-object v0, Llyiahf/vczjk/t94;->OooOOoo:Llyiahf/vczjk/t94;

    const/4 v1, 0x0

    if-ne p1, v0, :cond_0

    iput-boolean v1, p0, Llyiahf/vczjk/yg3;->OooOOOO:Z

    return-object p0

    :cond_0
    sget-object v0, Llyiahf/vczjk/t94;->OooOOo:Llyiahf/vczjk/t94;

    if-ne p1, v0, :cond_1

    invoke-virtual {p0, v1}, Llyiahf/vczjk/u94;->OoooOoo(I)V

    return-object p0

    :cond_1
    sget-object v0, Llyiahf/vczjk/t94;->OooOo0:Llyiahf/vczjk/t94;

    if-ne p1, v0, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/yg3;->OooOOOo:Llyiahf/vczjk/yc4;

    const/4 v0, 0x0

    iput-object v0, p1, Llyiahf/vczjk/yc4;->OooO0o0:Llyiahf/vczjk/ld9;

    iput-object p1, p0, Llyiahf/vczjk/yg3;->OooOOOo:Llyiahf/vczjk/yc4;

    :cond_2
    return-object p0
.end method

.method public final OooOoOO()Llyiahf/vczjk/yc4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/yg3;->OooOOOo:Llyiahf/vczjk/yc4;

    return-object v0
.end method

.method public final OooOooo(Llyiahf/vczjk/t94;)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/yg3;->OooOOO:I

    invoke-virtual {p1}, Llyiahf/vczjk/t94;->OooO0OO()I

    move-result p1

    and-int/2addr p1, v0

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OoooO00(II)Llyiahf/vczjk/u94;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/yg3;->OooOOO:I

    not-int v1, p2

    and-int/2addr v1, v0

    and-int/2addr p1, p2

    or-int/2addr p1, v1

    xor-int p2, v0, p1

    if-eqz p2, :cond_0

    iput p1, p0, Llyiahf/vczjk/yg3;->OooOOO:I

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/yg3;->o000O0o(II)V

    :cond_0
    return-object p0
.end method

.method public final OoooOO0(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/yg3;->OooOOOo:Llyiahf/vczjk/yc4;

    if-eqz v0, :cond_0

    iput-object p1, v0, Llyiahf/vczjk/yc4;->OooO0oo:Ljava/lang/Object;

    :cond_0
    return-void
.end method

.method public o0000Oo(Ljava/lang/String;)V
    .locals 1

    const-string v0, "write raw value"

    invoke-virtual {p0, v0}, Llyiahf/vczjk/yg3;->o000Ooo(Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/u94;->o0000OOO(Ljava/lang/String;)V

    return-void
.end method

.method public o0000OoO(Llyiahf/vczjk/fg8;)V
    .locals 1

    const-string v0, "write raw value"

    invoke-virtual {p0, v0}, Llyiahf/vczjk/yg3;->o000Ooo(Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/u94;->o0000OOo(Llyiahf/vczjk/fg8;)V

    return-void
.end method

.method public o000O0o(II)V
    .locals 2

    sget v0, Llyiahf/vczjk/yg3;->OooOOo0:I

    and-int/2addr v0, p2

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    sget-object v0, Llyiahf/vczjk/t94;->OooOOoo:Llyiahf/vczjk/t94;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/t94;->OooO0O0(I)Z

    move-result v0

    iput-boolean v0, p0, Llyiahf/vczjk/yg3;->OooOOOO:Z

    sget-object v0, Llyiahf/vczjk/t94;->OooOOo:Llyiahf/vczjk/t94;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/t94;->OooO0O0(I)Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-virtual {v0, p1}, Llyiahf/vczjk/t94;->OooO0O0(I)Z

    move-result v0

    if-eqz v0, :cond_1

    const/16 v0, 0x7f

    invoke-virtual {p0, v0}, Llyiahf/vczjk/u94;->OoooOoo(I)V

    goto :goto_0

    :cond_1
    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/u94;->OoooOoo(I)V

    :cond_2
    :goto_0
    sget-object v0, Llyiahf/vczjk/t94;->OooOo0:Llyiahf/vczjk/t94;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/t94;->OooO0O0(I)Z

    move-result p2

    if-eqz p2, :cond_4

    invoke-virtual {v0, p1}, Llyiahf/vczjk/t94;->OooO0O0(I)Z

    move-result p1

    if-eqz p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/yg3;->OooOOOo:Llyiahf/vczjk/yc4;

    iget-object p2, p1, Llyiahf/vczjk/yc4;->OooO0o0:Llyiahf/vczjk/ld9;

    if-nez p2, :cond_4

    new-instance p2, Llyiahf/vczjk/ld9;

    invoke-direct {p2, p0}, Llyiahf/vczjk/ld9;-><init>(Ljava/io/Closeable;)V

    iput-object p2, p1, Llyiahf/vczjk/yc4;->OooO0o0:Llyiahf/vczjk/ld9;

    iput-object p1, p0, Llyiahf/vczjk/yg3;->OooOOOo:Llyiahf/vczjk/yc4;

    return-void

    :cond_3
    iget-object p1, p0, Llyiahf/vczjk/yg3;->OooOOOo:Llyiahf/vczjk/yc4;

    const/4 p2, 0x0

    iput-object p2, p1, Llyiahf/vczjk/yc4;->OooO0o0:Llyiahf/vczjk/ld9;

    iput-object p1, p0, Llyiahf/vczjk/yg3;->OooOOOo:Llyiahf/vczjk/yc4;

    :cond_4
    :goto_1
    return-void
.end method

.method public final o000OoO(Ljava/math/BigDecimal;)Ljava/lang/String;
    .locals 3

    sget-object v0, Llyiahf/vczjk/t94;->OooOo00:Llyiahf/vczjk/t94;

    iget v1, p0, Llyiahf/vczjk/yg3;->OooOOO:I

    invoke-virtual {v0, v1}, Llyiahf/vczjk/t94;->OooO0O0(I)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Ljava/math/BigDecimal;->scale()I

    move-result v0

    const/16 v1, -0x270f

    const/16 v2, 0x270f

    if-lt v0, v1, :cond_0

    if-gt v0, v2, :cond_0

    invoke-virtual {p1}, Ljava/math/BigDecimal;->toPlainString()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    filled-new-array {p1, v0, v1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v0, "Attempt to write plain `java.math.BigDecimal` (see JsonGenerator.Feature.WRITE_BIGDECIMAL_AS_PLAIN) with illegal scale (%d): needs to be between [-%d, %d]"

    invoke-static {v0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/u94;->OooO0Oo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1

    :cond_1
    invoke-virtual {p1}, Ljava/math/BigDecimal;->toString()Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public abstract o000Ooo(Ljava/lang/String;)V
.end method
