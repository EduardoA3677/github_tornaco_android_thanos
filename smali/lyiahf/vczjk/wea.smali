.class public final Llyiahf/vczjk/wea;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Comparable;


# static fields
.field public static final OooOOo:Llyiahf/vczjk/wea;


# instance fields
.field public final OooOOO:I

.field public final OooOOO0:I

.field public final OooOOOO:I

.field public final OooOOOo:Ljava/lang/String;

.field public final OooOOo0:Llyiahf/vczjk/sc9;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/wea;

    const/4 v1, 0x0

    const-string v2, ""

    invoke-direct {v0, v1, v1, v1, v2}, Llyiahf/vczjk/wea;-><init>(IIILjava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/wea;

    const/4 v3, 0x1

    invoke-direct {v0, v1, v3, v1, v2}, Llyiahf/vczjk/wea;-><init>(IIILjava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/wea;->OooOOo:Llyiahf/vczjk/wea;

    new-instance v0, Llyiahf/vczjk/wea;

    invoke-direct {v0, v3, v1, v1, v2}, Llyiahf/vczjk/wea;-><init>(IIILjava/lang/String;)V

    return-void
.end method

.method public constructor <init>(IIILjava/lang/String;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/wea;->OooOOO0:I

    iput p2, p0, Llyiahf/vczjk/wea;->OooOOO:I

    iput p3, p0, Llyiahf/vczjk/wea;->OooOOOO:I

    iput-object p4, p0, Llyiahf/vczjk/wea;->OooOOOo:Ljava/lang/String;

    new-instance p1, Llyiahf/vczjk/vea;

    invoke-direct {p1, p0}, Llyiahf/vczjk/vea;-><init>(Llyiahf/vczjk/wea;)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/wea;->OooOOo0:Llyiahf/vczjk/sc9;

    return-void
.end method


# virtual methods
.method public final compareTo(Ljava/lang/Object;)I
    .locals 2

    check-cast p1, Llyiahf/vczjk/wea;

    const-string v0, "other"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/wea;->OooOOo0:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    const-string v1, "getValue(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/math/BigInteger;

    iget-object p1, p1, Llyiahf/vczjk/wea;->OooOOo0:Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Ljava/math/BigInteger;

    invoke-virtual {v0, p1}, Ljava/math/BigInteger;->compareTo(Ljava/math/BigInteger;)I

    move-result p1

    return p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    instance-of v0, p1, Llyiahf/vczjk/wea;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    return v1

    :cond_0
    check-cast p1, Llyiahf/vczjk/wea;

    iget v0, p1, Llyiahf/vczjk/wea;->OooOOO0:I

    iget v2, p0, Llyiahf/vczjk/wea;->OooOOO0:I

    if-ne v2, v0, :cond_1

    iget v0, p0, Llyiahf/vczjk/wea;->OooOOO:I

    iget v2, p1, Llyiahf/vczjk/wea;->OooOOO:I

    if-ne v0, v2, :cond_1

    iget v0, p0, Llyiahf/vczjk/wea;->OooOOOO:I

    iget p1, p1, Llyiahf/vczjk/wea;->OooOOOO:I

    if-ne v0, p1, :cond_1

    const/4 p1, 0x1

    return p1

    :cond_1
    return v1
.end method

.method public final hashCode()I
    .locals 2

    const/16 v0, 0x20f

    iget v1, p0, Llyiahf/vczjk/wea;->OooOOO0:I

    add-int/2addr v0, v1

    mul-int/lit8 v0, v0, 0x1f

    iget v1, p0, Llyiahf/vczjk/wea;->OooOOO:I

    add-int/2addr v0, v1

    mul-int/lit8 v0, v0, 0x1f

    iget v1, p0, Llyiahf/vczjk/wea;->OooOOOO:I

    add-int/2addr v0, v1

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/wea;->OooOOOo:Ljava/lang/String;

    invoke-static {v0}, Llyiahf/vczjk/z69;->OoooOO0(Ljava/lang/CharSequence;)Z

    move-result v1

    if-nez v1, :cond_0

    const-string v1, "-"

    invoke-static {v1, v0}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    goto :goto_0

    :cond_0
    const-string v0, ""

    :goto_0
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    iget v2, p0, Llyiahf/vczjk/wea;->OooOOO0:I

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const/16 v2, 0x2e

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget v3, p0, Llyiahf/vczjk/wea;->OooOOO:I

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget v2, p0, Llyiahf/vczjk/wea;->OooOOOO:I

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/u81;->OooOOOO(Ljava/lang/StringBuilder;ILjava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
