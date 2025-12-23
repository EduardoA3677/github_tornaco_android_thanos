.class public final Llyiahf/vczjk/ac4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/ac4;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field private final _contentNulls:Llyiahf/vczjk/d56;

.field private final _nulls:Llyiahf/vczjk/d56;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/ac4;

    sget-object v1, Llyiahf/vczjk/d56;->OooOOOo:Llyiahf/vczjk/d56;

    invoke-direct {v0, v1, v1}, Llyiahf/vczjk/ac4;-><init>(Llyiahf/vczjk/d56;Llyiahf/vczjk/d56;)V

    sput-object v0, Llyiahf/vczjk/ac4;->OooOOO0:Llyiahf/vczjk/ac4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/d56;Llyiahf/vczjk/d56;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ac4;->_nulls:Llyiahf/vczjk/d56;

    iput-object p2, p0, Llyiahf/vczjk/ac4;->_contentNulls:Llyiahf/vczjk/d56;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/d56;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ac4;->_contentNulls:Llyiahf/vczjk/d56;

    sget-object v1, Llyiahf/vczjk/d56;->OooOOOo:Llyiahf/vczjk/d56;

    if-ne v0, v1, :cond_0

    const/4 v0, 0x0

    :cond_0
    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/d56;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ac4;->_nulls:Llyiahf/vczjk/d56;

    sget-object v1, Llyiahf/vczjk/d56;->OooOOOo:Llyiahf/vczjk/d56;

    if-ne v0, v1, :cond_0

    const/4 v0, 0x0

    :cond_0
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    const/4 v0, 0x1

    if-ne p1, p0, :cond_0

    return v0

    :cond_0
    const/4 v1, 0x0

    if-nez p1, :cond_1

    return v1

    :cond_1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    const-class v3, Llyiahf/vczjk/ac4;

    if-ne v2, v3, :cond_2

    check-cast p1, Llyiahf/vczjk/ac4;

    iget-object v2, p1, Llyiahf/vczjk/ac4;->_nulls:Llyiahf/vczjk/d56;

    iget-object v3, p0, Llyiahf/vczjk/ac4;->_nulls:Llyiahf/vczjk/d56;

    if-ne v2, v3, :cond_2

    iget-object p1, p1, Llyiahf/vczjk/ac4;->_contentNulls:Llyiahf/vczjk/d56;

    iget-object v2, p0, Llyiahf/vczjk/ac4;->_contentNulls:Llyiahf/vczjk/d56;

    if-ne p1, v2, :cond_2

    return v0

    :cond_2
    return v1
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ac4;->_nulls:Llyiahf/vczjk/d56;

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/ac4;->_contentNulls:Llyiahf/vczjk/d56;

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    shl-int/lit8 v1, v1, 0x2

    add-int/2addr v0, v1

    return v0
.end method

.method public readResolve()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ac4;->_nulls:Llyiahf/vczjk/d56;

    iget-object v1, p0, Llyiahf/vczjk/ac4;->_contentNulls:Llyiahf/vczjk/d56;

    sget-object v2, Llyiahf/vczjk/d56;->OooOOOo:Llyiahf/vczjk/d56;

    if-ne v0, v2, :cond_0

    if-ne v1, v2, :cond_0

    sget-object v0, Llyiahf/vczjk/ac4;->OooOOO0:Llyiahf/vczjk/ac4;

    return-object v0

    :cond_0
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/ac4;->_nulls:Llyiahf/vczjk/d56;

    iget-object v1, p0, Llyiahf/vczjk/ac4;->_contentNulls:Llyiahf/vczjk/d56;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "JsonSetter.Value(valueNulls="

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, ",contentNulls="

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, ")"

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
