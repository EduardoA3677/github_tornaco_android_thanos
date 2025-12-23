.class public final Llyiahf/vczjk/o4a;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:[Llyiahf/vczjk/b4a;

.field public final OooO0O0:Llyiahf/vczjk/d59;


# direct methods
.method public constructor <init>([Llyiahf/vczjk/b4a;)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-virtual {p1}, [Llyiahf/vczjk/b4a;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/b4a;

    iput-object v0, p0, Llyiahf/vczjk/o4a;->OooO00o:[Llyiahf/vczjk/b4a;

    new-instance v0, Llyiahf/vczjk/d59;

    array-length v1, p1

    invoke-direct {v0, v1}, Llyiahf/vczjk/x13;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/o4a;->OooO0O0:Llyiahf/vczjk/d59;

    const/4 v0, 0x0

    :goto_0
    array-length v1, p1

    if-ge v0, v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/o4a;->OooO0O0:Llyiahf/vczjk/d59;

    aget-object v2, p1, v0

    iget-object v2, v2, Llyiahf/vczjk/b4a;->OooO0O0:Llyiahf/vczjk/p1a;

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/x13;->OooO0o(ILjava/lang/Object;)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/o4a;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/o4a;

    iget-object p1, p1, Llyiahf/vczjk/o4a;->OooO00o:[Llyiahf/vczjk/b4a;

    iget-object v0, p0, Llyiahf/vczjk/o4a;->OooO00o:[Llyiahf/vczjk/b4a;

    invoke-static {p1, v0}, Ljava/util/Arrays;->equals([Ljava/lang/Object;[Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o4a;->OooO00o:[Llyiahf/vczjk/b4a;

    invoke-static {v0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const/4 v1, 0x0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/o4a;->OooO00o:[Llyiahf/vczjk/b4a;

    array-length v3, v2

    if-ge v1, v3, :cond_1

    if-lez v1, :cond_0

    const-string v3, ", "

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_0
    aget-object v2, v2, v1

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
