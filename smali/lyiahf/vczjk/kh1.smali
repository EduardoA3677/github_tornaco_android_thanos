.class public final Llyiahf/vczjk/kh1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ica;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/rm4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    check-cast p1, Llyiahf/vczjk/rm4;

    iput-object p1, p0, Llyiahf/vczjk/kh1;->OooO00o:Llyiahf/vczjk/rm4;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ps6;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kh1;->OooO00o:Llyiahf/vczjk/rm4;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    if-ne p0, p1, :cond_0

    goto :goto_1

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/kh1;

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    check-cast p1, Llyiahf/vczjk/kh1;

    iget-object v0, p0, Llyiahf/vczjk/kh1;->OooO00o:Llyiahf/vczjk/rm4;

    iget-object p1, p1, Llyiahf/vczjk/kh1;->OooO00o:Llyiahf/vczjk/rm4;

    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_2

    :goto_0
    const/4 p1, 0x0

    return p1

    :cond_2
    :goto_1
    const/4 p1, 0x1

    return p1
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kh1;->OooO00o:Llyiahf/vczjk/rm4;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "ComputedValueHolder(compute="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/kh1;->OooO00o:Llyiahf/vczjk/rm4;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
