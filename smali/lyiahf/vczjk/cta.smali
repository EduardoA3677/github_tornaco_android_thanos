.class public final Llyiahf/vczjk/cta;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/kma;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ima;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ima;)V
    .locals 1

    const-string v0, "whitePoint"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cta;->OooO00o:Llyiahf/vczjk/ima;

    const-string p1, "XYZ"

    invoke-static {p1}, Llyiahf/vczjk/b31;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/y05;

    return-void
.end method


# virtual methods
.method public final OooO0Oo()Llyiahf/vczjk/ima;
    .locals 0

    const/4 p0, 0x0

    throw p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/cta;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/cta;

    iget-object p1, p1, Llyiahf/vczjk/cta;->OooO00o:Llyiahf/vczjk/ima;

    iget-object v0, p0, Llyiahf/vczjk/cta;->OooO00o:Llyiahf/vczjk/ima;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

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

    iget-object v0, p0, Llyiahf/vczjk/cta;->OooO00o:Llyiahf/vczjk/ima;

    invoke-virtual {v0}, Llyiahf/vczjk/ima;->hashCode()I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "XYZColorSpace("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/cta;->OooO00o:Llyiahf/vczjk/ima;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
