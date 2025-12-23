.class public final Llyiahf/vczjk/gx2;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/b4a;

.field public final OooO0O0:Ljava/lang/String;

.field public final OooO0OO:Llyiahf/vczjk/lt1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/b4a;Llyiahf/vczjk/b4a;Ljava/lang/String;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-eqz p2, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/gx2;->OooO00o:Llyiahf/vczjk/b4a;

    iput-object p3, p0, Llyiahf/vczjk/gx2;->OooO0O0:Ljava/lang/String;

    new-instance v0, Llyiahf/vczjk/xt1;

    new-instance v1, Llyiahf/vczjk/zt1;

    invoke-direct {v1, p3}, Llyiahf/vczjk/zt1;-><init>(Ljava/lang/String;)V

    new-instance p3, Llyiahf/vczjk/zt1;

    iget-object p2, p2, Llyiahf/vczjk/b4a;->OooO00o:Ljava/lang/String;

    invoke-direct {p3, p2}, Llyiahf/vczjk/zt1;-><init>(Ljava/lang/String;)V

    invoke-direct {v0, v1, p3}, Llyiahf/vczjk/xt1;-><init>(Llyiahf/vczjk/zt1;Llyiahf/vczjk/zt1;)V

    new-instance p2, Llyiahf/vczjk/lt1;

    iget-object p1, p1, Llyiahf/vczjk/b4a;->OooO0OO:Llyiahf/vczjk/au1;

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/vt1;-><init>(Llyiahf/vczjk/au1;Llyiahf/vczjk/xt1;)V

    iput-object p2, p0, Llyiahf/vczjk/gx2;->OooO0OO:Llyiahf/vczjk/lt1;

    return-void

    :cond_0
    const/4 p1, 0x0

    throw p1
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    instance-of v0, p1, Llyiahf/vczjk/gx2;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/gx2;

    iget-object v0, p1, Llyiahf/vczjk/gx2;->OooO00o:Llyiahf/vczjk/b4a;

    iget-object v1, p0, Llyiahf/vczjk/gx2;->OooO00o:Llyiahf/vczjk/b4a;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/b4a;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/gx2;->OooO0O0:Ljava/lang/String;

    iget-object v0, p0, Llyiahf/vczjk/gx2;->OooO0O0:Ljava/lang/String;

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/gx2;->OooO00o:Llyiahf/vczjk/b4a;

    iget-object v0, v0, Llyiahf/vczjk/b4a;->OooO00o:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/gx2;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    move-result v1

    mul-int/lit8 v1, v1, 0x25

    add-int/2addr v1, v0

    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/gx2;->OooO00o:Llyiahf/vczjk/b4a;

    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "."

    invoke-static {v0, v1}, Llyiahf/vczjk/ii5;->OooOOOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/gx2;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
