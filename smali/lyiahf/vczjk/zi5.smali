.class public final Llyiahf/vczjk/zi5;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/b4a;

.field public final OooO0O0:Llyiahf/vczjk/b4a;

.field public final OooO0OO:Ljava/lang/String;

.field public final OooO0Oo:Llyiahf/vczjk/o4a;

.field public final OooO0o0:Llyiahf/vczjk/wt1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/b4a;Llyiahf/vczjk/b4a;Ljava/lang/String;Llyiahf/vczjk/o4a;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-eqz p1, :cond_0

    if-eqz p2, :cond_0

    if-eqz p3, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/zi5;->OooO00o:Llyiahf/vczjk/b4a;

    iput-object p2, p0, Llyiahf/vczjk/zi5;->OooO0O0:Llyiahf/vczjk/b4a;

    iput-object p3, p0, Llyiahf/vczjk/zi5;->OooO0OO:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/zi5;->OooO0Oo:Llyiahf/vczjk/o4a;

    new-instance p2, Llyiahf/vczjk/xt1;

    new-instance p4, Llyiahf/vczjk/zt1;

    invoke-direct {p4, p3}, Llyiahf/vczjk/zt1;-><init>(Ljava/lang/String;)V

    new-instance p3, Llyiahf/vczjk/zt1;

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/zi5;->OooO00o(Z)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p3, v0}, Llyiahf/vczjk/zt1;-><init>(Ljava/lang/String;)V

    invoke-direct {p2, p4, p3}, Llyiahf/vczjk/xt1;-><init>(Llyiahf/vczjk/zt1;Llyiahf/vczjk/zt1;)V

    new-instance p3, Llyiahf/vczjk/wt1;

    iget-object p1, p1, Llyiahf/vczjk/b4a;->OooO0OO:Llyiahf/vczjk/au1;

    invoke-direct {p3, p1, p2}, Llyiahf/vczjk/wt1;-><init>(Llyiahf/vczjk/au1;Llyiahf/vczjk/xt1;)V

    iput-object p3, p0, Llyiahf/vczjk/zi5;->OooO0o0:Llyiahf/vczjk/wt1;

    return-void

    :cond_0
    const/4 p1, 0x0

    throw p1
.end method


# virtual methods
.method public final OooO00o(Z)Ljava/lang/String;
    .locals 4

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/zi5;->OooO00o:Llyiahf/vczjk/b4a;

    iget-object p1, p1, Llyiahf/vczjk/b4a;->OooO00o:Ljava/lang/String;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/zi5;->OooO0Oo:Llyiahf/vczjk/o4a;

    iget-object p1, p1, Llyiahf/vczjk/o4a;->OooO00o:[Llyiahf/vczjk/b4a;

    array-length v1, p1

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_1

    aget-object v3, p1, v2

    iget-object v3, v3, Llyiahf/vczjk/b4a;->OooO00o:Ljava/lang/String;

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    const-string p1, ")"

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object p1, p0, Llyiahf/vczjk/zi5;->OooO0O0:Llyiahf/vczjk/b4a;

    iget-object p1, p1, Llyiahf/vczjk/b4a;->OooO00o:Ljava/lang/String;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    instance-of v0, p1, Llyiahf/vczjk/zi5;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/zi5;

    iget-object v0, p1, Llyiahf/vczjk/zi5;->OooO00o:Llyiahf/vczjk/b4a;

    iget-object v1, p0, Llyiahf/vczjk/zi5;->OooO00o:Llyiahf/vczjk/b4a;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/b4a;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p1, Llyiahf/vczjk/zi5;->OooO0OO:Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/zi5;->OooO0OO:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p1, Llyiahf/vczjk/zi5;->OooO0Oo:Llyiahf/vczjk/o4a;

    iget-object v1, p0, Llyiahf/vczjk/zi5;->OooO0Oo:Llyiahf/vczjk/o4a;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/o4a;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/zi5;->OooO0O0:Llyiahf/vczjk/b4a;

    iget-object v0, p0, Llyiahf/vczjk/zi5;->OooO0O0:Llyiahf/vczjk/b4a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/b4a;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/zi5;->OooO00o:Llyiahf/vczjk/b4a;

    iget-object v0, v0, Llyiahf/vczjk/b4a;->OooO00o:Ljava/lang/String;

    const/16 v1, 0x20f

    const/16 v2, 0x1f

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/q99;->OooO00o(IILjava/lang/String;)I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/zi5;->OooO0OO:Ljava/lang/String;

    invoke-static {v0, v2, v1}, Llyiahf/vczjk/q99;->OooO00o(IILjava/lang/String;)I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/zi5;->OooO0Oo:Llyiahf/vczjk/o4a;

    iget-object v1, v1, Llyiahf/vczjk/o4a;->OooO00o:[Llyiahf/vczjk/b4a;

    invoke-static {v1}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    move-result v1

    add-int/2addr v1, v0

    mul-int/2addr v1, v2

    iget-object v0, p0, Llyiahf/vczjk/zi5;->OooO0O0:Llyiahf/vczjk/b4a;

    iget-object v0, v0, Llyiahf/vczjk/b4a;->OooO00o:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    move-result v0

    add-int/2addr v0, v1

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/zi5;->OooO00o:Llyiahf/vczjk/b4a;

    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/zi5;->OooO0Oo:Llyiahf/vczjk/o4a;

    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, "."

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v0, p0, Llyiahf/vczjk/zi5;->OooO0OO:Ljava/lang/String;

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, "("

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, ")"

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
