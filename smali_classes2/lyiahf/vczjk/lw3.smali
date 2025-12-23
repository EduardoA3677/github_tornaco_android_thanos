.class public final Llyiahf/vczjk/lw3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/vi7;


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/by0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/by0;)V
    .locals 1

    const-string v0, "classDescriptor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/lw3;->OooOOO0:Llyiahf/vczjk/by0;

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    instance-of v0, p1, Llyiahf/vczjk/lw3;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/lw3;

    goto :goto_0

    :cond_0
    move-object p1, v1

    :goto_0
    if-eqz p1, :cond_1

    iget-object v1, p1, Llyiahf/vczjk/lw3;->OooOOO0:Llyiahf/vczjk/by0;

    :cond_1
    iget-object p1, p0, Llyiahf/vczjk/lw3;->OooOOO0:Llyiahf/vczjk/by0;

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final getType()Llyiahf/vczjk/uk4;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/lw3;->OooOOO0:Llyiahf/vczjk/by0;

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    const-string v1, "getDefaultType(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/lw3;->OooOOO0:Llyiahf/vczjk/by0;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Class{"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/lw3;->OooOOO0:Llyiahf/vczjk/by0;

    invoke-interface {v1}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v1

    const-string v2, "getDefaultType(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x7d

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
