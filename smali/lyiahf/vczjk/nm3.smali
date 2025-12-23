.class public final Llyiahf/vczjk/nm3;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ug0;

.field public final OooO0O0:Llyiahf/vczjk/mm3;

.field public final OooO0OO:Llyiahf/vczjk/tqa;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ug0;Llyiahf/vczjk/mm3;Llyiahf/vczjk/tqa;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/nm3;->OooO00o:Llyiahf/vczjk/ug0;

    iput-object p2, p0, Llyiahf/vczjk/nm3;->OooO0O0:Llyiahf/vczjk/mm3;

    iput-object p3, p0, Llyiahf/vczjk/nm3;->OooO0OO:Llyiahf/vczjk/tqa;

    invoke-virtual {p1}, Llyiahf/vczjk/ug0;->OooO0O0()I

    move-result p2

    if-nez p2, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/ug0;->OooO00o()I

    move-result p2

    if-eqz p2, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "Bounds must be non zero"

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :goto_0
    iget p2, p1, Llyiahf/vczjk/ug0;->OooO00o:I

    if-eqz p2, :cond_3

    iget p1, p1, Llyiahf/vczjk/ug0;->OooO0O0:I

    if-nez p1, :cond_2

    goto :goto_1

    :cond_2
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "Bounding rectangle must start at the top or left window edge for folding features"

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_3
    :goto_1
    return-void
.end method


# virtual methods
.method public final OooO00o()Z
    .locals 3

    sget-object v0, Llyiahf/vczjk/mm3;->OooO0Oo:Llyiahf/vczjk/mm3;

    iget-object v1, p0, Llyiahf/vczjk/nm3;->OooO0O0:Llyiahf/vczjk/mm3;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    const/4 v2, 0x1

    if-eqz v0, :cond_0

    return v2

    :cond_0
    sget-object v0, Llyiahf/vczjk/mm3;->OooO0OO:Llyiahf/vczjk/mm3;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    sget-object v0, Llyiahf/vczjk/tqa;->OooOOOo:Llyiahf/vczjk/tqa;

    iget-object v1, p0, Llyiahf/vczjk/nm3;->OooO0OO:Llyiahf/vczjk/tqa;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    return v2

    :cond_1
    const/4 v0, 0x0

    return v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    if-eqz p1, :cond_1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    goto :goto_0

    :cond_1
    const/4 v1, 0x0

    :goto_0
    const-class v2, Llyiahf/vczjk/nm3;

    invoke-virtual {v2, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    const/4 v2, 0x0

    if-nez v1, :cond_2

    return v2

    :cond_2
    const-string v1, "null cannot be cast to non-null type androidx.window.layout.HardwareFoldingFeature"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/nm3;

    iget-object v1, p0, Llyiahf/vczjk/nm3;->OooO00o:Llyiahf/vczjk/ug0;

    iget-object v3, p1, Llyiahf/vczjk/nm3;->OooO00o:Llyiahf/vczjk/ug0;

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3

    return v2

    :cond_3
    iget-object v1, p0, Llyiahf/vczjk/nm3;->OooO0O0:Llyiahf/vczjk/mm3;

    iget-object v3, p1, Llyiahf/vczjk/nm3;->OooO0O0:Llyiahf/vczjk/mm3;

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4

    return v2

    :cond_4
    iget-object v1, p0, Llyiahf/vczjk/nm3;->OooO0OO:Llyiahf/vczjk/tqa;

    iget-object p1, p1, Llyiahf/vczjk/nm3;->OooO0OO:Llyiahf/vczjk/tqa;

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_5

    return v2

    :cond_5
    return v0
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/nm3;->OooO00o:Llyiahf/vczjk/ug0;

    invoke-virtual {v0}, Llyiahf/vczjk/ug0;->hashCode()I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    iget-object v1, p0, Llyiahf/vczjk/nm3;->OooO0O0:Llyiahf/vczjk/mm3;

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    mul-int/lit8 v1, v1, 0x1f

    iget-object v0, p0, Llyiahf/vczjk/nm3;->OooO0OO:Llyiahf/vczjk/tqa;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    add-int/2addr v0, v1

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-class v1, Llyiahf/vczjk/nm3;

    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " { "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/nm3;->OooO00o:Llyiahf/vczjk/ug0;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", type="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/nm3;->OooO0O0:Llyiahf/vczjk/mm3;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", state="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/nm3;->OooO0OO:Llyiahf/vczjk/tqa;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " }"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
