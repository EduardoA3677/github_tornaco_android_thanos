.class public final Llyiahf/vczjk/ts1;
.super Llyiahf/vczjk/mc4;
.source "SourceFile"


# instance fields
.field public final OooOo:Llyiahf/vczjk/sb0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/sb0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ts1;->OooOo:Llyiahf/vczjk/sb0;

    return-void
.end method


# virtual methods
.method public final OooOOOO(ILlyiahf/vczjk/yn4;Llyiahf/vczjk/ow6;I)I
    .locals 0

    iget-object p3, p0, Llyiahf/vczjk/ts1;->OooOo:Llyiahf/vczjk/sb0;

    const/4 p4, 0x0

    invoke-virtual {p3, p4, p1, p2}, Llyiahf/vczjk/sb0;->OooO00o(IILlyiahf/vczjk/yn4;)I

    move-result p1

    return p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    if-ne p0, p1, :cond_0

    goto :goto_1

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/ts1;

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    check-cast p1, Llyiahf/vczjk/ts1;

    iget-object v0, p0, Llyiahf/vczjk/ts1;->OooOo:Llyiahf/vczjk/sb0;

    iget-object p1, p1, Llyiahf/vczjk/ts1;->OooOo:Llyiahf/vczjk/sb0;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

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

    iget-object v0, p0, Llyiahf/vczjk/ts1;->OooOo:Llyiahf/vczjk/sb0;

    iget v0, v0, Llyiahf/vczjk/sb0;->OooO00o:F

    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "HorizontalCrossAxisAlignment(horizontal="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/ts1;->OooOo:Llyiahf/vczjk/sb0;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
