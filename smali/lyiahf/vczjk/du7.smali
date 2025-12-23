.class public final Llyiahf/vczjk/du7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/px3;


# instance fields
.field public final OooO00o:Z

.field public final OooO0O0:F

.field public final OooO0OO:J


# direct methods
.method public constructor <init>(ZFJ)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/du7;->OooO00o:Z

    iput p2, p0, Llyiahf/vczjk/du7;->OooO0O0:F

    iput-wide p3, p0, Llyiahf/vczjk/du7;->OooO0OO:J

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/n24;)Llyiahf/vczjk/l52;
    .locals 4

    new-instance v0, Llyiahf/vczjk/s52;

    const/4 v1, 0x2

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/s52;-><init>(Ljava/lang/Object;I)V

    new-instance v1, Llyiahf/vczjk/v52;

    iget v2, p0, Llyiahf/vczjk/du7;->OooO0O0:F

    iget-boolean v3, p0, Llyiahf/vczjk/du7;->OooO00o:Z

    invoke-direct {v1, p1, v3, v2, v0}, Llyiahf/vczjk/v52;-><init>(Llyiahf/vczjk/n24;ZFLlyiahf/vczjk/w21;)V

    return-object v1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    if-ne p0, p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/du7;

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    check-cast p1, Llyiahf/vczjk/du7;

    iget-boolean v0, p1, Llyiahf/vczjk/du7;->OooO00o:Z

    iget-boolean v1, p0, Llyiahf/vczjk/du7;->OooO00o:Z

    if-eq v1, v0, :cond_2

    goto :goto_0

    :cond_2
    iget v0, p0, Llyiahf/vczjk/du7;->OooO0O0:F

    iget v1, p1, Llyiahf/vczjk/du7;->OooO0O0:F

    invoke-static {v0, v1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v0

    if-nez v0, :cond_3

    :goto_0
    const/4 p1, 0x0

    return p1

    :cond_3
    iget-wide v0, p0, Llyiahf/vczjk/du7;->OooO0OO:J

    iget-wide v2, p1, Llyiahf/vczjk/du7;->OooO0OO:J

    invoke-static {v0, v1, v2, v3}, Llyiahf/vczjk/n21;->OooO0OO(JJ)Z

    move-result p1

    return p1
.end method

.method public final hashCode()I
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/du7;->OooO00o:Z

    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    iget v1, p0, Llyiahf/vczjk/du7;->OooO0O0:F

    const/16 v2, 0x3c1

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/u81;->OooO0OO(IFI)I

    move-result v0

    sget v1, Llyiahf/vczjk/n21;->OooOO0O:I

    iget-wide v1, p0, Llyiahf/vczjk/du7;->OooO0OO:J

    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method
