.class public final Llyiahf/vczjk/cy3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wl;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/xj2;

.field public final OooO0O0:Llyiahf/vczjk/gq7;

.field public final OooO0OO:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xj2;Llyiahf/vczjk/gq7;J)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cy3;->OooO00o:Llyiahf/vczjk/xj2;

    iput-object p2, p0, Llyiahf/vczjk/cy3;->OooO0O0:Llyiahf/vczjk/gq7;

    iput-wide p3, p0, Llyiahf/vczjk/cy3;->OooO0OO:J

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/yda;
    .locals 4

    new-instance v0, Llyiahf/vczjk/cea;

    iget-object v1, p0, Llyiahf/vczjk/cy3;->OooO00o:Llyiahf/vczjk/xj2;

    invoke-interface {v1, p1}, Llyiahf/vczjk/xj2;->OooO00o(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/aea;

    move-result-object p1

    iget-wide v1, p0, Llyiahf/vczjk/cy3;->OooO0OO:J

    iget-object v3, p0, Llyiahf/vczjk/cy3;->OooO0O0:Llyiahf/vczjk/gq7;

    invoke-direct {v0, p1, v3, v1, v2}, Llyiahf/vczjk/cea;-><init>(Llyiahf/vczjk/aea;Llyiahf/vczjk/gq7;J)V

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 6

    instance-of v0, p1, Llyiahf/vczjk/cy3;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/cy3;

    iget-object v0, p1, Llyiahf/vczjk/cy3;->OooO00o:Llyiahf/vczjk/xj2;

    iget-object v2, p0, Llyiahf/vczjk/cy3;->OooO00o:Llyiahf/vczjk/xj2;

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p1, Llyiahf/vczjk/cy3;->OooO0O0:Llyiahf/vczjk/gq7;

    iget-object v2, p0, Llyiahf/vczjk/cy3;->OooO0O0:Llyiahf/vczjk/gq7;

    if-ne v0, v2, :cond_0

    iget-wide v2, p1, Llyiahf/vczjk/cy3;->OooO0OO:J

    iget-wide v4, p0, Llyiahf/vczjk/cy3;->OooO0OO:J

    cmp-long p1, v2, v4

    if-nez p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    return v1
.end method

.method public final hashCode()I
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/cy3;->OooO00o:Llyiahf/vczjk/xj2;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    iget-object v1, p0, Llyiahf/vczjk/cy3;->OooO0O0:Llyiahf/vczjk/gq7;

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    mul-int/lit8 v1, v1, 0x1f

    iget-wide v2, p0, Llyiahf/vczjk/cy3;->OooO0OO:J

    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    move-result v0

    add-int/2addr v0, v1

    return v0
.end method
