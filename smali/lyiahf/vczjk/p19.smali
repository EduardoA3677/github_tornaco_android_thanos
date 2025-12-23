.class public final Llyiahf/vczjk/p19;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wl;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/p13;

.field public final OooO0O0:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/p13;J)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/p19;->OooO00o:Llyiahf/vczjk/p13;

    iput-wide p2, p0, Llyiahf/vczjk/p19;->OooO0O0:J

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/yda;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/p19;->OooO00o:Llyiahf/vczjk/p13;

    invoke-interface {v0, p1}, Llyiahf/vczjk/wl;->OooO00o(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/yda;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/q19;

    iget-wide v1, p0, Llyiahf/vczjk/p19;->OooO0O0:J

    invoke-direct {v0, p1, v1, v2}, Llyiahf/vczjk/q19;-><init>(Llyiahf/vczjk/yda;J)V

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    instance-of v0, p1, Llyiahf/vczjk/p19;

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    check-cast p1, Llyiahf/vczjk/p19;

    iget-wide v0, p1, Llyiahf/vczjk/p19;->OooO0O0:J

    iget-wide v2, p0, Llyiahf/vczjk/p19;->OooO0O0:J

    cmp-long v0, v0, v2

    if-nez v0, :cond_1

    iget-object p1, p1, Llyiahf/vczjk/p19;->OooO00o:Llyiahf/vczjk/p13;

    iget-object v0, p0, Llyiahf/vczjk/p19;->OooO00o:Llyiahf/vczjk/p13;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    const/4 p1, 0x1

    return p1

    :cond_1
    :goto_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/p19;->OooO00o:Llyiahf/vczjk/p13;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    iget-wide v1, p0, Llyiahf/vczjk/p19;->OooO0O0:J

    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method
