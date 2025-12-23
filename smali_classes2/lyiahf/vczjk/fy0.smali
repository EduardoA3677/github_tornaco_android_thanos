.class public final Llyiahf/vczjk/fy0;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/hy0;

.field public final OooO0O0:Llyiahf/vczjk/vx0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hy0;Llyiahf/vczjk/vx0;)V
    .locals 1

    const-string v0, "classId"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fy0;->OooO00o:Llyiahf/vczjk/hy0;

    iput-object p2, p0, Llyiahf/vczjk/fy0;->OooO0O0:Llyiahf/vczjk/vx0;

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/fy0;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/fy0;

    iget-object p1, p1, Llyiahf/vczjk/fy0;->OooO00o:Llyiahf/vczjk/hy0;

    iget-object v0, p0, Llyiahf/vczjk/fy0;->OooO00o:Llyiahf/vczjk/hy0;

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

    iget-object v0, p0, Llyiahf/vczjk/fy0;->OooO00o:Llyiahf/vczjk/hy0;

    invoke-virtual {v0}, Llyiahf/vczjk/hy0;->hashCode()I

    move-result v0

    return v0
.end method
