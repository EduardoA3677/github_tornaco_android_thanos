.class public final Llyiahf/vczjk/by8;
.super Llyiahf/vczjk/bx2;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/nv3;

.field public final OooO0O0:Ljava/lang/String;

.field public final OooO0OO:Llyiahf/vczjk/zx1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nv3;Ljava/lang/String;Llyiahf/vczjk/zx1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/by8;->OooO00o:Llyiahf/vczjk/nv3;

    iput-object p2, p0, Llyiahf/vczjk/by8;->OooO0O0:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/by8;->OooO0OO:Llyiahf/vczjk/zx1;

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    instance-of v1, p1, Llyiahf/vczjk/by8;

    if-eqz v1, :cond_1

    check-cast p1, Llyiahf/vczjk/by8;

    iget-object v1, p1, Llyiahf/vczjk/by8;->OooO00o:Llyiahf/vczjk/nv3;

    iget-object v2, p0, Llyiahf/vczjk/by8;->OooO00o:Llyiahf/vczjk/nv3;

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/by8;->OooO0O0:Ljava/lang/String;

    iget-object v2, p1, Llyiahf/vczjk/by8;->OooO0O0:Ljava/lang/String;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/by8;->OooO0OO:Llyiahf/vczjk/zx1;

    iget-object p1, p1, Llyiahf/vczjk/by8;->OooO0OO:Llyiahf/vczjk/zx1;

    if-ne v1, p1, :cond_1

    return v0

    :cond_1
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/by8;->OooO00o:Llyiahf/vczjk/nv3;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    iget-object v1, p0, Llyiahf/vczjk/by8;->OooO0O0:Ljava/lang/String;

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    add-int/2addr v0, v1

    mul-int/lit8 v0, v0, 0x1f

    iget-object v1, p0, Llyiahf/vczjk/by8;->OooO0OO:Llyiahf/vczjk/zx1;

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method
