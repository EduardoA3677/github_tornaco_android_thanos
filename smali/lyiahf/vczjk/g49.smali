.class public final Llyiahf/vczjk/g49;
.super Llyiahf/vczjk/h49;
.source "SourceFile"


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/a4a;->OooOOO:Llyiahf/vczjk/a4a;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Ljava/lang/Short;->TYPE:Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/a4a;->OooOOOO(Ljava/lang/Class;)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z
    .locals 0

    check-cast p2, [S

    array-length p1, p2

    if-nez p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 3

    check-cast p1, [S

    array-length v0, p1

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-ne v0, v2, :cond_1

    invoke-virtual {p0, p3}, Llyiahf/vczjk/my;->OooOOOO(Llyiahf/vczjk/tg8;)Z

    move-result p3

    if-eqz p3, :cond_1

    array-length p3, p1

    :goto_0
    if-ge v1, p3, :cond_0

    aget-short v0, p1, v1

    invoke-virtual {p2, v0}, Llyiahf/vczjk/u94;->o0000oo(I)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    return-void

    :cond_1
    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/u94;->o0000o0O(ILjava/lang/Object;)V

    array-length p3, p1

    :goto_1
    if-ge v1, p3, :cond_2

    aget-short v0, p1, v1

    invoke-virtual {p2, v0}, Llyiahf/vczjk/u94;->o0000oo(I)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_1

    :cond_2
    invoke-virtual {p2}, Llyiahf/vczjk/u94;->o00000O()V

    return-void
.end method

.method public final OooOOOo(Llyiahf/vczjk/db0;Ljava/lang/Boolean;)Llyiahf/vczjk/zb4;
    .locals 1

    new-instance v0, Llyiahf/vczjk/g49;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/my;-><init>(Llyiahf/vczjk/my;Llyiahf/vczjk/db0;Ljava/lang/Boolean;)V

    return-object v0
.end method

.method public final OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 2

    check-cast p1, [S

    array-length p3, p1

    const/4 v0, 0x0

    :goto_0
    if-ge v0, p3, :cond_0

    aget-short v1, p1, v0

    invoke-virtual {p2, v1}, Llyiahf/vczjk/u94;->o0000oo(I)V

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method
