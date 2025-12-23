.class public final Llyiahf/vczjk/ft4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:[Llyiahf/vczjk/bt4;

.field public OooO0O0:Llyiahf/vczjk/rk1;

.field public OooO0OO:I

.field public OooO0Oo:I

.field public OooO0o:I

.field public OooO0o0:I

.field public OooO0oO:I

.field public final synthetic OooO0oo:Landroidx/compose/foundation/lazy/layout/OooO0OO;


# direct methods
.method public constructor <init>(Landroidx/compose/foundation/lazy/layout/OooO0OO;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ft4;->OooO0oo:Landroidx/compose/foundation/lazy/layout/OooO0OO;

    sget-object p1, Llyiahf/vczjk/l4a;->OooO0o:[Llyiahf/vczjk/bt4;

    iput-object p1, p0, Llyiahf/vczjk/ft4;->OooO00o:[Llyiahf/vczjk/bt4;

    const/4 p1, 0x1

    iput p1, p0, Llyiahf/vczjk/ft4;->OooO0o0:I

    return-void
.end method

.method public static OooO0O0(Llyiahf/vczjk/ft4;Llyiahf/vczjk/ut4;Llyiahf/vczjk/xr1;Llyiahf/vczjk/ij3;II)V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/ft4;->OooO0oo:Landroidx/compose/foundation/lazy/layout/OooO0OO;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v0, 0x0

    invoke-interface {p1, v0}, Llyiahf/vczjk/ut4;->OooO(I)J

    move-result-wide v0

    invoke-interface {p1}, Llyiahf/vczjk/ut4;->OooO0oO()Z

    move-result v2

    if-nez v2, :cond_0

    const-wide v2, 0xffffffffL

    and-long/2addr v0, v2

    :goto_0
    long-to-int v0, v0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move v5, p4

    move v6, p5

    move v7, v0

    goto :goto_1

    :cond_0
    const/16 v2, 0x20

    shr-long/2addr v0, v2

    goto :goto_0

    :goto_1
    invoke-virtual/range {v1 .. v7}, Llyiahf/vczjk/ft4;->OooO00o(Llyiahf/vczjk/ut4;Llyiahf/vczjk/xr1;Llyiahf/vczjk/ij3;III)V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ut4;Llyiahf/vczjk/xr1;Llyiahf/vczjk/ij3;III)V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/ft4;->OooO00o:[Llyiahf/vczjk/bt4;

    array-length v1, v0

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    if-ge v3, v1, :cond_1

    aget-object v4, v0, v3

    if-eqz v4, :cond_0

    iget-boolean v4, v4, Llyiahf/vczjk/bt4;->OooO0oO:Z

    const/4 v5, 0x1

    if-ne v4, v5, :cond_0

    goto :goto_1

    :cond_0
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    iput p4, p0, Llyiahf/vczjk/ft4;->OooO0o:I

    iput p5, p0, Llyiahf/vczjk/ft4;->OooO0oO:I

    :goto_1
    invoke-interface {p1}, Llyiahf/vczjk/ut4;->OooO0O0()I

    move-result p4

    iget-object p5, p0, Llyiahf/vczjk/ft4;->OooO00o:[Llyiahf/vczjk/bt4;

    array-length p5, p5

    :goto_2
    if-ge p4, p5, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/ft4;->OooO00o:[Llyiahf/vczjk/bt4;

    aget-object v0, v0, p4

    if-eqz v0, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/bt4;->OooO0OO()V

    :cond_2
    add-int/lit8 p4, p4, 0x1

    goto :goto_2

    :cond_3
    iget-object p4, p0, Llyiahf/vczjk/ft4;->OooO00o:[Llyiahf/vczjk/bt4;

    array-length p4, p4

    invoke-interface {p1}, Llyiahf/vczjk/ut4;->OooO0O0()I

    move-result p5

    if-eq p4, p5, :cond_4

    iget-object p4, p0, Llyiahf/vczjk/ft4;->OooO00o:[Llyiahf/vczjk/bt4;

    invoke-interface {p1}, Llyiahf/vczjk/ut4;->OooO0O0()I

    move-result p5

    invoke-static {p4, p5}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p4

    const-string p5, "copyOf(...)"

    invoke-static {p4, p5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p4, [Llyiahf/vczjk/bt4;

    iput-object p4, p0, Llyiahf/vczjk/ft4;->OooO00o:[Llyiahf/vczjk/bt4;

    :cond_4
    invoke-interface {p1}, Llyiahf/vczjk/ut4;->OooO0o()J

    move-result-wide p4

    new-instance v0, Llyiahf/vczjk/rk1;

    invoke-direct {v0, p4, p5}, Llyiahf/vczjk/rk1;-><init>(J)V

    iput-object v0, p0, Llyiahf/vczjk/ft4;->OooO0O0:Llyiahf/vczjk/rk1;

    iput p6, p0, Llyiahf/vczjk/ft4;->OooO0OO:I

    invoke-interface {p1}, Llyiahf/vczjk/ut4;->OooOO0()I

    move-result p4

    iput p4, p0, Llyiahf/vczjk/ft4;->OooO0Oo:I

    invoke-interface {p1}, Llyiahf/vczjk/ut4;->OooO0Oo()I

    move-result p4

    iput p4, p0, Llyiahf/vczjk/ft4;->OooO0o0:I

    invoke-interface {p1}, Llyiahf/vczjk/ut4;->OooO0O0()I

    move-result p4

    :goto_3
    if-ge v2, p4, :cond_9

    invoke-interface {p1, v2}, Llyiahf/vczjk/ut4;->OooO0o0(I)Ljava/lang/Object;

    move-result-object p5

    instance-of p6, p5, Llyiahf/vczjk/is4;

    const/4 v0, 0x0

    if-eqz p6, :cond_5

    check-cast p5, Llyiahf/vczjk/is4;

    goto :goto_4

    :cond_5
    move-object p5, v0

    :goto_4
    if-nez p5, :cond_7

    iget-object p5, p0, Llyiahf/vczjk/ft4;->OooO00o:[Llyiahf/vczjk/bt4;

    aget-object p5, p5, v2

    if-eqz p5, :cond_6

    invoke-virtual {p5}, Llyiahf/vczjk/bt4;->OooO0OO()V

    :cond_6
    iget-object p5, p0, Llyiahf/vczjk/ft4;->OooO00o:[Llyiahf/vczjk/bt4;

    aput-object v0, p5, v2

    goto :goto_5

    :cond_7
    iget-object p6, p0, Llyiahf/vczjk/ft4;->OooO00o:[Llyiahf/vczjk/bt4;

    aget-object p6, p6, v2

    if-nez p6, :cond_8

    new-instance p6, Llyiahf/vczjk/bt4;

    new-instance v0, Llyiahf/vczjk/et4;

    iget-object v1, p0, Llyiahf/vczjk/ft4;->OooO0oo:Landroidx/compose/foundation/lazy/layout/OooO0OO;

    invoke-direct {v0, v1}, Llyiahf/vczjk/et4;-><init>(Landroidx/compose/foundation/lazy/layout/OooO0OO;)V

    invoke-direct {p6, p2, p3, v0}, Llyiahf/vczjk/bt4;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/ij3;Llyiahf/vczjk/et4;)V

    iget-object v0, p0, Llyiahf/vczjk/ft4;->OooO00o:[Llyiahf/vczjk/bt4;

    aput-object p6, v0, v2

    :cond_8
    iget-object v0, p5, Llyiahf/vczjk/is4;->OooOoOO:Llyiahf/vczjk/wz8;

    iput-object v0, p6, Llyiahf/vczjk/bt4;->OooO0Oo:Llyiahf/vczjk/wz8;

    iget-object v0, p5, Llyiahf/vczjk/is4;->OooOoo0:Llyiahf/vczjk/wz8;

    iput-object v0, p6, Llyiahf/vczjk/bt4;->OooO0o0:Llyiahf/vczjk/wz8;

    iget-object p5, p5, Llyiahf/vczjk/is4;->OooOoo:Llyiahf/vczjk/wz8;

    iput-object p5, p6, Llyiahf/vczjk/bt4;->OooO0o:Llyiahf/vczjk/wz8;

    :goto_5
    add-int/lit8 v2, v2, 0x1

    goto :goto_3

    :cond_9
    return-void
.end method
