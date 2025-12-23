.class public final Llyiahf/vczjk/ci6;
.super Llyiahf/vczjk/z04;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/bi6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bi6;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/z04;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ci6;->OooOOO:Llyiahf/vczjk/bi6;

    return-void
.end method


# virtual methods
.method public final OooOO0(Llyiahf/vczjk/kna;)Llyiahf/vczjk/kna;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ei6;

    iget-object v1, p0, Llyiahf/vczjk/ci6;->OooOOO:Llyiahf/vczjk/bi6;

    invoke-direct {v0, v1}, Llyiahf/vczjk/ei6;-><init>(Llyiahf/vczjk/bi6;)V

    new-instance v1, Llyiahf/vczjk/m1;

    invoke-direct {v1, v0, p1}, Llyiahf/vczjk/m1;-><init>(Llyiahf/vczjk/ei6;Llyiahf/vczjk/kna;)V

    return-object v1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    if-ne p0, p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/ci6;

    if-nez v0, :cond_1

    const/4 p1, 0x0

    return p1

    :cond_1
    check-cast p1, Llyiahf/vczjk/ci6;

    iget-object p1, p1, Llyiahf/vczjk/ci6;->OooOOO:Llyiahf/vczjk/bi6;

    iget-object v0, p0, Llyiahf/vczjk/ci6;->OooOOO:Llyiahf/vczjk/bi6;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ci6;->OooOOO:Llyiahf/vczjk/bi6;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    return v0
.end method
