.class public final Llyiahf/vczjk/ml1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/nl5;


# instance fields
.field public OooOOO:Llyiahf/vczjk/kna;

.field public final OooOOO0:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ml1;->OooOOO0:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final OooO0o(Llyiahf/vczjk/sl5;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/uoa;->OooO00o:Llyiahf/vczjk/ie7;

    invoke-interface {p1, v0}, Llyiahf/vczjk/sl5;->OooO0OO(Llyiahf/vczjk/ie7;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/kna;

    iget-object v0, p0, Llyiahf/vczjk/ml1;->OooOOO:Llyiahf/vczjk/kna;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/ml1;->OooOOO:Llyiahf/vczjk/kna;

    iget-object v0, p0, Llyiahf/vczjk/ml1;->OooOOO0:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    instance-of v1, p1, Llyiahf/vczjk/ml1;

    const/4 v2, 0x0

    if-nez v1, :cond_1

    return v2

    :cond_1
    check-cast p1, Llyiahf/vczjk/ml1;

    iget-object p1, p1, Llyiahf/vczjk/ml1;->OooOOO0:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Llyiahf/vczjk/ml1;->OooOOO0:Llyiahf/vczjk/oe3;

    if-ne p1, v1, :cond_2

    return v0

    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ml1;->OooOOO0:Llyiahf/vczjk/oe3;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    return v0
.end method
