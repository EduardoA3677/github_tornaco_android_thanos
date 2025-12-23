.class public final Llyiahf/vczjk/ip4;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/cp6;


# instance fields
.field public OooOoOO:F

.field public OooOoo0:Z


# virtual methods
.method public final OooooOo(Llyiahf/vczjk/f62;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    instance-of p1, p2, Llyiahf/vczjk/ew7;

    if-eqz p1, :cond_0

    check-cast p2, Llyiahf/vczjk/ew7;

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    if-nez p2, :cond_1

    new-instance p2, Llyiahf/vczjk/ew7;

    invoke-direct {p2}, Llyiahf/vczjk/ew7;-><init>()V

    :cond_1
    iget p1, p0, Llyiahf/vczjk/ip4;->OooOoOO:F

    iput p1, p2, Llyiahf/vczjk/ew7;->OooO00o:F

    iget-boolean p1, p0, Llyiahf/vczjk/ip4;->OooOoo0:Z

    iput-boolean p1, p2, Llyiahf/vczjk/ew7;->OooO0O0:Z

    return-object p2
.end method
