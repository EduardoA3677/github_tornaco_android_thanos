.class public final Llyiahf/vczjk/xa8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/v98;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/db8;

.field public final synthetic OooO0O0:Llyiahf/vczjk/lz5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lz5;Llyiahf/vczjk/db8;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/xa8;->OooO00o:Llyiahf/vczjk/db8;

    iput-object p1, p0, Llyiahf/vczjk/xa8;->OooO0O0:Llyiahf/vczjk/lz5;

    return-void
.end method


# virtual methods
.method public final OooO00o(F)F
    .locals 4

    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    move-result v0

    const/4 v1, 0x0

    cmpg-float v0, v0, v1

    iget-object v2, p0, Llyiahf/vczjk/xa8;->OooO00o:Llyiahf/vczjk/db8;

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    cmpl-float v0, p1, v1

    if-lez v0, :cond_1

    iget-object v0, v2, Llyiahf/vczjk/db8;->OooO00o:Llyiahf/vczjk/sa8;

    invoke-interface {v0}, Llyiahf/vczjk/sa8;->OooO0Oo()Z

    move-result v0

    if-eqz v0, :cond_3

    :cond_1
    cmpg-float v0, p1, v1

    if-gez v0, :cond_2

    iget-object v0, v2, Llyiahf/vczjk/db8;->OooO00o:Llyiahf/vczjk/sa8;

    invoke-interface {v0}, Llyiahf/vczjk/sa8;->OooO0O0()Z

    move-result v0

    if-eqz v0, :cond_3

    :cond_2
    iget-object v0, v2, Llyiahf/vczjk/db8;->OooO0oO:Llyiahf/vczjk/na8;

    invoke-virtual {v0}, Llyiahf/vczjk/na8;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_3

    :goto_0
    invoke-virtual {v2, p1}, Llyiahf/vczjk/db8;->OooO0oO(F)J

    move-result-wide v0

    invoke-virtual {v2, v0, v1}, Llyiahf/vczjk/db8;->OooO0Oo(J)J

    move-result-wide v0

    iget-object p1, p0, Llyiahf/vczjk/xa8;->OooO0O0:Llyiahf/vczjk/lz5;

    check-cast p1, Llyiahf/vczjk/za8;

    const/4 v3, 0x2

    invoke-virtual {p1, v3, v0, v1}, Llyiahf/vczjk/za8;->OooO00o(IJ)J

    move-result-wide v0

    invoke-virtual {v2, v0, v1}, Llyiahf/vczjk/db8;->OooO0o(J)F

    move-result p1

    invoke-virtual {v2, p1}, Llyiahf/vczjk/db8;->OooO0OO(F)F

    move-result p1

    return p1

    :cond_3
    new-instance p1, Llyiahf/vczjk/r23;

    const-string v0, "The fling animation was cancelled"

    const/4 v1, 0x0

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/r23;-><init>(Ljava/lang/String;I)V

    throw p1
.end method
