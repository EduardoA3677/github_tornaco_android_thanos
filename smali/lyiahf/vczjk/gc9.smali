.class public final Llyiahf/vczjk/gc9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bz5;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/xr1;

.field public final OooOOO0:Llyiahf/vczjk/jc9;

.field public final OooOOOO:Llyiahf/vczjk/zb9;

.field public OooOOOo:Z

.field public OooOOo0:F


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jc9;Llyiahf/vczjk/xr1;Llyiahf/vczjk/zb9;)V
    .locals 1

    const-string v0, "state"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gc9;->OooOOO0:Llyiahf/vczjk/jc9;

    iput-object p2, p0, Llyiahf/vczjk/gc9;->OooOOO:Llyiahf/vczjk/xr1;

    iput-object p3, p0, Llyiahf/vczjk/gc9;->OooOOOO:Llyiahf/vczjk/zb9;

    return-void
.end method


# virtual methods
.method public final OooO00o(J)J
    .locals 5

    invoke-static {p1, p2}, Llyiahf/vczjk/p86;->OooO0Oo(J)F

    move-result v0

    const/4 v1, 0x0

    cmpl-float v0, v0, v1

    iget-object v2, p0, Llyiahf/vczjk/gc9;->OooOOO0:Llyiahf/vczjk/jc9;

    if-lez v0, :cond_0

    iget-object v0, v2, Llyiahf/vczjk/jc9;->OooO0Oo:Llyiahf/vczjk/qs5;

    sget-object v3, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, v3}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/jc9;->OooO00o()F

    move-result v0

    invoke-static {v0}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, v2, Llyiahf/vczjk/jc9;->OooO0Oo:Llyiahf/vczjk/qs5;

    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, v3}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :cond_1
    :goto_0
    invoke-static {p1, p2}, Llyiahf/vczjk/p86;->OooO0Oo(J)F

    move-result p1

    const/high16 p2, 0x3f000000    # 0.5f

    mul-float/2addr p1, p2

    invoke-virtual {v2}, Llyiahf/vczjk/jc9;->OooO00o()F

    move-result v0

    add-float/2addr v0, p1

    cmpg-float p1, v0, v1

    if-gez p1, :cond_2

    move v0, v1

    :cond_2
    invoke-virtual {v2}, Llyiahf/vczjk/jc9;->OooO00o()F

    move-result p1

    sub-float/2addr v0, p1

    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    move-result p1

    cmpl-float p1, p1, p2

    if-ltz p1, :cond_3

    new-instance p1, Llyiahf/vczjk/fc9;

    const/4 v2, 0x0

    invoke-direct {p1, p0, v0, v2}, Llyiahf/vczjk/fc9;-><init>(Llyiahf/vczjk/gc9;FLlyiahf/vczjk/yo1;)V

    iget-object v3, p0, Llyiahf/vczjk/gc9;->OooOOO:Llyiahf/vczjk/xr1;

    const/4 v4, 0x3

    invoke-static {v3, v2, v2, p1, v4}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    div-float/2addr v0, p2

    invoke-static {v1, v0}, Llyiahf/vczjk/sb;->OooOO0o(FF)J

    move-result-wide p1

    return-wide p1

    :cond_3
    const-wide/16 p1, 0x0

    return-wide p1
.end method

.method public final Oooo00O(IJ)J
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/gc9;->OooOOOo:Z

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/gc9;->OooOOO0:Llyiahf/vczjk/jc9;

    invoke-virtual {v0}, Llyiahf/vczjk/jc9;->OooO0O0()Z

    move-result v0

    if-eqz v0, :cond_1

    goto :goto_0

    :cond_1
    const/4 v0, 0x1

    if-ne p1, v0, :cond_2

    invoke-static {p2, p3}, Llyiahf/vczjk/p86;->OooO0Oo(J)F

    move-result p1

    const/4 v0, 0x0

    cmpg-float p1, p1, v0

    if-gez p1, :cond_2

    invoke-virtual {p0, p2, p3}, Llyiahf/vczjk/gc9;->OooO00o(J)J

    move-result-wide p1

    return-wide p1

    :cond_2
    :goto_0
    const-wide/16 p1, 0x0

    return-wide p1
.end method

.method public final OoooOO0(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/gc9;->OooOOO0:Llyiahf/vczjk/jc9;

    invoke-virtual {p1}, Llyiahf/vczjk/jc9;->OooO0O0()Z

    move-result p2

    if-nez p2, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/jc9;->OooO00o()F

    move-result p2

    iget p3, p0, Llyiahf/vczjk/gc9;->OooOOo0:F

    cmpl-float p2, p2, p3

    if-ltz p2, :cond_0

    iget-object p2, p0, Llyiahf/vczjk/gc9;->OooOOOO:Llyiahf/vczjk/zb9;

    invoke-virtual {p2}, Llyiahf/vczjk/zb9;->OooO00o()Ljava/lang/Object;

    :cond_0
    iget-object p1, p1, Llyiahf/vczjk/jc9;->OooO0Oo:Llyiahf/vczjk/qs5;

    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/fea;

    const-wide/16 p2, 0x0

    invoke-direct {p1, p2, p3}, Llyiahf/vczjk/fea;-><init>(J)V

    return-object p1
.end method

.method public final Ooooooo(IJJ)J
    .locals 0

    iget-boolean p2, p0, Llyiahf/vczjk/gc9;->OooOOOo:Z

    if-nez p2, :cond_0

    goto :goto_0

    :cond_0
    iget-object p2, p0, Llyiahf/vczjk/gc9;->OooOOO0:Llyiahf/vczjk/jc9;

    invoke-virtual {p2}, Llyiahf/vczjk/jc9;->OooO0O0()Z

    move-result p2

    if-eqz p2, :cond_1

    goto :goto_0

    :cond_1
    const/4 p2, 0x1

    if-ne p1, p2, :cond_2

    invoke-static {p4, p5}, Llyiahf/vczjk/p86;->OooO0Oo(J)F

    move-result p1

    const/4 p2, 0x0

    cmpl-float p1, p1, p2

    if-lez p1, :cond_2

    invoke-virtual {p0, p4, p5}, Llyiahf/vczjk/gc9;->OooO00o(J)J

    move-result-wide p1

    return-wide p1

    :cond_2
    :goto_0
    const-wide/16 p1, 0x0

    return-wide p1
.end method
