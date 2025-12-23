.class public final Llyiahf/vczjk/wo4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/e89;
.implements Llyiahf/vczjk/nf5;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/fp4;

.field public final synthetic OooOOO0:Llyiahf/vczjk/zo4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fp4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wo4;->OooOOO:Llyiahf/vczjk/fp4;

    iget-object p1, p1, Llyiahf/vczjk/fp4;->OooOo00:Llyiahf/vczjk/zo4;

    iput-object p1, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/util/List;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO:Llyiahf/vczjk/fp4;

    iget-object v1, v0, Llyiahf/vczjk/fp4;->OooOOoo:Llyiahf/vczjk/js5;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ro4;

    iget-object v2, v0, Llyiahf/vczjk/fp4;->OooOOO0:Llyiahf/vczjk/ro4;

    if-eqz v1, :cond_0

    invoke-virtual {v2}, Llyiahf/vczjk/ro4;->OooOOo0()Ljava/util/List;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ts5;

    iget-object v3, v3, Llyiahf/vczjk/ts5;->OooOOO0:Llyiahf/vczjk/ws5;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/ws5;->OooO(Ljava/lang/Object;)I

    move-result v3

    iget v4, v0, Llyiahf/vczjk/fp4;->OooOOOo:I

    if-ge v3, v4, :cond_0

    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OooOOO()Ljava/util/List;

    move-result-object p1

    return-object p1

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/fp4;->OooOoO0:Llyiahf/vczjk/ws5;

    iget v3, v1, Llyiahf/vczjk/ws5;->OooOOOO:I

    iget v4, v0, Llyiahf/vczjk/fp4;->OooOOo0:I

    if-lt v3, v4, :cond_1

    goto :goto_0

    :cond_1
    const-string v3, "Error: currentApproachIndex cannot be greater than the size of theapproachComposedSlotIds list."

    invoke-static {v3}, Llyiahf/vczjk/pz3;->OooO00o(Ljava/lang/String;)V

    :goto_0
    iget v3, v1, Llyiahf/vczjk/ws5;->OooOOOO:I

    iget v4, v0, Llyiahf/vczjk/fp4;->OooOOo0:I

    if-ne v3, v4, :cond_2

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_2
    iget-object v1, v1, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object v3, v1, v4

    aput-object p1, v1, v4

    :goto_1
    iget v1, v0, Llyiahf/vczjk/fp4;->OooOOo0:I

    const/4 v3, 0x1

    add-int/2addr v1, v3

    iput v1, v0, Llyiahf/vczjk/fp4;->OooOOo0:I

    iget-object v1, v0, Llyiahf/vczjk/fp4;->OooOo0O:Llyiahf/vczjk/js5;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/js5;->OooO0O0(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_4

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/fp4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/z79;

    move-result-object p2

    iget-object v0, v0, Llyiahf/vczjk/fp4;->OooOo:Llyiahf/vczjk/js5;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    iget-object p2, v2, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object p2, p2, Llyiahf/vczjk/vo4;->OooO0Oo:Llyiahf/vczjk/lo4;

    sget-object v0, Llyiahf/vczjk/lo4;->OooOOOO:Llyiahf/vczjk/lo4;

    if-ne p2, v0, :cond_3

    invoke-virtual {v2, v3}, Llyiahf/vczjk/ro4;->OoooO(Z)V

    goto :goto_2

    :cond_3
    const/4 p2, 0x6

    invoke-static {v2, v3, p2}, Llyiahf/vczjk/ro4;->OoooOO0(Llyiahf/vczjk/ro4;ZI)V

    :cond_4
    :goto_2
    invoke-virtual {v1, p1}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ro4;

    if-eqz p1, :cond_6

    iget-object p1, p1, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object p1, p1, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    invoke-virtual {p1}, Llyiahf/vczjk/kf5;->o00oO0O()Ljava/util/List;

    move-result-object p1

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/ts5;

    iget-object v0, p2, Llyiahf/vczjk/ts5;->OooOOO0:Llyiahf/vczjk/ws5;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v1, 0x0

    :goto_3
    if-ge v1, v0, :cond_5

    invoke-virtual {p2, v1}, Llyiahf/vczjk/ts5;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/kf5;

    iget-object v2, v2, Llyiahf/vczjk/kf5;->OooOOo:Llyiahf/vczjk/vo4;

    iput-boolean v3, v2, Llyiahf/vczjk/vo4;->OooO0O0:Z

    add-int/lit8 v1, v1, 0x1

    goto :goto_3

    :cond_5
    return-object p1

    :cond_6
    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1
.end method

.method public final OooO0O0()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    iget v0, v0, Llyiahf/vczjk/zo4;->OooOOO:F

    return v0
.end method

.method public final OooOOO(F)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->OooOOO(F)J

    move-result-wide v0

    return-wide v0
.end method

.method public final OooOOOO(J)J
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->OooOOOO(J)J

    move-result-wide p1

    return-wide p1
.end method

.method public final OooOOo0(J)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->OooOOo0(J)F

    move-result p1

    return p1
.end method

.method public final OooOo(IILjava/util/Map;Llyiahf/vczjk/ow;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    move v1, p1

    move v2, p2

    move-object v3, p3

    move-object v4, p4

    move-object v5, p5

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/zo4;->OooOo(IILjava/util/Map;Llyiahf/vczjk/ow;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method

.method public final OooOooo(F)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->OooOooo(F)J

    move-result-wide v0

    return-wide v0
.end method

.method public final Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;
    .locals 6

    const/4 v4, 0x0

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    move v1, p1

    move v2, p2

    move-object v3, p3

    move-object v5, p4

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/zo4;->OooOo(IILjava/util/Map;Llyiahf/vczjk/ow;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method

.method public final Oooo0OO(I)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->Oooo0OO(I)F

    move-result p1

    return p1
.end method

.method public final Oooo0o(F)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    invoke-virtual {v0}, Llyiahf/vczjk/zo4;->OooO0O0()F

    move-result v0

    div-float/2addr p1, v0

    return p1
.end method

.method public final OoooOo0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    invoke-virtual {v0}, Llyiahf/vczjk/zo4;->OoooOo0()Z

    move-result v0

    return v0
.end method

.method public final Ooooo00(F)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    invoke-virtual {v0}, Llyiahf/vczjk/zo4;->OooO0O0()F

    move-result v0

    mul-float/2addr v0, p1

    return v0
.end method

.method public final getLayoutDirection()Llyiahf/vczjk/yn4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    iget-object v0, v0, Llyiahf/vczjk/zo4;->OooOOO0:Llyiahf/vczjk/yn4;

    return-object v0
.end method

.method public final o000oOoO()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    iget v0, v0, Llyiahf/vczjk/zo4;->OooOOOO:F

    return v0
.end method

.method public final o00Oo0(F)I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p1

    return p1
.end method

.method public final o00oO0o(J)J
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->o00oO0o(J)J

    move-result-wide p1

    return-wide p1
.end method

.method public final o0ooOO0(J)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wo4;->OooOOO0:Llyiahf/vczjk/zo4;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->o0ooOO0(J)F

    move-result p1

    return p1
.end method
