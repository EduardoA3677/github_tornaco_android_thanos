.class public final Llyiahf/vczjk/ie2;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/c0a;
.implements Llyiahf/vczjk/vn4;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/ie2;

.field public OooOoo:J

.field public OooOoo0:Llyiahf/vczjk/ie2;


# virtual methods
.method public final OooOO0O()Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/rp3;->OooOOOo:Llyiahf/vczjk/rp3;

    return-object v0
.end method

.method public final OooOOO0(J)V
    .locals 0

    iput-wide p1, p0, Llyiahf/vczjk/ie2;->OooOoo:J

    return-void
.end method

.method public final o00000OO(Llyiahf/vczjk/de2;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ie2;->OooOoOO:Llyiahf/vczjk/ie2;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ie2;->OooOoo0:Llyiahf/vczjk/ie2;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o00000OO(Llyiahf/vczjk/de2;)Z

    move-result p1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1

    :cond_1
    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o00000OO(Llyiahf/vczjk/de2;)Z

    move-result p1

    return p1
.end method

.method public final o00000Oo(Llyiahf/vczjk/de2;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ie2;->OooOoo0:Llyiahf/vczjk/ie2;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ie2;->OooOoOO:Llyiahf/vczjk/ie2;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o00000Oo(Llyiahf/vczjk/de2;)V

    :cond_0
    return-void

    :cond_1
    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o00000Oo(Llyiahf/vczjk/de2;)V

    return-void
.end method

.method public final o00000o0(Llyiahf/vczjk/de2;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ie2;->OooOoo0:Llyiahf/vczjk/ie2;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o00000o0(Llyiahf/vczjk/de2;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ie2;->OooOoOO:Llyiahf/vczjk/ie2;

    if-eqz v0, :cond_1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o00000o0(Llyiahf/vczjk/de2;)V

    :cond_1
    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/ie2;->OooOoOO:Llyiahf/vczjk/ie2;

    return-void
.end method

.method public final o00000oO(Llyiahf/vczjk/de2;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ie2;->OooOoo0:Llyiahf/vczjk/ie2;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ie2;->OooOoOO:Llyiahf/vczjk/ie2;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o00000oO(Llyiahf/vczjk/de2;)V

    :cond_0
    return-void

    :cond_1
    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o00000oO(Llyiahf/vczjk/de2;)V

    return-void
.end method

.method public final o0000Ooo(Llyiahf/vczjk/de2;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ie2;->OooOoOO:Llyiahf/vczjk/ie2;

    if-eqz v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/yi4;->OoooOOO(Llyiahf/vczjk/de2;)J

    move-result-wide v1

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/mc4;->OooOOO(Llyiahf/vczjk/ie2;J)Z

    move-result v1

    const/4 v2, 0x1

    if-ne v1, v2, :cond_0

    move-object v1, v0

    goto :goto_1

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v1, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v1, :cond_1

    const/4 v1, 0x0

    goto :goto_0

    :cond_1
    new-instance v1, Llyiahf/vczjk/hl7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    new-instance v2, Llyiahf/vczjk/he2;

    invoke-direct {v2, v1, p0, p1}, Llyiahf/vczjk/he2;-><init>(Llyiahf/vczjk/hl7;Llyiahf/vczjk/ie2;Llyiahf/vczjk/de2;)V

    invoke-static {p0, v2}, Llyiahf/vczjk/er8;->OooOo(Llyiahf/vczjk/c0a;Llyiahf/vczjk/oe3;)V

    iget-object v1, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/c0a;

    :goto_0
    check-cast v1, Llyiahf/vczjk/ie2;

    :goto_1
    if-eqz v1, :cond_2

    if-nez v0, :cond_2

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ie2;->o00000Oo(Llyiahf/vczjk/de2;)V

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ie2;->o0000Ooo(Llyiahf/vczjk/de2;)V

    iget-object v0, p0, Llyiahf/vczjk/ie2;->OooOoo0:Llyiahf/vczjk/ie2;

    if-eqz v0, :cond_8

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o00000o0(Llyiahf/vczjk/de2;)V

    goto :goto_2

    :cond_2
    if-nez v1, :cond_4

    if-eqz v0, :cond_4

    iget-object v2, p0, Llyiahf/vczjk/ie2;->OooOoo0:Llyiahf/vczjk/ie2;

    if-eqz v2, :cond_3

    invoke-virtual {v2, p1}, Llyiahf/vczjk/ie2;->o00000Oo(Llyiahf/vczjk/de2;)V

    invoke-virtual {v2, p1}, Llyiahf/vczjk/ie2;->o0000Ooo(Llyiahf/vczjk/de2;)V

    :cond_3
    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o00000o0(Llyiahf/vczjk/de2;)V

    goto :goto_2

    :cond_4
    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_6

    if-eqz v1, :cond_5

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ie2;->o00000Oo(Llyiahf/vczjk/de2;)V

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ie2;->o0000Ooo(Llyiahf/vczjk/de2;)V

    :cond_5
    if-eqz v0, :cond_8

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o00000o0(Llyiahf/vczjk/de2;)V

    goto :goto_2

    :cond_6
    if-eqz v1, :cond_7

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ie2;->o0000Ooo(Llyiahf/vczjk/de2;)V

    goto :goto_2

    :cond_7
    iget-object v0, p0, Llyiahf/vczjk/ie2;->OooOoo0:Llyiahf/vczjk/ie2;

    if-eqz v0, :cond_8

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o0000Ooo(Llyiahf/vczjk/de2;)V

    :cond_8
    :goto_2
    iput-object v1, p0, Llyiahf/vczjk/ie2;->OooOoOO:Llyiahf/vczjk/ie2;

    return-void
.end method

.method public final o000OOo()V
    .locals 1

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/ie2;->OooOoo0:Llyiahf/vczjk/ie2;

    iput-object v0, p0, Llyiahf/vczjk/ie2;->OooOoOO:Llyiahf/vczjk/ie2;

    return-void
.end method
