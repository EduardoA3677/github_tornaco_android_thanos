.class public final Llyiahf/vczjk/zf2;
.super Llyiahf/vczjk/kf2;
.source "SourceFile"


# instance fields
.field public Oooo:Z

.field public Oooo0OO:Llyiahf/vczjk/ag2;

.field public Oooo0o:Z

.field public Oooo0o0:Llyiahf/vczjk/nf6;

.field public Oooo0oO:Llyiahf/vczjk/rf2;

.field public Oooo0oo:Llyiahf/vczjk/bf3;


# virtual methods
.method public final o0000O0()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/zf2;->Oooo0o:Z

    return v0
.end method

.method public final o0000O00(Llyiahf/vczjk/if2;Llyiahf/vczjk/jf2;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/zf2;->Oooo0OO:Llyiahf/vczjk/ag2;

    sget-object v1, Llyiahf/vczjk/at5;->OooOOO0:Llyiahf/vczjk/at5;

    new-instance v1, Llyiahf/vczjk/wf2;

    const/4 v2, 0x0

    invoke-direct {v1, p1, p0, v2}, Llyiahf/vczjk/wf2;-><init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/zf2;Llyiahf/vczjk/yo1;)V

    invoke-interface {v0, v1, p2}, Llyiahf/vczjk/ag2;->OooO00o(Llyiahf/vczjk/wf2;Llyiahf/vczjk/jf2;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final o0000oO(J)V
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/zf2;->Oooo0oo:Llyiahf/vczjk/bf3;

    sget-object v1, Llyiahf/vczjk/uf2;->OooO0O0:Llyiahf/vczjk/sf2;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v2, Llyiahf/vczjk/yf2;

    const/4 v3, 0x0

    invoke-direct {v2, p0, p1, p2, v3}, Llyiahf/vczjk/yf2;-><init>(Llyiahf/vczjk/zf2;JLlyiahf/vczjk/yo1;)V

    const/4 p1, 0x1

    invoke-static {v0, v3, v1, v2, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_1
    :goto_0
    return-void
.end method

.method public final o0000oo(J)V
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/zf2;->Oooo0oO:Llyiahf/vczjk/rf2;

    sget-object v1, Llyiahf/vczjk/uf2;->OooO00o:Llyiahf/vczjk/rf2;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v2, Llyiahf/vczjk/xf2;

    const/4 v3, 0x0

    invoke-direct {v2, p0, p1, p2, v3}, Llyiahf/vczjk/xf2;-><init>(Llyiahf/vczjk/zf2;JLlyiahf/vczjk/yo1;)V

    const/4 p1, 0x1

    invoke-static {v0, v3, v1, v2, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_1
    :goto_0
    return-void
.end method
