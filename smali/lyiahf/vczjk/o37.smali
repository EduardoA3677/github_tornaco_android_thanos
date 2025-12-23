.class public final Llyiahf/vczjk/o37;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/l37;
.implements Llyiahf/vczjk/f62;


# instance fields
.field public OooOOO:Z

.field public final synthetic OooOOO0:Llyiahf/vczjk/f62;

.field public OooOOOO:Z

.field public final OooOOOo:Llyiahf/vczjk/mt5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f62;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/o37;->OooOOO0:Llyiahf/vczjk/f62;

    new-instance p1, Llyiahf/vczjk/mt5;

    invoke-direct {p1}, Llyiahf/vczjk/mt5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/o37;->OooOOOo:Llyiahf/vczjk/mt5;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 2

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/o37;->OooOOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/o37;->OooOOOo:Llyiahf/vczjk/mt5;

    invoke-virtual {v0}, Llyiahf/vczjk/mt5;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/mt5;->OooO0Oo(Ljava/lang/Object;)V

    :cond_0
    return-void
.end method

.method public final OooO0O0()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o37;->OooOOO0:Llyiahf/vczjk/f62;

    invoke-interface {v0}, Llyiahf/vczjk/f62;->OooO0O0()F

    move-result v0

    return v0
.end method

.method public final OooO0OO()V
    .locals 2

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/o37;->OooOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/o37;->OooOOOo:Llyiahf/vczjk/mt5;

    invoke-virtual {v0}, Llyiahf/vczjk/mt5;->OooO0o0()Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/mt5;->OooO0Oo(Ljava/lang/Object;)V

    :cond_0
    return-void
.end method

.method public final OooO0Oo(Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 4

    instance-of v0, p1, Llyiahf/vczjk/m37;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/m37;

    iget v1, v0, Llyiahf/vczjk/m37;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/m37;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/m37;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/m37;-><init>(Llyiahf/vczjk/o37;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/m37;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/m37;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/m37;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/o37;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iput-object p0, v0, Llyiahf/vczjk/m37;->L$0:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/m37;->label:I

    iget-object p1, p0, Llyiahf/vczjk/o37;->OooOOOo:Llyiahf/vczjk/mt5;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_3

    return-object v1

    :cond_3
    move-object v0, p0

    :goto_1
    const/4 p1, 0x0

    iput-boolean p1, v0, Llyiahf/vczjk/o37;->OooOOO:Z

    iput-boolean p1, v0, Llyiahf/vczjk/o37;->OooOOOO:Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0o(Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 4

    instance-of v0, p1, Llyiahf/vczjk/n37;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/n37;

    iget v1, v0, Llyiahf/vczjk/n37;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/n37;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/n37;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/n37;-><init>(Llyiahf/vczjk/o37;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/n37;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/n37;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/n37;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/o37;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-boolean p1, p0, Llyiahf/vczjk/o37;->OooOOO:Z

    if-nez p1, :cond_4

    iget-boolean p1, p0, Llyiahf/vczjk/o37;->OooOOOO:Z

    if-nez p1, :cond_4

    iput-object p0, v0, Llyiahf/vczjk/n37;->L$0:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/n37;->label:I

    iget-object p1, p0, Llyiahf/vczjk/o37;->OooOOOo:Llyiahf/vczjk/mt5;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_3

    return-object v1

    :cond_3
    move-object v0, p0

    :goto_1
    iget-object p1, v0, Llyiahf/vczjk/o37;->OooOOOo:Llyiahf/vczjk/mt5;

    const/4 v1, 0x0

    invoke-virtual {p1, v1}, Llyiahf/vczjk/mt5;->OooO0Oo(Ljava/lang/Object;)V

    goto :goto_2

    :cond_4
    move-object v0, p0

    :goto_2
    iget-boolean p1, v0, Llyiahf/vczjk/o37;->OooOOO:Z

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method

.method public final OooOOO(F)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/o37;->OooOOO0:Llyiahf/vczjk/f62;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->OooOOO(F)J

    move-result-wide v0

    return-wide v0
.end method

.method public final OooOOOO(J)J
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o37;->OooOOO0:Llyiahf/vczjk/f62;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->OooOOOO(J)J

    move-result-wide p1

    return-wide p1
.end method

.method public final OooOOo0(J)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o37;->OooOOO0:Llyiahf/vczjk/f62;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->OooOOo0(J)F

    move-result p1

    return p1
.end method

.method public final OooOooo(F)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/o37;->OooOOO0:Llyiahf/vczjk/f62;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->OooOooo(F)J

    move-result-wide v0

    return-wide v0
.end method

.method public final Oooo0OO(I)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o37;->OooOOO0:Llyiahf/vczjk/f62;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->Oooo0OO(I)F

    move-result p1

    return p1
.end method

.method public final Oooo0o(F)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o37;->OooOOO0:Llyiahf/vczjk/f62;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->Oooo0o(F)F

    move-result p1

    return p1
.end method

.method public final Ooooo00(F)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o37;->OooOOO0:Llyiahf/vczjk/f62;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result p1

    return p1
.end method

.method public final o000oOoO()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o37;->OooOOO0:Llyiahf/vczjk/f62;

    invoke-interface {v0}, Llyiahf/vczjk/f62;->o000oOoO()F

    move-result v0

    return v0
.end method

.method public final o00Oo0(F)I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o37;->OooOOO0:Llyiahf/vczjk/f62;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p1

    return p1
.end method

.method public final o00oO0o(J)J
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o37;->OooOOO0:Llyiahf/vczjk/f62;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->o00oO0o(J)J

    move-result-wide p1

    return-wide p1
.end method

.method public final o0ooOO0(J)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o37;->OooOOO0:Llyiahf/vczjk/f62;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->o0ooOO0(J)F

    move-result p1

    return p1
.end method
