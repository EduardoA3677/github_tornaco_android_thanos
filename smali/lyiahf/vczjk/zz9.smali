.class public final Llyiahf/vczjk/zz9;
.super Llyiahf/vczjk/ps5;
.source "SourceFile"


# instance fields
.field public final OooOOOO:Llyiahf/vczjk/ps5;

.field public final OooOOOo:Z

.field public OooOOo:Llyiahf/vczjk/oe3;

.field public final OooOOo0:Z

.field public OooOOoo:Llyiahf/vczjk/oe3;

.field public final OooOo00:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ps5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;ZZ)V
    .locals 7

    sget-object v0, Llyiahf/vczjk/vv8;->OooO00o:Llyiahf/vczjk/ed5;

    sget-object v4, Llyiahf/vczjk/rv8;->OooOOo0:Llyiahf/vczjk/rv8;

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/ps5;->OooOoO0()Llyiahf/vczjk/oe3;

    move-result-object v0

    if-nez v0, :cond_1

    :cond_0
    sget-object v0, Llyiahf/vczjk/vv8;->OooO:Llyiahf/vczjk/li3;

    iget-object v0, v0, Llyiahf/vczjk/ps5;->OooO0o0:Llyiahf/vczjk/oe3;

    :cond_1
    invoke-static {p2, v0, p4}, Llyiahf/vczjk/vv8;->OooOO0o(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Z)Llyiahf/vczjk/oe3;

    move-result-object v5

    if-eqz p1, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/ps5;->OooO()Llyiahf/vczjk/oe3;

    move-result-object p2

    if-nez p2, :cond_3

    :cond_2
    sget-object p2, Llyiahf/vczjk/vv8;->OooO:Llyiahf/vczjk/li3;

    iget-object p2, p2, Llyiahf/vczjk/ps5;->OooO0o:Llyiahf/vczjk/oe3;

    :cond_3
    invoke-static {p3, p2}, Llyiahf/vczjk/vv8;->OooO0O0(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/oe3;

    move-result-object v6

    const-wide/16 v2, 0x0

    move-object v1, p0

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/ps5;-><init>(JLlyiahf/vczjk/rv8;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    iput-object p1, v1, Llyiahf/vczjk/zz9;->OooOOOO:Llyiahf/vczjk/ps5;

    iput-boolean p4, v1, Llyiahf/vczjk/zz9;->OooOOOo:Z

    iput-boolean p5, v1, Llyiahf/vczjk/zz9;->OooOOo0:Z

    iget-object p1, v1, Llyiahf/vczjk/ps5;->OooO0o0:Llyiahf/vczjk/oe3;

    iput-object p1, v1, Llyiahf/vczjk/zz9;->OooOOo:Llyiahf/vczjk/oe3;

    iget-object p1, v1, Llyiahf/vczjk/ps5;->OooO0o:Llyiahf/vczjk/oe3;

    iput-object p1, v1, Llyiahf/vczjk/zz9;->OooOOoo:Llyiahf/vczjk/oe3;

    invoke-static {}, Llyiahf/vczjk/vt6;->OooOoO0()J

    move-result-wide p1

    iput-wide p1, v1, Llyiahf/vczjk/zz9;->OooOo00:J

    return-void
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/oe3;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zz9;->OooOOoo:Llyiahf/vczjk/oe3;

    return-object v0
.end method

.method public final OooO0OO()V
    .locals 1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/nv8;->OooO0OO:Z

    iget-boolean v0, p0, Llyiahf/vczjk/zz9;->OooOOo0:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/zz9;->OooOOOO:Llyiahf/vczjk/ps5;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/ps5;->OooO0OO()V

    :cond_0
    return-void
.end method

.method public final OooO0Oo()Llyiahf/vczjk/rv8;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/zz9;->OooOooO()Llyiahf/vczjk/ps5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/nv8;->OooO0Oo()Llyiahf/vczjk/rv8;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0o()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/zz9;->OooOooO()Llyiahf/vczjk/ps5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ps5;->OooO0o()Z

    move-result v0

    return v0
.end method

.method public final OooO0o0()Llyiahf/vczjk/oe3;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zz9;->OooOOo:Llyiahf/vczjk/oe3;

    return-object v0
.end method

.method public final OooO0oO()J
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/zz9;->OooOooO()Llyiahf/vczjk/ps5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/nv8;->OooO0oO()J

    move-result-wide v0

    return-wide v0
.end method

.method public final OooO0oo()I
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/zz9;->OooOooO()Llyiahf/vczjk/ps5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ps5;->OooO0oo()I

    move-result v0

    return v0
.end method

.method public final OooOO0O()V
    .locals 1

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOoo0()V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOO0o()V
    .locals 1

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOoo0()V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOOO(Llyiahf/vczjk/b39;)V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/zz9;->OooOooO()Llyiahf/vczjk/ps5;

    move-result-object v0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ps5;->OooOOO(Llyiahf/vczjk/b39;)V

    return-void
.end method

.method public final OooOOO0()V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/zz9;->OooOooO()Llyiahf/vczjk/ps5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ps5;->OooOOO0()V

    return-void
.end method

.method public final OooOOo(Llyiahf/vczjk/rv8;)V
    .locals 0

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOoo0()V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooOOoo(J)V
    .locals 0

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOoo0()V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooOo()Llyiahf/vczjk/ks5;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/zz9;->OooOooO()Llyiahf/vczjk/ps5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ps5;->OooOo()Llyiahf/vczjk/ks5;

    move-result-object v0

    return-object v0
.end method

.method public final OooOo0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/nv8;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/zz9;->OooOOo:Llyiahf/vczjk/oe3;

    const/4 v1, 0x1

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/vv8;->OooOO0o(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Z)Llyiahf/vczjk/oe3;

    move-result-object p1

    iget-boolean v0, p0, Llyiahf/vczjk/zz9;->OooOOOo:Z

    if-nez v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/zz9;->OooOooO()Llyiahf/vczjk/ps5;

    move-result-object v0

    const/4 v2, 0x0

    invoke-virtual {v0, v2}, Llyiahf/vczjk/ps5;->OooOo0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/nv8;

    move-result-object v0

    invoke-static {v0, p1, v1}, Llyiahf/vczjk/vv8;->OooO0oo(Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;Z)Llyiahf/vczjk/nv8;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/zz9;->OooOooO()Llyiahf/vczjk/ps5;

    move-result-object v0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ps5;->OooOo0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/nv8;

    move-result-object p1

    return-object p1
.end method

.method public final OooOo00(I)V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/zz9;->OooOooO()Llyiahf/vczjk/ps5;

    move-result-object v0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ps5;->OooOo00(I)V

    return-void
.end method

.method public final OooOo0o()Llyiahf/vczjk/xr6;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/zz9;->OooOooO()Llyiahf/vczjk/ps5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ps5;->OooOo0o()Llyiahf/vczjk/xr6;

    move-result-object v0

    return-object v0
.end method

.method public final OooOoO0()Llyiahf/vczjk/oe3;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zz9;->OooOOo:Llyiahf/vczjk/oe3;

    return-object v0
.end method

.method public final OooOoo(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/ps5;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/zz9;->OooOOo:Llyiahf/vczjk/oe3;

    const/4 v1, 0x1

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/vv8;->OooOO0o(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Z)Llyiahf/vczjk/oe3;

    move-result-object v4

    iget-object p1, p0, Llyiahf/vczjk/zz9;->OooOOoo:Llyiahf/vczjk/oe3;

    invoke-static {p2, p1}, Llyiahf/vczjk/vv8;->OooO0O0(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/oe3;

    move-result-object v5

    iget-boolean p1, p0, Llyiahf/vczjk/zz9;->OooOOOo:Z

    if-nez p1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/zz9;->OooOooO()Llyiahf/vczjk/ps5;

    move-result-object p1

    const/4 p2, 0x0

    invoke-virtual {p1, p2, v5}, Llyiahf/vczjk/ps5;->OooOoo(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/ps5;

    move-result-object v3

    new-instance v2, Llyiahf/vczjk/zz9;

    const/4 v6, 0x0

    const/4 v7, 0x1

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/zz9;-><init>(Llyiahf/vczjk/ps5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;ZZ)V

    return-object v2

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/zz9;->OooOooO()Llyiahf/vczjk/ps5;

    move-result-object p1

    invoke-virtual {p1, v4, v5}, Llyiahf/vczjk/ps5;->OooOoo(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/ps5;

    move-result-object p1

    return-object p1
.end method

.method public final OooOoo0(Llyiahf/vczjk/ks5;)V
    .locals 0

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOoo0()V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooOooO()Llyiahf/vczjk/ps5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zz9;->OooOOOO:Llyiahf/vczjk/ps5;

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/vv8;->OooO:Llyiahf/vczjk/li3;

    :cond_0
    return-object v0
.end method
