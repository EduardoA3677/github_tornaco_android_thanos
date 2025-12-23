.class public final Llyiahf/vczjk/a0a;
.super Llyiahf/vczjk/nv8;
.source "SourceFile"


# instance fields
.field public final OooO0o:Z

.field public final OooO0o0:Llyiahf/vczjk/nv8;

.field public OooO0oO:Llyiahf/vczjk/oe3;

.field public final OooO0oo:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;Z)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/vv8;->OooO00o:Llyiahf/vczjk/ed5;

    sget-object v0, Llyiahf/vczjk/rv8;->OooOOo0:Llyiahf/vczjk/rv8;

    const-wide/16 v1, 0x0

    invoke-direct {p0, v1, v2, v0}, Llyiahf/vczjk/nv8;-><init>(JLlyiahf/vczjk/rv8;)V

    iput-object p1, p0, Llyiahf/vczjk/a0a;->OooO0o0:Llyiahf/vczjk/nv8;

    iput-boolean p3, p0, Llyiahf/vczjk/a0a;->OooO0o:Z

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/nv8;->OooO0o0()Llyiahf/vczjk/oe3;

    move-result-object p1

    if-nez p1, :cond_1

    :cond_0
    sget-object p1, Llyiahf/vczjk/vv8;->OooO:Llyiahf/vczjk/li3;

    iget-object p1, p1, Llyiahf/vczjk/ps5;->OooO0o0:Llyiahf/vczjk/oe3;

    :cond_1
    const/4 p3, 0x0

    invoke-static {p2, p1, p3}, Llyiahf/vczjk/vv8;->OooOO0o(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Z)Llyiahf/vczjk/oe3;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/a0a;->OooO0oO:Llyiahf/vczjk/oe3;

    invoke-static {}, Llyiahf/vczjk/vt6;->OooOoO0()J

    move-result-wide p1

    iput-wide p1, p0, Llyiahf/vczjk/a0a;->OooO0oo:J

    return-void
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/oe3;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooO0OO()V
    .locals 1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/nv8;->OooO0OO:Z

    iget-boolean v0, p0, Llyiahf/vczjk/a0a;->OooO0o:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/a0a;->OooO0o0:Llyiahf/vczjk/nv8;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/nv8;->OooO0OO()V

    :cond_0
    return-void
.end method

.method public final OooO0Oo()Llyiahf/vczjk/rv8;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/a0a;->OooOo0O()Llyiahf/vczjk/nv8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/nv8;->OooO0Oo()Llyiahf/vczjk/rv8;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0o()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/a0a;->OooOo0O()Llyiahf/vczjk/nv8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/nv8;->OooO0o()Z

    move-result v0

    return v0
.end method

.method public final OooO0o0()Llyiahf/vczjk/oe3;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a0a;->OooO0oO:Llyiahf/vczjk/oe3;

    return-object v0
.end method

.method public final OooO0oO()J
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/a0a;->OooOo0O()Llyiahf/vczjk/nv8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/nv8;->OooO0oO()J

    move-result-wide v0

    return-wide v0
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

    invoke-virtual {p0}, Llyiahf/vczjk/a0a;->OooOo0O()Llyiahf/vczjk/nv8;

    move-result-object v0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/nv8;->OooOOO(Llyiahf/vczjk/b39;)V

    return-void
.end method

.method public final OooOOO0()V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/a0a;->OooOo0O()Llyiahf/vczjk/nv8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/nv8;->OooOOO0()V

    return-void
.end method

.method public final OooOo0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/nv8;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/a0a;->OooO0oO:Llyiahf/vczjk/oe3;

    const/4 v1, 0x1

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/vv8;->OooOO0o(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Z)Llyiahf/vczjk/oe3;

    move-result-object p1

    invoke-virtual {p0}, Llyiahf/vczjk/a0a;->OooOo0O()Llyiahf/vczjk/nv8;

    move-result-object v0

    const/4 v2, 0x0

    invoke-virtual {v0, v2}, Llyiahf/vczjk/nv8;->OooOo0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/nv8;

    move-result-object v0

    invoke-static {v0, p1, v1}, Llyiahf/vczjk/vv8;->OooO0oo(Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;Z)Llyiahf/vczjk/nv8;

    move-result-object p1

    return-object p1
.end method

.method public final OooOo0O()Llyiahf/vczjk/nv8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a0a;->OooO0o0:Llyiahf/vczjk/nv8;

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/vv8;->OooO:Llyiahf/vczjk/li3;

    :cond_0
    return-object v0
.end method
