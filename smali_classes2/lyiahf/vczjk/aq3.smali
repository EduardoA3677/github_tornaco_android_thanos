.class public final Llyiahf/vczjk/aq3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/rq8;


# instance fields
.field public OooOOO:Z

.field public final OooOOO0:Llyiahf/vczjk/gc3;

.field public final synthetic OooOOOO:Llyiahf/vczjk/fq3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fq3;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/aq3;->OooOOOO:Llyiahf/vczjk/fq3;

    new-instance v0, Llyiahf/vczjk/gc3;

    iget-object p1, p1, Llyiahf/vczjk/fq3;->OooO0o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/hh7;

    iget-object p1, p1, Llyiahf/vczjk/hh7;->OooOOO0:Llyiahf/vczjk/rq8;

    invoke-interface {p1}, Llyiahf/vczjk/rq8;->OooO0O0()Llyiahf/vczjk/fs9;

    move-result-object p1

    invoke-direct {v0, p1}, Llyiahf/vczjk/gc3;-><init>(Llyiahf/vczjk/fs9;)V

    iput-object v0, p0, Llyiahf/vczjk/aq3;->OooOOO0:Llyiahf/vczjk/gc3;

    return-void
.end method


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/fs9;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/aq3;->OooOOO0:Llyiahf/vczjk/gc3;

    return-object v0
.end method

.method public final Oooo0O0(Llyiahf/vczjk/yi0;J)V
    .locals 4

    const-string v0, "source"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-boolean v0, p0, Llyiahf/vczjk/aq3;->OooOOO:Z

    const-string v1, "closed"

    if-nez v0, :cond_2

    const-wide/16 v2, 0x0

    cmp-long v0, p2, v2

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/aq3;->OooOOOO:Llyiahf/vczjk/fq3;

    iget-object v2, v0, Llyiahf/vczjk/fq3;->OooO0o:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/hh7;

    iget-boolean v3, v2, Llyiahf/vczjk/hh7;->OooOOOO:Z

    if-nez v3, :cond_1

    iget-object v1, v2, Llyiahf/vczjk/hh7;->OooOOO:Llyiahf/vczjk/yi0;

    invoke-virtual {v1, p2, p3}, Llyiahf/vczjk/yi0;->o0000oO(J)V

    invoke-virtual {v2}, Llyiahf/vczjk/hh7;->OooO0Oo()Llyiahf/vczjk/mj0;

    iget-object v0, v0, Llyiahf/vczjk/fq3;->OooO0o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/hh7;

    const-string v1, "\r\n"

    invoke-virtual {v0, v1}, Llyiahf/vczjk/hh7;->o000oOoO(Ljava/lang/String;)Llyiahf/vczjk/mj0;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/hh7;->Oooo0O0(Llyiahf/vczjk/yi0;J)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/hh7;->o000oOoO(Ljava/lang/String;)Llyiahf/vczjk/mj0;

    return-void

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final declared-synchronized close()V
    .locals 3

    monitor-enter p0

    :try_start_0
    iget-boolean v0, p0, Llyiahf/vczjk/aq3;->OooOOO:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v0, :cond_0

    monitor-exit p0

    return-void

    :cond_0
    const/4 v0, 0x1

    :try_start_1
    iput-boolean v0, p0, Llyiahf/vczjk/aq3;->OooOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/aq3;->OooOOOO:Llyiahf/vczjk/fq3;

    iget-object v0, v0, Llyiahf/vczjk/fq3;->OooO0o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/hh7;

    const-string v1, "0\r\n\r\n"

    invoke-virtual {v0, v1}, Llyiahf/vczjk/hh7;->o000oOoO(Ljava/lang/String;)Llyiahf/vczjk/mj0;

    iget-object v0, p0, Llyiahf/vczjk/aq3;->OooOOOO:Llyiahf/vczjk/fq3;

    iget-object v1, p0, Llyiahf/vczjk/aq3;->OooOOO0:Llyiahf/vczjk/gc3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, v1, Llyiahf/vczjk/gc3;->OooO0o0:Llyiahf/vczjk/fs9;

    sget-object v2, Llyiahf/vczjk/fs9;->OooO0Oo:Llyiahf/vczjk/es9;

    iput-object v2, v1, Llyiahf/vczjk/gc3;->OooO0o0:Llyiahf/vczjk/fs9;

    invoke-virtual {v0}, Llyiahf/vczjk/fs9;->OooO00o()Llyiahf/vczjk/fs9;

    invoke-virtual {v0}, Llyiahf/vczjk/fs9;->OooO0O0()Llyiahf/vczjk/fs9;

    iget-object v0, p0, Llyiahf/vczjk/aq3;->OooOOOO:Llyiahf/vczjk/fq3;

    const/4 v1, 0x3

    iput v1, v0, Llyiahf/vczjk/fq3;->OooO0O0:I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit p0

    return-void

    :catchall_0
    move-exception v0

    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw v0
.end method

.method public final declared-synchronized flush()V
    .locals 1

    monitor-enter p0

    :try_start_0
    iget-boolean v0, p0, Llyiahf/vczjk/aq3;->OooOOO:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v0, :cond_0

    monitor-exit p0

    return-void

    :cond_0
    :try_start_1
    iget-object v0, p0, Llyiahf/vczjk/aq3;->OooOOOO:Llyiahf/vczjk/fq3;

    iget-object v0, v0, Llyiahf/vczjk/fq3;->OooO0o:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/hh7;

    invoke-virtual {v0}, Llyiahf/vczjk/hh7;->flush()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit p0

    return-void

    :catchall_0
    move-exception v0

    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw v0
.end method
