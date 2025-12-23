.class public final Llyiahf/vczjk/fh7;
.super Llyiahf/vczjk/nv8;
.source "SourceFile"


# instance fields
.field public OooO0o:I

.field public final OooO0o0:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(JLlyiahf/vczjk/rv8;Llyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0, p1, p2, p3}, Llyiahf/vczjk/nv8;-><init>(JLlyiahf/vczjk/rv8;)V

    iput-object p4, p0, Llyiahf/vczjk/fh7;->OooO0o0:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    iput p1, p0, Llyiahf/vczjk/fh7;->OooO0o:I

    return-void
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/oe3;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooO0OO()V
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/nv8;->OooO0OO:Z

    if-nez v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/fh7;->OooOO0o()V

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/nv8;->OooO0OO:Z

    sget-object v0, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    invoke-virtual {p0}, Llyiahf/vczjk/nv8;->OooOOOO()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    return-void

    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1

    :cond_0
    return-void
.end method

.method public final OooO0o()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooO0o0()Llyiahf/vczjk/oe3;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fh7;->OooO0o0:Llyiahf/vczjk/oe3;

    return-object v0
.end method

.method public final OooOO0O()V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/fh7;->OooO0o:I

    add-int/lit8 v0, v0, 0x1

    iput v0, p0, Llyiahf/vczjk/fh7;->OooO0o:I

    return-void
.end method

.method public final OooOO0o()V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/fh7;->OooO0o:I

    add-int/lit8 v0, v0, -0x1

    iput v0, p0, Llyiahf/vczjk/fh7;->OooO0o:I

    if-nez v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/nv8;->OooO00o()V

    :cond_0
    return-void
.end method

.method public final OooOOO(Llyiahf/vczjk/b39;)V
    .locals 1

    sget-object p1, Llyiahf/vczjk/vv8;->OooO00o:Llyiahf/vczjk/ed5;

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Cannot modify a state object in a read-only snapshot"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooOOO0()V
    .locals 0

    return-void
.end method

.method public final OooOo0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/nv8;
    .locals 6

    invoke-static {p0}, Llyiahf/vczjk/vv8;->OooO0Oo(Llyiahf/vczjk/nv8;)V

    new-instance v0, Llyiahf/vczjk/az5;

    iget-wide v1, p0, Llyiahf/vczjk/nv8;->OooO0O0:J

    iget-object v3, p0, Llyiahf/vczjk/nv8;->OooO00o:Llyiahf/vczjk/rv8;

    const/4 v4, 0x1

    iget-object v5, p0, Llyiahf/vczjk/fh7;->OooO0o0:Llyiahf/vczjk/oe3;

    invoke-static {p1, v5, v4}, Llyiahf/vczjk/vv8;->OooOO0o(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Z)Llyiahf/vczjk/oe3;

    move-result-object v4

    move-object v5, p0

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/az5;-><init>(JLlyiahf/vczjk/rv8;Llyiahf/vczjk/oe3;Llyiahf/vczjk/nv8;)V

    return-object v0
.end method
