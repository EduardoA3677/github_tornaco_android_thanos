.class public abstract Llyiahf/vczjk/jl5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/l52;


# instance fields
.field public OooOOO:Llyiahf/vczjk/to1;

.field public OooOOO0:Llyiahf/vczjk/jl5;

.field public OooOOOO:I

.field public OooOOOo:I

.field public OooOOo:Llyiahf/vczjk/jl5;

.field public OooOOo0:Llyiahf/vczjk/jl5;

.field public OooOOoo:Llyiahf/vczjk/m86;

.field public OooOo:Z

.field public OooOo0:Z

.field public OooOo00:Llyiahf/vczjk/v16;

.field public OooOo0O:Z

.field public OooOo0o:Z

.field public OooOoO:Z

.field public OooOoO0:Llyiahf/vczjk/ao3;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p0, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    const/4 v0, -0x1

    iput v0, p0, Llyiahf/vczjk/jl5;->OooOOOo:I

    return-void
.end method


# virtual methods
.method public o00000()V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    const-string v0, "node detached multiple times"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/jl5;->OooOo00:Llyiahf/vczjk/v16;

    if-eqz v0, :cond_1

    goto :goto_0

    :cond_1
    const-string v0, "detach invoked on a node without a coordinator"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :goto_0
    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOo:Z

    if-nez v0, :cond_2

    const-string v0, "Must run runDetachLifecycle() once after runAttachLifecycle() and before markAsDetached()"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_2
    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOo:Z

    iget-object v0, p0, Llyiahf/vczjk/jl5;->OooOoO0:Llyiahf/vczjk/ao3;

    if-eqz v0, :cond_3

    invoke-virtual {v0}, Llyiahf/vczjk/ao3;->OooO00o()Ljava/lang/Object;

    :cond_3
    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o000OOo()V

    return-void
.end method

.method public o000000()V
    .locals 0

    return-void
.end method

.method public o000000O()V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    const-string v0, "reset() called on an unattached node"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o000000()V

    return-void
.end method

.method public o000000o()V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    const-string v0, "Must run markAsAttached() prior to runAttachLifecycle"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOo0o:Z

    if-nez v0, :cond_1

    const-string v0, "Must run runAttachLifecycle() only once after markAsAttached()"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_1
    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOo0o:Z

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0O0O00()V

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOo:Z

    return-void
.end method

.method public o00000O(Llyiahf/vczjk/v16;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jl5;->OooOo00:Llyiahf/vczjk/v16;

    return-void
.end method

.method public o00000O0(Llyiahf/vczjk/jl5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    return-void
.end method

.method public o000OOo()V
    .locals 0

    return-void
.end method

.method public o0O0O00()V
    .locals 0

    return-void
.end method

.method public o0OO00O()V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v0, :cond_0

    const-string v0, "node attached multiple times"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/jl5;->OooOo00:Llyiahf/vczjk/v16;

    if-eqz v0, :cond_1

    goto :goto_0

    :cond_1
    const-string v0, "attach invoked on a node without a coordinator"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :goto_0
    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    iput-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOo0o:Z

    return-void
.end method

.method public final o0OOO0o()Llyiahf/vczjk/xr1;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/jl5;->OooOOO:Llyiahf/vczjk/to1;

    if-nez v0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getCoroutineContext()Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/xa;

    invoke-virtual {v1}, Llyiahf/vczjk/xa;->getCoroutineContext()Llyiahf/vczjk/or1;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/ws7;->OooOOo0:Llyiahf/vczjk/ws7;

    invoke-interface {v1, v2}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/v74;

    new-instance v2, Llyiahf/vczjk/x74;

    invoke-direct {v2, v1}, Llyiahf/vczjk/x74;-><init>(Llyiahf/vczjk/v74;)V

    invoke-interface {v0, v2}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooO0oO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/to1;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/jl5;->OooOOO:Llyiahf/vczjk/to1;

    :cond_0
    return-object v0
.end method

.method public o0Oo0oo()Z
    .locals 1

    instance-of v0, p0, Llyiahf/vczjk/n93;

    xor-int/lit8 v0, v0, 0x1

    return v0
.end method

.method public oo0o0Oo()V
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    const-string v0, "Cannot detach a node that is not attached"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOo0o:Z

    if-eqz v0, :cond_1

    const-string v0, "Must run runAttachLifecycle() before markAsDetached()"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_1
    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOo:Z

    if-eqz v0, :cond_2

    const-string v0, "Must run runDetachLifecycle() before markAsDetached()"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_2
    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    iget-object v0, p0, Llyiahf/vczjk/jl5;->OooOOO:Llyiahf/vczjk/to1;

    if-eqz v0, :cond_3

    new-instance v1, Llyiahf/vczjk/r23;

    const-string v2, "The Modifier.Node was detached"

    const/4 v3, 0x1

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/r23;-><init>(Ljava/lang/String;I)V

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo0(Llyiahf/vczjk/xr1;Ljava/util/concurrent/CancellationException;)V

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/jl5;->OooOOO:Llyiahf/vczjk/to1;

    :cond_3
    return-void
.end method
