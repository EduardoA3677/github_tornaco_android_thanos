.class public abstract Llyiahf/vczjk/hc2;
.super Llyiahf/vczjk/jg9;
.source "SourceFile"


# instance fields
.field public OooOOOO:I


# direct methods
.method public constructor <init>(I)V
    .locals 3

    const-wide/16 v0, 0x0

    const/4 v2, 0x0

    invoke-direct {p0, v0, v1, v2}, Llyiahf/vczjk/jg9;-><init>(JZ)V

    iput p1, p0, Llyiahf/vczjk/hc2;->OooOOOO:I

    return-void
.end method


# virtual methods
.method public OooO0O0(Ljava/util/concurrent/CancellationException;)V
    .locals 0

    return-void
.end method

.method public abstract OooO0OO()Llyiahf/vczjk/yo1;
.end method

.method public OooO0Oo(Ljava/lang/Object;)Ljava/lang/Throwable;
    .locals 2

    instance-of v0, p1, Llyiahf/vczjk/j61;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/j61;

    goto :goto_0

    :cond_0
    move-object p1, v1

    :goto_0
    if-eqz p1, :cond_1

    iget-object p1, p1, Llyiahf/vczjk/j61;->OooO00o:Ljava/lang/Throwable;

    return-object p1

    :cond_1
    return-object v1
.end method

.method public final OooO0o(Ljava/lang/Throwable;)V
    .locals 3

    new-instance v0, Llyiahf/vczjk/es1;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Fatal exception in coroutines machinery for "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, ". Please read KDoc to \'handleFatalException\' method and report this incident to maintainers"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1, p1}, Ljava/lang/Error;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    invoke-virtual {p0}, Llyiahf/vczjk/hc2;->OooO0OO()Llyiahf/vczjk/yo1;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/u34;->OooOooO(Ljava/lang/Throwable;Llyiahf/vczjk/or1;)V

    return-void
.end method

.method public OooO0o0(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    return-object p1
.end method

.method public abstract OooO0oO()Ljava/lang/Object;
.end method

.method public final run()V
    .locals 11

    :try_start_0
    invoke-virtual {p0}, Llyiahf/vczjk/hc2;->OooO0OO()Llyiahf/vczjk/yo1;

    move-result-object v0

    const-string v1, "null cannot be cast to non-null type kotlinx.coroutines.internal.DispatchedContinuation<T of kotlinx.coroutines.DispatchedTask>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/fc2;

    iget-object v1, v0, Llyiahf/vczjk/fc2;->OooOOo0:Llyiahf/vczjk/zo1;

    iget-object v0, v0, Llyiahf/vczjk/fc2;->OooOOoo:Ljava/lang/Object;

    invoke-interface {v1}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v2

    invoke-static {v2, v0}, Llyiahf/vczjk/jp8;->OooooO0(Llyiahf/vczjk/or1;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    sget-object v3, Llyiahf/vczjk/jp8;->OooOOo:Llyiahf/vczjk/h87;

    const/4 v4, 0x0

    if-eq v0, v3, :cond_0

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/t51;->Oooooo0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/or1;Ljava/lang/Object;)Llyiahf/vczjk/k8a;

    move-result-object v3
    :try_end_0
    .catch Llyiahf/vczjk/dc2; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    goto/16 :goto_5

    :catch_0
    move-exception v0

    goto/16 :goto_6

    :cond_0
    move-object v3, v4

    :goto_0
    :try_start_1
    invoke-interface {v1}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v5

    invoke-virtual {p0}, Llyiahf/vczjk/hc2;->OooO0oO()Ljava/lang/Object;

    move-result-object v6

    invoke-virtual {p0, v6}, Llyiahf/vczjk/hc2;->OooO0Oo(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v7

    if-nez v7, :cond_3

    iget v8, p0, Llyiahf/vczjk/hc2;->OooOOOO:I

    const/4 v9, 0x1

    if-eq v8, v9, :cond_2

    const/4 v10, 0x2

    if-ne v8, v10, :cond_1

    goto :goto_1

    :cond_1
    const/4 v9, 0x0

    :cond_2
    :goto_1
    if-eqz v9, :cond_3

    sget-object v4, Llyiahf/vczjk/ws7;->OooOOo0:Llyiahf/vczjk/ws7;

    invoke-interface {v5, v4}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/v74;

    goto :goto_2

    :catchall_1
    move-exception v1

    goto :goto_4

    :cond_3
    :goto_2
    if-eqz v4, :cond_4

    invoke-interface {v4}, Llyiahf/vczjk/v74;->OooO0Oo()Z

    move-result v5

    if-nez v5, :cond_4

    invoke-interface {v4}, Llyiahf/vczjk/v74;->OooOoOO()Ljava/util/concurrent/CancellationException;

    move-result-object v4

    invoke-virtual {p0, v4}, Llyiahf/vczjk/hc2;->OooO0O0(Ljava/util/concurrent/CancellationException;)V

    invoke-static {v4}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v4

    invoke-interface {v1, v4}, Llyiahf/vczjk/yo1;->resumeWith(Ljava/lang/Object;)V

    goto :goto_3

    :cond_4
    if-eqz v7, :cond_5

    invoke-static {v7}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v4

    invoke-interface {v1, v4}, Llyiahf/vczjk/yo1;->resumeWith(Ljava/lang/Object;)V

    goto :goto_3

    :cond_5
    invoke-virtual {p0, v6}, Llyiahf/vczjk/hc2;->OooO0o0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    invoke-interface {v1, v4}, Llyiahf/vczjk/yo1;->resumeWith(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :goto_3
    if-eqz v3, :cond_6

    :try_start_2
    invoke-virtual {v3}, Llyiahf/vczjk/k8a;->Ooooooo()Z

    move-result v1

    if-eqz v1, :cond_9

    :cond_6
    invoke-static {v2, v0}, Llyiahf/vczjk/jp8;->OoooOO0(Llyiahf/vczjk/or1;Ljava/lang/Object;)V

    return-void

    :goto_4
    if-eqz v3, :cond_7

    invoke-virtual {v3}, Llyiahf/vczjk/k8a;->Ooooooo()Z

    move-result v3

    if-eqz v3, :cond_8

    :cond_7
    invoke-static {v2, v0}, Llyiahf/vczjk/jp8;->OoooOO0(Llyiahf/vczjk/or1;Ljava/lang/Object;)V

    :cond_8
    throw v1
    :try_end_2
    .catch Llyiahf/vczjk/dc2; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    :goto_5
    invoke-virtual {p0, v0}, Llyiahf/vczjk/hc2;->OooO0o(Ljava/lang/Throwable;)V

    goto :goto_7

    :goto_6
    invoke-virtual {p0}, Llyiahf/vczjk/hc2;->OooO0OO()Llyiahf/vczjk/yo1;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v1

    invoke-virtual {v0}, Llyiahf/vczjk/dc2;->getCause()Ljava/lang/Throwable;

    move-result-object v0

    invoke-static {v0, v1}, Llyiahf/vczjk/u34;->OooOooO(Ljava/lang/Throwable;Llyiahf/vczjk/or1;)V

    :cond_9
    :goto_7
    return-void
.end method
