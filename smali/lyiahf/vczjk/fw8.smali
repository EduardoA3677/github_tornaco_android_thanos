.class public abstract Llyiahf/vczjk/fw8;
.super Llyiahf/vczjk/c39;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/dw8;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/gw8;

.field public OooOOOO:Llyiahf/vczjk/ew8;


# direct methods
.method public constructor <init>(Ljava/lang/Object;Llyiahf/vczjk/gw8;)V
    .locals 3

    invoke-direct {p0}, Llyiahf/vczjk/c39;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/fw8;->OooOOO:Llyiahf/vczjk/gw8;

    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object p2

    new-instance v0, Llyiahf/vczjk/ew8;

    invoke-virtual {p2}, Llyiahf/vczjk/nv8;->OooO0oO()J

    move-result-wide v1

    invoke-direct {v0, v1, v2, p1}, Llyiahf/vczjk/ew8;-><init>(JLjava/lang/Object;)V

    instance-of p2, p2, Llyiahf/vczjk/li3;

    if-nez p2, :cond_0

    new-instance p2, Llyiahf/vczjk/ew8;

    const/4 v1, 0x1

    int-to-long v1, v1

    invoke-direct {p2, v1, v2, p1}, Llyiahf/vczjk/ew8;-><init>(JLjava/lang/Object;)V

    iput-object p2, v0, Llyiahf/vczjk/d39;->OooO0O0:Llyiahf/vczjk/d39;

    :cond_0
    iput-object v0, p0, Llyiahf/vczjk/fw8;->OooOOOO:Llyiahf/vczjk/ew8;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/d39;)V
    .locals 0

    check-cast p1, Llyiahf/vczjk/ew8;

    iput-object p1, p0, Llyiahf/vczjk/fw8;->OooOOOO:Llyiahf/vczjk/ew8;

    return-void
.end method

.method public final OooO00o(Llyiahf/vczjk/d39;Llyiahf/vczjk/d39;Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;
    .locals 1

    check-cast p1, Llyiahf/vczjk/ew8;

    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/ew8;

    check-cast p3, Llyiahf/vczjk/ew8;

    iget-object p1, p1, Llyiahf/vczjk/ew8;->OooO0OO:Ljava/lang/Object;

    iget-object p3, p3, Llyiahf/vczjk/ew8;->OooO0OO:Ljava/lang/Object;

    iget-object v0, p0, Llyiahf/vczjk/fw8;->OooOOO:Llyiahf/vczjk/gw8;

    invoke-interface {v0, p1, p3}, Llyiahf/vczjk/gw8;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    return-object p2

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooO0O0()Llyiahf/vczjk/d39;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fw8;->OooOOOO:Llyiahf/vczjk/ew8;

    return-object v0
.end method

.method public final OooO0o()Llyiahf/vczjk/gw8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fw8;->OooOOO:Llyiahf/vczjk/gw8;

    return-object v0
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fw8;->OooOOOO:Llyiahf/vczjk/ew8;

    invoke-static {v0, p0}, Llyiahf/vczjk/vv8;->OooOo00(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ew8;

    iget-object v0, v0, Llyiahf/vczjk/ew8;->OooO0OO:Ljava/lang/Object;

    return-object v0
.end method

.method public final setValue(Ljava/lang/Object;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/fw8;->OooOOOO:Llyiahf/vczjk/ew8;

    invoke-static {v0}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ew8;

    iget-object v1, p0, Llyiahf/vczjk/fw8;->OooOOO:Llyiahf/vczjk/gw8;

    iget-object v2, v0, Llyiahf/vczjk/ew8;->OooO0OO:Ljava/lang/Object;

    invoke-interface {v1, v2, p1}, Llyiahf/vczjk/gw8;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/fw8;->OooOOOO:Llyiahf/vczjk/ew8;

    sget-object v2, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v2

    :try_start_0
    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v3

    invoke-static {v1, p0, v3, v0}, Llyiahf/vczjk/vv8;->OooOOOO(Llyiahf/vczjk/d39;Llyiahf/vczjk/c39;Llyiahf/vczjk/nv8;Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ew8;

    iput-object p1, v0, Llyiahf/vczjk/ew8;->OooO0OO:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v2

    invoke-static {v3, p0}, Llyiahf/vczjk/vv8;->OooOOO(Llyiahf/vczjk/nv8;Llyiahf/vczjk/b39;)V

    return-void

    :catchall_0
    move-exception p1

    monitor-exit v2

    throw p1

    :cond_0
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/fw8;->OooOOOO:Llyiahf/vczjk/ew8;

    invoke-static {v0}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ew8;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "MutableState(value="

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v0, v0, Llyiahf/vczjk/ew8;->OooO0OO:Ljava/lang/Object;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, ")@"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
