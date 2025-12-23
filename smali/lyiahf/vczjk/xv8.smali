.class public abstract Llyiahf/vczjk/xv8;
.super Llyiahf/vczjk/c39;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/dw8;
.implements Llyiahf/vczjk/p29;
.implements Llyiahf/vczjk/qs5;


# instance fields
.field public final synthetic OooOOO:I

.field public OooOOOO:Llyiahf/vczjk/d39;


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/xv8;->OooOOO:I

    invoke-direct {p0}, Llyiahf/vczjk/c39;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/d39;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/xv8;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/cw8;

    iput-object p1, p0, Llyiahf/vczjk/xv8;->OooOOOO:Llyiahf/vczjk/d39;

    return-void

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/wv8;

    iput-object p1, p0, Llyiahf/vczjk/xv8;->OooOOOO:Llyiahf/vczjk/d39;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO00o(Llyiahf/vczjk/d39;Llyiahf/vczjk/d39;Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;
    .locals 4

    iget p1, p0, Llyiahf/vczjk/xv8;->OooOOO:I

    packed-switch p1, :pswitch_data_0

    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/cw8;

    check-cast p3, Llyiahf/vczjk/cw8;

    iget-wide v0, p1, Llyiahf/vczjk/cw8;->OooO0OO:J

    iget-wide v2, p3, Llyiahf/vczjk/cw8;->OooO0OO:J

    cmp-long p1, v0, v2

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    return-object p2

    :pswitch_0
    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/wv8;

    check-cast p3, Llyiahf/vczjk/wv8;

    iget-wide v0, p1, Llyiahf/vczjk/wv8;->OooO0OO:D

    iget-wide v2, p3, Llyiahf/vczjk/wv8;->OooO0OO:D

    cmpg-double p1, v0, v2

    if-nez p1, :cond_1

    goto :goto_1

    :cond_1
    const/4 p2, 0x0

    :goto_1
    return-object p2

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0O0()Llyiahf/vczjk/d39;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/xv8;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/xv8;->OooOOOO:Llyiahf/vczjk/d39;

    check-cast v0, Llyiahf/vczjk/cw8;

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/xv8;->OooOOOO:Llyiahf/vczjk/d39;

    check-cast v0, Llyiahf/vczjk/wv8;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0o()Llyiahf/vczjk/gw8;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/xv8;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    sget-object v0, Llyiahf/vczjk/rp3;->OooOo0O:Llyiahf/vczjk/rp3;

    return-object v0

    :pswitch_0
    sget-object v0, Llyiahf/vczjk/rp3;->OooOo0O:Llyiahf/vczjk/rp3;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public OooOOoo(J)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/xv8;->OooOOOO:Llyiahf/vczjk/d39;

    check-cast v0, Llyiahf/vczjk/cw8;

    invoke-static {v0}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cw8;

    iget-wide v1, v0, Llyiahf/vczjk/cw8;->OooO0OO:J

    cmp-long v1, v1, p1

    if-eqz v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/xv8;->OooOOOO:Llyiahf/vczjk/d39;

    check-cast v1, Llyiahf/vczjk/cw8;

    sget-object v2, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v2

    :try_start_0
    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v3

    invoke-static {v1, p0, v3, v0}, Llyiahf/vczjk/vv8;->OooOOOO(Llyiahf/vczjk/d39;Llyiahf/vczjk/c39;Llyiahf/vczjk/nv8;Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cw8;

    iput-wide p1, v0, Llyiahf/vczjk/cw8;->OooO0OO:J
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

.method public getValue()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/xv8;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/xv8;->OooOOOO:Llyiahf/vczjk/d39;

    check-cast v0, Llyiahf/vczjk/cw8;

    invoke-static {v0, p0}, Llyiahf/vczjk/vv8;->OooOo00(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cw8;

    iget-wide v0, v0, Llyiahf/vczjk/cw8;->OooO0OO:J

    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/xv8;->OooOOOO:Llyiahf/vczjk/d39;

    check-cast v0, Llyiahf/vczjk/wv8;

    invoke-static {v0, p0}, Llyiahf/vczjk/vv8;->OooOo00(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/wv8;

    iget-wide v0, v0, Llyiahf/vczjk/wv8;->OooO0OO:D

    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public setValue(Ljava/lang/Object;)V
    .locals 5

    iget v0, p0, Llyiahf/vczjk/xv8;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    move-result-wide v0

    invoke-virtual {p0, v0, v1}, Llyiahf/vczjk/xv8;->OooOOoo(J)V

    return-void

    :pswitch_0
    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->doubleValue()D

    move-result-wide v0

    iget-object p1, p0, Llyiahf/vczjk/xv8;->OooOOOO:Llyiahf/vczjk/d39;

    check-cast p1, Llyiahf/vczjk/wv8;

    invoke-static {p1}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wv8;

    iget-wide v2, p1, Llyiahf/vczjk/wv8;->OooO0OO:D

    cmpg-double v2, v2, v0

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    iget-object v2, p0, Llyiahf/vczjk/xv8;->OooOOOO:Llyiahf/vczjk/d39;

    check-cast v2, Llyiahf/vczjk/wv8;

    sget-object v3, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v3

    :try_start_0
    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v4

    invoke-static {v2, p0, v4, p1}, Llyiahf/vczjk/vv8;->OooOOOO(Llyiahf/vczjk/d39;Llyiahf/vczjk/c39;Llyiahf/vczjk/nv8;Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wv8;

    iput-wide v0, p1, Llyiahf/vczjk/wv8;->OooO0OO:D
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v3

    invoke-static {v4, p0}, Llyiahf/vczjk/vv8;->OooOOO(Llyiahf/vczjk/nv8;Llyiahf/vczjk/b39;)V

    :goto_0
    return-void

    :catchall_0
    move-exception p1

    monitor-exit v3

    throw p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/xv8;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/xv8;->OooOOOO:Llyiahf/vczjk/d39;

    check-cast v0, Llyiahf/vczjk/cw8;

    invoke-static {v0}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cw8;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "MutableLongState(value="

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-wide v2, v0, Llyiahf/vczjk/cw8;->OooO0OO:J

    invoke-virtual {v1, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string v0, ")@"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/xv8;->OooOOOO:Llyiahf/vczjk/d39;

    check-cast v0, Llyiahf/vczjk/wv8;

    invoke-static {v0}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/wv8;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "MutableDoubleState(value="

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-wide v2, v0, Llyiahf/vczjk/wv8;->OooO0OO:D

    invoke-virtual {v1, v2, v3}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    const-string v0, ")@"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
