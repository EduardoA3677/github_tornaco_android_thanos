.class public abstract Llyiahf/vczjk/pr2;
.super Llyiahf/vczjk/qr1;
.source "SourceFile"


# static fields
.field public static final synthetic OooOOo:I


# instance fields
.field public OooOOOO:J

.field public OooOOOo:Z

.field public OooOOo0:Llyiahf/vczjk/xx;


# virtual methods
.method public final o0000(Z)V
    .locals 4

    iget-wide v0, p0, Llyiahf/vczjk/pr2;->OooOOOO:J

    if-eqz p1, :cond_0

    const-wide v2, 0x100000000L

    goto :goto_0

    :cond_0
    const-wide/16 v2, 0x1

    :goto_0
    sub-long/2addr v0, v2

    iput-wide v0, p0, Llyiahf/vczjk/pr2;->OooOOOO:J

    const-wide/16 v2, 0x0

    cmp-long p1, v0, v2

    if-lez p1, :cond_1

    goto :goto_1

    :cond_1
    iget-boolean p1, p0, Llyiahf/vczjk/pr2;->OooOOOo:Z

    if-eqz p1, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/pr2;->shutdown()V

    :cond_2
    :goto_1
    return-void
.end method

.method public final o00000oo(I)Llyiahf/vczjk/qr1;
    .locals 0

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOoOO(I)V

    return-object p0
.end method

.method public abstract o0000O0()J
.end method

.method public final o0000O00(Llyiahf/vczjk/hc2;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pr2;->OooOOo0:Llyiahf/vczjk/xx;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/xx;

    invoke-direct {v0}, Llyiahf/vczjk/xx;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/pr2;->OooOOo0:Llyiahf/vczjk/xx;

    :cond_0
    invoke-virtual {v0, p1}, Llyiahf/vczjk/xx;->addLast(Ljava/lang/Object;)V

    return-void
.end method

.method public final o0000O0O()Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/pr2;->OooOOo0:Llyiahf/vczjk/xx;

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/xx;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_1

    const/4 v0, 0x0

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/xx;->removeFirst()Ljava/lang/Object;

    move-result-object v0

    :goto_0
    check-cast v0, Llyiahf/vczjk/hc2;

    if-nez v0, :cond_2

    :goto_1
    const/4 v0, 0x0

    return v0

    :cond_2
    invoke-virtual {v0}, Llyiahf/vczjk/hc2;->run()V

    const/4 v0, 0x1

    return v0
.end method

.method public final o0000oO(Z)V
    .locals 4

    iget-wide v0, p0, Llyiahf/vczjk/pr2;->OooOOOO:J

    if-eqz p1, :cond_0

    const-wide v2, 0x100000000L

    goto :goto_0

    :cond_0
    const-wide/16 v2, 0x1

    :goto_0
    add-long/2addr v2, v0

    iput-wide v2, p0, Llyiahf/vczjk/pr2;->OooOOOO:J

    if-nez p1, :cond_1

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/pr2;->OooOOOo:Z

    :cond_1
    return-void
.end method

.method public abstract o0000oo()Ljava/lang/Thread;
.end method

.method public o000OO(JLlyiahf/vczjk/mr2;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/b22;->OooOo0O:Llyiahf/vczjk/b22;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/or2;->o0000OOo(JLlyiahf/vczjk/mr2;)V

    return-void
.end method

.method public abstract shutdown()V
.end method
