.class public final Llyiahf/vczjk/hz6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/l48;


# instance fields
.field public final OooOOO:J

.field public final OooOOO0:Llyiahf/vczjk/l48;

.field public final synthetic OooOOOO:Llyiahf/vczjk/oz6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oz6;Llyiahf/vczjk/l48;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-string v0, "delegate"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/hz6;->OooOOOO:Llyiahf/vczjk/oz6;

    iput-object p2, p0, Llyiahf/vczjk/hz6;->OooOOO0:Llyiahf/vczjk/l48;

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOOO0()J

    move-result-wide p1

    iput-wide p1, p0, Llyiahf/vczjk/hz6;->OooOOO:J

    return-void
.end method


# virtual methods
.method public final OooO0OO(IJ)V
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOOO:Llyiahf/vczjk/oz6;

    iget-object v0, v0, Llyiahf/vczjk/oz6;->OooO0Oo:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v0

    const/4 v1, 0x0

    const/16 v2, 0x15

    if-nez v0, :cond_1

    iget-wide v3, p0, Llyiahf/vczjk/hz6;->OooOOO:J

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOOO0()J

    move-result-wide v5

    cmp-long v0, v3, v5

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOO0:Llyiahf/vczjk/l48;

    invoke-interface {v0, p1, p2, p3}, Llyiahf/vczjk/l48;->OooO0OO(IJ)V

    return-void

    :cond_0
    const-string p1, "Attempted to use statement on a different thread"

    invoke-static {v2, p1}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1

    :cond_1
    const-string p1, "Statement is recycled"

    invoke-static {v2, p1}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1
.end method

.method public final OooO0o0(I)V
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOOO:Llyiahf/vczjk/oz6;

    iget-object v0, v0, Llyiahf/vczjk/oz6;->OooO0Oo:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v0

    const/4 v1, 0x0

    const/16 v2, 0x15

    if-nez v0, :cond_1

    iget-wide v3, p0, Llyiahf/vczjk/hz6;->OooOOO:J

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOOO0()J

    move-result-wide v5

    cmp-long v0, v3, v5

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOO0:Llyiahf/vczjk/l48;

    invoke-interface {v0, p1}, Llyiahf/vczjk/l48;->OooO0o0(I)V

    return-void

    :cond_0
    const-string p1, "Attempted to use statement on a different thread"

    invoke-static {v2, p1}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1

    :cond_1
    const-string p1, "Statement is recycled"

    invoke-static {v2, p1}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1
.end method

.method public final OooOoo0(ILjava/lang/String;)V
    .locals 7

    const-string v0, "value"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOOO:Llyiahf/vczjk/oz6;

    iget-object v0, v0, Llyiahf/vczjk/oz6;->OooO0Oo:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v0

    const/4 v1, 0x0

    const/16 v2, 0x15

    if-nez v0, :cond_1

    iget-wide v3, p0, Llyiahf/vczjk/hz6;->OooOOO:J

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOOO0()J

    move-result-wide v5

    cmp-long v0, v3, v5

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOO0:Llyiahf/vczjk/l48;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/l48;->OooOoo0(ILjava/lang/String;)V

    return-void

    :cond_0
    const-string p1, "Attempted to use statement on a different thread"

    invoke-static {v2, p1}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1

    :cond_1
    const-string p1, "Statement is recycled"

    invoke-static {v2, p1}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1
.end method

.method public final Oooo0o(I)Z
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOOO:Llyiahf/vczjk/oz6;

    iget-object v0, v0, Llyiahf/vczjk/oz6;->OooO0Oo:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v0

    const/4 v1, 0x0

    const/16 v2, 0x15

    if-nez v0, :cond_1

    iget-wide v3, p0, Llyiahf/vczjk/hz6;->OooOOO:J

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOOO0()J

    move-result-wide v5

    cmp-long v0, v3, v5

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOO0:Llyiahf/vczjk/l48;

    invoke-interface {v0, p1}, Llyiahf/vczjk/l48;->Oooo0o(I)Z

    move-result p1

    return p1

    :cond_0
    const-string p1, "Attempted to use statement on a different thread"

    invoke-static {v2, p1}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1

    :cond_1
    const-string p1, "Statement is recycled"

    invoke-static {v2, p1}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1
.end method

.method public final Oooo0oo(I)Ljava/lang/String;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOOO:Llyiahf/vczjk/oz6;

    iget-object v0, v0, Llyiahf/vczjk/oz6;->OooO0Oo:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v0

    const/4 v1, 0x0

    const/16 v2, 0x15

    if-nez v0, :cond_1

    iget-wide v3, p0, Llyiahf/vczjk/hz6;->OooOOO:J

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOOO0()J

    move-result-wide v5

    cmp-long v0, v3, v5

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOO0:Llyiahf/vczjk/l48;

    invoke-interface {v0, p1}, Llyiahf/vczjk/l48;->Oooo0oo(I)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_0
    const-string p1, "Attempted to use statement on a different thread"

    invoke-static {v2, p1}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1

    :cond_1
    const-string p1, "Statement is recycled"

    invoke-static {v2, p1}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1
.end method

.method public final OooooOO(I)Ljava/lang/String;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOOO:Llyiahf/vczjk/oz6;

    iget-object v0, v0, Llyiahf/vczjk/oz6;->OooO0Oo:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v0

    const/4 v1, 0x0

    const/16 v2, 0x15

    if-nez v0, :cond_1

    iget-wide v3, p0, Llyiahf/vczjk/hz6;->OooOOO:J

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOOO0()J

    move-result-wide v5

    cmp-long v0, v3, v5

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOO0:Llyiahf/vczjk/l48;

    invoke-interface {v0, p1}, Llyiahf/vczjk/l48;->OooooOO(I)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_0
    const-string p1, "Attempted to use statement on a different thread"

    invoke-static {v2, p1}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1

    :cond_1
    const-string p1, "Statement is recycled"

    invoke-static {v2, p1}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1
.end method

.method public final OooooOo()I
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOOO:Llyiahf/vczjk/oz6;

    iget-object v0, v0, Llyiahf/vczjk/oz6;->OooO0Oo:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v0

    const/4 v1, 0x0

    const/16 v2, 0x15

    if-nez v0, :cond_1

    iget-wide v3, p0, Llyiahf/vczjk/hz6;->OooOOO:J

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOOO0()J

    move-result-wide v5

    cmp-long v0, v3, v5

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOO0:Llyiahf/vczjk/l48;

    invoke-interface {v0}, Llyiahf/vczjk/l48;->OooooOo()I

    move-result v0

    return v0

    :cond_0
    const-string v0, "Attempted to use statement on a different thread"

    invoke-static {v2, v0}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1

    :cond_1
    const-string v0, "Statement is recycled"

    invoke-static {v2, v0}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1
.end method

.method public final close()V
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOOO:Llyiahf/vczjk/oz6;

    iget-object v0, v0, Llyiahf/vczjk/oz6;->OooO0Oo:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v0

    const/4 v1, 0x0

    const/16 v2, 0x15

    if-nez v0, :cond_1

    iget-wide v3, p0, Llyiahf/vczjk/hz6;->OooOOO:J

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOOO0()J

    move-result-wide v5

    cmp-long v0, v3, v5

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOO0:Llyiahf/vczjk/l48;

    invoke-interface {v0}, Ljava/lang/AutoCloseable;->close()V

    return-void

    :cond_0
    const-string v0, "Attempted to use statement on a different thread"

    invoke-static {v2, v0}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1

    :cond_1
    const-string v0, "Statement is recycled"

    invoke-static {v2, v0}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1
.end method

.method public final getLong(I)J
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOOO:Llyiahf/vczjk/oz6;

    iget-object v0, v0, Llyiahf/vczjk/oz6;->OooO0Oo:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v0

    const/4 v1, 0x0

    const/16 v2, 0x15

    if-nez v0, :cond_1

    iget-wide v3, p0, Llyiahf/vczjk/hz6;->OooOOO:J

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOOO0()J

    move-result-wide v5

    cmp-long v0, v3, v5

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOO0:Llyiahf/vczjk/l48;

    invoke-interface {v0, p1}, Llyiahf/vczjk/l48;->getLong(I)J

    move-result-wide v0

    return-wide v0

    :cond_0
    const-string p1, "Attempted to use statement on a different thread"

    invoke-static {v2, p1}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1

    :cond_1
    const-string p1, "Statement is recycled"

    invoke-static {v2, p1}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1
.end method

.method public final o000000()Z
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOOO:Llyiahf/vczjk/oz6;

    iget-object v0, v0, Llyiahf/vczjk/oz6;->OooO0Oo:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v0

    const/4 v1, 0x0

    const/16 v2, 0x15

    if-nez v0, :cond_1

    iget-wide v3, p0, Llyiahf/vczjk/hz6;->OooOOO:J

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOOO0()J

    move-result-wide v5

    cmp-long v0, v3, v5

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOO0:Llyiahf/vczjk/l48;

    invoke-interface {v0}, Llyiahf/vczjk/l48;->o000000()Z

    move-result v0

    return v0

    :cond_0
    const-string v0, "Attempted to use statement on a different thread"

    invoke-static {v2, v0}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1

    :cond_1
    const-string v0, "Statement is recycled"

    invoke-static {v2, v0}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1
.end method

.method public final reset()V
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOOO:Llyiahf/vczjk/oz6;

    iget-object v0, v0, Llyiahf/vczjk/oz6;->OooO0Oo:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    move-result v0

    const/4 v1, 0x0

    const/16 v2, 0x15

    if-nez v0, :cond_1

    iget-wide v3, p0, Llyiahf/vczjk/hz6;->OooOOO:J

    invoke-static {}, Llyiahf/vczjk/ht6;->OooOOO0()J

    move-result-wide v5

    cmp-long v0, v3, v5

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/hz6;->OooOOO0:Llyiahf/vczjk/l48;

    invoke-interface {v0}, Llyiahf/vczjk/l48;->reset()V

    return-void

    :cond_0
    const-string v0, "Attempted to use statement on a different thread"

    invoke-static {v2, v0}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1

    :cond_1
    const-string v0, "Statement is recycled"

    invoke-static {v2, v0}, Llyiahf/vczjk/vl6;->OooOooo(ILjava/lang/String;)V

    throw v1
.end method
