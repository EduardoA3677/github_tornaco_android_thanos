.class public final Llyiahf/vczjk/qw8;
.super Llyiahf/vczjk/d39;
.source "SourceFile"


# instance fields
.field public OooO0OO:Llyiahf/vczjk/o00O;

.field public OooO0Oo:I

.field public OooO0o0:I


# direct methods
.method public constructor <init>(JLlyiahf/vczjk/o00O;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/d39;-><init>(J)V

    iput-object p3, p0, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/d39;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/ng0;->OooO0oO:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    const-string v1, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord>"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/qw8;

    iget-object v1, v1, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;

    iput-object v1, p0, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/qw8;

    iget v1, v1, Llyiahf/vczjk/qw8;->OooO0Oo:I

    iput v1, p0, Llyiahf/vczjk/qw8;->OooO0Oo:I

    check-cast p1, Llyiahf/vczjk/qw8;

    iget p1, p1, Llyiahf/vczjk/qw8;->OooO0o0:I

    iput p1, p0, Llyiahf/vczjk/qw8;->OooO0o0:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    return-void

    :catchall_0
    move-exception p1

    monitor-exit v0

    throw p1
.end method

.method public final OooO0O0(J)Llyiahf/vczjk/d39;
    .locals 2

    new-instance v0, Llyiahf/vczjk/qw8;

    iget-object v1, p0, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;

    invoke-direct {v0, p1, p2, v1}, Llyiahf/vczjk/qw8;-><init>(JLlyiahf/vczjk/o00O;)V

    return-object v0
.end method
