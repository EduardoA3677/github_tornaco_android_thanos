.class public final Llyiahf/vczjk/zb2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Closeable;
.implements Ljava/lang/AutoCloseable;


# instance fields
.field public OooOOO:Z

.field public final OooOOO0:Llyiahf/vczjk/yb2;

.field public final synthetic OooOOOO:Llyiahf/vczjk/cc2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cc2;Llyiahf/vczjk/yb2;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zb2;->OooOOOO:Llyiahf/vczjk/cc2;

    iput-object p2, p0, Llyiahf/vczjk/zb2;->OooOOO0:Llyiahf/vczjk/yb2;

    return-void
.end method


# virtual methods
.method public final close()V
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/zb2;->OooOOO:Z

    if-nez v0, :cond_1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/zb2;->OooOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/zb2;->OooOOOO:Llyiahf/vczjk/cc2;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/zb2;->OooOOO0:Llyiahf/vczjk/yb2;

    iget v2, v1, Llyiahf/vczjk/yb2;->OooO0oo:I

    add-int/lit8 v2, v2, -0x1

    iput v2, v1, Llyiahf/vczjk/yb2;->OooO0oo:I

    if-nez v2, :cond_0

    iget-boolean v2, v1, Llyiahf/vczjk/yb2;->OooO0o:Z

    if-eqz v2, :cond_0

    sget-object v2, Llyiahf/vczjk/cc2;->OooOoo:Llyiahf/vczjk/on7;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/cc2;->OoooOO0(Llyiahf/vczjk/yb2;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_0
    monitor-exit v0

    return-void

    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1

    :cond_1
    return-void
.end method
