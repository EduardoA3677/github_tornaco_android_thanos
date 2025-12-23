.class public final Llyiahf/vczjk/hl8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sc2;


# instance fields
.field public final OooOOO:J

.field public final OooOOO0:Llyiahf/vczjk/jl8;

.field public final OooOOOO:Ljava/lang/Object;

.field public final OooOOOo:Llyiahf/vczjk/yp0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jl8;JLjava/lang/Object;Llyiahf/vczjk/yp0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/hl8;->OooOOO0:Llyiahf/vczjk/jl8;

    iput-wide p2, p0, Llyiahf/vczjk/hl8;->OooOOO:J

    iput-object p4, p0, Llyiahf/vczjk/hl8;->OooOOOO:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/hl8;->OooOOOo:Llyiahf/vczjk/yp0;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/hl8;->OooOOO0:Llyiahf/vczjk/jl8;

    monitor-enter v0

    :try_start_0
    iget-wide v1, p0, Llyiahf/vczjk/hl8;->OooOOO:J

    invoke-virtual {v0}, Llyiahf/vczjk/jl8;->OooOo00()J

    move-result-wide v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    cmp-long v1, v1, v3

    if-gez v1, :cond_0

    monitor-exit v0

    return-void

    :cond_0
    :try_start_1
    iget-object v1, v0, Llyiahf/vczjk/jl8;->OooOo00:[Ljava/lang/Object;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-wide v2, p0, Llyiahf/vczjk/hl8;->OooOOO:J

    long-to-int v4, v2

    array-length v5, v1

    add-int/lit8 v5, v5, -0x1

    and-int/2addr v4, v5

    aget-object v4, v1, v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-eq v4, p0, :cond_1

    monitor-exit v0

    return-void

    :cond_1
    :try_start_2
    sget-object v4, Llyiahf/vczjk/zsa;->OooO0oo:Llyiahf/vczjk/h87;

    invoke-static {v1, v2, v3, v4}, Llyiahf/vczjk/zsa;->OooOo0O([Ljava/lang/Object;JLjava/lang/Object;)V

    invoke-virtual {v0}, Llyiahf/vczjk/jl8;->OooOOOO()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    monitor-exit v0

    return-void

    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1
.end method
