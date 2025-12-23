.class public final Llyiahf/vczjk/to7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xr1;
.implements Llyiahf/vczjk/no7;


# static fields
.field public static final OooOOOo:Llyiahf/vczjk/bq0;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/to7;

.field public final OooOOO0:Llyiahf/vczjk/or1;

.field public volatile OooOOOO:Llyiahf/vczjk/or1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/bq0;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/bq0;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/to7;->OooOOOo:Llyiahf/vczjk/bq0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/or1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/to7;->OooOOO0:Llyiahf/vczjk/or1;

    iput-object p0, p0, Llyiahf/vczjk/to7;->OooOOO:Llyiahf/vczjk/to7;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/to7;->OooO0Oo()V

    return-void
.end method

.method public final OooO0O0()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/to7;->OooO0Oo()V

    return-void
.end method

.method public final OooO0OO()V
    .locals 0

    return-void
.end method

.method public final OooO0Oo()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/to7;->OooOOO:Llyiahf/vczjk/to7;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/to7;->OooOOOO:Llyiahf/vczjk/or1;

    if-nez v1, :cond_0

    sget-object v1, Llyiahf/vczjk/to7;->OooOOOo:Llyiahf/vczjk/bq0;

    iput-object v1, p0, Llyiahf/vczjk/to7;->OooOOOO:Llyiahf/vczjk/or1;

    goto :goto_0

    :catchall_0
    move-exception v1

    goto :goto_1

    :cond_0
    new-instance v2, Llyiahf/vczjk/tb3;

    const/4 v3, 0x0

    invoke-direct {v2, v3}, Llyiahf/vczjk/tb3;-><init>(I)V

    invoke-static {v1, v2}, Llyiahf/vczjk/zsa;->OooOoOO(Llyiahf/vczjk/or1;Ljava/util/concurrent/CancellationException;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :goto_0
    monitor-exit v0

    return-void

    :goto_1
    monitor-exit v0

    throw v1
.end method

.method public final OoooOO0()Llyiahf/vczjk/or1;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/to7;->OooOOOO:Llyiahf/vczjk/or1;

    if-eqz v0, :cond_0

    sget-object v1, Llyiahf/vczjk/to7;->OooOOOo:Llyiahf/vczjk/bq0;

    if-ne v0, v1, :cond_3

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/to7;->OooOOO:Llyiahf/vczjk/to7;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/to7;->OooOOOO:Llyiahf/vczjk/or1;

    if-nez v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/to7;->OooOOO0:Llyiahf/vczjk/or1;

    sget-object v2, Llyiahf/vczjk/ws7;->OooOOo0:Llyiahf/vczjk/ws7;

    invoke-interface {v1, v2}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/v74;

    new-instance v3, Llyiahf/vczjk/x74;

    invoke-direct {v3, v2}, Llyiahf/vczjk/x74;-><init>(Llyiahf/vczjk/v74;)V

    invoke-interface {v1, v3}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    invoke-interface {v1, v2}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v1

    goto :goto_0

    :catchall_0
    move-exception v1

    goto :goto_1

    :cond_1
    sget-object v2, Llyiahf/vczjk/to7;->OooOOOo:Llyiahf/vczjk/bq0;

    if-ne v1, v2, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/to7;->OooOOO0:Llyiahf/vczjk/or1;

    sget-object v2, Llyiahf/vczjk/ws7;->OooOOo0:Llyiahf/vczjk/ws7;

    invoke-interface {v1, v2}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/v74;

    new-instance v3, Llyiahf/vczjk/x74;

    invoke-direct {v3, v2}, Llyiahf/vczjk/x74;-><init>(Llyiahf/vczjk/v74;)V

    new-instance v2, Llyiahf/vczjk/tb3;

    const/4 v4, 0x0

    invoke-direct {v2, v4}, Llyiahf/vczjk/tb3;-><init>(I)V

    invoke-virtual {v3, v2}, Llyiahf/vczjk/k84;->OooOOoo(Ljava/util/concurrent/CancellationException;)V

    invoke-interface {v1, v3}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    invoke-interface {v1, v2}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v1

    :cond_2
    :goto_0
    iput-object v1, p0, Llyiahf/vczjk/to7;->OooOOOO:Llyiahf/vczjk/or1;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    move-object v0, v1

    :cond_3
    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-object v0

    :goto_1
    monitor-exit v0

    throw v1
.end method
