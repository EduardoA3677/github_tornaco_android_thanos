.class public final Llyiahf/vczjk/nq3;
.super Llyiahf/vczjk/ig9;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o:I

.field public final synthetic OooO0o0:Llyiahf/vczjk/qq3;


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/qq3;ILlyiahf/vczjk/fq2;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/nq3;->OooO0o0:Llyiahf/vczjk/qq3;

    iput p3, p0, Llyiahf/vczjk/nq3;->OooO0o:I

    const/4 p2, 0x1

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ig9;-><init>(Ljava/lang/String;Z)V

    return-void
.end method


# virtual methods
.method public final OooO00o()J
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/nq3;->OooO0o0:Llyiahf/vczjk/qq3;

    iget-object v0, v0, Llyiahf/vczjk/qq3;->OooOo0o:Llyiahf/vczjk/xj0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p0, Llyiahf/vczjk/nq3;->OooO0o0:Llyiahf/vczjk/qq3;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/nq3;->OooO0o0:Llyiahf/vczjk/qq3;

    iget-object v1, v1, Llyiahf/vczjk/qq3;->Oooo0OO:Ljava/util/LinkedHashSet;

    iget v2, p0, Llyiahf/vczjk/nq3;->OooO0o:I

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-interface {v1, v2}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    const-wide/16 v0, -0x1

    return-wide v0

    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1
.end method
