.class public final Llyiahf/vczjk/lq3;
.super Llyiahf/vczjk/ig9;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o:I

.field public final synthetic OooO0o0:Llyiahf/vczjk/qq3;

.field public final synthetic OooO0oO:Llyiahf/vczjk/yi0;

.field public final synthetic OooO0oo:I


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/qq3;ILlyiahf/vczjk/yi0;IZ)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/lq3;->OooO0o0:Llyiahf/vczjk/qq3;

    iput p3, p0, Llyiahf/vczjk/lq3;->OooO0o:I

    iput-object p4, p0, Llyiahf/vczjk/lq3;->OooO0oO:Llyiahf/vczjk/yi0;

    iput p5, p0, Llyiahf/vczjk/lq3;->OooO0oo:I

    const/4 p2, 0x1

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ig9;-><init>(Ljava/lang/String;Z)V

    return-void
.end method


# virtual methods
.method public final OooO00o()J
    .locals 4

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/lq3;->OooO0o0:Llyiahf/vczjk/qq3;

    iget-object v0, v0, Llyiahf/vczjk/qq3;->OooOo0o:Llyiahf/vczjk/xj0;

    iget-object v1, p0, Llyiahf/vczjk/lq3;->OooO0oO:Llyiahf/vczjk/yi0;

    iget v2, p0, Llyiahf/vczjk/lq3;->OooO0oo:I

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    int-to-long v2, v2

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/yi0;->skip(J)V

    iget-object v0, p0, Llyiahf/vczjk/lq3;->OooO0o0:Llyiahf/vczjk/qq3;

    iget-object v0, v0, Llyiahf/vczjk/qq3;->Oooo0:Llyiahf/vczjk/yq3;

    iget v1, p0, Llyiahf/vczjk/lq3;->OooO0o:I

    sget-object v2, Llyiahf/vczjk/fq2;->OooOOo:Llyiahf/vczjk/fq2;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/yq3;->OooOooo(ILlyiahf/vczjk/fq2;)V

    iget-object v0, p0, Llyiahf/vczjk/lq3;->OooO0o0:Llyiahf/vczjk/qq3;

    monitor-enter v0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    :try_start_1
    iget-object v1, p0, Llyiahf/vczjk/lq3;->OooO0o0:Llyiahf/vczjk/qq3;

    iget-object v1, v1, Llyiahf/vczjk/qq3;->Oooo0OO:Ljava/util/LinkedHashSet;

    iget v2, p0, Llyiahf/vczjk/lq3;->OooO0o:I

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-interface {v1, v2}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :try_start_2
    monitor-exit v0

    goto :goto_0

    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    :catch_0
    :goto_0
    const-wide/16 v0, -0x1

    return-wide v0
.end method
