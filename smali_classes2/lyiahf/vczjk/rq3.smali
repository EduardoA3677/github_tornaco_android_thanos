.class public final Llyiahf/vczjk/rq3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/zr2;


# static fields
.field public static final OooO0oO:Ljava/util/List;

.field public static final OooO0oo:Ljava/util/List;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/qh7;

.field public final OooO0O0:Llyiahf/vczjk/ki7;

.field public final OooO0OO:Llyiahf/vczjk/qq3;

.field public volatile OooO0Oo:Llyiahf/vczjk/xq3;

.field public volatile OooO0o:Z

.field public final OooO0o0:Llyiahf/vczjk/fe7;


# direct methods
.method static constructor <clinit>()V
    .locals 12

    const-string v8, ":method"

    const-string v9, ":path"

    const-string v0, "connection"

    const-string v1, "host"

    const-string v2, "keep-alive"

    const-string v3, "proxy-connection"

    const-string v4, "te"

    const-string v5, "transfer-encoding"

    const-string v6, "encoding"

    const-string v7, "upgrade"

    const-string v10, ":scheme"

    const-string v11, ":authority"

    filled-new-array/range {v0 .. v11}, [Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/kba;->OooOO0O([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/rq3;->OooO0oO:Ljava/util/List;

    const-string v5, "te"

    const-string v6, "transfer-encoding"

    const-string v1, "connection"

    const-string v2, "host"

    const-string v3, "keep-alive"

    const-string v4, "proxy-connection"

    const-string v7, "encoding"

    const-string v8, "upgrade"

    filled-new-array/range {v1 .. v8}, [Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/kba;->OooOO0O([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/rq3;->OooO0oo:Ljava/util/List;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/e96;Llyiahf/vczjk/qh7;Llyiahf/vczjk/ki7;Llyiahf/vczjk/qq3;)V
    .locals 1

    const-string v0, "client"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "connection"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "http2Connection"

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/rq3;->OooO00o:Llyiahf/vczjk/qh7;

    iput-object p3, p0, Llyiahf/vczjk/rq3;->OooO0O0:Llyiahf/vczjk/ki7;

    iput-object p4, p0, Llyiahf/vczjk/rq3;->OooO0OO:Llyiahf/vczjk/qq3;

    sget-object p2, Llyiahf/vczjk/fe7;->OooOOo0:Llyiahf/vczjk/fe7;

    iget-object p1, p1, Llyiahf/vczjk/e96;->OooOooO:Ljava/util/List;

    invoke-interface {p1, p2}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    sget-object p2, Llyiahf/vczjk/fe7;->OooOOOo:Llyiahf/vczjk/fe7;

    :goto_0
    iput-object p2, p0, Llyiahf/vczjk/rq3;->OooO0o0:Llyiahf/vczjk/fe7;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rq3;->OooO0Oo:Llyiahf/vczjk/xq3;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v0}, Llyiahf/vczjk/xq3;->OooO0o()Llyiahf/vczjk/uq3;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uq3;->close()V

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/lr;)V
    .locals 12

    const-string v0, "request"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/rq3;->OooO0Oo:Llyiahf/vczjk/xq3;

    if-eqz v0, :cond_0

    return-void

    :cond_0
    iget-object v0, p1, Llyiahf/vczjk/lr;->OooOOo0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cr7;

    const/4 v1, 0x1

    const/4 v2, 0x0

    if-eqz v0, :cond_1

    move v0, v1

    goto :goto_0

    :cond_1
    move v0, v2

    :goto_0
    new-instance v3, Ljava/util/ArrayList;

    iget-object v4, p1, Llyiahf/vczjk/lr;->OooOOOo:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/vm3;

    invoke-virtual {v4}, Llyiahf/vczjk/vm3;->size()I

    move-result v5

    add-int/lit8 v5, v5, 0x4

    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    new-instance v5, Llyiahf/vczjk/qm3;

    sget-object v6, Llyiahf/vczjk/qm3;->OooO0o:Llyiahf/vczjk/jm0;

    iget-object v7, p1, Llyiahf/vczjk/lr;->OooOOOO:Ljava/lang/Object;

    check-cast v7, Ljava/lang/String;

    invoke-direct {v5, v6, v7}, Llyiahf/vczjk/qm3;-><init>(Llyiahf/vczjk/jm0;Ljava/lang/String;)V

    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v5, Llyiahf/vczjk/qm3;

    sget-object v6, Llyiahf/vczjk/qm3;->OooO0oO:Llyiahf/vczjk/jm0;

    const-string v7, "url"

    iget-object v8, p1, Llyiahf/vczjk/lr;->OooOOO:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/lr3;

    invoke-static {v8, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v8}, Llyiahf/vczjk/lr3;->OooO0O0()Ljava/lang/String;

    move-result-object v7

    invoke-virtual {v8}, Llyiahf/vczjk/lr3;->OooO0Oo()Ljava/lang/String;

    move-result-object v9

    if-eqz v9, :cond_2

    new-instance v10, Ljava/lang/StringBuilder;

    invoke-direct {v10}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v10, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v7, 0x3f

    invoke-virtual {v10, v7}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v10, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    :cond_2
    invoke-direct {v5, v6, v7}, Llyiahf/vczjk/qm3;-><init>(Llyiahf/vczjk/jm0;Ljava/lang/String;)V

    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    const-string v5, "Host"

    iget-object p1, p1, Llyiahf/vczjk/lr;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/vm3;

    invoke-virtual {p1, v5}, Llyiahf/vczjk/vm3;->OooO00o(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_3

    new-instance v5, Llyiahf/vczjk/qm3;

    sget-object v6, Llyiahf/vczjk/qm3;->OooO:Llyiahf/vczjk/jm0;

    invoke-direct {v5, v6, p1}, Llyiahf/vczjk/qm3;-><init>(Llyiahf/vczjk/jm0;Ljava/lang/String;)V

    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_3
    new-instance p1, Llyiahf/vczjk/qm3;

    sget-object v5, Llyiahf/vczjk/qm3;->OooO0oo:Llyiahf/vczjk/jm0;

    iget-object v6, v8, Llyiahf/vczjk/lr3;->OooO00o:Ljava/lang/String;

    invoke-direct {p1, v5, v6}, Llyiahf/vczjk/qm3;-><init>(Llyiahf/vczjk/jm0;Ljava/lang/String;)V

    invoke-virtual {v3, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {v4}, Llyiahf/vczjk/vm3;->size()I

    move-result p1

    move v5, v2

    :goto_1
    if-ge v5, p1, :cond_6

    invoke-virtual {v4, v5}, Llyiahf/vczjk/vm3;->OooO0O0(I)Ljava/lang/String;

    move-result-object v6

    sget-object v7, Ljava/util/Locale;->US:Ljava/util/Locale;

    const-string v8, "US"

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v6, v7}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object v6

    const-string v7, "this as java.lang.String).toLowerCase(locale)"

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v7, Llyiahf/vczjk/rq3;->OooO0oO:Ljava/util/List;

    invoke-interface {v7, v6}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_4

    const-string v7, "te"

    invoke-virtual {v6, v7}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_5

    invoke-virtual {v4, v5}, Llyiahf/vczjk/vm3;->OooO0oo(I)Ljava/lang/String;

    move-result-object v7

    const-string v8, "trailers"

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_5

    :cond_4
    new-instance v7, Llyiahf/vczjk/qm3;

    invoke-virtual {v4, v5}, Llyiahf/vczjk/vm3;->OooO0oo(I)Ljava/lang/String;

    move-result-object v8

    invoke-direct {v7, v6, v8}, Llyiahf/vczjk/qm3;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_5
    add-int/lit8 v5, v5, 0x1

    goto :goto_1

    :cond_6
    iget-object v8, p0, Llyiahf/vczjk/rq3;->OooO0OO:Llyiahf/vczjk/qq3;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    xor-int/lit8 v9, v0, 0x1

    iget-object p1, v8, Llyiahf/vczjk/qq3;->Oooo0:Llyiahf/vczjk/yq3;

    monitor-enter p1

    :try_start_0
    monitor-enter v8
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    :try_start_1
    iget v4, v8, Llyiahf/vczjk/qq3;->OooOOo0:I

    const v5, 0x3fffffff    # 1.9999999f

    if-le v4, v5, :cond_7

    sget-object v4, Llyiahf/vczjk/fq2;->OooOOo0:Llyiahf/vczjk/fq2;

    invoke-virtual {v8, v4}, Llyiahf/vczjk/qq3;->OooOoO(Llyiahf/vczjk/fq2;)V

    goto :goto_2

    :catchall_0
    move-exception v0

    goto/16 :goto_4

    :cond_7
    :goto_2
    iget-boolean v4, v8, Llyiahf/vczjk/qq3;->OooOOo:Z

    if-nez v4, :cond_d

    iget v7, v8, Llyiahf/vczjk/qq3;->OooOOo0:I

    add-int/lit8 v4, v7, 0x2

    iput v4, v8, Llyiahf/vczjk/qq3;->OooOOo0:I

    new-instance v6, Llyiahf/vczjk/xq3;

    const/4 v11, 0x0

    const/4 v10, 0x0

    invoke-direct/range {v6 .. v11}, Llyiahf/vczjk/xq3;-><init>(ILlyiahf/vczjk/qq3;ZZLlyiahf/vczjk/vm3;)V

    if-eqz v0, :cond_9

    iget-wide v4, v8, Llyiahf/vczjk/qq3;->Oooo000:J

    iget-wide v10, v8, Llyiahf/vczjk/qq3;->Oooo00O:J

    cmp-long v0, v4, v10

    if-gez v0, :cond_9

    iget-wide v4, v6, Llyiahf/vczjk/xq3;->OooO0o0:J

    iget-wide v10, v6, Llyiahf/vczjk/xq3;->OooO0o:J

    cmp-long v0, v4, v10

    if-ltz v0, :cond_8

    goto :goto_3

    :cond_8
    move v1, v2

    :cond_9
    :goto_3
    invoke-virtual {v6}, Llyiahf/vczjk/xq3;->OooO0oo()Z

    move-result v0

    if-eqz v0, :cond_a

    iget-object v0, v8, Llyiahf/vczjk/qq3;->OooOOO:Ljava/util/LinkedHashMap;

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-interface {v0, v2, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :cond_a
    :try_start_2
    monitor-exit v8

    iget-object v0, v8, Llyiahf/vczjk/qq3;->Oooo0:Llyiahf/vczjk/yq3;

    invoke-virtual {v0, v7, v3, v9}, Llyiahf/vczjk/yq3;->OooOoO(ILjava/util/ArrayList;Z)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    monitor-exit p1

    if-eqz v1, :cond_b

    iget-object p1, v8, Llyiahf/vczjk/qq3;->Oooo0:Llyiahf/vczjk/yq3;

    invoke-virtual {p1}, Llyiahf/vczjk/yq3;->flush()V

    :cond_b
    iput-object v6, p0, Llyiahf/vczjk/rq3;->OooO0Oo:Llyiahf/vczjk/xq3;

    iget-boolean p1, p0, Llyiahf/vczjk/rq3;->OooO0o:Z

    if-nez p1, :cond_c

    iget-object p1, p0, Llyiahf/vczjk/rq3;->OooO0Oo:Llyiahf/vczjk/xq3;

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object p1, p1, Llyiahf/vczjk/xq3;->OooOO0O:Llyiahf/vczjk/wq3;

    iget-object v0, p0, Llyiahf/vczjk/rq3;->OooO0O0:Llyiahf/vczjk/ki7;

    iget v0, v0, Llyiahf/vczjk/ki7;->OooO0oO:I

    int-to-long v0, v0

    sget-object v2, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/fs9;->OooO0oO(J)Llyiahf/vczjk/fs9;

    iget-object p1, p0, Llyiahf/vczjk/rq3;->OooO0Oo:Llyiahf/vczjk/xq3;

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object p1, p1, Llyiahf/vczjk/xq3;->OooOO0o:Llyiahf/vczjk/wq3;

    iget-object v0, p0, Llyiahf/vczjk/rq3;->OooO0O0:Llyiahf/vczjk/ki7;

    iget v0, v0, Llyiahf/vczjk/ki7;->OooO0oo:I

    int-to-long v0, v0

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/fs9;->OooO0oO(J)Llyiahf/vczjk/fs9;

    return-void

    :cond_c
    iget-object p1, p0, Llyiahf/vczjk/rq3;->OooO0Oo:Llyiahf/vczjk/xq3;

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/fq2;->OooOOo:Llyiahf/vczjk/fq2;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/xq3;->OooO0o0(Llyiahf/vczjk/fq2;)V

    new-instance p1, Ljava/io/IOException;

    const-string v0, "Canceled"

    invoke-direct {p1, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p1

    :catchall_1
    move-exception v0

    goto :goto_5

    :cond_d
    :try_start_3
    new-instance v0, Llyiahf/vczjk/mi1;

    invoke-direct {v0}, Ljava/io/IOException;-><init>()V

    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    :goto_4
    :try_start_4
    monitor-exit v8

    throw v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    :goto_5
    monitor-exit p1

    throw v0
.end method

.method public final OooO0OO(Z)Llyiahf/vczjk/gs7;
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/rq3;->OooO0Oo:Llyiahf/vczjk/xq3;

    if-eqz v0, :cond_8

    monitor-enter v0

    :try_start_0
    iget-object v1, v0, Llyiahf/vczjk/xq3;->OooOO0O:Llyiahf/vczjk/wq3;

    invoke-virtual {v1}, Llyiahf/vczjk/a10;->OooO0oo()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    :goto_0
    :try_start_1
    iget-object v1, v0, Llyiahf/vczjk/xq3;->OooO0oO:Ljava/util/ArrayDeque;

    invoke-virtual {v1}, Ljava/util/ArrayDeque;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    iget-object v1, v0, Llyiahf/vczjk/xq3;->OooOOO0:Llyiahf/vczjk/fq2;

    if-nez v1, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/xq3;->OooOO0O()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto/16 :goto_4

    :cond_0
    :try_start_2
    iget-object v1, v0, Llyiahf/vczjk/xq3;->OooOO0O:Llyiahf/vczjk/wq3;

    invoke-virtual {v1}, Llyiahf/vczjk/wq3;->OooOO0O()V

    iget-object v1, v0, Llyiahf/vczjk/xq3;->OooO0oO:Ljava/util/ArrayDeque;

    invoke-virtual {v1}, Ljava/util/ArrayDeque;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_6

    iget-object v1, v0, Llyiahf/vczjk/xq3;->OooO0oO:Ljava/util/ArrayDeque;

    invoke-virtual {v1}, Ljava/util/ArrayDeque;->removeFirst()Ljava/lang/Object;

    move-result-object v1

    const-string v2, "headersQueue.removeFirst()"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, Llyiahf/vczjk/vm3;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    monitor-exit v0

    iget-object v0, p0, Llyiahf/vczjk/rq3;->OooO0o0:Llyiahf/vczjk/fe7;

    const-string v2, "protocol"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Ljava/util/ArrayList;

    const/16 v3, 0x14

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v1}, Llyiahf/vczjk/vm3;->size()I

    move-result v3

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v7, v4

    move v6, v5

    :goto_1
    if-ge v6, v3, :cond_3

    invoke-virtual {v1, v6}, Llyiahf/vczjk/vm3;->OooO0O0(I)Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v1, v6}, Llyiahf/vczjk/vm3;->OooO0oo(I)Ljava/lang/String;

    move-result-object v9

    const-string v10, ":status"

    invoke-static {v8, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_1

    new-instance v7, Ljava/lang/StringBuilder;

    const-string v8, "HTTP/1.1 "

    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v7, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v7

    invoke-static {v7}, Llyiahf/vczjk/wr6;->OooOOo(Ljava/lang/String;)Llyiahf/vczjk/yw;

    move-result-object v7

    goto :goto_2

    :cond_1
    sget-object v10, Llyiahf/vczjk/rq3;->OooO0oo:Ljava/util/List;

    invoke-interface {v10, v8}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_2

    const-string v10, "name"

    invoke-static {v8, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v10, "value"

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-static {v9}, Llyiahf/vczjk/z69;->o00o0O(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object v8

    invoke-virtual {v8}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_2
    :goto_2
    add-int/lit8 v6, v6, 0x1

    goto :goto_1

    :cond_3
    if-eqz v7, :cond_5

    new-instance v1, Llyiahf/vczjk/gs7;

    invoke-direct {v1}, Llyiahf/vczjk/gs7;-><init>()V

    iput-object v0, v1, Llyiahf/vczjk/gs7;->OooO0O0:Llyiahf/vczjk/fe7;

    iget v0, v7, Llyiahf/vczjk/yw;->OooO0O0:I

    iput v0, v1, Llyiahf/vczjk/gs7;->OooO0OO:I

    iget-object v0, v7, Llyiahf/vczjk/yw;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Ljava/lang/String;

    iput-object v0, v1, Llyiahf/vczjk/gs7;->OooO0Oo:Ljava/lang/String;

    new-array v0, v5, [Ljava/lang/String;

    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Ljava/lang/String;

    new-instance v2, Llyiahf/vczjk/oO0OOo0o;

    const/16 v3, 0x15

    invoke-direct {v2, v3}, Llyiahf/vczjk/oO0OOo0o;-><init>(I)V

    iget-object v3, v2, Llyiahf/vczjk/oO0OOo0o;->OooOOO:Ljava/lang/Object;

    check-cast v3, Ljava/util/ArrayList;

    invoke-static {v3, v0}, Llyiahf/vczjk/j21;->OoooOoo(Ljava/util/Collection;[Ljava/lang/Object;)V

    iput-object v2, v1, Llyiahf/vczjk/gs7;->OooO0o:Llyiahf/vczjk/oO0OOo0o;

    if-eqz p1, :cond_4

    iget p1, v1, Llyiahf/vczjk/gs7;->OooO0OO:I

    const/16 v0, 0x64

    if-ne p1, v0, :cond_4

    return-object v4

    :cond_4
    return-object v1

    :cond_5
    new-instance p1, Ljava/net/ProtocolException;

    const-string v0, "Expected \':status\' header not present"

    invoke-direct {p1, v0}, Ljava/net/ProtocolException;-><init>(Ljava/lang/String;)V

    throw p1

    :catchall_1
    move-exception p1

    goto :goto_5

    :cond_6
    :try_start_3
    iget-object p1, v0, Llyiahf/vczjk/xq3;->OooOOO:Ljava/io/IOException;

    if-eqz p1, :cond_7

    goto :goto_3

    :cond_7
    new-instance p1, Llyiahf/vczjk/c69;

    iget-object v1, v0, Llyiahf/vczjk/xq3;->OooOOO0:Llyiahf/vczjk/fq2;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-direct {p1, v1}, Llyiahf/vczjk/c69;-><init>(Llyiahf/vczjk/fq2;)V

    :goto_3
    throw p1

    :goto_4
    iget-object v1, v0, Llyiahf/vczjk/xq3;->OooOO0O:Llyiahf/vczjk/wq3;

    invoke-virtual {v1}, Llyiahf/vczjk/wq3;->OooOO0O()V

    throw p1

    :goto_5
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    throw p1

    :cond_8
    new-instance p1, Ljava/io/IOException;

    const-string v0, "stream wasn\'t created"

    invoke-direct {p1, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0Oo()Llyiahf/vczjk/qh7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rq3;->OooO00o:Llyiahf/vczjk/qh7;

    return-object v0
.end method

.method public final OooO0o()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rq3;->OooO0OO:Llyiahf/vczjk/qq3;

    invoke-virtual {v0}, Llyiahf/vczjk/qq3;->flush()V

    return-void
.end method

.method public final OooO0o0(Llyiahf/vczjk/is7;)J
    .locals 2

    invoke-static {p1}, Llyiahf/vczjk/cr3;->OooO00o(Llyiahf/vczjk/is7;)Z

    move-result v0

    if-nez v0, :cond_0

    const-wide/16 v0, 0x0

    return-wide v0

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/kba;->OooOO0(Llyiahf/vczjk/is7;)J

    move-result-wide v0

    return-wide v0
.end method

.method public final OooO0oO(Llyiahf/vczjk/is7;)Llyiahf/vczjk/rx8;
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/rq3;->OooO0Oo:Llyiahf/vczjk/xq3;

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object p1, p1, Llyiahf/vczjk/xq3;->OooO:Llyiahf/vczjk/vq3;

    return-object p1
.end method

.method public final OooO0oo(Llyiahf/vczjk/lr;J)Llyiahf/vczjk/rq8;
    .locals 0

    const-string p2, "request"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/rq3;->OooO0Oo:Llyiahf/vczjk/xq3;

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {p1}, Llyiahf/vczjk/xq3;->OooO0o()Llyiahf/vczjk/uq3;

    move-result-object p1

    return-object p1
.end method

.method public final cancel()V
    .locals 2

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/rq3;->OooO0o:Z

    iget-object v0, p0, Llyiahf/vczjk/rq3;->OooO0Oo:Llyiahf/vczjk/xq3;

    if-eqz v0, :cond_0

    sget-object v1, Llyiahf/vczjk/fq2;->OooOOo:Llyiahf/vczjk/fq2;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/xq3;->OooO0o0(Llyiahf/vczjk/fq2;)V

    :cond_0
    return-void
.end method
