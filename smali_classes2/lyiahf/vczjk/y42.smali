.class public final Llyiahf/vczjk/y42;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/zw8;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/x42;

.field public OooO0O0:Llyiahf/vczjk/zw8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x42;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/y42;->OooO00o:Llyiahf/vczjk/x42;

    return-void
.end method


# virtual methods
.method public final OooO00o()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooO0O0(Ljavax/net/ssl/SSLSocket;)Ljava/lang/String;
    .locals 1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/y42;->OooO0o0(Ljavax/net/ssl/SSLSocket;)Llyiahf/vczjk/zw8;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, Llyiahf/vczjk/zw8;->OooO0O0(Ljavax/net/ssl/SSLSocket;)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooO0OO(Ljavax/net/ssl/SSLSocket;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/y42;->OooO00o:Llyiahf/vczjk/x42;

    invoke-interface {v0, p1}, Llyiahf/vczjk/x42;->OooO0OO(Ljavax/net/ssl/SSLSocket;)Z

    move-result p1

    return p1
.end method

.method public final OooO0Oo(Ljavax/net/ssl/SSLSocket;Ljava/lang/String;Ljava/util/List;)V
    .locals 1

    const-string v0, "protocols"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/y42;->OooO0o0(Ljavax/net/ssl/SSLSocket;)Llyiahf/vczjk/zw8;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-interface {v0, p1, p2, p3}, Llyiahf/vczjk/zw8;->OooO0Oo(Ljavax/net/ssl/SSLSocket;Ljava/lang/String;Ljava/util/List;)V

    :cond_0
    return-void
.end method

.method public final declared-synchronized OooO0o0(Ljavax/net/ssl/SSLSocket;)Llyiahf/vczjk/zw8;
    .locals 1

    monitor-enter p0

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/y42;->OooO0O0:Llyiahf/vczjk/zw8;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/y42;->OooO00o:Llyiahf/vczjk/x42;

    invoke-interface {v0, p1}, Llyiahf/vczjk/x42;->OooO0OO(Ljavax/net/ssl/SSLSocket;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/y42;->OooO00o:Llyiahf/vczjk/x42;

    invoke-interface {v0, p1}, Llyiahf/vczjk/x42;->OooO0oO(Ljavax/net/ssl/SSLSocket;)Llyiahf/vczjk/zw8;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/y42;->OooO0O0:Llyiahf/vczjk/zw8;

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/y42;->OooO0O0:Llyiahf/vczjk/zw8;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p0

    return-object p1

    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1
.end method
