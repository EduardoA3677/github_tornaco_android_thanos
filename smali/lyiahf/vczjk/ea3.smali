.class public final Llyiahf/vczjk/ea3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/aa3;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/hd;

.field public final OooO0O0:Llyiahf/vczjk/id;

.field public final OooO0OO:Llyiahf/vczjk/f6a;

.field public final OooO0Oo:Llyiahf/vczjk/ja3;

.field public final OooO0o:Llyiahf/vczjk/ca3;

.field public final OooO0o0:Llyiahf/vczjk/uz5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hd;Llyiahf/vczjk/id;)V
    .locals 5

    sget-object v0, Llyiahf/vczjk/fa3;->OooO00o:Llyiahf/vczjk/f6a;

    new-instance v1, Llyiahf/vczjk/ja3;

    sget-object v2, Llyiahf/vczjk/fa3;->OooO0O0:Llyiahf/vczjk/uqa;

    invoke-direct {v1, v2}, Llyiahf/vczjk/ja3;-><init>(Llyiahf/vczjk/uqa;)V

    new-instance v2, Llyiahf/vczjk/uz5;

    const/16 v3, 0x1d

    const/4 v4, 0x0

    invoke-direct {v2, v3, v4}, Llyiahf/vczjk/uz5;-><init>(IB)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ea3;->OooO00o:Llyiahf/vczjk/hd;

    iput-object p2, p0, Llyiahf/vczjk/ea3;->OooO0O0:Llyiahf/vczjk/id;

    iput-object v0, p0, Llyiahf/vczjk/ea3;->OooO0OO:Llyiahf/vczjk/f6a;

    iput-object v1, p0, Llyiahf/vczjk/ea3;->OooO0Oo:Llyiahf/vczjk/ja3;

    iput-object v2, p0, Llyiahf/vczjk/ea3;->OooO0o0:Llyiahf/vczjk/uz5;

    new-instance p1, Llyiahf/vczjk/ca3;

    invoke-direct {p1, p0}, Llyiahf/vczjk/ca3;-><init>(Llyiahf/vczjk/ea3;)V

    iput-object p1, p0, Llyiahf/vczjk/ea3;->OooO0o:Llyiahf/vczjk/ca3;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/d6a;)Llyiahf/vczjk/i6a;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/ea3;->OooO0OO:Llyiahf/vczjk/f6a;

    new-instance v1, Llyiahf/vczjk/da3;

    invoke-direct {v1, p0, p1}, Llyiahf/vczjk/da3;-><init>(Llyiahf/vczjk/ea3;Llyiahf/vczjk/d6a;)V

    iget-object v2, v0, Llyiahf/vczjk/f6a;->OooO00o:Llyiahf/vczjk/sp3;

    monitor-enter v2

    :try_start_0
    iget-object v3, v0, Llyiahf/vczjk/f6a;->OooO0O0:Llyiahf/vczjk/i95;

    invoke-virtual {v3, p1}, Llyiahf/vczjk/i95;->OooO0O0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/i6a;

    if-eqz v3, :cond_1

    invoke-interface {v3}, Llyiahf/vczjk/i6a;->OooO0o0()Z

    move-result v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v4, :cond_0

    monitor-exit v2

    return-object v3

    :cond_0
    :try_start_1
    iget-object v3, v0, Llyiahf/vczjk/f6a;->OooO0O0:Llyiahf/vczjk/i95;

    invoke-virtual {v3, p1}, Llyiahf/vczjk/i95;->OooO0Oo(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/i6a;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_3

    :cond_1
    :goto_0
    monitor-exit v2

    :try_start_2
    new-instance v2, Llyiahf/vczjk/e6a;

    invoke-direct {v2, v0, p1}, Llyiahf/vczjk/e6a;-><init>(Llyiahf/vczjk/f6a;Llyiahf/vczjk/d6a;)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/da3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/i6a;
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    iget-object v2, v0, Llyiahf/vczjk/f6a;->OooO00o:Llyiahf/vczjk/sp3;

    monitor-enter v2

    :try_start_3
    iget-object v3, v0, Llyiahf/vczjk/f6a;->OooO0O0:Llyiahf/vczjk/i95;

    invoke-virtual {v3, p1}, Llyiahf/vczjk/i95;->OooO0O0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    if-nez v3, :cond_2

    invoke-interface {v1}, Llyiahf/vczjk/i6a;->OooO0o0()Z

    move-result v3

    if-eqz v3, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/f6a;->OooO0O0:Llyiahf/vczjk/i95;

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/i95;->OooO0OO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    goto :goto_1

    :catchall_1
    move-exception p1

    goto :goto_2

    :cond_2
    :goto_1
    monitor-exit v2

    return-object v1

    :goto_2
    monitor-exit v2

    throw p1

    :catch_0
    move-exception p1

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Could not load font"

    invoke-direct {v0, v1, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0

    :goto_3
    monitor-exit v2

    throw p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/ba3;Llyiahf/vczjk/ib3;II)Llyiahf/vczjk/i6a;
    .locals 6

    new-instance v0, Llyiahf/vczjk/d6a;

    iget-object v1, p0, Llyiahf/vczjk/ea3;->OooO0O0:Llyiahf/vczjk/id;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v1, v1, Llyiahf/vczjk/id;->OooOOO0:I

    if-eqz v1, :cond_1

    const v2, 0x7fffffff

    if-ne v1, v2, :cond_0

    goto :goto_0

    :cond_0
    iget p2, p2, Llyiahf/vczjk/ib3;->OooOOO0:I

    add-int/2addr p2, v1

    const/4 v1, 0x1

    const/16 v2, 0x3e8

    invoke-static {p2, v1, v2}, Llyiahf/vczjk/vt6;->OooOOo(III)I

    move-result p2

    new-instance v1, Llyiahf/vczjk/ib3;

    invoke-direct {v1, p2}, Llyiahf/vczjk/ib3;-><init>(I)V

    move-object v2, v1

    goto :goto_1

    :cond_1
    :goto_0
    move-object v2, p2

    :goto_1
    iget-object p2, p0, Llyiahf/vczjk/ea3;->OooO00o:Llyiahf/vczjk/hd;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v5, 0x0

    move-object v1, p1

    move v3, p3

    move v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/d6a;-><init>(Llyiahf/vczjk/ba3;Llyiahf/vczjk/ib3;IILjava/lang/Object;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/ea3;->OooO00o(Llyiahf/vczjk/d6a;)Llyiahf/vczjk/i6a;

    move-result-object p1

    return-object p1
.end method
