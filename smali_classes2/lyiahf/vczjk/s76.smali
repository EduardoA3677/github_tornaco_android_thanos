.class public final Llyiahf/vczjk/s76;
.super Llyiahf/vczjk/oo0o0O0;
.source "SourceFile"


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/j86;)V
    .locals 3

    :try_start_0
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    new-instance v1, Llyiahf/vczjk/r76;

    const/4 v2, 0x0

    invoke-direct {v1, p1, v0, v2}, Llyiahf/vczjk/r76;-><init>(Llyiahf/vczjk/j86;Ljava/lang/Object;I)V

    iget-object p1, p0, Llyiahf/vczjk/oo0o0O0;->OooOOO0:Llyiahf/vczjk/o76;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/o76;->OooO0Oo(Llyiahf/vczjk/j86;)V

    return-void

    :catchall_0
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    sget-object v1, Llyiahf/vczjk/xm2;->OooOOO0:Llyiahf/vczjk/xm2;

    invoke-interface {p1, v1}, Llyiahf/vczjk/j86;->OooO0O0(Llyiahf/vczjk/nc2;)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/j86;->OooO0OO(Ljava/lang/Throwable;)V

    return-void
.end method
