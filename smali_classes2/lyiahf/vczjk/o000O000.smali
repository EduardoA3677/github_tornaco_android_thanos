.class public abstract Llyiahf/vczjk/o000O000;
.super Llyiahf/vczjk/k84;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/yo1;
.implements Llyiahf/vczjk/xr1;


# instance fields
.field public final OooOOOO:Llyiahf/vczjk/or1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/or1;Z)V
    .locals 0

    invoke-direct {p0, p2}, Llyiahf/vczjk/k84;-><init>(Z)V

    sget-object p2, Llyiahf/vczjk/ws7;->OooOOo0:Llyiahf/vczjk/ws7;

    invoke-interface {p1, p2}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/v74;

    invoke-virtual {p0, p2}, Llyiahf/vczjk/k84;->Oooo0O0(Llyiahf/vczjk/v74;)V

    invoke-interface {p1, p0}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/o000O000;->OooOOOO:Llyiahf/vczjk/or1;

    return-void
.end method


# virtual methods
.method public final OooOo0()Ljava/lang/String;
    .locals 2

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    const-string v1, " was cancelled"

    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final Oooo0(Llyiahf/vczjk/k61;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o000O000;->OooOOOO:Llyiahf/vczjk/or1;

    invoke-static {p1, v0}, Llyiahf/vczjk/u34;->OooOooO(Ljava/lang/Throwable;Llyiahf/vczjk/or1;)V

    return-void
.end method

.method public final OoooOO0()Llyiahf/vczjk/or1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o000O000;->OooOOOO:Llyiahf/vczjk/or1;

    return-object v0
.end method

.method public OooooOO(Ljava/lang/Throwable;Z)V
    .locals 0

    return-void
.end method

.method public OooooOo(Ljava/lang/Object;)V
    .locals 0

    return-void
.end method

.method public final Oooooo(Llyiahf/vczjk/as1;Llyiahf/vczjk/o000O000;Llyiahf/vczjk/ze3;)V
    .locals 3

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz p1, :cond_5

    const/4 v1, 0x1

    if-eq p1, v1, :cond_4

    const/4 v1, 0x2

    if-eq p1, v1, :cond_3

    const/4 v0, 0x3

    if-ne p1, v0, :cond_2

    :try_start_0
    iget-object p1, p0, Llyiahf/vczjk/o000O000;->OooOOOO:Llyiahf/vczjk/or1;

    const/4 v0, 0x0

    invoke-static {p1, v0}, Llyiahf/vczjk/jp8;->OooooO0(Llyiahf/vczjk/or1;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    :try_start_1
    instance-of v2, p3, Llyiahf/vczjk/p70;

    if-nez v2, :cond_0

    invoke-static {p3, p2, p0}, Llyiahf/vczjk/dn8;->o000OOo(Llyiahf/vczjk/ze3;Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p2

    goto :goto_0

    :catchall_0
    move-exception p2

    goto :goto_1

    :cond_0
    invoke-static {v1, p3}, Llyiahf/vczjk/l4a;->OooOO0(ILjava/lang/Object;)Ljava/lang/Object;

    check-cast p3, Llyiahf/vczjk/ze3;

    invoke-interface {p3, p2, p0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :goto_0
    :try_start_2
    invoke-static {p1, v0}, Llyiahf/vczjk/jp8;->OoooOO0(Llyiahf/vczjk/or1;Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-eq p2, p1, :cond_4

    invoke-virtual {p0, p2}, Llyiahf/vczjk/o000O000;->resumeWith(Ljava/lang/Object;)V

    return-void

    :catchall_1
    move-exception p1

    goto :goto_2

    :goto_1
    :try_start_3
    invoke-static {p1, v0}, Llyiahf/vczjk/jp8;->OoooOO0(Llyiahf/vczjk/or1;Ljava/lang/Object;)V

    throw p2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    :goto_2
    instance-of p2, p1, Llyiahf/vczjk/dc2;

    if-eqz p2, :cond_1

    check-cast p1, Llyiahf/vczjk/dc2;

    invoke-virtual {p1}, Llyiahf/vczjk/dc2;->getCause()Ljava/lang/Throwable;

    move-result-object p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/o000O000;->resumeWith(Ljava/lang/Object;)V

    goto :goto_3

    :cond_2
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_3
    const-string p1, "<this>"

    invoke-static {p3, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p2, p0, p3}, Llyiahf/vczjk/dn8;->Oooo0o(Llyiahf/vczjk/yo1;Llyiahf/vczjk/yo1;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/yo1;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    invoke-interface {p1, v0}, Llyiahf/vczjk/yo1;->resumeWith(Ljava/lang/Object;)V

    :cond_4
    :goto_3
    return-void

    :cond_5
    :try_start_4
    invoke-static {p2, p0, p3}, Llyiahf/vczjk/dn8;->Oooo0o(Llyiahf/vczjk/yo1;Llyiahf/vczjk/yo1;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/yo1;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/dn8;->o00oO0O(Ljava/lang/Object;Llyiahf/vczjk/yo1;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    return-void

    :catchall_2
    move-exception p1

    instance-of p2, p1, Llyiahf/vczjk/dc2;

    if-eqz p2, :cond_6

    check-cast p1, Llyiahf/vczjk/dc2;

    invoke-virtual {p1}, Llyiahf/vczjk/dc2;->getCause()Ljava/lang/Throwable;

    move-result-object p1

    :cond_6
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p2

    invoke-virtual {p0, p2}, Llyiahf/vczjk/o000O000;->resumeWith(Ljava/lang/Object;)V

    throw p1
.end method

.method public final getContext()Llyiahf/vczjk/or1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o000O000;->OooOOOO:Llyiahf/vczjk/or1;

    return-object v0
.end method

.method public final o000oOoO(Ljava/lang/Object;)V
    .locals 2

    instance-of v0, p1, Llyiahf/vczjk/j61;

    if-eqz v0, :cond_1

    check-cast p1, Llyiahf/vczjk/j61;

    iget-object v0, p1, Llyiahf/vczjk/j61;->OooO00o:Ljava/lang/Throwable;

    sget-object v1, Llyiahf/vczjk/j61;->OooO0O0:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    invoke-virtual {v1, p1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->get(Ljava/lang/Object;)I

    move-result p1

    const/4 v1, 0x1

    if-ne p1, v1, :cond_0

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    invoke-virtual {p0, v0, v1}, Llyiahf/vczjk/o000O000;->OooooOO(Ljava/lang/Throwable;Z)V

    return-void

    :cond_1
    invoke-virtual {p0, p1}, Llyiahf/vczjk/o000O000;->OooooOo(Ljava/lang/Object;)V

    return-void
.end method

.method public final resumeWith(Ljava/lang/Object;)V
    .locals 2

    invoke-static {p1}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Llyiahf/vczjk/j61;

    const/4 v1, 0x0

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/j61;-><init>(Ljava/lang/Throwable;Z)V

    :goto_0
    invoke-virtual {p0, p1}, Llyiahf/vczjk/k84;->Oooo(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/cp7;->OooO0o0:Llyiahf/vczjk/h87;

    if-ne p1, v0, :cond_1

    return-void

    :cond_1
    invoke-virtual {p0, p1}, Llyiahf/vczjk/o000O000;->OooOOO(Ljava/lang/Object;)V

    return-void
.end method
