.class public final Llyiahf/vczjk/rw4;
.super Llyiahf/vczjk/r09;
.source "SourceFile"


# instance fields
.field public final OooOOOo:Llyiahf/vczjk/yo1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/o000O000;-><init>(Llyiahf/vczjk/or1;Z)V

    invoke-static {p0, p0, p2}, Llyiahf/vczjk/dn8;->Oooo0o(Llyiahf/vczjk/yo1;Llyiahf/vczjk/yo1;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/yo1;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/rw4;->OooOOOo:Llyiahf/vczjk/yo1;

    return-void
.end method


# virtual methods
.method public final OoooOOO()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/rw4;->OooOOOo:Llyiahf/vczjk/yo1;

    :try_start_0
    invoke-static {v0}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-static {v1, v0}, Llyiahf/vczjk/dn8;->o00oO0O(Ljava/lang/Object;Llyiahf/vczjk/yo1;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception v0

    instance-of v1, v0, Llyiahf/vczjk/dc2;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/dc2;

    invoke-virtual {v0}, Llyiahf/vczjk/dc2;->getCause()Ljava/lang/Throwable;

    move-result-object v0

    :cond_0
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v1

    invoke-virtual {p0, v1}, Llyiahf/vczjk/o000O000;->resumeWith(Ljava/lang/Object;)V

    throw v0
.end method
