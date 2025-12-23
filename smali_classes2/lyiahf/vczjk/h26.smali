.class public final Llyiahf/vczjk/h26;
.super Llyiahf/vczjk/o000O0o;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/v74;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/h26;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/h26;

    sget-object v1, Llyiahf/vczjk/ws7;->OooOOo0:Llyiahf/vczjk/ws7;

    invoke-direct {v0, v1}, Llyiahf/vczjk/o000O0o;-><init>(Llyiahf/vczjk/nr1;)V

    sput-object v0, Llyiahf/vczjk/h26;->OooOOO:Llyiahf/vczjk/h26;

    return-void
.end method


# virtual methods
.method public final OooO0Oo()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooO0oO(Ljava/util/concurrent/CancellationException;)V
    .locals 0

    return-void
.end method

.method public final OooOoOO()Ljava/util/concurrent/CancellationException;
    .locals 2

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "This job is always active"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OoooO00(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/sc2;
    .locals 0

    sget-object p1, Llyiahf/vczjk/i26;->OooOOO0:Llyiahf/vczjk/i26;

    return-object p1
.end method

.method public final Oooooo0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 1

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string v0, "This job is always active"

    invoke-direct {p1, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final isCancelled()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final o00000O(Llyiahf/vczjk/k84;)Llyiahf/vczjk/ov0;
    .locals 0

    sget-object p1, Llyiahf/vczjk/i26;->OooOOO0:Llyiahf/vczjk/i26;

    return-object p1
.end method

.method public final o0OoOo0(ZZLlyiahf/vczjk/o00000;)Llyiahf/vczjk/sc2;
    .locals 0

    sget-object p1, Llyiahf/vczjk/i26;->OooOOO0:Llyiahf/vczjk/i26;

    return-object p1
.end method

.method public final start()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    const-string v0, "NonCancellable"

    return-object v0
.end method
