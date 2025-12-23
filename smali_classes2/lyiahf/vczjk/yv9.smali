.class public final enum Llyiahf/vczjk/yv9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "AfterDoctypeName"

    const/16 v1, 0x35

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 2

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooOO0()Z

    move-result v0

    sget-object v1, Llyiahf/vczjk/rw9;->OooOOO0:Llyiahf/vczjk/mu9;

    if-eqz v0, :cond_0

    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOO0o(Llyiahf/vczjk/rw9;)V

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooOOO0:Llyiahf/vczjk/kt9;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooOO0()V

    iput-object v1, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_0
    const/4 v0, 0x5

    new-array v0, v0, [C

    fill-array-data v0, :array_0

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zt0;->OooOOO([C)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO00o()V

    return-void

    :cond_1
    const/16 v0, 0x3e

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zt0;->OooOOO0(C)Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooOO0()V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/bu9;->OooO00o(Llyiahf/vczjk/rw9;)V

    return-void

    :cond_2
    const-string v0, "PUBLIC"

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zt0;->OooOO0o(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_3

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooOOO0:Llyiahf/vczjk/kt9;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p2, Llyiahf/vczjk/rw9;->o00Oo0:Llyiahf/vczjk/zv9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_3
    const-string v0, "SYSTEM"

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zt0;->OooOO0o(Ljava/lang/String;)Z

    move-result p2

    if-eqz p2, :cond_4

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooOOO0:Llyiahf/vczjk/kt9;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p2, Llyiahf/vczjk/rw9;->o00oO0O:Llyiahf/vczjk/gw9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_4
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooOOO0:Llyiahf/vczjk/kt9;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p2, Llyiahf/vczjk/rw9;->o0Oo0oo:Llyiahf/vczjk/lw9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO00o(Llyiahf/vczjk/rw9;)V

    return-void

    nop

    :array_0
    .array-data 2
        0x9s
        0xas
        0xds
        0xcs
        0x20s
    .end array-data
.end method
