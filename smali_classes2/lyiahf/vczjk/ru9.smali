.class public final enum Llyiahf/vczjk/ru9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "ScriptDataEscapedDashDash"

    const/16 v1, 0x17

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 2

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooOO0()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOO0o(Llyiahf/vczjk/rw9;)V

    sget-object p2, Llyiahf/vczjk/rw9;->OooOOO0:Llyiahf/vczjk/mu9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO0Oo()C

    move-result p2

    sget-object v0, Llyiahf/vczjk/rw9;->Oooo00O:Llyiahf/vczjk/pu9;

    if-eqz p2, :cond_4

    const/16 v1, 0x2d

    if-eq p2, v1, :cond_3

    const/16 v1, 0x3c

    if-eq p2, v1, :cond_2

    const/16 v1, 0x3e

    if-eq p2, v1, :cond_1

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO0o(C)V

    iput-object v0, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_1
    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO0o(C)V

    sget-object p2, Llyiahf/vczjk/rw9;->OooOOo:Llyiahf/vczjk/nw9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_2
    sget-object p2, Llyiahf/vczjk/rw9;->Oooo0O0:Llyiahf/vczjk/su9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_3
    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO0o(C)V

    return-void

    :cond_4
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    const p2, 0xfffd

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO0o(C)V

    iput-object v0, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void
.end method
