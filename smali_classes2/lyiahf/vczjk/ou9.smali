.class public final enum Llyiahf/vczjk/ou9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "ScriptDataEscapeStartDash"

    const/16 v1, 0x14

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 1

    const/16 v0, 0x2d

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zt0;->OooOOO0(C)Z

    move-result p2

    if-eqz p2, :cond_0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/bu9;->OooO0o(C)V

    sget-object p2, Llyiahf/vczjk/rw9;->Oooo0:Llyiahf/vczjk/ru9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO00o(Llyiahf/vczjk/rw9;)V

    return-void

    :cond_0
    sget-object p2, Llyiahf/vczjk/rw9;->OooOOo:Llyiahf/vczjk/nw9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void
.end method
