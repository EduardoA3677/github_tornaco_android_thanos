.class public final enum Llyiahf/vczjk/pw9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "TagOpen"

    const/4 v1, 0x7

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 2

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO()C

    move-result v0

    const/16 v1, 0x21

    if-eq v0, v1, :cond_3

    const/16 v1, 0x2f

    if-eq v0, v1, :cond_2

    const/16 v1, 0x3f

    if-eq v0, v1, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooOOOO()Z

    move-result p2

    if-eqz p2, :cond_0

    const/4 p2, 0x1

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO0Oo(Z)Llyiahf/vczjk/pt9;

    sget-object p2, Llyiahf/vczjk/rw9;->OooOo0:Llyiahf/vczjk/cu9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_0
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    const/16 p2, 0x3c

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO0o(C)V

    sget-object p2, Llyiahf/vczjk/rw9;->OooOOO0:Llyiahf/vczjk/mu9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_1
    sget-object p2, Llyiahf/vczjk/rw9;->Ooooo00:Llyiahf/vczjk/mv9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO00o(Llyiahf/vczjk/rw9;)V

    return-void

    :cond_2
    sget-object p2, Llyiahf/vczjk/rw9;->OooOo00:Llyiahf/vczjk/qw9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO00o(Llyiahf/vczjk/rw9;)V

    return-void

    :cond_3
    sget-object p2, Llyiahf/vczjk/rw9;->Ooooo0o:Llyiahf/vczjk/nv9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO00o(Llyiahf/vczjk/rw9;)V

    return-void
.end method
