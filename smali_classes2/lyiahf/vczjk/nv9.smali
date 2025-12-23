.class public final enum Llyiahf/vczjk/nv9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "MarkupDeclarationOpen"

    const/16 v1, 0x2b

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 1

    const-string v0, "--"

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zt0;->OooOO0O(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooOOO:Llyiahf/vczjk/jt9;

    invoke-virtual {p2}, Llyiahf/vczjk/jt9;->OooOO0O()Llyiahf/vczjk/vu7;

    sget-object p2, Llyiahf/vczjk/rw9;->OooooO0:Llyiahf/vczjk/ov9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_0
    const-string v0, "DOCTYPE"

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zt0;->OooOO0o(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_1

    sget-object p2, Llyiahf/vczjk/rw9;->Ooooooo:Llyiahf/vczjk/vv9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_1
    const-string v0, "[CDATA["

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zt0;->OooOO0O(Ljava/lang/String;)Z

    move-result p2

    if-eqz p2, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooO0o0()V

    sget-object p2, Llyiahf/vczjk/rw9;->o0OO00O:Llyiahf/vczjk/mw9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_2
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    sget-object p2, Llyiahf/vczjk/rw9;->Ooooo00:Llyiahf/vczjk/mv9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO00o(Llyiahf/vczjk/rw9;)V

    return-void
.end method
