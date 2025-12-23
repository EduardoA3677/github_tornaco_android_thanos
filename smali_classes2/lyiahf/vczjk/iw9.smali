.class public final enum Llyiahf/vczjk/iw9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "DoctypeSystemIdentifier_doubleQuoted"

    const/16 v1, 0x3e

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 2

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO0Oo()C

    move-result p2

    if-eqz p2, :cond_3

    const/16 v0, 0x22

    if-eq p2, v0, :cond_2

    sget-object v0, Llyiahf/vczjk/rw9;->OooOOO0:Llyiahf/vczjk/mu9;

    const/16 v1, 0x3e

    if-eq p2, v1, :cond_1

    const v1, 0xffff

    if-eq p2, v1, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/bu9;->OooOOO0:Llyiahf/vczjk/kt9;

    iget-object p1, p1, Llyiahf/vczjk/kt9;->OooO0Oo:Ljava/lang/StringBuilder;

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    return-void

    :cond_0
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOO0o(Llyiahf/vczjk/rw9;)V

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooOOO0:Llyiahf/vczjk/kt9;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooOO0()V

    iput-object v0, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_1
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooOOO0:Llyiahf/vczjk/kt9;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooOO0()V

    iput-object v0, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_2
    sget-object p2, Llyiahf/vczjk/rw9;->o0OOO0o:Llyiahf/vczjk/kw9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_3
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    iget-object p1, p1, Llyiahf/vczjk/bu9;->OooOOO0:Llyiahf/vczjk/kt9;

    iget-object p1, p1, Llyiahf/vczjk/kt9;->OooO0Oo:Ljava/lang/StringBuilder;

    const p2, 0xfffd

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    return-void
.end method
