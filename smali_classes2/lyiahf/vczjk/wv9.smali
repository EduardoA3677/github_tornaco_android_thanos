.class public final enum Llyiahf/vczjk/wv9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "BeforeDoctypeName"

    const/16 v1, 0x33

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 2

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooOOOO()Z

    move-result v0

    sget-object v1, Llyiahf/vczjk/rw9;->ooOO:Llyiahf/vczjk/xv9;

    if-eqz v0, :cond_0

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooOOO0:Llyiahf/vczjk/kt9;

    invoke-virtual {p2}, Llyiahf/vczjk/kt9;->OooOO0O()Llyiahf/vczjk/vu7;

    iput-object v1, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO0Oo()C

    move-result p2

    if-eqz p2, :cond_3

    const/16 v0, 0x20

    if-eq p2, v0, :cond_2

    const v0, 0xffff

    if-eq p2, v0, :cond_1

    const/16 v0, 0x9

    if-eq p2, v0, :cond_2

    const/16 v0, 0xa

    if-eq p2, v0, :cond_2

    const/16 v0, 0xc

    if-eq p2, v0, :cond_2

    const/16 v0, 0xd

    if-eq p2, v0, :cond_2

    iget-object v0, p1, Llyiahf/vczjk/bu9;->OooOOO0:Llyiahf/vczjk/kt9;

    invoke-virtual {v0}, Llyiahf/vczjk/kt9;->OooOO0O()Llyiahf/vczjk/vu7;

    iget-object v0, p1, Llyiahf/vczjk/bu9;->OooOOO0:Llyiahf/vczjk/kt9;

    iget-object v0, v0, Llyiahf/vczjk/kt9;->OooO0O0:Ljava/lang/StringBuilder;

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iput-object v1, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_1
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOO0o(Llyiahf/vczjk/rw9;)V

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooOOO0:Llyiahf/vczjk/kt9;

    invoke-virtual {p2}, Llyiahf/vczjk/kt9;->OooOO0O()Llyiahf/vczjk/vu7;

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooOOO0:Llyiahf/vczjk/kt9;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooOO0()V

    sget-object p2, Llyiahf/vczjk/rw9;->OooOOO0:Llyiahf/vczjk/mu9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    :cond_2
    return-void

    :cond_3
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooOOO0:Llyiahf/vczjk/kt9;

    invoke-virtual {p2}, Llyiahf/vczjk/kt9;->OooOO0O()Llyiahf/vczjk/vu7;

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooOOO0:Llyiahf/vczjk/kt9;

    iget-object p2, p2, Llyiahf/vczjk/kt9;->OooO0O0:Ljava/lang/StringBuilder;

    const v0, 0xfffd

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iput-object v1, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void
.end method
