.class public final enum Llyiahf/vczjk/fu9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "RCDATAEndTagName"

    const/16 v1, 0xc

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method

.method public static OooO0o0(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "</"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/bu9;->OooO0oo:Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/bu9;->OooO0oO(Ljava/lang/String;)V

    invoke-virtual {p1}, Llyiahf/vczjk/zt0;->OooOOo0()V

    sget-object p1, Llyiahf/vczjk/rw9;->OooOOOO:Llyiahf/vczjk/iv9;

    iput-object p1, p0, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 2

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooOOOO()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO0o0()Ljava/lang/String;

    move-result-object p2

    iget-object v0, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/pt9;->OooOOo0(Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/bu9;->OooO0oo:Ljava/lang/StringBuilder;

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    return-void

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO0Oo()C

    move-result v0

    const/16 v1, 0x9

    if-eq v0, v1, :cond_5

    const/16 v1, 0xa

    if-eq v0, v1, :cond_5

    const/16 v1, 0xc

    if-eq v0, v1, :cond_5

    const/16 v1, 0xd

    if-eq v0, v1, :cond_5

    const/16 v1, 0x20

    if-eq v0, v1, :cond_5

    const/16 v1, 0x2f

    if-eq v0, v1, :cond_3

    const/16 v1, 0x3e

    if-eq v0, v1, :cond_1

    invoke-static {p1, p2}, Llyiahf/vczjk/fu9;->OooO0o0(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V

    return-void

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooOOO()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooOO0O()V

    sget-object p2, Llyiahf/vczjk/rw9;->OooOOO0:Llyiahf/vczjk/mu9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_2
    invoke-static {p1, p2}, Llyiahf/vczjk/fu9;->OooO0o0(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V

    return-void

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooOOO()Z

    move-result v0

    if-eqz v0, :cond_4

    sget-object p2, Llyiahf/vczjk/rw9;->OoooOoo:Llyiahf/vczjk/lv9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_4
    invoke-static {p1, p2}, Llyiahf/vczjk/fu9;->OooO0o0(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V

    return-void

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooOOO()Z

    move-result v0

    if-eqz v0, :cond_6

    sget-object p2, Llyiahf/vczjk/rw9;->OoooO0O:Llyiahf/vczjk/cv9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_6
    invoke-static {p1, p2}, Llyiahf/vczjk/fu9;->OooO0o0(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V

    return-void
.end method
