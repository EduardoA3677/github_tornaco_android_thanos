.class public final enum Llyiahf/vczjk/rv9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "CommentEndDash"

    const/16 v1, 0x2f

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 3

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO0Oo()C

    move-result p2

    sget-object v0, Llyiahf/vczjk/rw9;->OooooOo:Llyiahf/vczjk/qv9;

    const/16 v1, 0x2d

    if-eqz p2, :cond_2

    if-eq p2, v1, :cond_1

    const v2, 0xffff

    if-eq p2, v2, :cond_0

    iget-object v2, p1, Llyiahf/vczjk/bu9;->OooOOO:Llyiahf/vczjk/jt9;

    iget-object v2, v2, Llyiahf/vczjk/jt9;->OooO0O0:Ljava/lang/StringBuilder;

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iput-object v0, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_0
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOO0o(Llyiahf/vczjk/rw9;)V

    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooO()V

    sget-object p2, Llyiahf/vczjk/rw9;->OooOOO0:Llyiahf/vczjk/mu9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_1
    sget-object p2, Llyiahf/vczjk/rw9;->Oooooo:Llyiahf/vczjk/sv9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_2
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooOOO:Llyiahf/vczjk/jt9;

    iget-object p2, p2, Llyiahf/vczjk/jt9;->OooO0O0:Ljava/lang/StringBuilder;

    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    const v1, 0xfffd

    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iput-object v0, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void
.end method
