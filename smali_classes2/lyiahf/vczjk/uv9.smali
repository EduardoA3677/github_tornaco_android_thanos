.class public final enum Llyiahf/vczjk/uv9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "CommentEndBang"

    const/16 v1, 0x31

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 4

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO0Oo()C

    move-result p2

    sget-object v0, Llyiahf/vczjk/rw9;->OooooOo:Llyiahf/vczjk/qv9;

    const-string v1, "--!"

    if-eqz p2, :cond_3

    const/16 v2, 0x2d

    if-eq p2, v2, :cond_2

    sget-object v2, Llyiahf/vczjk/rw9;->OooOOO0:Llyiahf/vczjk/mu9;

    const/16 v3, 0x3e

    if-eq p2, v3, :cond_1

    const v3, 0xffff

    if-eq p2, v3, :cond_0

    iget-object v2, p1, Llyiahf/vczjk/bu9;->OooOOO:Llyiahf/vczjk/jt9;

    iget-object v2, v2, Llyiahf/vczjk/jt9;->OooO0O0:Ljava/lang/StringBuilder;

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iput-object v0, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_0
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOO0o(Llyiahf/vczjk/rw9;)V

    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooO()V

    iput-object v2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooO()V

    iput-object v2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_2
    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooOOO:Llyiahf/vczjk/jt9;

    iget-object p2, p2, Llyiahf/vczjk/jt9;->OooO0O0:Ljava/lang/StringBuilder;

    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    sget-object p2, Llyiahf/vczjk/rw9;->Oooooo0:Llyiahf/vczjk/rv9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_3
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooOOO:Llyiahf/vczjk/jt9;

    iget-object p2, p2, Llyiahf/vczjk/jt9;->OooO0O0:Ljava/lang/StringBuilder;

    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const v1, 0xfffd

    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iput-object v0, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void
.end method
