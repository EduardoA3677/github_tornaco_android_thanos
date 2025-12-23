.class public final enum Llyiahf/vczjk/mv9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "BogusComment"

    const/16 v1, 0x2a

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 2

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooOOo0()V

    new-instance v0, Llyiahf/vczjk/jt9;

    invoke-direct {v0}, Llyiahf/vczjk/jt9;-><init>()V

    const/16 v1, 0x3e

    invoke-virtual {p2, v1}, Llyiahf/vczjk/zt0;->OooO0o(C)Ljava/lang/String;

    move-result-object p2

    iget-object v1, v0, Llyiahf/vczjk/jt9;->OooO0O0:Ljava/lang/StringBuilder;

    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/bu9;->OooO0oo(Llyiahf/vczjk/vu7;)V

    sget-object p2, Llyiahf/vczjk/rw9;->OooOOO0:Llyiahf/vczjk/mu9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO00o(Llyiahf/vczjk/rw9;)V

    return-void
.end method
