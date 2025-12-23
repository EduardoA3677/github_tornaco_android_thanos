.class public final enum Llyiahf/vczjk/mu9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "Data"

    const/4 v1, 0x0

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 7

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO()C

    move-result v0

    if-eqz v0, :cond_6

    const/16 v1, 0x26

    if-eq v0, v1, :cond_5

    const/16 v2, 0x3c

    if-eq v0, v2, :cond_4

    const v3, 0xffff

    if-eq v0, v3, :cond_3

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO0O0()V

    iget v0, p2, Llyiahf/vczjk/zt0;->OooO0o0:I

    iget v3, p2, Llyiahf/vczjk/zt0;->OooO0OO:I

    :goto_0
    iget v4, p2, Llyiahf/vczjk/zt0;->OooO0o0:I

    iget-object v5, p2, Llyiahf/vczjk/zt0;->OooO00o:[C

    if-ge v4, v3, :cond_1

    aget-char v6, v5, v4

    if-eq v6, v1, :cond_1

    if-eq v6, v2, :cond_1

    if-nez v6, :cond_0

    goto :goto_1

    :cond_0
    add-int/lit8 v4, v4, 0x1

    iput v4, p2, Llyiahf/vczjk/zt0;->OooO0o0:I

    goto :goto_0

    :cond_1
    :goto_1
    if-le v4, v0, :cond_2

    iget-object p2, p2, Llyiahf/vczjk/zt0;->OooO0oo:[Ljava/lang/String;

    sub-int/2addr v4, v0

    invoke-static {v5, p2, v0, v4}, Llyiahf/vczjk/zt0;->OooO0OO([C[Ljava/lang/String;II)Ljava/lang/String;

    move-result-object p2

    goto :goto_2

    :cond_2
    const-string p2, ""

    :goto_2
    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO0oO(Ljava/lang/String;)V

    return-void

    :cond_3
    new-instance p2, Llyiahf/vczjk/lt9;

    invoke-direct {p2}, Llyiahf/vczjk/lt9;-><init>()V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO0oo(Llyiahf/vczjk/vu7;)V

    return-void

    :cond_4
    sget-object p2, Llyiahf/vczjk/rw9;->OooOOoo:Llyiahf/vczjk/pw9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO00o(Llyiahf/vczjk/rw9;)V

    return-void

    :cond_5
    sget-object p2, Llyiahf/vczjk/rw9;->OooOOO:Llyiahf/vczjk/xu9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO00o(Llyiahf/vczjk/rw9;)V

    return-void

    :cond_6
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO0Oo()C

    move-result p2

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO0o(C)V

    return-void
.end method
