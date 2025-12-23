.class public final enum Llyiahf/vczjk/du9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "RcdataLessthanSign"

    const/16 v1, 0xa

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 4

    const/16 v0, 0x2f

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zt0;->OooOOO0(C)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooO0o0()V

    sget-object p2, Llyiahf/vczjk/rw9;->OooOo0o:Llyiahf/vczjk/eu9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO00o(Llyiahf/vczjk/rw9;)V

    return-void

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooOOOO()Z

    move-result v0

    if-eqz v0, :cond_3

    iget-object v0, p1, Llyiahf/vczjk/bu9;->OooOOOO:Ljava/lang/String;

    if-eqz v0, :cond_3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "</"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p1, Llyiahf/vczjk/bu9;->OooOOOO:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    sget-object v1, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    invoke-virtual {v0, v1}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v1}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2, v2}, Llyiahf/vczjk/zt0;->OooOOOo(Ljava/lang/String;)I

    move-result v2

    const/4 v3, -0x1

    if-gt v2, v3, :cond_3

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zt0;->OooOOOo(Ljava/lang/String;)I

    move-result v0

    if-le v0, v3, :cond_1

    goto :goto_1

    :cond_1
    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/bu9;->OooO0Oo(Z)Llyiahf/vczjk/pt9;

    move-result-object v0

    iget-object v2, p1, Llyiahf/vczjk/bu9;->OooOOOO:Ljava/lang/String;

    iput-object v2, v0, Llyiahf/vczjk/pt9;->OooO0O0:Ljava/lang/String;

    if-eqz v2, :cond_2

    invoke-virtual {v2, v1}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object v1

    goto :goto_0

    :cond_2
    const-string v1, ""

    :goto_0
    iput-object v1, v0, Llyiahf/vczjk/pt9;->OooO0OO:Ljava/lang/String;

    iput-object v0, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooOO0O()V

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooOOo0()V

    sget-object p2, Llyiahf/vczjk/rw9;->OooOOO0:Llyiahf/vczjk/mu9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_3
    :goto_1
    const-string p2, "<"

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO0oO(Ljava/lang/String;)V

    sget-object p2, Llyiahf/vczjk/rw9;->OooOOOO:Llyiahf/vczjk/iv9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void
.end method
