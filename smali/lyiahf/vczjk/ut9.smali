.class public final Llyiahf/vczjk/ut9;
.super Llyiahf/vczjk/a59;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 3

    new-instance v0, Llyiahf/vczjk/tt9;

    const/4 v1, 0x0

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/tt9;-><init>(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)V

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    invoke-virtual {p2, v1}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v1

    if-nez v1, :cond_0

    invoke-virtual {v0, p2}, Llyiahf/vczjk/tt9;->o000O0oO(Llyiahf/vczjk/eb4;)V

    return-object v0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/tt9;->o0000oO0()V

    :cond_1
    invoke-virtual {v0, p2}, Llyiahf/vczjk/tt9;->o000O0oO(Llyiahf/vczjk/eb4;)V

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-eq v1, v2, :cond_1

    sget-object p2, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    if-ne v1, p2, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/tt9;->o00000o0()V

    return-object v0

    :cond_2
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "Expected END_OBJECT after copying contents of a JsonParser into TokenBuffer, got "

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p1, p1, Llyiahf/vczjk/v72;->OooOo:Llyiahf/vczjk/eb4;

    const-class v1, Llyiahf/vczjk/tt9;

    invoke-static {v1, v0, p1, p2}, Llyiahf/vczjk/v72;->o0000o0(Ljava/lang/Class;Ljava/lang/String;Llyiahf/vczjk/eb4;Llyiahf/vczjk/gc4;)Llyiahf/vczjk/qj5;

    move-result-object p1

    throw p1
.end method
