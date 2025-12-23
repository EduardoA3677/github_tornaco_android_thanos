.class public final Llyiahf/vczjk/v26;
.super Llyiahf/vczjk/o52;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ev1;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/dp8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dp8;)V
    .locals 1

    const-string v0, "delegate"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/v26;->OooOOO:Llyiahf/vczjk/dp8;

    return-void
.end method


# virtual methods
.method public final Oooo0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;
    .locals 4

    const-string v0, "replacement"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/l5a;->OooO0o(Llyiahf/vczjk/uk4;)Z

    move-result v0

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/l5a;->OooO0o0(Llyiahf/vczjk/uk4;)Z

    move-result v0

    if-nez v0, :cond_0

    return-object p1

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/dp8;

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    check-cast p1, Llyiahf/vczjk/dp8;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-static {p1}, Llyiahf/vczjk/l5a;->OooO0o(Llyiahf/vczjk/uk4;)Z

    move-result p1

    if-nez p1, :cond_1

    return-object v0

    :cond_1
    new-instance p1, Llyiahf/vczjk/v26;

    invoke-direct {p1, v0}, Llyiahf/vczjk/v26;-><init>(Llyiahf/vczjk/dp8;)V

    return-object p1

    :cond_2
    instance-of v0, p1, Llyiahf/vczjk/k23;

    if-eqz v0, :cond_5

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/k23;

    iget-object v2, v0, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object v3

    invoke-static {v2}, Llyiahf/vczjk/l5a;->OooO0o(Llyiahf/vczjk/uk4;)Z

    move-result v2

    if-nez v2, :cond_3

    goto :goto_0

    :cond_3
    new-instance v2, Llyiahf/vczjk/v26;

    invoke-direct {v2, v3}, Llyiahf/vczjk/v26;-><init>(Llyiahf/vczjk/dp8;)V

    move-object v3, v2

    :goto_0
    iget-object v0, v0, Llyiahf/vczjk/k23;->OooOOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object v1

    invoke-static {v0}, Llyiahf/vczjk/l5a;->OooO0o(Llyiahf/vczjk/uk4;)Z

    move-result v0

    if-nez v0, :cond_4

    goto :goto_1

    :cond_4
    new-instance v0, Llyiahf/vczjk/v26;

    invoke-direct {v0, v1}, Llyiahf/vczjk/v26;-><init>(Llyiahf/vczjk/dp8;)V

    move-object v1, v0

    :goto_1
    invoke-static {v3, v1}, Llyiahf/vczjk/so8;->OooOoOO(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/iaa;

    move-result-object v0

    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooO0oO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/uk4;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/qu6;->OooOo0o(Llyiahf/vczjk/iaa;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object p1

    return-object p1

    :cond_5
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1
.end method

.method public final o000000o()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final o00000o0(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/iaa;
    .locals 2

    const-string v0, "newAttributes"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/v26;

    iget-object v1, p0, Llyiahf/vczjk/v26;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/dp8;->o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;

    move-result-object p1

    invoke-direct {v0, p1}, Llyiahf/vczjk/v26;-><init>(Llyiahf/vczjk/dp8;)V

    return-object v0
.end method

.method public final o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;
    .locals 2

    const-string v0, "newAttributes"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/v26;

    iget-object v1, p0, Llyiahf/vczjk/v26;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/dp8;->o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;

    move-result-object p1

    invoke-direct {v0, p1}, Llyiahf/vczjk/v26;-><init>(Llyiahf/vczjk/dp8;)V

    return-object v0
.end method

.method public final o00000oo()Llyiahf/vczjk/dp8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v26;->OooOOO:Llyiahf/vczjk/dp8;

    return-object v0
.end method

.method public final o0000O00(Llyiahf/vczjk/dp8;)Llyiahf/vczjk/o52;
    .locals 1

    new-instance v0, Llyiahf/vczjk/v26;

    invoke-direct {v0, p1}, Llyiahf/vczjk/v26;-><init>(Llyiahf/vczjk/dp8;)V

    return-object v0
.end method

.method public final o0000Ooo(Z)Llyiahf/vczjk/dp8;
    .locals 1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    iget-object v0, p0, Llyiahf/vczjk/v26;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1

    :cond_0
    return-object p0
.end method

.method public final o000oOoO()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method
