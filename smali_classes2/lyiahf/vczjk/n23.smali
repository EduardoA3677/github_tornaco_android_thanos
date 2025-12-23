.class public final Llyiahf/vczjk/n23;
.super Llyiahf/vczjk/k23;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/p5a;


# instance fields
.field public final OooOOOo:Llyiahf/vczjk/k23;

.field public final OooOOo0:Llyiahf/vczjk/uk4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k23;Llyiahf/vczjk/uk4;)V
    .locals 2

    const-string v0, "origin"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "enhancement"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p1, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    iget-object v1, p1, Llyiahf/vczjk/k23;->OooOOOO:Llyiahf/vczjk/dp8;

    invoke-direct {p0, v0, v1}, Llyiahf/vczjk/k23;-><init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)V

    iput-object p1, p0, Llyiahf/vczjk/n23;->OooOOOo:Llyiahf/vczjk/k23;

    iput-object p2, p0, Llyiahf/vczjk/n23;->OooOOo0:Llyiahf/vczjk/uk4;

    return-void
.end method


# virtual methods
.method public final OooOOOO()Llyiahf/vczjk/uk4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/n23;->OooOOo0:Llyiahf/vczjk/uk4;

    return-object v0
.end method

.method public final OoooOOo()Llyiahf/vczjk/iaa;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/n23;->OooOOOo:Llyiahf/vczjk/k23;

    return-object v0
.end method

.method public final o00000O0(Llyiahf/vczjk/al4;)Llyiahf/vczjk/uk4;
    .locals 3

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/n23;

    iget-object v0, p0, Llyiahf/vczjk/n23;->OooOOOo:Llyiahf/vczjk/k23;

    const-string v1, "type"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, p0, Llyiahf/vczjk/n23;->OooOOo0:Llyiahf/vczjk/uk4;

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p1, v0, v2}, Llyiahf/vczjk/n23;-><init>(Llyiahf/vczjk/k23;Llyiahf/vczjk/uk4;)V

    return-object p1
.end method

.method public final o00000OO(Z)Llyiahf/vczjk/iaa;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/n23;->OooOOOo:Llyiahf/vczjk/k23;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/iaa;->o00000OO(Z)Llyiahf/vczjk/iaa;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/n23;->OooOOo0:Llyiahf/vczjk/uk4;

    invoke-virtual {v1}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object v1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/iaa;->o00000OO(Z)Llyiahf/vczjk/iaa;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/qu6;->OooOo0o(Llyiahf/vczjk/iaa;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object p1

    return-object p1
.end method

.method public final o00000Oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/iaa;
    .locals 3

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/n23;

    iget-object v0, p0, Llyiahf/vczjk/n23;->OooOOOo:Llyiahf/vczjk/k23;

    const-string v1, "type"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, p0, Llyiahf/vczjk/n23;->OooOOo0:Llyiahf/vczjk/uk4;

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p1, v0, v2}, Llyiahf/vczjk/n23;-><init>(Llyiahf/vczjk/k23;Llyiahf/vczjk/uk4;)V

    return-object p1
.end method

.method public final o00000o0(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/iaa;
    .locals 1

    const-string v0, "newAttributes"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/n23;->OooOOOo:Llyiahf/vczjk/k23;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/iaa;->o00000o0(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/iaa;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/n23;->OooOOo0:Llyiahf/vczjk/uk4;

    invoke-static {p1, v0}, Llyiahf/vczjk/qu6;->OooOo0o(Llyiahf/vczjk/iaa;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object p1

    return-object p1
.end method

.method public final o00000oO(Llyiahf/vczjk/h72;Llyiahf/vczjk/h72;)Ljava/lang/String;
    .locals 3

    const-string v0, "renderer"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p2, Llyiahf/vczjk/h72;->OooO00o:Llyiahf/vczjk/l72;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/l72;->OoooOo0:[Llyiahf/vczjk/th4;

    const/16 v2, 0xb

    aget-object v1, v1, v2

    iget-object v2, v0, Llyiahf/vczjk/l72;->OooOOO0:Llyiahf/vczjk/k72;

    invoke-virtual {v2, v0, v1}, Llyiahf/vczjk/k72;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object p2, p0, Llyiahf/vczjk/n23;->OooOOo0:Llyiahf/vczjk/uk4;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/h72;->OoooOOo(Llyiahf/vczjk/uk4;)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/n23;->OooOOOo:Llyiahf/vczjk/k23;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/k23;->o00000oO(Llyiahf/vczjk/h72;Llyiahf/vczjk/h72;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public final o0000Ooo()Llyiahf/vczjk/dp8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/n23;->OooOOOo:Llyiahf/vczjk/k23;

    invoke-virtual {v0}, Llyiahf/vczjk/k23;->o0000Ooo()Llyiahf/vczjk/dp8;

    move-result-object v0

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "[@EnhancedForWarnings("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/n23;->OooOOo0:Llyiahf/vczjk/uk4;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ")] "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/n23;->OooOOOo:Llyiahf/vczjk/k23;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
