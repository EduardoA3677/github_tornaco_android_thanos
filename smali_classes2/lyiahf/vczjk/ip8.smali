.class public final Llyiahf/vczjk/ip8;
.super Llyiahf/vczjk/o52;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/p5a;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/dp8;

.field public final OooOOOO:Llyiahf/vczjk/uk4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/uk4;)V
    .locals 1

    const-string v0, "delegate"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "enhancement"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ip8;->OooOOO:Llyiahf/vczjk/dp8;

    iput-object p2, p0, Llyiahf/vczjk/ip8;->OooOOOO:Llyiahf/vczjk/uk4;

    return-void
.end method


# virtual methods
.method public final OooOOOO()Llyiahf/vczjk/uk4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ip8;->OooOOOO:Llyiahf/vczjk/uk4;

    return-object v0
.end method

.method public final OoooOOo()Llyiahf/vczjk/iaa;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ip8;->OooOOO:Llyiahf/vczjk/dp8;

    return-object v0
.end method

.method public final bridge synthetic o0000(Llyiahf/vczjk/al4;)Llyiahf/vczjk/dp8;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ip8;->o0000oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/ip8;

    move-result-object p1

    return-object p1
.end method

.method public final bridge synthetic o00000O0(Llyiahf/vczjk/al4;)Llyiahf/vczjk/uk4;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ip8;->o0000oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/ip8;

    move-result-object p1

    return-object p1
.end method

.method public final bridge synthetic o00000Oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/iaa;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ip8;->o0000oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/ip8;

    move-result-object p1

    return-object p1
.end method

.method public final o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;
    .locals 1

    const-string v0, "newAttributes"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/ip8;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/dp8;->o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/ip8;->OooOOOO:Llyiahf/vczjk/uk4;

    invoke-static {p1, v0}, Llyiahf/vczjk/qu6;->OooOo0o(Llyiahf/vczjk/iaa;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object p1

    const-string v0, "null cannot be cast to non-null type org.jetbrains.kotlin.types.SimpleType"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/dp8;

    return-object p1
.end method

.method public final o00000oo()Llyiahf/vczjk/dp8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ip8;->OooOOO:Llyiahf/vczjk/dp8;

    return-object v0
.end method

.method public final o0000O00(Llyiahf/vczjk/dp8;)Llyiahf/vczjk/o52;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ip8;

    iget-object v1, p0, Llyiahf/vczjk/ip8;->OooOOOO:Llyiahf/vczjk/uk4;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/ip8;-><init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/uk4;)V

    return-object v0
.end method

.method public final o0000Ooo(Z)Llyiahf/vczjk/dp8;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ip8;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/ip8;->OooOOOO:Llyiahf/vczjk/uk4;

    invoke-virtual {v1}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object v1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/iaa;->o00000OO(Z)Llyiahf/vczjk/iaa;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/qu6;->OooOo0o(Llyiahf/vczjk/iaa;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object p1

    const-string v0, "null cannot be cast to non-null type org.jetbrains.kotlin.types.SimpleType"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/dp8;

    return-object p1
.end method

.method public final o0000oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/ip8;
    .locals 3

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/ip8;

    iget-object v0, p0, Llyiahf/vczjk/ip8;->OooOOO:Llyiahf/vczjk/dp8;

    const-string v1, "type"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, p0, Llyiahf/vczjk/ip8;->OooOOOO:Llyiahf/vczjk/uk4;

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p1, v0, v2}, Llyiahf/vczjk/ip8;-><init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/uk4;)V

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "[@EnhancedForWarnings("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/ip8;->OooOOOO:Llyiahf/vczjk/uk4;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ")] "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/ip8;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
