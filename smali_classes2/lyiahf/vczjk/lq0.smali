.class public final Llyiahf/vczjk/lq0;
.super Llyiahf/vczjk/dp8;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/qq0;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/z4a;

.field public final OooOOOO:Llyiahf/vczjk/oq0;

.field public final OooOOOo:Z

.field public final OooOOo0:Llyiahf/vczjk/d3a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/z4a;Llyiahf/vczjk/oq0;ZLlyiahf/vczjk/d3a;)V
    .locals 1

    const-string v0, "typeProjection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "attributes"

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/lq0;->OooOOO:Llyiahf/vczjk/z4a;

    iput-object p2, p0, Llyiahf/vczjk/lq0;->OooOOOO:Llyiahf/vczjk/oq0;

    iput-boolean p3, p0, Llyiahf/vczjk/lq0;->OooOOOo:Z

    iput-object p4, p0, Llyiahf/vczjk/lq0;->OooOOo0:Llyiahf/vczjk/d3a;

    return-void
.end method


# virtual methods
.method public final OoooOO0()Llyiahf/vczjk/jg5;
    .locals 3

    sget-object v0, Llyiahf/vczjk/pq2;->OooOOO0:Llyiahf/vczjk/pq2;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/String;

    const/4 v2, 0x1

    invoke-static {v0, v2, v1}, Llyiahf/vczjk/uq2;->OooO00o(Llyiahf/vczjk/pq2;Z[Ljava/lang/String;)Llyiahf/vczjk/oq2;

    move-result-object v0

    return-object v0
.end method

.method public final o000000()Llyiahf/vczjk/n3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/lq0;->OooOOOO:Llyiahf/vczjk/oq0;

    return-object v0
.end method

.method public final o000000o()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/lq0;->OooOOOo:Z

    return v0
.end method

.method public final o00000O0(Llyiahf/vczjk/al4;)Llyiahf/vczjk/uk4;
    .locals 4

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/lq0;

    iget-object v1, p0, Llyiahf/vczjk/lq0;->OooOOO:Llyiahf/vczjk/z4a;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/z4a;->OooO0Oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/z4a;

    move-result-object p1

    iget-object v1, p0, Llyiahf/vczjk/lq0;->OooOOOO:Llyiahf/vczjk/oq0;

    iget-boolean v2, p0, Llyiahf/vczjk/lq0;->OooOOOo:Z

    iget-object v3, p0, Llyiahf/vczjk/lq0;->OooOOo0:Llyiahf/vczjk/d3a;

    invoke-direct {v0, p1, v1, v2, v3}, Llyiahf/vczjk/lq0;-><init>(Llyiahf/vczjk/z4a;Llyiahf/vczjk/oq0;ZLlyiahf/vczjk/d3a;)V

    return-object v0
.end method

.method public final o00000OO(Z)Llyiahf/vczjk/iaa;
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/lq0;->OooOOOo:Z

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/lq0;

    iget-object v1, p0, Llyiahf/vczjk/lq0;->OooOOOO:Llyiahf/vczjk/oq0;

    iget-object v2, p0, Llyiahf/vczjk/lq0;->OooOOo0:Llyiahf/vczjk/d3a;

    iget-object v3, p0, Llyiahf/vczjk/lq0;->OooOOO:Llyiahf/vczjk/z4a;

    invoke-direct {v0, v3, v1, p1, v2}, Llyiahf/vczjk/lq0;-><init>(Llyiahf/vczjk/z4a;Llyiahf/vczjk/oq0;ZLlyiahf/vczjk/d3a;)V

    return-object v0
.end method

.method public final o00000Oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/iaa;
    .locals 4

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/lq0;

    iget-object v1, p0, Llyiahf/vczjk/lq0;->OooOOO:Llyiahf/vczjk/z4a;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/z4a;->OooO0Oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/z4a;

    move-result-object p1

    iget-object v1, p0, Llyiahf/vczjk/lq0;->OooOOOO:Llyiahf/vczjk/oq0;

    iget-boolean v2, p0, Llyiahf/vczjk/lq0;->OooOOOo:Z

    iget-object v3, p0, Llyiahf/vczjk/lq0;->OooOOo0:Llyiahf/vczjk/d3a;

    invoke-direct {v0, p1, v1, v2, v3}, Llyiahf/vczjk/lq0;-><init>(Llyiahf/vczjk/z4a;Llyiahf/vczjk/oq0;ZLlyiahf/vczjk/d3a;)V

    return-object v0
.end method

.method public final o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;
    .locals 4

    const-string v0, "newAttributes"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/lq0;

    iget-object v1, p0, Llyiahf/vczjk/lq0;->OooOOOO:Llyiahf/vczjk/oq0;

    iget-boolean v2, p0, Llyiahf/vczjk/lq0;->OooOOOo:Z

    iget-object v3, p0, Llyiahf/vczjk/lq0;->OooOOO:Llyiahf/vczjk/z4a;

    invoke-direct {v0, v3, v1, v2, p1}, Llyiahf/vczjk/lq0;-><init>(Llyiahf/vczjk/z4a;Llyiahf/vczjk/oq0;ZLlyiahf/vczjk/d3a;)V

    return-object v0
.end method

.method public final o0000Ooo(Z)Llyiahf/vczjk/dp8;
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/lq0;->OooOOOo:Z

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/lq0;

    iget-object v1, p0, Llyiahf/vczjk/lq0;->OooOOOO:Llyiahf/vczjk/oq0;

    iget-object v2, p0, Llyiahf/vczjk/lq0;->OooOOo0:Llyiahf/vczjk/d3a;

    iget-object v3, p0, Llyiahf/vczjk/lq0;->OooOOO:Llyiahf/vczjk/z4a;

    invoke-direct {v0, v3, v1, p1, v2}, Llyiahf/vczjk/lq0;-><init>(Llyiahf/vczjk/z4a;Llyiahf/vczjk/oq0;ZLlyiahf/vczjk/d3a;)V

    return-object v0
.end method

.method public final o00ooo()Ljava/util/List;
    .locals 1

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object v0
.end method

.method public final o0OOO0o()Llyiahf/vczjk/d3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/lq0;->OooOOo0:Llyiahf/vczjk/d3a;

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Captured("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/lq0;->OooOOO:Llyiahf/vczjk/z4a;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-boolean v1, p0, Llyiahf/vczjk/lq0;->OooOOOo:Z

    if-eqz v1, :cond_0

    const-string v1, "?"

    goto :goto_0

    :cond_0
    const-string v1, ""

    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
