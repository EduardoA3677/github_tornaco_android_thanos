.class public abstract Llyiahf/vczjk/uk4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/gm;
.implements Llyiahf/vczjk/yk4;


# instance fields
.field public OooOOO0:I


# virtual methods
.method public final OooOOo0()Llyiahf/vczjk/ko;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/ro;->OooO00o(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/ko;

    move-result-object v0

    return-object v0
.end method

.method public abstract OoooOO0()Llyiahf/vczjk/jg5;
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    if-ne p0, p1, :cond_0

    goto :goto_0

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/uk4;

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result v0

    check-cast p1, Llyiahf/vczjk/uk4;

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result v1

    if-ne v0, v1, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/uk2;->OooOo0:Llyiahf/vczjk/uk2;

    invoke-static {v1, v0, p1}, Llyiahf/vczjk/cp7;->Oooo(Llyiahf/vczjk/fz0;Llyiahf/vczjk/yk4;Llyiahf/vczjk/yk4;)Z

    move-result p1

    if-eqz p1, :cond_2

    :goto_0
    const/4 p1, 0x1

    return p1

    :cond_2
    :goto_1
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 2

    iget v0, p0, Llyiahf/vczjk/uk4;->OooOOO0:I

    if-eqz v0, :cond_0

    return v0

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/jp8;->OooOooO(Llyiahf/vczjk/uk4;)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-super {p0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    goto :goto_0

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    mul-int/lit8 v1, v1, 0x1f

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000o()Z

    move-result v0

    add-int/2addr v0, v1

    :goto_0
    iput v0, p0, Llyiahf/vczjk/uk4;->OooOOO0:I

    return v0
.end method

.method public abstract o000000()Llyiahf/vczjk/n3a;
.end method

.method public abstract o000000o()Z
.end method

.method public abstract o00000O()Llyiahf/vczjk/iaa;
.end method

.method public abstract o00000O0(Llyiahf/vczjk/al4;)Llyiahf/vczjk/uk4;
.end method

.method public abstract o00ooo()Ljava/util/List;
.end method

.method public abstract o0OOO0o()Llyiahf/vczjk/d3a;
.end method
