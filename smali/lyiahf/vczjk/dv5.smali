.class public Llyiahf/vczjk/dv5;
.super Llyiahf/vczjk/av5;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Iterable;
.implements Llyiahf/vczjk/cg4;


# static fields
.field public static final synthetic OooOOoo:I


# instance fields
.field public final OooOOo:Llyiahf/vczjk/rr0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hv5;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/av5;-><init>(Llyiahf/vczjk/sy5;)V

    new-instance p1, Llyiahf/vczjk/rr0;

    invoke-direct {p1, p0}, Llyiahf/vczjk/rr0;-><init>(Llyiahf/vczjk/dv5;)V

    iput-object p1, p0, Llyiahf/vczjk/dv5;->OooOOo:Llyiahf/vczjk/rr0;

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/String;ZLlyiahf/vczjk/av5;)Llyiahf/vczjk/zu5;
    .locals 7

    const-string v0, "route"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "lastVisited"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/dv5;->OooOOo:Llyiahf/vczjk/rr0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, v0, Llyiahf/vczjk/rr0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/dv5;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, v0, Llyiahf/vczjk/av5;->OooOOO:Llyiahf/vczjk/j1;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/j1;->OooOOOO(Ljava/lang/String;)Llyiahf/vczjk/zu5;

    move-result-object v1

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v0}, Llyiahf/vczjk/dv5;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_0
    :goto_0
    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/fv5;

    invoke-virtual {v4}, Llyiahf/vczjk/fv5;->hasNext()Z

    move-result v5

    const/4 v6, 0x0

    if-eqz v5, :cond_3

    invoke-virtual {v4}, Llyiahf/vczjk/fv5;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/av5;

    invoke-static {v4, p3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1

    goto :goto_1

    :cond_1
    instance-of v5, v4, Llyiahf/vczjk/dv5;

    if-eqz v5, :cond_2

    check-cast v4, Llyiahf/vczjk/dv5;

    const/4 v5, 0x0

    invoke-virtual {v4, p1, v5, v0}, Llyiahf/vczjk/dv5;->OooO(Ljava/lang/String;ZLlyiahf/vczjk/av5;)Llyiahf/vczjk/zu5;

    move-result-object v6

    goto :goto_1

    :cond_2
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v4, v4, Llyiahf/vczjk/av5;->OooOOO:Llyiahf/vczjk/j1;

    invoke-virtual {v4, p1}, Llyiahf/vczjk/j1;->OooOOOO(Ljava/lang/String;)Llyiahf/vczjk/zu5;

    move-result-object v6

    :goto_1
    if-eqz v6, :cond_0

    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_3
    invoke-static {v2}, Llyiahf/vczjk/d21;->oo0o0Oo(Ljava/util/ArrayList;)Ljava/lang/Comparable;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/zu5;

    iget-object v3, v0, Llyiahf/vczjk/av5;->OooOOOO:Llyiahf/vczjk/dv5;

    if-eqz v3, :cond_4

    if-eqz p2, :cond_4

    invoke-virtual {v3, p3}, Llyiahf/vczjk/dv5;->equals(Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_4

    const/4 p2, 0x1

    invoke-virtual {v3, p1, p2, v0}, Llyiahf/vczjk/dv5;->OooO(Ljava/lang/String;ZLlyiahf/vczjk/av5;)Llyiahf/vczjk/zu5;

    move-result-object v6

    :cond_4
    filled-new-array {v1, v2, v6}, [Llyiahf/vczjk/zu5;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/sy;->o0OO00O([Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/d21;->oo0o0Oo(Ljava/util/ArrayList;)Ljava/lang/Comparable;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/zu5;

    return-object p1
.end method

.method public final OooO0o(Llyiahf/vczjk/ed5;)Llyiahf/vczjk/zu5;
    .locals 4

    invoke-super {p0, p1}, Llyiahf/vczjk/av5;->OooO0o(Llyiahf/vczjk/ed5;)Llyiahf/vczjk/zu5;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/dv5;->OooOOo:Llyiahf/vczjk/rr0;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, v1, Llyiahf/vczjk/rr0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/dv5;

    const/4 v3, 0x0

    invoke-virtual {v1, v0, p1, v3, v2}, Llyiahf/vczjk/rr0;->OooOOOO(Llyiahf/vczjk/zu5;Llyiahf/vczjk/ed5;ZLlyiahf/vczjk/av5;)Llyiahf/vczjk/zu5;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0oo(Llyiahf/vczjk/ed5;Llyiahf/vczjk/av5;)Llyiahf/vczjk/zu5;
    .locals 3

    const-string v0, "lastVisited"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-super {p0, p1}, Llyiahf/vczjk/av5;->OooO0o(Llyiahf/vczjk/ed5;)Llyiahf/vczjk/zu5;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/dv5;->OooOOo:Llyiahf/vczjk/rr0;

    const/4 v2, 0x1

    invoke-virtual {v1, v0, p1, v2, p2}, Llyiahf/vczjk/rr0;->OooOOOO(Llyiahf/vczjk/zu5;Llyiahf/vczjk/ed5;ZLlyiahf/vczjk/av5;)Llyiahf/vczjk/zu5;

    move-result-object p1

    return-object p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    if-ne p0, p1, :cond_0

    goto :goto_0

    :cond_0
    if-eqz p1, :cond_4

    instance-of v0, p1, Llyiahf/vczjk/dv5;

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-super {p0, p1}, Llyiahf/vczjk/av5;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/dv5;->OooOOo:Llyiahf/vczjk/rr0;

    iget-object v1, v0, Llyiahf/vczjk/rr0;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ly8;

    invoke-virtual {v1}, Llyiahf/vczjk/ly8;->OooO0oO()I

    move-result v1

    check-cast p1, Llyiahf/vczjk/dv5;

    iget-object p1, p1, Llyiahf/vczjk/dv5;->OooOOo:Llyiahf/vczjk/rr0;

    iget-object v2, p1, Llyiahf/vczjk/rr0;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ly8;

    invoke-virtual {v2}, Llyiahf/vczjk/ly8;->OooO0oO()I

    move-result v2

    if-ne v1, v2, :cond_4

    iget v1, v0, Llyiahf/vczjk/rr0;->OooOOO:I

    iget v2, p1, Llyiahf/vczjk/rr0;->OooOOO:I

    if-ne v1, v2, :cond_4

    const-string v1, "<this>"

    iget-object v0, v0, Llyiahf/vczjk/rr0;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ly8;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/o00O000;

    const/4 v2, 0x2

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/o00O000;-><init>(Ljava/lang/Object;I)V

    invoke-static {v1}, Llyiahf/vczjk/ag8;->Oooo00O(Ljava/util/Iterator;)Llyiahf/vczjk/wf8;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/mj1;

    invoke-virtual {v0}, Llyiahf/vczjk/mj1;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/av5;

    iget-object v2, v1, Llyiahf/vczjk/av5;->OooOOO:Llyiahf/vczjk/j1;

    iget v2, v2, Llyiahf/vczjk/j1;->OooO00o:I

    iget-object v3, p1, Llyiahf/vczjk/rr0;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ly8;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/ly8;->OooO0OO(I)Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/av5;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2

    goto :goto_1

    :cond_3
    :goto_0
    const/4 p1, 0x1

    return p1

    :cond_4
    :goto_1
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/dv5;->OooOOo:Llyiahf/vczjk/rr0;

    iget v1, v0, Llyiahf/vczjk/rr0;->OooOOO:I

    iget-object v0, v0, Llyiahf/vczjk/rr0;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ly8;

    invoke-virtual {v0}, Llyiahf/vczjk/ly8;->OooO0oO()I

    move-result v2

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_0

    invoke-virtual {v0, v3}, Llyiahf/vczjk/ly8;->OooO0Oo(I)I

    move-result v4

    invoke-virtual {v0, v3}, Llyiahf/vczjk/ly8;->OooO0oo(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/av5;

    const/16 v6, 0x1f

    const/16 v7, 0x1f

    invoke-static {v1, v6, v4, v7}, Llyiahf/vczjk/ii5;->OooO0O0(IIII)I

    move-result v1

    invoke-virtual {v5}, Llyiahf/vczjk/av5;->hashCode()I

    move-result v4

    add-int/2addr v1, v4

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    return v1
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/dv5;->OooOOo:Llyiahf/vczjk/rr0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/fv5;

    invoke-direct {v1, v0}, Llyiahf/vczjk/fv5;-><init>(Llyiahf/vczjk/rr0;)V

    return-object v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-super {p0}, Llyiahf/vczjk/av5;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/dv5;->OooOOo:Llyiahf/vczjk/rr0;

    iget-object v2, v1, Llyiahf/vczjk/rr0;->OooOOo:Ljava/lang/Object;

    check-cast v2, Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-eqz v2, :cond_1

    invoke-static {v2}, Llyiahf/vczjk/z69;->OoooOO0(Ljava/lang/CharSequence;)Z

    move-result v3

    if-eqz v3, :cond_0

    goto :goto_0

    :cond_0
    const/4 v3, 0x1

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/rr0;->OooO0o0(Ljava/lang/String;Z)Llyiahf/vczjk/av5;

    move-result-object v2

    goto :goto_1

    :cond_1
    :goto_0
    const/4 v2, 0x0

    :goto_1
    if-nez v2, :cond_2

    iget v2, v1, Llyiahf/vczjk/rr0;->OooOOO:I

    invoke-virtual {v1, v2}, Llyiahf/vczjk/rr0;->OooO0Oo(I)Llyiahf/vczjk/av5;

    move-result-object v2

    :cond_2
    const-string v3, " startDestination="

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    if-nez v2, :cond_5

    iget-object v2, v1, Llyiahf/vczjk/rr0;->OooOOo:Ljava/lang/Object;

    check-cast v2, Ljava/lang/String;

    if-eqz v2, :cond_3

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_2

    :cond_3
    iget-object v2, v1, Llyiahf/vczjk/rr0;->OooOOo0:Ljava/io/Serializable;

    check-cast v2, Ljava/lang/String;

    if-eqz v2, :cond_4

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_2

    :cond_4
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "0x"

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget v1, v1, Llyiahf/vczjk/rr0;->OooOOO:I

    invoke-static {v1}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_2

    :cond_5
    const-string v1, "{"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Llyiahf/vczjk/av5;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "}"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :goto_2
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "toString(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method
