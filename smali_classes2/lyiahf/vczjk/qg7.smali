.class public final Llyiahf/vczjk/qg7;
.super Llyiahf/vczjk/k23;
.source "SourceFile"


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)V
    .locals 1

    const-string v0, "lowerBound"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "upperBound"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/k23;-><init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)V

    sget-object v0, Llyiahf/vczjk/wk4;->OooO00o:Llyiahf/vczjk/v06;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/v06;->OooO0O0(Llyiahf/vczjk/uk4;Llyiahf/vczjk/uk4;)Z

    return-void
.end method

.method public static final o0000(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    const/16 v0, 0x3c

    invoke-static {p0, v0}, Llyiahf/vczjk/z69;->Oooo0o0(Ljava/lang/CharSequence;C)Z

    move-result v1

    if-nez v1, :cond_0

    return-object p0

    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-static {v0, p0, p0}, Llyiahf/vczjk/z69;->o0OoOo0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 p1, 0x3e

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-static {p1, p0, p0}, Llyiahf/vczjk/z69;->OoooooO(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final o00000oo(Llyiahf/vczjk/h72;Llyiahf/vczjk/uk4;)Ljava/util/ArrayList;
    .locals 10

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object p1

    new-instance v0, Ljava/util/ArrayList;

    const/16 v1, 0xa

    invoke-static {p1, v1}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/z4a;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v2, "typeProjection"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    new-instance v8, Llyiahf/vczjk/g72;

    const/4 v1, 0x0

    invoke-direct {v8, p0, v1}, Llyiahf/vczjk/g72;-><init>(Llyiahf/vczjk/h72;I)V

    const/4 v6, 0x0

    const/4 v7, 0x0

    const-string v5, ", "

    const/16 v9, 0x3c

    invoke-static/range {v3 .. v9}, Llyiahf/vczjk/d21;->o0ooOOo(Ljava/lang/Iterable;Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)V

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    return-object v0
.end method


# virtual methods
.method public final OoooOO0()Llyiahf/vczjk/jg5;
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/k23;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/by0;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/by0;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    new-instance v1, Llyiahf/vczjk/pg7;

    invoke-direct {v1}, Llyiahf/vczjk/pg7;-><init>()V

    invoke-interface {v0, v1}, Llyiahf/vczjk/by0;->OooOooO(Llyiahf/vczjk/g5a;)Llyiahf/vczjk/jg5;

    move-result-object v0

    const-string v1, "getMemberScope(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Incorrect classifier: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/k23;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final o00000O0(Llyiahf/vczjk/al4;)Llyiahf/vczjk/uk4;
    .locals 3

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/qg7;

    iget-object v0, p0, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    const-string v1, "type"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, p0, Llyiahf/vczjk/k23;->OooOOOO:Llyiahf/vczjk/dp8;

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p1, v0, v2}, Llyiahf/vczjk/k23;-><init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)V

    return-object p1
.end method

.method public final o00000OO(Z)Llyiahf/vczjk/iaa;
    .locals 3

    new-instance v0, Llyiahf/vczjk/qg7;

    iget-object v1, p0, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/k23;->OooOOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v2, p1}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object p1

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/qg7;-><init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)V

    return-object v0
.end method

.method public final o00000Oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/iaa;
    .locals 3

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Llyiahf/vczjk/qg7;

    iget-object v0, p0, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    const-string v1, "type"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, p0, Llyiahf/vczjk/k23;->OooOOOO:Llyiahf/vczjk/dp8;

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p1, v0, v2}, Llyiahf/vczjk/k23;-><init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)V

    return-object p1
.end method

.method public final o00000o0(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/iaa;
    .locals 3

    const-string v0, "newAttributes"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/qg7;

    iget-object v1, p0, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/dp8;->o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/k23;->OooOOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v2, p1}, Llyiahf/vczjk/dp8;->o00000oO(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/dp8;

    move-result-object p1

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/qg7;-><init>(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)V

    return-object v0
.end method

.method public final o00000oO(Llyiahf/vczjk/h72;Llyiahf/vczjk/h72;)Ljava/lang/String;
    .locals 10

    const-string v0, "renderer"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/h72;->OoooOOo(Llyiahf/vczjk/uk4;)Ljava/lang/String;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/k23;->OooOOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/h72;->OoooOOo(Llyiahf/vczjk/uk4;)Ljava/lang/String;

    move-result-object v3

    iget-object p2, p2, Llyiahf/vczjk/h72;->OooO00o:Llyiahf/vczjk/l72;

    invoke-virtual {p2}, Llyiahf/vczjk/l72;->OooOOO()Z

    move-result p2

    if-eqz p2, :cond_0

    new-instance p1, Ljava/lang/StringBuilder;

    const-string p2, "raw ("

    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p2, ".."

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 p2, 0x29

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object p2

    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    move-result p2

    if-eqz p2, :cond_1

    invoke-static {p0}, Llyiahf/vczjk/fu6;->OooOO0o(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/hk4;

    move-result-object p2

    invoke-virtual {p1, v1, v3, p2}, Llyiahf/vczjk/h72;->Oooo000(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/hk4;)Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_1
    invoke-static {p1, v0}, Llyiahf/vczjk/qg7;->o00000oo(Llyiahf/vczjk/h72;Llyiahf/vczjk/uk4;)Ljava/util/ArrayList;

    move-result-object v4

    invoke-static {p1, v2}, Llyiahf/vczjk/qg7;->o00000oo(Llyiahf/vczjk/h72;Llyiahf/vczjk/uk4;)Ljava/util/ArrayList;

    move-result-object p2

    sget-object v8, Llyiahf/vczjk/iu6;->OooOOOo:Llyiahf/vczjk/iu6;

    const/4 v6, 0x0

    const/4 v7, 0x0

    const-string v5, ", "

    const/16 v9, 0x1e

    invoke-static/range {v4 .. v9}, Llyiahf/vczjk/d21;->o0ooOoO(Ljava/lang/Iterable;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object v0

    invoke-static {v4, p2}, Llyiahf/vczjk/d21;->o0000Oo(Ljava/util/Collection;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object p2

    invoke-virtual {p2}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {p2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :cond_3
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_4

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/xn6;

    invoke-virtual {v2}, Llyiahf/vczjk/xn6;->OooO0OO()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    invoke-virtual {v2}, Llyiahf/vczjk/xn6;->OooO0Oo()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    const-string v5, "out "

    invoke-static {v2, v5}, Llyiahf/vczjk/z69;->OoooOoo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_3

    const-string v4, "*"

    invoke-virtual {v2, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_5

    goto :goto_0

    :cond_4
    :goto_1
    invoke-static {v3, v0}, Llyiahf/vczjk/qg7;->o0000(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    :cond_5
    invoke-static {v1, v0}, Llyiahf/vczjk/qg7;->o0000(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-static {p2, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_6

    return-object p2

    :cond_6
    invoke-static {p0}, Llyiahf/vczjk/fu6;->OooOO0o(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/hk4;

    move-result-object v0

    invoke-virtual {p1, p2, v3, v0}, Llyiahf/vczjk/h72;->Oooo000(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/hk4;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public final o0000Ooo()Llyiahf/vczjk/dp8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    return-object v0
.end method
