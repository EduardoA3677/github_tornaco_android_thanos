.class public final Llyiahf/vczjk/ac2;
.super Llyiahf/vczjk/ez2;
.source "SourceFile"


# instance fields
.field public final OooO0O0:Llyiahf/vczjk/we4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/we4;)V
    .locals 1

    const-string v0, "delegate"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ac2;->OooO0O0:Llyiahf/vczjk/we4;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/sd4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ac2;->OooO0O0:Llyiahf/vczjk/we4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/we4;->OooO(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/sd4;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/zp6;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ac2;->OooO0O0:Llyiahf/vczjk/we4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/we4;->OooO0O0(Llyiahf/vczjk/zp6;)V

    return-void
.end method

.method public final OooO0OO(Llyiahf/vczjk/zp6;)V
    .locals 1

    const-string v0, "path"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/ac2;->OooO0O0:Llyiahf/vczjk/we4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/we4;->OooO0OO(Llyiahf/vczjk/zp6;)V

    return-void
.end method

.method public final OooO0o(Llyiahf/vczjk/zp6;)Ljava/util/List;
    .locals 3

    const-string v0, "dir"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/ac2;->OooO0O0:Llyiahf/vczjk/we4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/we4;->OooO0o(Llyiahf/vczjk/zp6;)Ljava/util/List;

    move-result-object p1

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    check-cast p1, Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/zp6;

    const-string v2, "path"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    invoke-static {v0}, Llyiahf/vczjk/i21;->OoooOOO(Ljava/util/List;)V

    return-object v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/o62;
    .locals 10

    const-string v0, "path"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/ac2;->OooO0O0:Llyiahf/vczjk/we4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/we4;->OooO0oo(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/o62;

    move-result-object p1

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    iget-object v0, p1, Llyiahf/vczjk/o62;->OooO0Oo:Ljava/lang/Object;

    move-object v4, v0

    check-cast v4, Llyiahf/vczjk/zp6;

    if-nez v4, :cond_1

    return-object p1

    :cond_1
    iget-object v0, p1, Llyiahf/vczjk/o62;->OooO:Ljava/lang/Object;

    move-object v9, v0

    check-cast v9, Ljava/util/Map;

    const-string v0, "extras"

    invoke-static {v9, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/o62;

    iget-object v0, p1, Llyiahf/vczjk/o62;->OooO0oO:Ljava/io/Serializable;

    move-object v7, v0

    check-cast v7, Ljava/lang/Long;

    iget-object v0, p1, Llyiahf/vczjk/o62;->OooO0oo:Ljava/lang/Object;

    move-object v8, v0

    check-cast v8, Ljava/lang/Long;

    iget-boolean v2, p1, Llyiahf/vczjk/o62;->OooO0O0:Z

    iget-boolean v3, p1, Llyiahf/vczjk/o62;->OooO0OO:Z

    iget-object v0, p1, Llyiahf/vczjk/o62;->OooO0o0:Ljava/lang/Object;

    move-object v5, v0

    check-cast v5, Ljava/lang/Long;

    iget-object p1, p1, Llyiahf/vczjk/o62;->OooO0o:Ljava/io/Serializable;

    move-object v6, p1

    check-cast v6, Ljava/lang/Long;

    invoke-direct/range {v1 .. v9}, Llyiahf/vczjk/o62;-><init>(ZZLlyiahf/vczjk/zp6;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Ljava/util/Map;)V

    return-object v1
.end method

.method public final OooOO0(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/rq8;
    .locals 1

    invoke-virtual {p1}, Llyiahf/vczjk/zp6;->OooO0OO()Llyiahf/vczjk/zp6;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/ez2;->OooO00o(Llyiahf/vczjk/zp6;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ac2;->OooO0O0:Llyiahf/vczjk/we4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/we4;->OooOO0(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/rq8;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0O(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/rx8;
    .locals 1

    const-string v0, "file"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/ac2;->OooO0O0:Llyiahf/vczjk/we4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/we4;->OooOO0O(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/rx8;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0o(Llyiahf/vczjk/zp6;Llyiahf/vczjk/zp6;)V
    .locals 1

    const-string v0, "source"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "target"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/ac2;->OooO0O0:Llyiahf/vczjk/we4;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/we4;->OooOO0o(Llyiahf/vczjk/zp6;Llyiahf/vczjk/zp6;)V

    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    const-class v2, Llyiahf/vczjk/ac2;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zm7;->OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/gf4;->OooO0O0()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x28

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/ac2;->OooO0O0:Llyiahf/vczjk/we4;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
