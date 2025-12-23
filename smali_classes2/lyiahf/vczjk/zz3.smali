.class public final Llyiahf/vczjk/zz3;
.super Llyiahf/vczjk/kg5;
.source "SourceFile"


# instance fields
.field public final OooO0O0:Llyiahf/vczjk/jg5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jg5;)V
    .locals 1

    const-string v0, "workerScope"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zz3;->OooO0O0:Llyiahf/vczjk/jg5;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/util/Set;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zz3;->OooO0O0:Llyiahf/vczjk/jg5;

    invoke-interface {v0}, Llyiahf/vczjk/jg5;->OooO00o()Ljava/util/Set;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "location"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/zz3;->OooO0O0:Llyiahf/vczjk/jg5;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/mr7;->OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;

    move-result-object p1

    const/4 p2, 0x0

    if-eqz p1, :cond_2

    instance-of v0, p1, Llyiahf/vczjk/by0;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/by0;

    goto :goto_0

    :cond_0
    move-object v0, p2

    :goto_0
    if-eqz v0, :cond_1

    return-object v0

    :cond_1
    instance-of v0, p1, Llyiahf/vczjk/a3a;

    if-eqz v0, :cond_2

    check-cast p1, Llyiahf/vczjk/a3a;

    return-object p1

    :cond_2
    return-object p2
.end method

.method public final OooO0OO()Ljava/util/Set;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zz3;->OooO0O0:Llyiahf/vczjk/jg5;

    invoke-interface {v0}, Llyiahf/vczjk/jg5;->OooO0OO()Ljava/util/Set;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/Collection;
    .locals 2

    const-string v0, "kindFilter"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Llyiahf/vczjk/e72;->OooOO0o:I

    iget v1, p1, Llyiahf/vczjk/e72;->OooO0O0:I

    and-int/2addr v0, v1

    if-nez v0, :cond_0

    const/4 p1, 0x0

    goto :goto_0

    :cond_0
    new-instance v1, Llyiahf/vczjk/e72;

    iget-object p1, p1, Llyiahf/vczjk/e72;->OooO00o:Ljava/util/List;

    invoke-direct {v1, v0, p1}, Llyiahf/vczjk/e72;-><init>(ILjava/util/List;)V

    move-object p1, v1

    :goto_0
    if-nez p1, :cond_1

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/zz3;->OooO0O0:Llyiahf/vczjk/jg5;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/mr7;->OooO0o(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/Collection;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    new-instance p2, Ljava/util/ArrayList;

    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_2
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/hz0;

    if-eqz v1, :cond_2

    invoke-virtual {p2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_3
    return-object p2
.end method

.method public final OooO0oO()Ljava/util/Set;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zz3;->OooO0O0:Llyiahf/vczjk/jg5;

    invoke-interface {v0}, Llyiahf/vczjk/jg5;->OooO0oO()Ljava/util/Set;

    move-result-object v0

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Classes from "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/zz3;->OooO0O0:Llyiahf/vczjk/jg5;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
