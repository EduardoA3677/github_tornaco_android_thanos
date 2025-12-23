.class public final Llyiahf/vczjk/h89;
.super Llyiahf/vczjk/kg5;
.source "SourceFile"


# instance fields
.field public final OooO0O0:Llyiahf/vczjk/cm5;

.field public final OooO0OO:Llyiahf/vczjk/hc3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hc3;)V
    .locals 1

    const-string v0, "moduleDescriptor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "fqName"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/h89;->OooO0O0:Llyiahf/vczjk/cm5;

    iput-object p2, p0, Llyiahf/vczjk/h89;->OooO0OO:Llyiahf/vczjk/hc3;

    return-void
.end method


# virtual methods
.method public final OooO0OO()Ljava/util/Set;
    .locals 1

    sget-object v0, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/Collection;
    .locals 8

    const-string v0, "kindFilter"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Llyiahf/vczjk/e72;->OooO0oo:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/e72;->OooO00o(I)Z

    move-result v0

    sget-object v1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/h89;->OooO0OO:Llyiahf/vczjk/hc3;

    iget-object v2, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v2}, Llyiahf/vczjk/ic3;->OooO0OO()Z

    move-result v2

    if-eqz v2, :cond_1

    sget-object v2, Llyiahf/vczjk/b72;->OooO00o:Llyiahf/vczjk/b72;

    iget-object p1, p1, Llyiahf/vczjk/e72;->OooO00o:Ljava/util/List;

    invoke-interface {p1, v2}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    :goto_0
    return-object v1

    :cond_1
    iget-object p1, p0, Llyiahf/vczjk/h89;->OooO0O0:Llyiahf/vczjk/cm5;

    invoke-interface {p1, v0, p2}, Llyiahf/vczjk/cm5;->OooO0oo(Llyiahf/vczjk/hc3;Llyiahf/vczjk/oe3;)Ljava/util/Collection;

    move-result-object v1

    new-instance v2, Ljava/util/ArrayList;

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v3

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_2
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_5

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/hc3;

    iget-object v3, v3, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v3}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v3

    invoke-interface {p2, v3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Boolean;

    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    if-eqz v4, :cond_2

    iget-boolean v4, v3, Llyiahf/vczjk/qt5;->OooOOO:Z

    const/4 v5, 0x0

    if-eqz v4, :cond_3

    goto :goto_2

    :cond_3
    invoke-virtual {v0, v3}, Llyiahf/vczjk/hc3;->OooO00o(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hc3;

    move-result-object v3

    invoke-interface {p1, v3}, Llyiahf/vczjk/cm5;->OooooO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/vh6;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/hw4;

    iget-object v4, v3, Llyiahf/vczjk/hw4;->OooOo0:Llyiahf/vczjk/o45;

    sget-object v6, Llyiahf/vczjk/hw4;->OooOo0o:[Llyiahf/vczjk/th4;

    const/4 v7, 0x1

    aget-object v6, v6, v7

    invoke-static {v4, v6}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Boolean;

    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    if-eqz v4, :cond_4

    goto :goto_2

    :cond_4
    move-object v5, v3

    :goto_2
    invoke-static {v2, v5}, Llyiahf/vczjk/t51;->OooOO0o(Ljava/util/AbstractCollection;Ljava/lang/Object;)V

    goto :goto_1

    :cond_5
    return-object v2
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "subpackages of "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/h89;->OooO0OO:Llyiahf/vczjk/hc3;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " from "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/h89;->OooO0O0:Llyiahf/vczjk/cm5;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
