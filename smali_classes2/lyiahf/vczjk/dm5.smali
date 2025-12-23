.class public final Llyiahf/vczjk/dm5;
.super Llyiahf/vczjk/w02;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/cm5;


# instance fields
.field public final OooOOo:Llyiahf/vczjk/q45;

.field public final OooOOoo:Llyiahf/vczjk/hk4;

.field public final OooOo:Z

.field public final OooOo0:Llyiahf/vczjk/yh6;

.field public final OooOo00:Ljava/util/Map;

.field public OooOo0O:Llyiahf/vczjk/tg7;

.field public OooOo0o:Llyiahf/vczjk/lh6;

.field public final OooOoO:Llyiahf/vczjk/sc9;

.field public final OooOoO0:Llyiahf/vczjk/l45;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qt5;Llyiahf/vczjk/q45;Llyiahf/vczjk/hk4;I)V
    .locals 1

    sget-object p4, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    const-string v0, "moduleName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    invoke-direct {p0, v0, p1}, Llyiahf/vczjk/w02;-><init>(Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;)V

    iput-object p2, p0, Llyiahf/vczjk/dm5;->OooOOo:Llyiahf/vczjk/q45;

    iput-object p3, p0, Llyiahf/vczjk/dm5;->OooOOoo:Llyiahf/vczjk/hk4;

    iget-boolean p3, p1, Llyiahf/vczjk/qt5;->OooOOO:Z

    if-eqz p3, :cond_1

    iput-object p4, p0, Llyiahf/vczjk/dm5;->OooOo00:Ljava/util/Map;

    sget-object p1, Llyiahf/vczjk/yh6;->OooO00o:Llyiahf/vczjk/wh6;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/wh6;->OooO0O0:Llyiahf/vczjk/mm3;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/dm5;->OoooOoo(Llyiahf/vczjk/mm3;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/yh6;

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/xh6;->OooO0O0:Llyiahf/vczjk/xh6;

    :cond_0
    iput-object p1, p0, Llyiahf/vczjk/dm5;->OooOo0:Llyiahf/vczjk/yh6;

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/dm5;->OooOo:Z

    new-instance p1, Llyiahf/vczjk/oo000o;

    const/16 p3, 0x12

    invoke-direct {p1, p0, p3}, Llyiahf/vczjk/oo000o;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p2, p1}, Llyiahf/vczjk/q45;->OooO0O0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/l45;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/dm5;->OooOoO0:Llyiahf/vczjk/l45;

    new-instance p1, Llyiahf/vczjk/gd4;

    const/4 p2, 0x1

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/gd4;-><init>(Llyiahf/vczjk/dm5;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/dm5;->OooOoO:Llyiahf/vczjk/sc9;

    return-void

    :cond_1
    new-instance p2, Ljava/lang/IllegalArgumentException;

    new-instance p3, Ljava/lang/StringBuilder;

    const-string p4, "Module name must be special: "

    invoke-direct {p3, p4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2
.end method


# virtual methods
.method public final OooO0oo(Llyiahf/vczjk/hc3;Llyiahf/vczjk/oe3;)Ljava/util/Collection;
    .locals 1

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/dm5;->o0000oO()V

    invoke-virtual {p0}, Llyiahf/vczjk/dm5;->o0000oO()V

    iget-object v0, p0, Llyiahf/vczjk/dm5;->OooOoO:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ig1;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/ig1;->OooO0oo(Llyiahf/vczjk/hc3;Llyiahf/vczjk/oe3;)Ljava/util/Collection;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0O()Llyiahf/vczjk/hk4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/dm5;->OooOOoo:Llyiahf/vczjk/hk4;

    return-object v0
.end method

.method public final OooOO0o()Llyiahf/vczjk/v02;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OoooOoO(Llyiahf/vczjk/z02;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-interface {p1, p2, p0}, Llyiahf/vczjk/z02;->OoooO(Ljava/lang/Object;Llyiahf/vczjk/dm5;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OoooOoo(Llyiahf/vczjk/mm3;)Ljava/lang/Object;
    .locals 1

    const-string v0, "capability"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/dm5;->OooOo00:Ljava/util/Map;

    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_0

    const/4 p1, 0x0

    :cond_0
    return-object p1
.end method

.method public final Ooooo00(Llyiahf/vczjk/cm5;)Z
    .locals 1

    const-string v0, "targetModule"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/dm5;->OooOo0O:Llyiahf/vczjk/tg7;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    invoke-static {v0, p1}, Llyiahf/vczjk/d21;->OoooooO(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/dm5;->o00o0O()Ljava/util/List;

    instance-of v0, p1, Ljava/lang/Void;

    if-nez v0, :cond_2

    goto :goto_0

    :cond_2
    move-object v0, p1

    check-cast v0, Ljava/lang/Void;

    :goto_0
    invoke-interface {p1}, Llyiahf/vczjk/cm5;->o00o0O()Ljava/util/List;

    move-result-object p1

    invoke-interface {p1, p0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_3

    :goto_1
    const/4 p1, 0x1

    return p1

    :cond_3
    const/4 p1, 0x0

    return p1
.end method

.method public final OooooO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/vh6;
    .locals 1

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/dm5;->o0000oO()V

    iget-object v0, p0, Llyiahf/vczjk/dm5;->OooOoO0:Llyiahf/vczjk/l45;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/l45;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/vh6;

    return-object p1
.end method

.method public final o0000oO()V
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/dm5;->OooOo:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    sget-object v0, Llyiahf/vczjk/vc6;->OooO0OO:Llyiahf/vczjk/mm3;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/dm5;->OoooOoo(Llyiahf/vczjk/mm3;)Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_1

    new-instance v0, Llyiahf/vczjk/f44;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Accessing invalid module descriptor "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    const-string v2, "message"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    new-instance v0, Ljava/lang/ClassCastException;

    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    throw v0
.end method

.method public final o00o0O()Ljava/util/List;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/dm5;->OooOo0O:Llyiahf/vczjk/tg7;

    if-eqz v0, :cond_0

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object v0

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Dependencies of module "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/qt5;->OooOOO0:Ljava/lang/String;

    const-string v2, "toString(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " were not set"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/AssertionError;

    invoke-direct {v1, v0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-static {p0}, Llyiahf/vczjk/w02;->o0000oo(Llyiahf/vczjk/v02;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-boolean v1, p0, Llyiahf/vczjk/dm5;->OooOo:Z

    if-nez v1, :cond_0

    const-string v1, " !isValid"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_0
    const-string v1, " packageFragmentProvider: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/dm5;->OooOo0o:Llyiahf/vczjk/lh6;

    if-eqz v1, :cond_1

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v1

    goto :goto_0

    :cond_1
    const/4 v1, 0x0

    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
