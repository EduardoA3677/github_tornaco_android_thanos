.class public final Llyiahf/vczjk/rr4;
.super Llyiahf/vczjk/ds4;
.source "SourceFile"


# static fields
.field public static final synthetic OooOo0O:I


# instance fields
.field public final OooOOO:Llyiahf/vczjk/by0;

.field public final OooOOOO:Llyiahf/vczjk/cm7;

.field public final OooOOOo:Z

.field public final OooOOo:Llyiahf/vczjk/o45;

.field public final OooOOo0:Llyiahf/vczjk/o45;

.field public final OooOOoo:Llyiahf/vczjk/o45;

.field public final OooOo0:Llyiahf/vczjk/r60;

.field public final OooOo00:Llyiahf/vczjk/o45;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/by0;Llyiahf/vczjk/cm7;ZLlyiahf/vczjk/rr4;)V
    .locals 1

    const-string v0, "c"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "ownerDescriptor"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "jClass"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/ds4;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/rr4;)V

    iput-object p2, p0, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    iput-object p3, p0, Llyiahf/vczjk/rr4;->OooOOOO:Llyiahf/vczjk/cm7;

    iput-boolean p4, p0, Llyiahf/vczjk/rr4;->OooOOOo:Z

    iget-object p2, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/s64;

    iget-object p2, p2, Llyiahf/vczjk/s64;->OooO00o:Llyiahf/vczjk/q45;

    new-instance p3, Llyiahf/vczjk/or4;

    invoke-direct {p3, p0, p1}, Llyiahf/vczjk/or4;-><init>(Llyiahf/vczjk/rr4;Llyiahf/vczjk/ld9;)V

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p4, Llyiahf/vczjk/o45;

    invoke-direct {p4, p2, p3}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p4, p0, Llyiahf/vczjk/rr4;->OooOOo0:Llyiahf/vczjk/o45;

    new-instance p3, Llyiahf/vczjk/pr4;

    const/4 p4, 0x0

    invoke-direct {p3, p0, p4}, Llyiahf/vczjk/pr4;-><init>(Llyiahf/vczjk/rr4;I)V

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p4, Llyiahf/vczjk/o45;

    invoke-direct {p4, p2, p3}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p4, p0, Llyiahf/vczjk/rr4;->OooOOo:Llyiahf/vczjk/o45;

    new-instance p3, Llyiahf/vczjk/or4;

    invoke-direct {p3, p1, p0}, Llyiahf/vczjk/or4;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/rr4;)V

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p4, Llyiahf/vczjk/o45;

    invoke-direct {p4, p2, p3}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p4, p0, Llyiahf/vczjk/rr4;->OooOOoo:Llyiahf/vczjk/o45;

    new-instance p3, Llyiahf/vczjk/pr4;

    const/4 p4, 0x1

    invoke-direct {p3, p0, p4}, Llyiahf/vczjk/pr4;-><init>(Llyiahf/vczjk/rr4;I)V

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p4, Llyiahf/vczjk/o45;

    invoke-direct {p4, p2, p3}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p4, p0, Llyiahf/vczjk/rr4;->OooOo00:Llyiahf/vczjk/o45;

    new-instance p3, Llyiahf/vczjk/o0oOO;

    const/4 p4, 0x7

    invoke-direct {p3, p4, p0, p1}, Llyiahf/vczjk/o0oOO;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {p2, p3}, Llyiahf/vczjk/q45;->OooO0OO(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/r60;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/rr4;->OooOo0:Llyiahf/vczjk/r60;

    return-void
.end method

.method public static OooOoOO(Llyiahf/vczjk/ho8;Llyiahf/vczjk/rf3;Ljava/util/AbstractCollection;)Llyiahf/vczjk/ho8;
    .locals 2

    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :cond_1
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ho8;

    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/tf3;->OoooO00:Llyiahf/vczjk/rf3;

    if-nez v1, :cond_1

    invoke-static {v0, p1}, Llyiahf/vczjk/rr4;->OooOooO(Llyiahf/vczjk/rf3;Llyiahf/vczjk/rf3;)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p0}, Llyiahf/vczjk/rf3;->o0Oo0oo()Llyiahf/vczjk/qf3;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/qf3;->Oooo0()Llyiahf/vczjk/qf3;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/qf3;->build()Llyiahf/vczjk/rf3;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast p0, Llyiahf/vczjk/ho8;

    :cond_2
    :goto_0
    return-object p0
.end method

.method public static OooOoo0(Llyiahf/vczjk/ho8;)Llyiahf/vczjk/ho8;
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/tf3;->OoooOOO()Ljava/util/List;

    move-result-object v0

    const-string v1, "getValueParameters(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/d21;->o0OO00O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/tca;

    const/4 v2, 0x0

    if-eqz v0, :cond_5

    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/bda;

    invoke-virtual {v3}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v3

    invoke-interface {v3}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v3

    if-eqz v3, :cond_1

    invoke-static {v3}, Llyiahf/vczjk/p72;->OooO0oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/ic3;->OooO0Oo()Z

    move-result v4

    if-eqz v4, :cond_0

    goto :goto_0

    :cond_0
    move-object v3, v2

    :goto_0
    if-eqz v3, :cond_1

    invoke-virtual {v3}, Llyiahf/vczjk/ic3;->OooO0oO()Llyiahf/vczjk/hc3;

    move-result-object v3

    goto :goto_1

    :cond_1
    move-object v3, v2

    :goto_1
    sget-object v4, Llyiahf/vczjk/x09;->OooO0oO:Llyiahf/vczjk/hc3;

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_2

    goto :goto_2

    :cond_2
    move-object v0, v2

    :goto_2
    if-nez v0, :cond_3

    goto :goto_3

    :cond_3
    invoke-interface {p0}, Llyiahf/vczjk/rf3;->o0Oo0oo()Llyiahf/vczjk/qf3;

    move-result-object v2

    invoke-virtual {p0}, Llyiahf/vczjk/tf3;->OoooOOO()Ljava/util/List;

    move-result-object p0

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/d21;->ooOO(Ljava/util/List;)Ljava/util/List;

    move-result-object p0

    invoke-interface {v2, p0}, Llyiahf/vczjk/qf3;->OooO0OO(Ljava/util/List;)Llyiahf/vczjk/qf3;

    move-result-object p0

    check-cast v0, Llyiahf/vczjk/bda;

    invoke-virtual {v0}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object v0

    const/4 v1, 0x0

    invoke-interface {v0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/z4a;

    invoke-virtual {v0}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v0

    invoke-interface {p0, v0}, Llyiahf/vczjk/qf3;->OooOoO(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/qf3;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/qf3;->build()Llyiahf/vczjk/rf3;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/ho8;

    if-eqz p0, :cond_4

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/tf3;->Oooo0O0:Z

    :cond_4
    return-object p0

    :cond_5
    :goto_3
    return-object v2
.end method

.method public static OooOooO(Llyiahf/vczjk/rf3;Llyiahf/vczjk/rf3;)Z
    .locals 3

    sget-object v0, Llyiahf/vczjk/ng6;->OooO0OO:Llyiahf/vczjk/ng6;

    const/4 v1, 0x1

    invoke-virtual {v0, p1, p0, v1}, Llyiahf/vczjk/ng6;->OooOOO(Llyiahf/vczjk/co0;Llyiahf/vczjk/co0;Z)Llyiahf/vczjk/mg6;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/mg6;->OooO0O0()I

    move-result v0

    const-string v2, "getResult(...)"

    invoke-static {v0, v2}, Llyiahf/vczjk/u81;->OooOoO0(ILjava/lang/String;)V

    if-ne v0, v1, :cond_0

    invoke-static {p1, p0}, Llyiahf/vczjk/m6a;->Oooo0OO(Llyiahf/vczjk/co0;Llyiahf/vczjk/co0;)Z

    move-result p0

    if-nez p0, :cond_0

    return v1

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOooo(Llyiahf/vczjk/ho8;Llyiahf/vczjk/ho8;)Z
    .locals 2

    sget v0, Llyiahf/vczjk/kk0;->OooOO0o:I

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v0

    const-string v1, "removeAt"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/r02;->OooOO0O(Llyiahf/vczjk/co0;)Ljava/lang/String;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/ty8;->OooO0oO:Llyiahf/vczjk/py8;

    iget-object v1, v1, Llyiahf/vczjk/py8;->OooO0o0:Ljava/lang/String;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/ho8;->o0000o0O()Llyiahf/vczjk/ho8;

    move-result-object p1

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {p1, p0}, Llyiahf/vczjk/rr4;->OooOooO(Llyiahf/vczjk/rf3;Llyiahf/vczjk/rf3;)Z

    move-result p0

    return p0
.end method

.method public static Oooo000(Llyiahf/vczjk/sa7;Ljava/lang/String;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/ho8;
    .locals 4

    invoke-static {p1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p1

    invoke-interface {p2, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    const/4 v0, 0x0

    if-eqz p2, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/ho8;

    invoke-virtual {p2}, Llyiahf/vczjk/tf3;->OoooOOO()Ljava/util/List;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v1

    if-eqz v1, :cond_1

    goto :goto_1

    :cond_1
    sget-object v1, Llyiahf/vczjk/wk4;->OooO00o:Llyiahf/vczjk/v06;

    iget-object v2, p2, Llyiahf/vczjk/tf3;->OooOo0O:Llyiahf/vczjk/uk4;

    if-nez v2, :cond_2

    const/4 v1, 0x0

    goto :goto_0

    :cond_2
    invoke-interface {p0}, Llyiahf/vczjk/gca;->getType()Llyiahf/vczjk/uk4;

    move-result-object v3

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/v06;->OooO0O0(Llyiahf/vczjk/uk4;Llyiahf/vczjk/uk4;)Z

    move-result v1

    :goto_0
    if-eqz v1, :cond_3

    move-object v0, p2

    :cond_3
    :goto_1
    if-eqz v0, :cond_0

    :cond_4
    return-object v0
.end method

.method public static Oooo00o(Llyiahf/vczjk/sa7;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/ho8;
    .locals 5

    invoke-interface {p0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v0

    const-string v1, "asString(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/bd4;->OooO0O0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-interface {p1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_5

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ho8;

    invoke-virtual {v0}, Llyiahf/vczjk/tf3;->OoooOOO()Ljava/util/List;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v2

    const/4 v3, 0x1

    if-eq v2, v3, :cond_1

    goto :goto_0

    :cond_1
    iget-object v2, v0, Llyiahf/vczjk/tf3;->OooOo0O:Llyiahf/vczjk/uk4;

    if-nez v2, :cond_2

    goto :goto_0

    :cond_2
    sget-object v3, Llyiahf/vczjk/hk4;->OooO0o0:Llyiahf/vczjk/qt5;

    sget-object v3, Llyiahf/vczjk/w09;->OooO0Oo:Llyiahf/vczjk/ic3;

    invoke-static {v2, v3}, Llyiahf/vczjk/hk4;->OooOooo(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ic3;)Z

    move-result v2

    if-nez v2, :cond_3

    goto :goto_0

    :cond_3
    sget-object v2, Llyiahf/vczjk/wk4;->OooO00o:Llyiahf/vczjk/v06;

    invoke-virtual {v0}, Llyiahf/vczjk/tf3;->OoooOOO()Ljava/util/List;

    move-result-object v3

    const-string v4, "getValueParameters(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v3}, Llyiahf/vczjk/d21;->o00000o0(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/tca;

    check-cast v3, Llyiahf/vczjk/bda;

    invoke-virtual {v3}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v3

    invoke-interface {p0}, Llyiahf/vczjk/gca;->getType()Llyiahf/vczjk/uk4;

    move-result-object v4

    invoke-virtual {v2, v3, v4}, Llyiahf/vczjk/v06;->OooO00o(Llyiahf/vczjk/uk4;Llyiahf/vczjk/uk4;)Z

    move-result v2

    if-eqz v2, :cond_4

    move-object v1, v0

    :cond_4
    :goto_0
    if-eqz v1, :cond_0

    :cond_5
    return-object v1
.end method

.method public static Oooo0OO(Llyiahf/vczjk/ho8;Llyiahf/vczjk/rf3;)Z
    .locals 4

    const/4 v0, 0x2

    invoke-static {p0, v0}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1}, Llyiahf/vczjk/rf3;->OooO00o()Llyiahf/vczjk/rf3;

    move-result-object v2

    const-string v3, "getOriginal(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2, v0}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-static {p0, p1}, Llyiahf/vczjk/rr4;->OooOooO(Llyiahf/vczjk/rf3;Llyiahf/vczjk/rf3;)Z

    move-result p0

    if-nez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/e72;Llyiahf/vczjk/g13;)Ljava/util/Set;
    .locals 4

    const-string v0, "kindFilter"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    invoke-interface {v0}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/n3a;->OooO0O0()Ljava/util/Collection;

    move-result-object v1

    const-string v2, "getSupertypes(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, Ljava/lang/Iterable;

    new-instance v2, Ljava/util/LinkedHashSet;

    invoke-direct {v2}, Ljava/util/LinkedHashSet;-><init>()V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_0

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/uk4;

    invoke-virtual {v3}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v3

    invoke-interface {v3}, Llyiahf/vczjk/jg5;->OooO00o()Ljava/util/Set;

    move-result-object v3

    check-cast v3, Ljava/lang/Iterable;

    invoke-static {v3, v2}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/ds4;->OooO0o0:Llyiahf/vczjk/o45;

    invoke-virtual {v1}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/c12;

    invoke-interface {v3}, Llyiahf/vczjk/c12;->OooO00o()Ljava/util/Set;

    move-result-object v3

    check-cast v3, Ljava/util/Collection;

    invoke-virtual {v2, v3}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    invoke-virtual {v1}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/c12;

    invoke-interface {v1}, Llyiahf/vczjk/c12;->OooO0Oo()Ljava/util/Set;

    move-result-object v1

    check-cast v1, Ljava/util/Collection;

    invoke-virtual {v2, v1}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/rr4;->OooO0oo(Llyiahf/vczjk/e72;Llyiahf/vczjk/g13;)Ljava/util/Set;

    move-result-object p1

    invoke-virtual {v2, p1}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    iget-object p1, p0, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object p2, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/s64;

    iget-object p2, p2, Llyiahf/vczjk/s64;->OooOo:Llyiahf/vczjk/zc9;

    check-cast p2, Llyiahf/vczjk/up3;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string p2, "thisDescriptor"

    invoke-static {v0, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p2, "c"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v2, p1}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    return-object v2
.end method

.method public final OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "location"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/rr4;->Oooo0o(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)V

    iget-object p2, p0, Llyiahf/vczjk/ds4;->OooO0OO:Llyiahf/vczjk/rr4;

    if-eqz p2, :cond_0

    iget-object p2, p2, Llyiahf/vczjk/rr4;->OooOo0:Llyiahf/vczjk/r60;

    if-eqz p2, :cond_0

    invoke-virtual {p2, p1}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/by0;

    if-eqz p2, :cond_0

    return-object p2

    :cond_0
    iget-object p2, p0, Llyiahf/vczjk/rr4;->OooOo0:Llyiahf/vczjk/r60;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/r60;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gz0;

    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/rr4;->Oooo0o(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)V

    invoke-super {p0, p1, p2}, Llyiahf/vczjk/ds4;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/rr4;->Oooo0o(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)V

    invoke-super {p0, p1, p2}, Llyiahf/vczjk/ds4;->OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0oo(Llyiahf/vczjk/e72;Llyiahf/vczjk/g13;)Ljava/util/Set;
    .locals 0

    const-string p2, "kindFilter"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/rr4;->OooOOo:Llyiahf/vczjk/o45;

    invoke-virtual {p1}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Set;

    iget-object p2, p0, Llyiahf/vczjk/rr4;->OooOo00:Llyiahf/vczjk/o45;

    invoke-virtual {p2}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/util/Map;

    invoke-interface {p2}, Ljava/util/Map;->keySet()Ljava/util/Set;

    move-result-object p2

    check-cast p2, Ljava/lang/Iterable;

    invoke-static {p1, p2}, Llyiahf/vczjk/mh8;->OoooOO0(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0(Ljava/util/ArrayList;Llyiahf/vczjk/qt5;)V
    .locals 20

    move-object/from16 v0, p0

    move-object/from16 v1, p2

    const-string v2, "name"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v0, Llyiahf/vczjk/rr4;->OooOOOO:Llyiahf/vczjk/cm7;

    invoke-virtual {v2}, Llyiahf/vczjk/cm7;->OooO0oO()Z

    move-result v2

    iget-object v3, v0, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    iget-object v4, v0, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    if-eqz v2, :cond_3

    iget-object v2, v0, Llyiahf/vczjk/ds4;->OooO0o0:Llyiahf/vczjk/o45;

    invoke-virtual {v2}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/c12;

    invoke-interface {v5, v1}, Llyiahf/vczjk/c12;->OooO0OO(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/om7;

    move-result-object v5

    if-eqz v5, :cond_3

    invoke-interface/range {p1 .. p1}, Ljava/util/Collection;->isEmpty()Z

    move-result v5

    if-eqz v5, :cond_0

    goto :goto_0

    :cond_0
    invoke-interface/range {p1 .. p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :cond_1
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_2

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/ho8;

    invoke-virtual {v6}, Llyiahf/vczjk/tf3;->OoooOOO()Ljava/util/List;

    move-result-object v6

    invoke-interface {v6}, Ljava/util/List;->isEmpty()Z

    move-result v6

    if-eqz v6, :cond_1

    goto :goto_1

    :cond_2
    :goto_0
    invoke-virtual {v2}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/c12;

    invoke-interface {v2, v1}, Llyiahf/vczjk/c12;->OooO0OO(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/om7;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v4, v2}, Llyiahf/vczjk/dn8;->o00oO0o(Llyiahf/vczjk/ld9;Llyiahf/vczjk/b64;)Llyiahf/vczjk/lr4;

    move-result-object v5

    invoke-virtual {v2}, Llyiahf/vczjk/km7;->OooO0OO()Llyiahf/vczjk/qt5;

    move-result-object v6

    iget-object v7, v4, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/s64;

    iget-object v8, v7, Llyiahf/vczjk/s64;->OooOO0:Llyiahf/vczjk/rp3;

    invoke-virtual {v8, v2}, Llyiahf/vczjk/rp3;->OooOo0O(Llyiahf/vczjk/k64;)Llyiahf/vczjk/hz7;

    move-result-object v8

    const/4 v9, 0x1

    invoke-static {v3, v5, v6, v8, v9}, Llyiahf/vczjk/o64;->o0000oO0(Llyiahf/vczjk/v02;Llyiahf/vczjk/lr4;Llyiahf/vczjk/qt5;Llyiahf/vczjk/hz7;Z)Llyiahf/vczjk/o64;

    move-result-object v10

    sget-object v5, Llyiahf/vczjk/j5a;->OooOOO:Llyiahf/vczjk/j5a;

    const/4 v6, 0x0

    const/4 v8, 0x6

    const/4 v9, 0x0

    invoke-static {v5, v9, v6, v8}, Llyiahf/vczjk/nqa;->OoooO00(Llyiahf/vczjk/j5a;ZLlyiahf/vczjk/hs4;I)Llyiahf/vczjk/a74;

    move-result-object v5

    invoke-virtual {v2}, Llyiahf/vczjk/om7;->OooO0o()Llyiahf/vczjk/y64;

    move-result-object v2

    iget-object v6, v4, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/uqa;

    invoke-virtual {v6, v2, v5}, Llyiahf/vczjk/uqa;->Oooo0oo(Llyiahf/vczjk/y64;Llyiahf/vczjk/a74;)Llyiahf/vczjk/uk4;

    move-result-object v16

    invoke-virtual {v0}, Llyiahf/vczjk/rr4;->OooOOOo()Llyiahf/vczjk/mp4;

    move-result-object v12

    sget-object v13, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    sget-object v2, Llyiahf/vczjk/yk5;->OooOOO0:Llyiahf/vczjk/wp3;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v17, Llyiahf/vczjk/yk5;->OooOOOo:Llyiahf/vczjk/yk5;

    sget-object v18, Llyiahf/vczjk/r72;->OooO0o0:Llyiahf/vczjk/q72;

    const/16 v19, 0x0

    const/4 v11, 0x0

    move-object v14, v13

    move-object v15, v13

    invoke-virtual/range {v10 .. v19}, Llyiahf/vczjk/o64;->o0000o(Llyiahf/vczjk/mp4;Llyiahf/vczjk/mp4;Ljava/util/List;Ljava/util/List;Ljava/util/List;Llyiahf/vczjk/uk4;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;Llyiahf/vczjk/bn2;)Llyiahf/vczjk/ho8;

    invoke-virtual {v10, v9, v9}, Llyiahf/vczjk/o64;->o0000oOO(ZZ)V

    iget-object v2, v7, Llyiahf/vczjk/s64;->OooO0oO:Llyiahf/vczjk/vp3;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-object/from16 v2, p1

    invoke-virtual {v2, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_3
    :goto_1
    iget-object v2, v4, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s64;

    iget-object v2, v2, Llyiahf/vczjk/s64;->OooOo:Llyiahf/vczjk/zc9;

    check-cast v2, Llyiahf/vczjk/up3;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v2, "thisDescriptor"

    invoke-static {v3, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "name"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "c"

    invoke-static {v4, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method

.method public final OooOO0O()Llyiahf/vczjk/c12;
    .locals 3

    new-instance v0, Llyiahf/vczjk/yx0;

    sget-object v1, Llyiahf/vczjk/g13;->OooOo:Llyiahf/vczjk/g13;

    iget-object v2, p0, Llyiahf/vczjk/rr4;->OooOOOO:Llyiahf/vczjk/cm7;

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/yx0;-><init>(Llyiahf/vczjk/cm7;Llyiahf/vczjk/oe3;)V

    return-object v0
.end method

.method public final OooOOO(Ljava/util/ArrayList;Llyiahf/vczjk/qt5;)V
    .locals 22

    move-object/from16 v0, p0

    move-object/from16 v3, p1

    move-object/from16 v1, p2

    const/4 v2, 0x0

    const-string v4, "name"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v4, v0, Llyiahf/vczjk/rr4;->OooOOOO:Llyiahf/vczjk/cm7;

    iget-object v4, v4, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v4}, Ljava/lang/Class;->isAnnotation()Z

    move-result v4

    iget-object v5, v0, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    const/4 v6, 0x0

    if-eqz v4, :cond_1

    iget-object v4, v0, Llyiahf/vczjk/ds4;->OooO0o0:Llyiahf/vczjk/o45;

    invoke-virtual {v4}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/c12;

    invoke-interface {v4, v1}, Llyiahf/vczjk/c12;->OooO0O0(Llyiahf/vczjk/qt5;)Ljava/util/Collection;

    move-result-object v4

    check-cast v4, Ljava/lang/Iterable;

    invoke-static {v4}, Llyiahf/vczjk/d21;->o0000Ooo(Ljava/lang/Iterable;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/lm7;

    if-nez v4, :cond_0

    goto :goto_0

    :cond_0
    sget-object v7, Llyiahf/vczjk/yk5;->OooOOO0:Llyiahf/vczjk/wp3;

    invoke-static {v5, v4}, Llyiahf/vczjk/dn8;->o00oO0o(Llyiahf/vczjk/ld9;Llyiahf/vczjk/b64;)Llyiahf/vczjk/lr4;

    move-result-object v9

    invoke-virtual {v4}, Llyiahf/vczjk/km7;->OooO0o0()Llyiahf/vczjk/oO0Oo0oo;

    move-result-object v7

    invoke-static {v7}, Llyiahf/vczjk/ht6;->OooOoOO(Llyiahf/vczjk/oO0Oo0oo;)Llyiahf/vczjk/q72;

    move-result-object v10

    invoke-virtual {v4}, Llyiahf/vczjk/km7;->OooO0OO()Llyiahf/vczjk/qt5;

    move-result-object v12

    iget-object v7, v5, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/s64;

    iget-object v7, v7, Llyiahf/vczjk/s64;->OooOO0:Llyiahf/vczjk/rp3;

    invoke-virtual {v7, v4}, Llyiahf/vczjk/rp3;->OooOo0O(Llyiahf/vczjk/k64;)Llyiahf/vczjk/hz7;

    move-result-object v13

    iget-object v8, v0, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    const/4 v11, 0x0

    const/4 v14, 0x0

    invoke-static/range {v8 .. v14}, Llyiahf/vczjk/r64;->o0000Oo0(Llyiahf/vczjk/v02;Llyiahf/vczjk/lr4;Llyiahf/vczjk/q72;ZLlyiahf/vczjk/qt5;Llyiahf/vczjk/hz7;Z)Llyiahf/vczjk/r64;

    move-result-object v15

    sget-object v7, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    invoke-static {v15, v7}, Llyiahf/vczjk/dn8;->Oooo0oO(Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;)Llyiahf/vczjk/va7;

    move-result-object v7

    invoke-virtual {v15, v7, v6, v6, v6}, Llyiahf/vczjk/ua7;->o0000OO0(Llyiahf/vczjk/va7;Llyiahf/vczjk/hb7;Llyiahf/vczjk/fx2;Llyiahf/vczjk/fx2;)V

    const-string v8, "<this>"

    invoke-static {v5, v8}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v8, v5, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    iget-object v9, v5, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/s64;

    new-instance v10, Llyiahf/vczjk/rr0;

    invoke-direct {v10, v5, v15, v4, v2}, Llyiahf/vczjk/rr0;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/x02;Llyiahf/vczjk/e74;I)V

    new-instance v11, Llyiahf/vczjk/ld9;

    invoke-direct {v11, v9, v10, v8}, Llyiahf/vczjk/ld9;-><init>(Llyiahf/vczjk/s64;Llyiahf/vczjk/v4a;Llyiahf/vczjk/kp4;)V

    invoke-static {v4, v11}, Llyiahf/vczjk/ds4;->OooOO0o(Llyiahf/vczjk/lm7;Llyiahf/vczjk/ld9;)Llyiahf/vczjk/uk4;

    move-result-object v16

    sget-object v17, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-virtual {v0}, Llyiahf/vczjk/rr4;->OooOOOo()Llyiahf/vczjk/mp4;

    move-result-object v18

    const/16 v19, 0x0

    move-object/from16 v20, v17

    invoke-virtual/range {v15 .. v20}, Llyiahf/vczjk/ua7;->o0000OOo(Llyiahf/vczjk/uk4;Ljava/util/List;Llyiahf/vczjk/mp4;Llyiahf/vczjk/mp4;Ljava/util/List;)V

    move-object/from16 v4, v16

    iput-object v4, v7, Llyiahf/vczjk/va7;->OooOoo0:Llyiahf/vczjk/uk4;

    invoke-virtual {v3, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_1
    :goto_0
    invoke-virtual {v0, v1}, Llyiahf/vczjk/rr4;->Oooo0O0(Llyiahf/vczjk/qt5;)Ljava/util/Set;

    move-result-object v4

    invoke-interface {v4}, Ljava/util/Set;->isEmpty()Z

    move-result v7

    if-eqz v7, :cond_2

    return-void

    :cond_2
    new-instance v7, Llyiahf/vczjk/dt8;

    invoke-direct {v7}, Llyiahf/vczjk/dt8;-><init>()V

    new-instance v8, Llyiahf/vczjk/dt8;

    invoke-direct {v8}, Llyiahf/vczjk/dt8;-><init>()V

    new-instance v9, Llyiahf/vczjk/qr4;

    invoke-direct {v9, v0, v2}, Llyiahf/vczjk/qr4;-><init>(Llyiahf/vczjk/rr4;I)V

    invoke-virtual {v0, v4, v3, v7, v9}, Llyiahf/vczjk/rr4;->OooOoO0(Ljava/util/Set;Ljava/util/AbstractCollection;Llyiahf/vczjk/dt8;Llyiahf/vczjk/oe3;)V

    invoke-static {v4, v7}, Llyiahf/vczjk/mh8;->OoooO0O(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object v2

    new-instance v7, Llyiahf/vczjk/qr4;

    const/4 v9, 0x1

    invoke-direct {v7, v0, v9}, Llyiahf/vczjk/qr4;-><init>(Llyiahf/vczjk/rr4;I)V

    invoke-virtual {v0, v2, v8, v6, v7}, Llyiahf/vczjk/rr4;->OooOoO0(Ljava/util/Set;Ljava/util/AbstractCollection;Llyiahf/vczjk/dt8;Llyiahf/vczjk/oe3;)V

    invoke-static {v4, v8}, Llyiahf/vczjk/mh8;->OoooOO0(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    move-result-object v2

    iget-object v4, v5, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/s64;

    iget-object v5, v4, Llyiahf/vczjk/s64;->OooOo0:Llyiahf/vczjk/v06;

    iget-object v6, v5, Llyiahf/vczjk/v06;->OooO0Oo:Llyiahf/vczjk/ng6;

    iget-object v5, v0, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    iget-object v4, v4, Llyiahf/vczjk/s64;->OooO0o:Llyiahf/vczjk/qp3;

    move-object/from16 v21, v5

    move-object v5, v4

    move-object/from16 v4, v21

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/jp8;->OoooO00(Llyiahf/vczjk/qt5;Ljava/util/AbstractCollection;Ljava/util/Collection;Llyiahf/vczjk/by0;Llyiahf/vczjk/kq2;Llyiahf/vczjk/ng6;)Ljava/util/LinkedHashSet;

    move-result-object v1

    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    return-void
.end method

.method public final OooOOO0(Ljava/util/LinkedHashSet;Llyiahf/vczjk/qt5;)V
    .locals 12

    const-string v2, "name"

    invoke-static {p2, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p2}, Llyiahf/vczjk/rr4;->Oooo0(Llyiahf/vczjk/qt5;)Ljava/util/LinkedHashSet;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/ty8;->OooO00o:Ljava/util/ArrayList;

    sget-object v3, Llyiahf/vczjk/ty8;->OooOO0:Ljava/util/HashSet;

    invoke-virtual {v3, p2}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_5

    invoke-static {p2}, Llyiahf/vczjk/lk0;->OooO0O0(Llyiahf/vczjk/qt5;)Z

    move-result v3

    if-nez v3, :cond_5

    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_2

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/rf3;

    invoke-interface {v4}, Llyiahf/vczjk/rf3;->OooOOo()Z

    move-result v4

    if-eqz v4, :cond_1

    goto :goto_2

    :cond_2
    :goto_0
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_3
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_4

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    move-object v5, v4

    check-cast v5, Llyiahf/vczjk/ho8;

    invoke-virtual {p0, v5}, Llyiahf/vczjk/rr4;->Oooo0o0(Llyiahf/vczjk/ho8;)Z

    move-result v5

    if-eqz v5, :cond_3

    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_4
    const/4 v2, 0x0

    invoke-virtual {p0, p1, p2, v3, v2}, Llyiahf/vczjk/rr4;->OooOo0o(Ljava/util/LinkedHashSet;Llyiahf/vczjk/qt5;Ljava/util/ArrayList;Z)V

    return-void

    :cond_5
    :goto_2
    new-instance v9, Llyiahf/vczjk/dt8;

    invoke-direct {v9}, Llyiahf/vczjk/dt8;-><init>()V

    sget-object v3, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    sget-object v5, Llyiahf/vczjk/kq2;->OooO0oO:Llyiahf/vczjk/sp3;

    iget-object v4, p0, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object v4, v4, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/s64;

    iget-object v4, v4, Llyiahf/vczjk/s64;->OooOo0:Llyiahf/vczjk/v06;

    iget-object v6, v4, Llyiahf/vczjk/v06;->OooO0Oo:Llyiahf/vczjk/ng6;

    iget-object v4, p0, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    move-object v1, p2

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/jp8;->OoooO00(Llyiahf/vczjk/qt5;Ljava/util/AbstractCollection;Ljava/util/Collection;Llyiahf/vczjk/by0;Llyiahf/vczjk/kq2;Llyiahf/vczjk/ng6;)Ljava/util/LinkedHashSet;

    move-result-object v10

    move-object v11, v2

    new-instance v5, Llyiahf/vczjk/o00000;

    const-class v3, Llyiahf/vczjk/rr4;

    const-string v4, "searchMethodsByNameWithoutBuiltinMagic"

    const/4 v1, 0x1

    move-object v0, v5

    const-string v5, "searchMethodsByNameWithoutBuiltinMagic(Lorg/jetbrains/kotlin/name/Name;)Ljava/util/Collection;"

    const/4 v6, 0x0

    const/16 v7, 0x9

    move-object v2, p0

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/o00000;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    move-object v4, p1

    move-object v2, p1

    move-object v1, p2

    move-object v5, v0

    move-object v3, v10

    move-object v0, p0

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/rr4;->OooOo(Llyiahf/vczjk/qt5;Ljava/util/LinkedHashSet;Ljava/util/LinkedHashSet;Ljava/util/AbstractSet;Llyiahf/vczjk/oe3;)V

    move-object v8, v3

    new-instance v0, Llyiahf/vczjk/o00000;

    const-class v3, Llyiahf/vczjk/rr4;

    const-string v4, "searchMethodsInSupertypesWithoutBuiltinMagic"

    const/4 v1, 0x1

    const-string v5, "searchMethodsInSupertypesWithoutBuiltinMagic(Lorg/jetbrains/kotlin/name/Name;)Ljava/util/Collection;"

    const/4 v6, 0x0

    const/16 v7, 0xa

    move-object v2, p0

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/o00000;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    move-object v2, p1

    move-object v1, p2

    move-object v5, v0

    move-object v3, v8

    move-object v4, v9

    move-object v0, p0

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/rr4;->OooOo(Llyiahf/vczjk/qt5;Ljava/util/LinkedHashSet;Ljava/util/LinkedHashSet;Ljava/util/AbstractSet;Llyiahf/vczjk/oe3;)V

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :cond_6
    :goto_3
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_7

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    move-object v7, v6

    check-cast v7, Llyiahf/vczjk/ho8;

    invoke-virtual {p0, v7}, Llyiahf/vczjk/rr4;->Oooo0o0(Llyiahf/vczjk/ho8;)Z

    move-result v7

    if-eqz v7, :cond_6

    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_7
    invoke-static {v4, v3}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v3

    const/4 v4, 0x1

    invoke-virtual {p0, p1, p2, v3, v4}, Llyiahf/vczjk/rr4;->OooOo0o(Ljava/util/LinkedHashSet;Llyiahf/vczjk/qt5;Ljava/util/ArrayList;Z)V

    return-void
.end method

.method public final OooOOOO(Llyiahf/vczjk/e72;)Ljava/util/Set;
    .locals 2

    const-string v0, "kindFilter"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/rr4;->OooOOOO:Llyiahf/vczjk/cm7;

    iget-object p1, p1, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {p1}, Ljava/lang/Class;->isAnnotation()Z

    move-result p1

    if-eqz p1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/ds4;->OooO00o()Ljava/util/Set;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/util/LinkedHashSet;

    iget-object v0, p0, Llyiahf/vczjk/ds4;->OooO0o0:Llyiahf/vczjk/o45;

    invoke-virtual {v0}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/c12;

    invoke-interface {v0}, Llyiahf/vczjk/c12;->OooO0o0()Ljava/util/Set;

    move-result-object v0

    check-cast v0, Ljava/util/Collection;

    invoke-direct {p1, v0}, Ljava/util/LinkedHashSet;-><init>(Ljava/util/Collection;)V

    iget-object v0, p0, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    invoke-interface {v0}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO0O0()Ljava/util/Collection;

    move-result-object v0

    const-string v1, "getSupertypes(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Ljava/lang/Iterable;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/uk4;

    invoke-virtual {v1}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/jg5;->OooO0oO()Ljava/util/Set;

    move-result-object v1

    check-cast v1, Ljava/lang/Iterable;

    invoke-static {v1, p1}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_0

    :cond_1
    return-object p1
.end method

.method public final OooOOOo()Llyiahf/vczjk/mp4;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    if-eqz v0, :cond_0

    sget v1, Llyiahf/vczjk/n72;->OooO00o:I

    invoke-interface {v0}, Llyiahf/vczjk/by0;->o00000()Llyiahf/vczjk/mp4;

    move-result-object v0

    return-object v0

    :cond_0
    const/4 v0, 0x0

    invoke-static {v0}, Llyiahf/vczjk/n72;->OooO00o(I)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooOOo(Llyiahf/vczjk/o64;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rr4;->OooOOOO:Llyiahf/vczjk/cm7;

    iget-object v0, v0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->isAnnotation()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    invoke-virtual {p0, p1}, Llyiahf/vczjk/rr4;->Oooo0o0(Llyiahf/vczjk/ho8;)Z

    move-result p1

    return p1
.end method

.method public final OooOOo0()Llyiahf/vczjk/v02;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    return-object v0
.end method

.method public final OooOOoo(Llyiahf/vczjk/lm7;Ljava/util/ArrayList;Llyiahf/vczjk/uk4;Ljava/util/List;)Llyiahf/vczjk/cs4;
    .locals 1

    const-string v0, "method"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object p1, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s64;

    iget-object p1, p1, Llyiahf/vczjk/s64;->OooO0o0:Llyiahf/vczjk/xj0;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p1, p0, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    const/4 v0, 0x1

    if-eqz p1, :cond_1

    sget-object p1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    if-eqz p1, :cond_0

    new-instance v0, Llyiahf/vczjk/cs4;

    invoke-direct {v0, p3, p4, p2, p1}, Llyiahf/vczjk/cs4;-><init>(Llyiahf/vczjk/uk4;Ljava/util/List;Ljava/util/ArrayList;Ljava/util/List;)V

    return-object v0

    :cond_0
    const/4 p1, 0x3

    new-array p1, p1, [Ljava/lang/Object;

    const-string p2, "signatureErrors"

    const/4 p3, 0x0

    aput-object p2, p1, p3

    const-string p2, "kotlin/reflect/jvm/internal/impl/load/java/components/SignaturePropagator$PropagatedSignature"

    aput-object p2, p1, v0

    const-string p2, "<init>"

    const/4 p3, 0x2

    aput-object p2, p1, p3

    const-string p2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_1
    const/4 p1, 0x3

    new-array p1, p1, [Ljava/lang/Object;

    const/4 p2, 0x0

    packed-switch v0, :pswitch_data_0

    const-string p3, "method"

    aput-object p3, p1, p2

    goto :goto_0

    :pswitch_0
    const-string p3, "signatureErrors"

    aput-object p3, p1, p2

    goto :goto_0

    :pswitch_1
    const-string p3, "descriptor"

    aput-object p3, p1, p2

    goto :goto_0

    :pswitch_2
    const-string p3, "typeParameters"

    aput-object p3, p1, p2

    goto :goto_0

    :pswitch_3
    const-string p3, "valueParameters"

    aput-object p3, p1, p2

    goto :goto_0

    :pswitch_4
    const-string p3, "returnType"

    aput-object p3, p1, p2

    goto :goto_0

    :pswitch_5
    const-string p3, "owner"

    aput-object p3, p1, p2

    :goto_0
    const/4 p2, 0x1

    const-string p3, "kotlin/reflect/jvm/internal/impl/load/java/components/SignaturePropagator$1"

    aput-object p3, p1, p2

    const/4 p2, 0x2

    const-string p3, "resolvePropagatedSignature"

    aput-object p3, p1, p2

    const-string p2, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final OooOo(Llyiahf/vczjk/qt5;Ljava/util/LinkedHashSet;Ljava/util/LinkedHashSet;Ljava/util/AbstractSet;Llyiahf/vczjk/oe3;)V
    .locals 10

    invoke-interface {p3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object p3

    :goto_0
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_e

    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ho8;

    invoke-static {v0}, Llyiahf/vczjk/dl6;->OooO0oo(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/eo0;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ho8;

    const/4 v2, 0x0

    if-nez v1, :cond_1

    :cond_0
    move-object v1, v2

    goto :goto_1

    :cond_1
    invoke-static {v1}, Llyiahf/vczjk/dl6;->OooO0o0(Llyiahf/vczjk/rf3;)Ljava/lang/String;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v3}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v3

    invoke-interface {p5, v3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/Collection;

    invoke-interface {v3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_0

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ho8;

    invoke-interface {v4}, Llyiahf/vczjk/rf3;->o0Oo0oo()Llyiahf/vczjk/qf3;

    move-result-object v4

    invoke-interface {v4, p1}, Llyiahf/vczjk/qf3;->OooOoOO(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/qf3;

    invoke-interface {v4}, Llyiahf/vczjk/qf3;->OoooOO0()Llyiahf/vczjk/qf3;

    invoke-interface {v4}, Llyiahf/vczjk/qf3;->OooOOo()Llyiahf/vczjk/qf3;

    invoke-interface {v4}, Llyiahf/vczjk/qf3;->build()Llyiahf/vczjk/rf3;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v4, Llyiahf/vczjk/ho8;

    invoke-static {v1, v4}, Llyiahf/vczjk/rr4;->OooOooo(Llyiahf/vczjk/ho8;Llyiahf/vczjk/ho8;)Z

    move-result v5

    if-eqz v5, :cond_2

    invoke-static {v4, v1, p2}, Llyiahf/vczjk/rr4;->OooOoOO(Llyiahf/vczjk/ho8;Llyiahf/vczjk/rf3;Ljava/util/AbstractCollection;)Llyiahf/vczjk/ho8;

    move-result-object v1

    :goto_1
    invoke-static {p4, v1}, Llyiahf/vczjk/t51;->OooOO0o(Ljava/util/AbstractCollection;Ljava/lang/Object;)V

    invoke-static {v0}, Llyiahf/vczjk/lk0;->OooO00o(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/rf3;

    move-result-object v1

    const-string v3, "getName(...)"

    if-nez v1, :cond_4

    :cond_3
    move-object v1, v2

    goto/16 :goto_6

    :cond_4
    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/w02;

    invoke-virtual {v4}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v4

    invoke-static {v4, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p5, v4}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Iterable;

    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :cond_5
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_6

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    move-object v6, v5

    check-cast v6, Llyiahf/vczjk/ho8;

    invoke-static {v6, v1}, Llyiahf/vczjk/rr4;->Oooo0OO(Llyiahf/vczjk/ho8;Llyiahf/vczjk/rf3;)Z

    move-result v6

    if-eqz v6, :cond_5

    goto :goto_2

    :cond_6
    move-object v5, v2

    :goto_2
    check-cast v5, Llyiahf/vczjk/ho8;

    if-eqz v5, :cond_8

    invoke-interface {v5}, Llyiahf/vczjk/rf3;->o0Oo0oo()Llyiahf/vczjk/qf3;

    move-result-object v4

    invoke-interface {v1}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object v6

    const-string v7, "getValueParameters(...)"

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v8, Ljava/util/ArrayList;

    const/16 v9, 0xa

    invoke-static {v6, v9}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v9

    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :goto_3
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    if-eqz v9, :cond_7

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/tca;

    check-cast v9, Llyiahf/vczjk/bda;

    invoke-virtual {v9}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v9

    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_7
    invoke-virtual {v5}, Llyiahf/vczjk/tf3;->OoooOOO()Ljava/util/List;

    move-result-object v5

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v8, v5, v1}, Llyiahf/vczjk/wr6;->OooOO0O(Ljava/util/List;Ljava/util/List;Llyiahf/vczjk/rf3;)Ljava/util/ArrayList;

    move-result-object v5

    invoke-interface {v4, v5}, Llyiahf/vczjk/qf3;->OooO0OO(Ljava/util/List;)Llyiahf/vczjk/qf3;

    invoke-interface {v4}, Llyiahf/vczjk/qf3;->OoooOO0()Llyiahf/vczjk/qf3;

    invoke-interface {v4}, Llyiahf/vczjk/qf3;->OooOOo()Llyiahf/vczjk/qf3;

    invoke-interface {v4}, Llyiahf/vczjk/qf3;->OooOo0O()Llyiahf/vczjk/qf3;

    invoke-interface {v4}, Llyiahf/vczjk/qf3;->build()Llyiahf/vczjk/rf3;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ho8;

    goto :goto_4

    :cond_8
    move-object v4, v2

    :goto_4
    if-eqz v4, :cond_3

    invoke-virtual {p0, v4}, Llyiahf/vczjk/rr4;->Oooo0o0(Llyiahf/vczjk/ho8;)Z

    move-result v5

    if-eqz v5, :cond_9

    goto :goto_5

    :cond_9
    move-object v4, v2

    :goto_5
    if-eqz v4, :cond_3

    invoke-static {v4, v1, p2}, Llyiahf/vczjk/rr4;->OooOoOO(Llyiahf/vczjk/ho8;Llyiahf/vczjk/rf3;Ljava/util/AbstractCollection;)Llyiahf/vczjk/ho8;

    move-result-object v1

    :goto_6
    invoke-static {p4, v1}, Llyiahf/vczjk/t51;->OooOO0o(Ljava/util/AbstractCollection;Ljava/lang/Object;)V

    invoke-interface {v0}, Llyiahf/vczjk/rf3;->OooOOo()Z

    move-result v1

    if-nez v1, :cond_a

    goto :goto_8

    :cond_a
    invoke-virtual {v0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p5, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Iterable;

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_b
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_d

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ho8;

    invoke-static {v3}, Llyiahf/vczjk/rr4;->OooOoo0(Llyiahf/vczjk/ho8;)Llyiahf/vczjk/ho8;

    move-result-object v3

    if-eqz v3, :cond_c

    invoke-static {v3, v0}, Llyiahf/vczjk/rr4;->OooOooO(Llyiahf/vczjk/rf3;Llyiahf/vczjk/rf3;)Z

    move-result v4

    if-eqz v4, :cond_c

    goto :goto_7

    :cond_c
    move-object v3, v2

    :goto_7
    if-eqz v3, :cond_b

    move-object v2, v3

    :cond_d
    :goto_8
    invoke-static {p4, v2}, Llyiahf/vczjk/t51;->OooOO0o(Ljava/util/AbstractCollection;Ljava/lang/Object;)V

    goto/16 :goto_0

    :cond_e
    return-void
.end method

.method public final OooOo0O(Ljava/util/ArrayList;Llyiahf/vczjk/e64;ILlyiahf/vczjk/lm7;Llyiahf/vczjk/uk4;Llyiahf/vczjk/uk4;)V
    .locals 12

    move-object/from16 v0, p4

    move-object/from16 v1, p5

    move-object/from16 v2, p6

    sget-object v4, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    invoke-virtual {v0}, Llyiahf/vczjk/km7;->OooO0OO()Llyiahf/vczjk/qt5;

    move-result-object v5

    const/4 v3, 0x0

    if-eqz v1, :cond_7

    const/4 v6, 0x0

    invoke-static {v1, v6}, Llyiahf/vczjk/l5a;->OooO0oO(Llyiahf/vczjk/uk4;Z)Llyiahf/vczjk/iaa;

    move-result-object v1

    iget-object v7, v0, Llyiahf/vczjk/lm7;->OooO00o:Ljava/lang/reflect/Method;

    invoke-virtual {v7}, Ljava/lang/reflect/Method;->getDefaultValue()Ljava/lang/Object;

    move-result-object v7

    if-eqz v7, :cond_4

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/rl7;->OooO00o:Ljava/util/List;

    const-class v9, Ljava/lang/Enum;

    invoke-virtual {v9, v8}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v8

    if-eqz v8, :cond_0

    new-instance v8, Llyiahf/vczjk/hm7;

    check-cast v7, Ljava/lang/Enum;

    invoke-direct {v8, v3, v7}, Llyiahf/vczjk/hm7;-><init>(Llyiahf/vczjk/qt5;Ljava/lang/Enum;)V

    goto :goto_0

    :cond_0
    instance-of v8, v7, Ljava/lang/annotation/Annotation;

    if-eqz v8, :cond_1

    new-instance v8, Llyiahf/vczjk/ul7;

    check-cast v7, Ljava/lang/annotation/Annotation;

    invoke-direct {v8, v3, v7}, Llyiahf/vczjk/ul7;-><init>(Llyiahf/vczjk/qt5;Ljava/lang/annotation/Annotation;)V

    goto :goto_0

    :cond_1
    instance-of v8, v7, [Ljava/lang/Object;

    if-eqz v8, :cond_2

    new-instance v8, Llyiahf/vczjk/vl7;

    check-cast v7, [Ljava/lang/Object;

    invoke-direct {v8, v3, v7}, Llyiahf/vczjk/vl7;-><init>(Llyiahf/vczjk/qt5;[Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    instance-of v8, v7, Ljava/lang/Class;

    if-eqz v8, :cond_3

    new-instance v8, Llyiahf/vczjk/dm7;

    check-cast v7, Ljava/lang/Class;

    invoke-direct {v8, v3, v7}, Llyiahf/vczjk/dm7;-><init>(Llyiahf/vczjk/qt5;Ljava/lang/Class;)V

    goto :goto_0

    :cond_3
    new-instance v8, Llyiahf/vczjk/jm7;

    invoke-direct {v8, v3, v7}, Llyiahf/vczjk/jm7;-><init>(Llyiahf/vczjk/qt5;Ljava/lang/Object;)V

    goto :goto_0

    :cond_4
    move-object v8, v3

    :goto_0
    if-eqz v8, :cond_5

    const/4 v7, 0x1

    goto :goto_1

    :cond_5
    move v7, v6

    :goto_1
    if-eqz v2, :cond_6

    invoke-static {v2, v6}, Llyiahf/vczjk/l5a;->OooO0oO(Llyiahf/vczjk/uk4;Z)Llyiahf/vczjk/iaa;

    move-result-object v3

    :cond_6
    move-object v10, v3

    iget-object v2, p0, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object v2, v2, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s64;

    iget-object v2, v2, Llyiahf/vczjk/s64;->OooOO0:Llyiahf/vczjk/rp3;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/rp3;->OooOo0O(Llyiahf/vczjk/k64;)Llyiahf/vczjk/hz7;

    move-result-object v11

    new-instance v0, Llyiahf/vczjk/tca;

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v2, 0x0

    move v3, p3

    move-object v6, v1

    move-object v1, p2

    invoke-direct/range {v0 .. v11}, Llyiahf/vczjk/tca;-><init>(Llyiahf/vczjk/co0;Llyiahf/vczjk/tca;ILlyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/uk4;ZZZLlyiahf/vczjk/uk4;Llyiahf/vczjk/sx8;)V

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void

    :cond_7
    const/4 p1, 0x2

    invoke-static {p1}, Llyiahf/vczjk/l5a;->OooO00o(I)V

    throw v3
.end method

.method public final OooOo0o(Ljava/util/LinkedHashSet;Llyiahf/vczjk/qt5;Ljava/util/ArrayList;Z)V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object v0, v0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v1, v0, Llyiahf/vczjk/s64;->OooOo0:Llyiahf/vczjk/v06;

    iget-object v7, v1, Llyiahf/vczjk/v06;->OooO0Oo:Llyiahf/vczjk/ng6;

    iget-object v5, p0, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    iget-object v6, v0, Llyiahf/vczjk/s64;->OooO0o:Llyiahf/vczjk/qp3;

    move-object v4, p1

    move-object v2, p2

    move-object v3, p3

    invoke-static/range {v2 .. v7}, Llyiahf/vczjk/jp8;->OoooO00(Llyiahf/vczjk/qt5;Ljava/util/AbstractCollection;Ljava/util/Collection;Llyiahf/vczjk/by0;Llyiahf/vczjk/kq2;Llyiahf/vczjk/ng6;)Ljava/util/LinkedHashSet;

    move-result-object p1

    if-nez p4, :cond_0

    invoke-interface {v4, p1}, Ljava/util/Collection;->addAll(Ljava/util/Collection;)Z

    return-void

    :cond_0
    invoke-static {p1, v4}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object p2

    new-instance p3, Ljava/util/ArrayList;

    const/16 p4, 0xa

    invoke-static {p1, p4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result p4

    invoke-direct {p3, p4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p4

    if-eqz p4, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p4

    check-cast p4, Llyiahf/vczjk/ho8;

    invoke-static {p4}, Llyiahf/vczjk/dl6;->OooO(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/eo0;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ho8;

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-static {p4, v0, p2}, Llyiahf/vczjk/rr4;->OooOoOO(Llyiahf/vczjk/ho8;Llyiahf/vczjk/rf3;Ljava/util/AbstractCollection;)Llyiahf/vczjk/ho8;

    move-result-object p4

    :goto_1
    invoke-virtual {p3, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    invoke-interface {v4, p3}, Ljava/util/Collection;->addAll(Ljava/util/Collection;)Z

    return-void
.end method

.method public final OooOoO()Ljava/util/Collection;
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/rr4;->OooOOOo:Z

    const-string v1, "getSupertypes(...)"

    iget-object v2, p0, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    if-eqz v0, :cond_0

    invoke-interface {v2}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO0O0()Ljava/util/Collection;

    move-result-object v0

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object v0, v0, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooOo0:Llyiahf/vczjk/v06;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v0, "classDescriptor"

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v2}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO0O0()Ljava/util/Collection;

    move-result-object v0

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final OooOoO0(Ljava/util/Set;Ljava/util/AbstractCollection;Llyiahf/vczjk/dt8;Llyiahf/vczjk/oe3;)V
    .locals 21

    move-object/from16 v0, p0

    move-object/from16 v1, p3

    move-object/from16 v2, p4

    invoke-interface/range {p1 .. p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_7

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/sa7;

    invoke-virtual {v0, v4, v2}, Llyiahf/vczjk/rr4;->OooOoo(Llyiahf/vczjk/sa7;Llyiahf/vczjk/oe3;)Z

    move-result v5

    if-nez v5, :cond_1

    const/4 v6, 0x0

    goto/16 :goto_4

    :cond_1
    invoke-virtual {v0, v4, v2}, Llyiahf/vczjk/rr4;->Oooo00O(Llyiahf/vczjk/sa7;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/ho8;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {v4}, Llyiahf/vczjk/ada;->OoooooO()Z

    move-result v7

    if-eqz v7, :cond_2

    invoke-static {v4, v2}, Llyiahf/vczjk/rr4;->Oooo00o(Llyiahf/vczjk/sa7;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/ho8;

    move-result-object v7

    invoke-static {v7}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    const/4 v7, 0x0

    :goto_0
    if-eqz v7, :cond_3

    invoke-virtual {v7}, Llyiahf/vczjk/tf3;->OooO()Llyiahf/vczjk/yk5;

    invoke-virtual {v5}, Llyiahf/vczjk/tf3;->OooO()Llyiahf/vczjk/yk5;

    :cond_3
    new-instance v8, Llyiahf/vczjk/l64;

    const-string v9, "ownerDescriptor"

    iget-object v10, v0, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    invoke-static {v10, v9}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v9, v10

    sget-object v10, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    invoke-virtual {v5}, Llyiahf/vczjk/tf3;->OooO()Llyiahf/vczjk/yk5;

    move-result-object v11

    invoke-virtual {v5}, Llyiahf/vczjk/tf3;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v12

    const/4 v13, 0x0

    if-eqz v7, :cond_4

    const/4 v14, 0x1

    goto :goto_1

    :cond_4
    move v14, v13

    :goto_1
    invoke-interface {v4}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v15

    move/from16 v16, v13

    move v13, v14

    move-object v14, v15

    invoke-virtual {v5}, Llyiahf/vczjk/y02;->OooO0oO()Llyiahf/vczjk/sx8;

    move-result-object v15

    const/16 v18, 0x0

    const/16 v19, 0x0

    move/from16 v17, v16

    const/16 v16, 0x0

    move/from16 v20, v17

    const/16 v17, 0x1

    move/from16 v6, v20

    invoke-direct/range {v8 .. v19}, Llyiahf/vczjk/r64;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/ko;Llyiahf/vczjk/yk5;Llyiahf/vczjk/q72;ZLlyiahf/vczjk/qt5;Llyiahf/vczjk/sx8;Llyiahf/vczjk/sa7;IZLlyiahf/vczjk/xn6;)V

    iget-object v9, v5, Llyiahf/vczjk/tf3;->OooOo0O:Llyiahf/vczjk/uk4;

    invoke-static {v9}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object v10, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-virtual {v0}, Llyiahf/vczjk/rr4;->OooOOOo()Llyiahf/vczjk/mp4;

    move-result-object v11

    const/4 v12, 0x0

    move-object v13, v10

    invoke-virtual/range {v8 .. v13}, Llyiahf/vczjk/ua7;->o0000OOo(Llyiahf/vczjk/uk4;Ljava/util/List;Llyiahf/vczjk/mp4;Llyiahf/vczjk/mp4;Ljava/util/List;)V

    invoke-virtual {v5}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v9

    invoke-virtual {v5}, Llyiahf/vczjk/y02;->OooO0oO()Llyiahf/vczjk/sx8;

    move-result-object v10

    invoke-static {v8, v9, v6, v10}, Llyiahf/vczjk/dn8;->OoooO(Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;ZLlyiahf/vczjk/sx8;)Llyiahf/vczjk/va7;

    move-result-object v6

    iput-object v5, v6, Llyiahf/vczjk/la7;->OooOoOO:Llyiahf/vczjk/rf3;

    invoke-virtual {v8}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v5

    invoke-virtual {v6, v5}, Llyiahf/vczjk/va7;->o0000O(Llyiahf/vczjk/uk4;)V

    if-eqz v7, :cond_6

    invoke-virtual {v7}, Llyiahf/vczjk/tf3;->OoooOOO()Ljava/util/List;

    move-result-object v5

    const-string v9, "getValueParameters(...)"

    invoke-static {v5, v9}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v5}, Llyiahf/vczjk/d21;->oo000o(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/tca;

    if-eqz v5, :cond_5

    invoke-virtual {v7}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v9

    check-cast v5, Llyiahf/vczjk/l21;

    invoke-virtual {v5}, Llyiahf/vczjk/l21;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v10

    invoke-virtual {v7}, Llyiahf/vczjk/tf3;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v12

    invoke-virtual {v7}, Llyiahf/vczjk/y02;->OooO0oO()Llyiahf/vczjk/sx8;

    move-result-object v13

    const/4 v11, 0x0

    invoke-static/range {v8 .. v13}, Llyiahf/vczjk/dn8;->OoooOO0(Llyiahf/vczjk/sa7;Llyiahf/vczjk/ko;Llyiahf/vczjk/ko;ZLlyiahf/vczjk/q72;Llyiahf/vczjk/sx8;)Llyiahf/vczjk/hb7;

    move-result-object v5

    iput-object v7, v5, Llyiahf/vczjk/la7;->OooOoOO:Llyiahf/vczjk/rf3;

    :goto_2
    const/4 v7, 0x0

    goto :goto_3

    :cond_5
    new-instance v1, Ljava/lang/AssertionError;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "No parameter found for "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v1

    :cond_6
    const/4 v5, 0x0

    goto :goto_2

    :goto_3
    invoke-virtual {v8, v6, v5, v7, v7}, Llyiahf/vczjk/ua7;->o0000OO0(Llyiahf/vczjk/va7;Llyiahf/vczjk/hb7;Llyiahf/vczjk/fx2;Llyiahf/vczjk/fx2;)V

    move-object v6, v8

    :goto_4
    move-object/from16 v5, p2

    if-eqz v6, :cond_0

    invoke-interface {v5, v6}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    if-eqz v1, :cond_7

    invoke-virtual {v1, v4}, Llyiahf/vczjk/dt8;->add(Ljava/lang/Object;)Z

    :cond_7
    return-void
.end method

.method public final OooOoo(Llyiahf/vczjk/sa7;Llyiahf/vczjk/oe3;)Z
    .locals 1

    invoke-static {p1}, Llyiahf/vczjk/c6a;->OooooOo(Llyiahf/vczjk/sa7;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_1

    :cond_0
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/rr4;->Oooo00O(Llyiahf/vczjk/sa7;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/ho8;

    move-result-object v0

    invoke-static {p1, p2}, Llyiahf/vczjk/rr4;->Oooo00o(Llyiahf/vczjk/sa7;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/ho8;

    move-result-object p2

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-interface {p1}, Llyiahf/vczjk/ada;->OoooooO()Z

    move-result p1

    if-nez p1, :cond_2

    goto :goto_0

    :cond_2
    if-eqz p2, :cond_3

    invoke-virtual {p2}, Llyiahf/vczjk/tf3;->OooO()Llyiahf/vczjk/yk5;

    move-result-object p1

    invoke-virtual {v0}, Llyiahf/vczjk/tf3;->OooO()Llyiahf/vczjk/yk5;

    move-result-object p2

    if-ne p1, p2, :cond_3

    :goto_0
    const/4 p1, 0x1

    return p1

    :cond_3
    :goto_1
    const/4 p1, 0x0

    return p1
.end method

.method public final Oooo0(Llyiahf/vczjk/qt5;)Ljava/util/LinkedHashSet;
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/rr4;->OooOoO()Ljava/util/Collection;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    new-instance v1, Ljava/util/LinkedHashSet;

    invoke-direct {v1}, Ljava/util/LinkedHashSet;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/uk4;

    invoke-virtual {v2}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/h16;->OooOOo0:Llyiahf/vczjk/h16;

    invoke-interface {v2, p1, v3}, Llyiahf/vczjk/jg5;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object v2

    check-cast v2, Ljava/lang/Iterable;

    invoke-static {v2, v1}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_0

    :cond_0
    return-object v1
.end method

.method public final Oooo00O(Llyiahf/vczjk/sa7;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/ho8;
    .locals 4

    invoke-interface {p1}, Llyiahf/vczjk/sa7;->OooO0O0()Llyiahf/vczjk/va7;

    move-result-object v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/dl6;->OooO0oo(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/eo0;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/va7;

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    if-eqz v0, :cond_2

    invoke-static {v0}, Llyiahf/vczjk/hk4;->OooOoOO(Llyiahf/vczjk/v02;)Z

    invoke-static {v0}, Llyiahf/vczjk/p72;->OooOO0O(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/eo0;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/tn;->OooOo:Llyiahf/vczjk/tn;

    invoke-static {v2, v3}, Llyiahf/vczjk/p72;->OooO0O0(Llyiahf/vczjk/eo0;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/eo0;

    move-result-object v2

    if-nez v2, :cond_1

    goto :goto_1

    :cond_1
    sget-object v3, Llyiahf/vczjk/mk0;->OooO00o:Ljava/lang/Object;

    invoke-static {v2}, Llyiahf/vczjk/p72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hc3;

    move-result-object v2

    invoke-interface {v3, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/qt5;

    if-eqz v2, :cond_2

    invoke-virtual {v2}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v1

    :cond_2
    :goto_1
    if-eqz v1, :cond_3

    iget-object v2, p0, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    invoke-static {v2, v0}, Llyiahf/vczjk/dl6;->OooOO0(Llyiahf/vczjk/by0;Llyiahf/vczjk/eo0;)Z

    move-result v0

    if-nez v0, :cond_3

    invoke-static {p1, v1, p2}, Llyiahf/vczjk/rr4;->Oooo000(Llyiahf/vczjk/sa7;Ljava/lang/String;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/ho8;

    move-result-object p1

    return-object p1

    :cond_3
    invoke-interface {p1}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v0

    const-string v1, "asString(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/bd4;->OooO00o(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-static {p1, v0, p2}, Llyiahf/vczjk/rr4;->Oooo000(Llyiahf/vczjk/sa7;Ljava/lang/String;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/ho8;

    move-result-object p1

    return-object p1
.end method

.method public final Oooo0O0(Llyiahf/vczjk/qt5;)Ljava/util/Set;
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/rr4;->OooOoO()Ljava/util/Collection;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/uk4;

    invoke-virtual {v2}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/h16;->OooOOo0:Llyiahf/vczjk/h16;

    invoke-interface {v2, p1, v3}, Llyiahf/vczjk/jg5;->OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;

    move-result-object v2

    check-cast v2, Ljava/lang/Iterable;

    new-instance v3, Ljava/util/ArrayList;

    const/16 v4, 0xa

    invoke-static {v2, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_0

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/sa7;

    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_0
    invoke-static {v3, v1}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    goto :goto_0

    :cond_1
    invoke-static {v1}, Llyiahf/vczjk/d21;->o0000OOo(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object p1

    return-object p1
.end method

.method public final Oooo0o(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)V
    .locals 1

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "location"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/ds4;->OooO0O0:Llyiahf/vczjk/ld9;

    iget-object p1, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s64;

    const-string p2, "<this>"

    iget-object p1, p1, Llyiahf/vczjk/s64;->OooOOO:Llyiahf/vczjk/sp3;

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "scopeOwner"

    iget-object p2, p0, Llyiahf/vczjk/rr4;->OooOOO:Llyiahf/vczjk/by0;

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method

.method public final Oooo0o0(Llyiahf/vczjk/ho8;)Z
    .locals 11

    const/16 v0, 0x8

    invoke-virtual {p1}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v1

    const-string v2, "getName(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v3

    const-string v4, "asString(...)"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v5, Llyiahf/vczjk/bd4;->OooO00o:Llyiahf/vczjk/hc3;

    const-string v5, "get"

    const/4 v6, 0x0

    invoke-static {v3, v5, v6}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v7

    const/4 v8, 0x0

    const-string v9, "is"

    const-string v10, "set"

    if-nez v7, :cond_2

    invoke-static {v3, v9, v6}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v7

    if-eqz v7, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {v3, v10, v6}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v3

    if-eqz v3, :cond_1

    const/4 v3, 0x4

    invoke-static {v1, v10, v8, v3}, Llyiahf/vczjk/rd3;->OooOoO(Llyiahf/vczjk/qt5;Ljava/lang/String;Ljava/lang/String;I)Llyiahf/vczjk/qt5;

    move-result-object v5

    invoke-static {v1, v10, v9, v3}, Llyiahf/vczjk/rd3;->OooOoO(Llyiahf/vczjk/qt5;Ljava/lang/String;Ljava/lang/String;I)Llyiahf/vczjk/qt5;

    move-result-object v1

    filled-new-array {v5, v1}, [Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/sy;->o0OO00O([Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v1

    goto :goto_1

    :cond_1
    sget-object v3, Llyiahf/vczjk/mk0;->OooO0O0:Ljava/util/LinkedHashMap;

    invoke-virtual {v3, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/List;

    if-nez v1, :cond_4

    sget-object v1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    goto :goto_1

    :cond_2
    :goto_0
    const/16 v3, 0xc

    invoke-static {v1, v5, v8, v3}, Llyiahf/vczjk/rd3;->OooOoO(Llyiahf/vczjk/qt5;Ljava/lang/String;Ljava/lang/String;I)Llyiahf/vczjk/qt5;

    move-result-object v3

    if-nez v3, :cond_3

    invoke-static {v1, v9, v8, v0}, Llyiahf/vczjk/rd3;->OooOoO(Llyiahf/vczjk/qt5;Ljava/lang/String;Ljava/lang/String;I)Llyiahf/vczjk/qt5;

    move-result-object v3

    :cond_3
    invoke-static {v3}, Llyiahf/vczjk/e21;->OoooO00(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    :cond_4
    :goto_1
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_5

    goto :goto_3

    :cond_5
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_6
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_9

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/qt5;

    invoke-virtual {p0, v3}, Llyiahf/vczjk/rr4;->Oooo0O0(Llyiahf/vczjk/qt5;)Ljava/util/Set;

    move-result-object v3

    check-cast v3, Ljava/lang/Iterable;

    instance-of v5, v3, Ljava/util/Collection;

    if-eqz v5, :cond_7

    move-object v5, v3

    check-cast v5, Ljava/util/Collection;

    invoke-interface {v5}, Ljava/util/Collection;->isEmpty()Z

    move-result v5

    if-eqz v5, :cond_7

    goto :goto_2

    :cond_7
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_8
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_6

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/sa7;

    new-instance v7, Llyiahf/vczjk/o0oOO;

    invoke-direct {v7, v0, p1, p0}, Llyiahf/vczjk/o0oOO;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {p0, v5, v7}, Llyiahf/vczjk/rr4;->OooOoo(Llyiahf/vczjk/sa7;Llyiahf/vczjk/oe3;)Z

    move-result v7

    if-eqz v7, :cond_8

    invoke-interface {v5}, Llyiahf/vczjk/ada;->OoooooO()Z

    move-result v5

    if-nez v5, :cond_1a

    invoke-virtual {p1}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v5

    invoke-virtual {v5}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v5

    invoke-static {v5, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v5, v10, v6}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v5

    if-nez v5, :cond_8

    goto/16 :goto_8

    :cond_9
    :goto_3
    sget-object v0, Llyiahf/vczjk/ty8;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {p1}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/ty8;->OooOO0O:Ljava/util/LinkedHashMap;

    invoke-virtual {v1, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/qt5;

    if-nez v0, :cond_a

    goto :goto_5

    :cond_a
    invoke-virtual {p0, v0}, Llyiahf/vczjk/rr4;->Oooo0(Llyiahf/vczjk/qt5;)Ljava/util/LinkedHashSet;

    move-result-object v1

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_b
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_c

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    move-object v5, v4

    check-cast v5, Llyiahf/vczjk/ho8;

    const-string v7, "<this>"

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v5}, Llyiahf/vczjk/dl6;->OooO0oo(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/eo0;

    move-result-object v5

    if-eqz v5, :cond_b

    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_4

    :cond_c
    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_d

    goto :goto_5

    :cond_d
    invoke-interface {p1}, Llyiahf/vczjk/rf3;->o0Oo0oo()Llyiahf/vczjk/qf3;

    move-result-object v1

    invoke-interface {v1, v0}, Llyiahf/vczjk/qf3;->OooOoOO(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/qf3;

    invoke-interface {v1}, Llyiahf/vczjk/qf3;->OoooOO0()Llyiahf/vczjk/qf3;

    invoke-interface {v1}, Llyiahf/vczjk/qf3;->OooOOo()Llyiahf/vczjk/qf3;

    invoke-interface {v1}, Llyiahf/vczjk/qf3;->build()Llyiahf/vczjk/rf3;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v0, Llyiahf/vczjk/ho8;

    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_e

    goto :goto_5

    :cond_e
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_f
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_10

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ho8;

    invoke-static {v3, v0}, Llyiahf/vczjk/rr4;->OooOooo(Llyiahf/vczjk/ho8;Llyiahf/vczjk/ho8;)Z

    move-result v3

    if-eqz v3, :cond_f

    goto/16 :goto_8

    :cond_10
    :goto_5
    sget v0, Llyiahf/vczjk/lk0;->OooOO0o:I

    invoke-virtual {p1}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/lk0;->OooO0O0(Llyiahf/vczjk/qt5;)Z

    move-result v0

    if-nez v0, :cond_11

    goto :goto_7

    :cond_11
    invoke-virtual {p1}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/rr4;->Oooo0(Llyiahf/vczjk/qt5;)Ljava/util/LinkedHashSet;

    move-result-object v0

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_12
    :goto_6
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_13

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ho8;

    invoke-static {v3}, Llyiahf/vczjk/lk0;->OooO00o(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/rf3;

    move-result-object v3

    if-eqz v3, :cond_12

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_6

    :cond_13
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_14

    goto :goto_7

    :cond_14
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_15
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_16

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rf3;

    invoke-static {p1, v1}, Llyiahf/vczjk/rr4;->Oooo0OO(Llyiahf/vczjk/ho8;Llyiahf/vczjk/rf3;)Z

    move-result v1

    if-eqz v1, :cond_15

    goto :goto_8

    :cond_16
    :goto_7
    invoke-static {p1}, Llyiahf/vczjk/rr4;->OooOoo0(Llyiahf/vczjk/ho8;)Llyiahf/vczjk/ho8;

    move-result-object v0

    if-nez v0, :cond_17

    goto :goto_9

    :cond_17
    invoke-virtual {p1}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object p1

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/rr4;->Oooo0(Llyiahf/vczjk/qt5;)Ljava/util/LinkedHashSet;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_18

    goto :goto_9

    :cond_18
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_19
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1b

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ho8;

    invoke-interface {v1}, Llyiahf/vczjk/rf3;->OooOOo()Z

    move-result v2

    if-eqz v2, :cond_19

    invoke-static {v0, v1}, Llyiahf/vczjk/rr4;->OooOooO(Llyiahf/vczjk/rf3;Llyiahf/vczjk/rf3;)Z

    move-result v1

    if-eqz v1, :cond_19

    :cond_1a
    :goto_8
    return v6

    :cond_1b
    :goto_9
    const/4 p1, 0x1

    return p1
.end method

.method public final Oooo0oO(Llyiahf/vczjk/qt5;)Ljava/util/ArrayList;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ds4;->OooO0o0:Llyiahf/vczjk/o45;

    invoke-virtual {v0}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/c12;

    invoke-interface {v0, p1}, Llyiahf/vczjk/c12;->OooO0O0(Llyiahf/vczjk/qt5;)Ljava/util/Collection;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

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

    check-cast v1, Llyiahf/vczjk/lm7;

    invoke-virtual {p0, v1}, Llyiahf/vczjk/ds4;->OooOo00(Llyiahf/vczjk/lm7;)Llyiahf/vczjk/o64;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    return-object v0
.end method

.method public final Oooo0oo(Llyiahf/vczjk/qt5;)Ljava/util/ArrayList;
    .locals 4

    invoke-virtual {p0, p1}, Llyiahf/vczjk/rr4;->Oooo0(Llyiahf/vczjk/qt5;)Ljava/util/LinkedHashSet;

    move-result-object p1

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/ho8;

    const-string v3, "<this>"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2}, Llyiahf/vczjk/dl6;->OooO0oo(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/eo0;

    move-result-object v3

    if-eqz v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {v2}, Llyiahf/vczjk/lk0;->OooO00o(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/rf3;

    move-result-object v2

    if-eqz v2, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Lazy Java member scope for "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/rr4;->OooOOOO:Llyiahf/vczjk/cm7;

    invoke-virtual {v1}, Llyiahf/vczjk/cm7;->OooO0OO()Llyiahf/vczjk/hc3;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
