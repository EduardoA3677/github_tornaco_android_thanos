.class public final Llyiahf/vczjk/hs4;
.super Llyiahf/vczjk/o00oOoo;
.source "SourceFile"


# instance fields
.field public final OooOoO:Llyiahf/vczjk/ld9;

.field public final OooOoOO:Llyiahf/vczjk/qm7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/qm7;ILlyiahf/vczjk/x02;)V
    .locals 10

    const-string v0, "javaTypeParameter"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v2, v0, Llyiahf/vczjk/s64;->OooO00o:Llyiahf/vczjk/q45;

    new-instance v4, Llyiahf/vczjk/lr4;

    const/4 v1, 0x0

    invoke-direct {v4, p1, p2, v1}, Llyiahf/vczjk/lr4;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/b64;Z)V

    iget-object v1, p2, Llyiahf/vczjk/qm7;->OooO00o:Ljava/lang/reflect/TypeVariable;

    invoke-interface {v1}, Ljava/lang/reflect/TypeVariable;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    const/4 v7, 0x0

    iget-object v9, v0, Llyiahf/vczjk/s64;->OooOOO0:Llyiahf/vczjk/sp3;

    move-object v1, p0

    move v8, p3

    move-object v3, p4

    invoke-direct/range {v1 .. v9}, Llyiahf/vczjk/o00oOoo;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/v02;Llyiahf/vczjk/ko;Llyiahf/vczjk/qt5;Llyiahf/vczjk/cda;ZILlyiahf/vczjk/sp3;)V

    iput-object p1, v1, Llyiahf/vczjk/hs4;->OooOoO:Llyiahf/vczjk/ld9;

    iput-object p2, v1, Llyiahf/vczjk/hs4;->OooOoOO:Llyiahf/vczjk/qm7;

    return-void
.end method


# virtual methods
.method public final o0000O0(Ljava/util/List;)Ljava/util/List;
    .locals 11

    iget-object v3, p0, Llyiahf/vczjk/hs4;->OooOoO:Llyiahf/vczjk/ld9;

    iget-object v0, v3, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v6, v0, Llyiahf/vczjk/s64;->OooOOo:Llyiahf/vczjk/tp3;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v10, Ljava/util/ArrayList;

    const/16 v0, 0xa

    invoke-static {p1, v0}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v0

    invoke-direct {v10, v0}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    move-object v7, v0

    check-cast v7, Llyiahf/vczjk/uk4;

    sget-object v0, Llyiahf/vczjk/iu6;->OooOooO:Llyiahf/vczjk/iu6;

    const-string v1, "<this>"

    invoke-static {v7, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v1, 0x0

    invoke-static {v7, v0, v1}, Llyiahf/vczjk/l5a;->OooO0OO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/oe3;Llyiahf/vczjk/dt8;)Z

    move-result v0

    if-eqz v0, :cond_0

    move-object v4, v6

    move-object v6, v7

    goto :goto_1

    :cond_0
    new-instance v0, Llyiahf/vczjk/bv0;

    sget-object v4, Llyiahf/vczjk/bo;->OooOOo0:Llyiahf/vczjk/bo;

    const/4 v5, 0x0

    const/4 v2, 0x0

    move-object v1, p0

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/bv0;-><init>(Llyiahf/vczjk/x02;ZLlyiahf/vczjk/ld9;Llyiahf/vczjk/bo;Z)V

    move-object v4, v6

    move-object v6, v7

    sget-object v7, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    const/4 v9, 0x0

    const/4 v8, 0x0

    move-object v5, v0

    invoke-virtual/range {v4 .. v9}, Llyiahf/vczjk/tp3;->OooO0OO(Llyiahf/vczjk/bv0;Llyiahf/vczjk/uk4;Ljava/util/List;Llyiahf/vczjk/x3a;Z)Llyiahf/vczjk/uk4;

    move-result-object v7

    if-nez v7, :cond_1

    :goto_1
    move-object v7, v6

    :cond_1
    invoke-virtual {v10, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object v6, v4

    goto :goto_0

    :cond_2
    return-object v10
.end method

.method public final o0000O0O()Ljava/util/List;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/hs4;->OooOoOO:Llyiahf/vczjk/qm7;

    iget-object v0, v0, Llyiahf/vczjk/qm7;->OooO00o:Ljava/lang/reflect/TypeVariable;

    invoke-interface {v0}, Ljava/lang/reflect/TypeVariable;->getBounds()[Ljava/lang/reflect/Type;

    move-result-object v0

    const-string v1, "getBounds(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ljava/util/ArrayList;

    array-length v2, v0

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    array-length v2, v0

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v4, v2, :cond_0

    aget-object v5, v0, v4

    new-instance v6, Llyiahf/vczjk/em7;

    invoke-direct {v6, v5}, Llyiahf/vczjk/em7;-><init>(Ljava/lang/reflect/Type;)V

    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_0
    invoke-static {v1}, Llyiahf/vczjk/d21;->o00000oO(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/em7;

    if-eqz v0, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/em7;->OooO00o:Ljava/lang/reflect/Type;

    goto :goto_1

    :cond_1
    const/4 v0, 0x0

    :goto_1
    const-class v2, Ljava/lang/Object;

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    sget-object v1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :cond_2
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    iget-object v2, p0, Llyiahf/vczjk/hs4;->OooOoO:Llyiahf/vczjk/ld9;

    if-eqz v0, :cond_3

    iget-object v0, v2, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooOOOO:Llyiahf/vczjk/dm5;

    iget-object v0, v0, Llyiahf/vczjk/dm5;->OooOOoo:Llyiahf/vczjk/hk4;

    invoke-virtual {v0}, Llyiahf/vczjk/hk4;->OooO0o0()Llyiahf/vczjk/dp8;

    move-result-object v0

    iget-object v1, v2, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s64;

    iget-object v1, v1, Llyiahf/vczjk/s64;->OooOOOO:Llyiahf/vczjk/dm5;

    iget-object v1, v1, Llyiahf/vczjk/dm5;->OooOOoo:Llyiahf/vczjk/hk4;

    invoke-virtual {v1}, Llyiahf/vczjk/hk4;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/so8;->OooOoOO(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/iaa;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :cond_3
    new-instance v0, Ljava/util/ArrayList;

    const/16 v4, 0xa

    invoke-static {v1, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-direct {v0, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_4

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/em7;

    iget-object v5, v2, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/uqa;

    sget-object v6, Llyiahf/vczjk/j5a;->OooOOO:Llyiahf/vczjk/j5a;

    const/4 v7, 0x3

    invoke-static {v6, v3, p0, v7}, Llyiahf/vczjk/nqa;->OoooO00(Llyiahf/vczjk/j5a;ZLlyiahf/vczjk/hs4;I)Llyiahf/vczjk/a74;

    move-result-object v6

    invoke-virtual {v5, v4, v6}, Llyiahf/vczjk/uqa;->Oooo0oo(Llyiahf/vczjk/y64;Llyiahf/vczjk/a74;)Llyiahf/vczjk/uk4;

    move-result-object v4

    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_4
    return-object v0
.end method
