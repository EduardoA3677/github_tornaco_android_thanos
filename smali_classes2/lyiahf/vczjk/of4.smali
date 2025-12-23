.class public final Llyiahf/vczjk/of4;
.super Llyiahf/vczjk/yf4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/gf4;
.implements Llyiahf/vczjk/gi4;


# static fields
.field public static final synthetic OooOOOo:I


# instance fields
.field public final OooOOO:Ljava/lang/Class;

.field public final OooOOOO:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/Class;)V
    .locals 2

    const-string v0, "jClass"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/of4;->OooOOO:Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/ww4;->OooOOO0:Llyiahf/vczjk/ww4;

    new-instance v0, Llyiahf/vczjk/hf4;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/hf4;-><init>(Llyiahf/vczjk/of4;I)V

    invoke-static {p1, v0}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/of4;->OooOOOO:Ljava/lang/Object;

    return-void
.end method

.method public static OooOo00(Llyiahf/vczjk/hy0;Llyiahf/vczjk/gz7;)Llyiahf/vczjk/ey0;
    .locals 7

    new-instance v0, Llyiahf/vczjk/ey0;

    new-instance v1, Llyiahf/vczjk/dn2;

    iget-object p1, p1, Llyiahf/vczjk/gz7;->OooO00o:Llyiahf/vczjk/s72;

    iget-object v2, p1, Llyiahf/vczjk/s72;->OooO0O0:Llyiahf/vczjk/cm5;

    iget-object v3, p0, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    const/4 v4, 0x0

    invoke-direct {v1, v2, v3, v4}, Llyiahf/vczjk/dn2;-><init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hc3;I)V

    invoke-virtual {p0}, Llyiahf/vczjk/hy0;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/yk5;->OooOOO:Llyiahf/vczjk/yk5;

    sget-object v4, Llyiahf/vczjk/ly0;->OooOOO0:Llyiahf/vczjk/ly0;

    iget-object p0, p1, Llyiahf/vczjk/s72;->OooO0O0:Llyiahf/vczjk/cm5;

    invoke-interface {p0}, Llyiahf/vczjk/cm5;->OooOO0O()Llyiahf/vczjk/hk4;

    move-result-object p0

    const-string v5, "Any"

    invoke-virtual {p0, v5}, Llyiahf/vczjk/hk4;->OooOO0O(Ljava/lang/String;)Llyiahf/vczjk/by0;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v5

    iget-object v6, p1, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/ey0;-><init>(Llyiahf/vczjk/v02;Llyiahf/vczjk/qt5;Llyiahf/vczjk/yk5;Llyiahf/vczjk/ly0;Ljava/util/List;Llyiahf/vczjk/q45;)V

    new-instance p0, Llyiahf/vczjk/mf4;

    invoke-direct {p0, v6, v0}, Llyiahf/vczjk/kh3;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/oo0o0Oo;)V

    sget-object p1, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    const/4 v1, 0x0

    invoke-virtual {v0, p0, p1, v1}, Llyiahf/vczjk/ey0;->o00ooo(Llyiahf/vczjk/jg5;Ljava/util/Set;Llyiahf/vczjk/ux0;)V

    return-object v0
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/qt5;)Ljava/util/Collection;
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/of4;->OooOo0O()Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/h16;->OooOOO:Llyiahf/vczjk/h16;

    invoke-interface {v0, p1, v1}, Llyiahf/vczjk/jg5;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/of4;->OooOo0O()Llyiahf/vczjk/by0;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/by0;->OoooO0()Llyiahf/vczjk/jg5;

    move-result-object v2

    const-string v3, "getStaticScope(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v2, p1, v1}, Llyiahf/vczjk/jg5;->OooO0Oo(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    invoke-static {p1, v0}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object p1

    return-object p1
.end method

.method public final OooO00o()Ljava/lang/String;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/of4;->OooOOOO:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/kf4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/kf4;->OooOO0o:[Llyiahf/vczjk/th4;

    const/4 v2, 0x3

    aget-object v1, v1, v2

    iget-object v0, v0, Llyiahf/vczjk/kf4;->OooO0o0:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    return-object v0
.end method

.method public final OooO0O0()Ljava/lang/String;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/of4;->OooOOOO:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/kf4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/kf4;->OooOO0o:[Llyiahf/vczjk/th4;

    const/4 v2, 0x2

    aget-object v1, v1, v2

    iget-object v0, v0, Llyiahf/vczjk/kf4;->OooO0Oo:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    return-object v0
.end method

.method public final OooO0OO(Ljava/lang/Object;)Z
    .locals 2

    sget-object v0, Llyiahf/vczjk/rl7;->OooO00o:Ljava/util/List;

    iget-object v0, p0, Llyiahf/vczjk/of4;->OooOOO:Ljava/lang/Class;

    const-string v1, "<this>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/rl7;->OooO0Oo:Ljava/util/Map;

    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Integer;

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v0

    invoke-static {v0, p1}, Llyiahf/vczjk/l4a;->OooOooO(ILjava/lang/Object;)Z

    move-result p1

    return p1

    :cond_0
    sget-object v1, Llyiahf/vczjk/rl7;->OooO0OO:Ljava/util/Map;

    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Class;

    if-nez v1, :cond_1

    goto :goto_0

    :cond_1
    move-object v0, v1

    :goto_0
    invoke-virtual {v0, p1}, Ljava/lang/Class;->isInstance(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final OooO0Oo()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/of4;->OooOOO:Ljava/lang/Class;

    return-object v0
.end method

.method public final OooO0oo()Ljava/util/Collection;
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/of4;->OooOo0O()Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/by0;->getKind()Llyiahf/vczjk/ly0;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/ly0;->OooOOO:Llyiahf/vczjk/ly0;

    if-eq v1, v2, :cond_1

    invoke-interface {v0}, Llyiahf/vczjk/by0;->getKind()Llyiahf/vczjk/ly0;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/ly0;->OooOOo:Llyiahf/vczjk/ly0;

    if-ne v1, v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOoO()Ljava/util/Collection;

    move-result-object v0

    const-string v1, "getConstructors(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0

    :cond_1
    :goto_0
    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object v0
.end method

.method public final OooOO0()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/of4;->OooOo0O()Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOO0()Z

    move-result v0

    return v0
.end method

.method public final OooOO0O(I)Llyiahf/vczjk/sa7;
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/of4;->OooOOO:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v1

    const-string v2, "DefaultImpls"

    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/Class;->isInterface()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/rs;->Oooo0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/of4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/of4;->OooOO0O(I)Llyiahf/vczjk/sa7;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/of4;->OooOo0O()Llyiahf/vczjk/by0;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/h82;

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    check-cast v0, Llyiahf/vczjk/h82;

    goto :goto_0

    :cond_1
    move-object v0, v2

    :goto_0
    if-eqz v0, :cond_3

    sget-object v1, Llyiahf/vczjk/ue4;->OooOO0:Llyiahf/vczjk/ug3;

    const-string v3, "classLocalVariable"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "<this>"

    iget-object v4, v0, Llyiahf/vczjk/h82;->OooOOo0:Llyiahf/vczjk/zb7;

    invoke-static {v4, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v4, v1}, Llyiahf/vczjk/sg3;->OooO(Llyiahf/vczjk/ug3;)I

    move-result v3

    if-ge p1, v3, :cond_2

    invoke-virtual {v4, v1, p1}, Llyiahf/vczjk/sg3;->OooO0oo(Llyiahf/vczjk/ug3;I)Ljava/lang/Object;

    move-result-object p1

    goto :goto_1

    :cond_2
    move-object p1, v2

    :goto_1
    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/xc7;

    if-eqz v4, :cond_3

    iget-object p1, v0, Llyiahf/vczjk/h82;->OooOo:Llyiahf/vczjk/u72;

    iget-object v1, p1, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    move-object v5, v1

    check-cast v5, Llyiahf/vczjk/rt5;

    iget-object p1, p1, Llyiahf/vczjk/u72;->OooO0Oo:Ljava/lang/Object;

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/h87;

    sget-object v8, Llyiahf/vczjk/nf4;->OooOOO:Llyiahf/vczjk/nf4;

    iget-object v3, p0, Llyiahf/vczjk/of4;->OooOOO:Ljava/lang/Class;

    iget-object v7, v0, Llyiahf/vczjk/h82;->OooOOo:Llyiahf/vczjk/zb0;

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/mba;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/sg3;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;Llyiahf/vczjk/zb0;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/co0;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/sa7;

    return-object p1

    :cond_3
    return-object v2
.end method

.method public final OooOOO(Llyiahf/vczjk/qt5;)Ljava/util/Collection;
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/of4;->OooOo0O()Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->OoooOO0()Llyiahf/vczjk/jg5;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/h16;->OooOOO:Llyiahf/vczjk/h16;

    invoke-interface {v0, p1, v1}, Llyiahf/vczjk/jg5;->OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/of4;->OooOo0O()Llyiahf/vczjk/by0;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/by0;->OoooO0()Llyiahf/vczjk/jg5;

    move-result-object v2

    const-string v3, "getStaticScope(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v2, p1, v1}, Llyiahf/vczjk/jg5;->OooO0o0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/h16;)Ljava/util/Collection;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    invoke-static {p1, v0}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object p1

    return-object p1
.end method

.method public final OooOo0()Llyiahf/vczjk/hy0;
    .locals 3

    sget-object v0, Llyiahf/vczjk/iz7;->OooO00o:Llyiahf/vczjk/hy0;

    iget-object v0, p0, Llyiahf/vczjk/of4;->OooOOO:Ljava/lang/Class;

    const-string v1, "klass"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/lang/Class;->isArray()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_2

    invoke-virtual {v0}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    move-result-object v0

    const-string v1, "getComponentType(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/lang/Class;->isPrimitive()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/ee4;->OooO0O0(Ljava/lang/String;)Llyiahf/vczjk/ee4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ee4;->OooO0o0()Llyiahf/vczjk/q47;

    move-result-object v2

    :cond_0
    if-eqz v2, :cond_1

    new-instance v0, Llyiahf/vczjk/hy0;

    sget-object v1, Llyiahf/vczjk/x09;->OooOO0o:Llyiahf/vczjk/hc3;

    invoke-virtual {v2}, Llyiahf/vczjk/q47;->OooO0Oo()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    return-object v0

    :cond_1
    sget-object v0, Llyiahf/vczjk/w09;->OooO0oO:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0oO()Llyiahf/vczjk/hc3;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/hy0;

    invoke-virtual {v0}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v2

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    return-object v1

    :cond_2
    sget-object v1, Ljava/lang/Void;->TYPE:Ljava/lang/Class;

    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_3

    sget-object v0, Llyiahf/vczjk/iz7;->OooO00o:Llyiahf/vczjk/hy0;

    return-object v0

    :cond_3
    invoke-virtual {v0}, Ljava/lang/Class;->isPrimitive()Z

    move-result v1

    if-eqz v1, :cond_4

    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/ee4;->OooO0O0(Ljava/lang/String;)Llyiahf/vczjk/ee4;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/ee4;->OooO0o0()Llyiahf/vczjk/q47;

    move-result-object v2

    :cond_4
    if-eqz v2, :cond_5

    new-instance v0, Llyiahf/vczjk/hy0;

    sget-object v1, Llyiahf/vczjk/x09;->OooOO0o:Llyiahf/vczjk/hc3;

    invoke-virtual {v2}, Llyiahf/vczjk/q47;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    return-object v0

    :cond_5
    invoke-static {v0}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v0

    iget-boolean v1, v0, Llyiahf/vczjk/hy0;->OooO0OO:Z

    if-nez v1, :cond_6

    sget-object v1, Llyiahf/vczjk/w64;->OooO00o:Ljava/lang/String;

    invoke-virtual {v0}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object v1

    const-string v2, "fqName"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v2, Llyiahf/vczjk/w64;->OooO0oo:Ljava/util/HashMap;

    iget-object v1, v1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v2, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/hy0;

    if-eqz v1, :cond_6

    return-object v1

    :cond_6
    return-object v0
.end method

.method public final OooOo0O()Llyiahf/vczjk/by0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/of4;->OooOOOO:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/kf4;

    invoke-virtual {v0}, Llyiahf/vczjk/kf4;->OooO00o()Llyiahf/vczjk/by0;

    move-result-object v0

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/of4;

    if-eqz v0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/rs;->Oooo00o(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v0

    check-cast p1, Llyiahf/vczjk/gf4;

    invoke-static {p1}, Llyiahf/vczjk/rs;->Oooo00o(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 1

    invoke-static {p0}, Llyiahf/vczjk/rs;->Oooo00o(Llyiahf/vczjk/gf4;)Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "class "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/of4;->OooOo0()Llyiahf/vczjk/hy0;

    move-result-object v1

    iget-object v2, v1, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    iget-object v3, v2, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v3}, Llyiahf/vczjk/ic3;->OooO0OO()Z

    move-result v3

    const/16 v4, 0x2e

    if-eqz v3, :cond_0

    const-string v2, ""

    goto :goto_0

    :cond_0
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v2, v2, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v2, v2, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    invoke-static {v3, v2, v4}, Llyiahf/vczjk/ii5;->OooOO0O(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    move-result-object v2

    :goto_0
    iget-object v1, v1, Llyiahf/vczjk/hy0;->OooO0O0:Llyiahf/vczjk/hc3;

    iget-object v1, v1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object v1, v1, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    const/16 v3, 0x24

    invoke-static {v1, v4, v3}, Llyiahf/vczjk/g79;->OooOooo(Ljava/lang/String;CC)Ljava/lang/String;

    move-result-object v1

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
