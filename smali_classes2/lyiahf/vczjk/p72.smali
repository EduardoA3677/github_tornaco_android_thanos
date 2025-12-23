.class public abstract Llyiahf/vczjk/p72;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "value"

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    return-void
.end method

.method public static final OooO(Llyiahf/vczjk/cm5;)V
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/jp8;->OooOOO:Llyiahf/vczjk/mm3;

    invoke-interface {p0, v0}, Llyiahf/vczjk/cm5;->OoooOoo(Llyiahf/vczjk/mm3;)Ljava/lang/Object;

    move-result-object p0

    if-nez p0, :cond_0

    return-void

    :cond_0
    new-instance p0, Ljava/lang/ClassCastException;

    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    throw p0
.end method

.method public static final OooO00o(Llyiahf/vczjk/tca;)Z
    .locals 2

    invoke-static {p0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p0

    sget-object v0, Llyiahf/vczjk/op3;->OooOooO:Llyiahf/vczjk/op3;

    sget-object v1, Llyiahf/vczjk/o72;->OooOOO:Llyiahf/vczjk/o72;

    invoke-static {p0, v0, v1}, Llyiahf/vczjk/jp8;->OooOoo(Ljava/util/List;Llyiahf/vczjk/rv1;Llyiahf/vczjk/oe3;)Ljava/lang/Boolean;

    move-result-object p0

    const-string v0, "ifAny(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p0

    return p0
.end method

.method public static OooO0O0(Llyiahf/vczjk/eo0;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/eo0;
    .locals 3

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/hl7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    invoke-static {p0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object p0

    new-instance v1, Llyiahf/vczjk/tp3;

    const/16 v2, 0xf

    invoke-direct {v1, v2}, Llyiahf/vczjk/tp3;-><init>(I)V

    new-instance v2, Llyiahf/vczjk/qv1;

    invoke-direct {v2, v0, p1}, Llyiahf/vczjk/qv1;-><init>(Llyiahf/vczjk/hl7;Llyiahf/vczjk/oe3;)V

    invoke-static {p0, v1, v2}, Llyiahf/vczjk/jp8;->OooOo00(Ljava/util/List;Llyiahf/vczjk/rv1;Llyiahf/vczjk/so8;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/eo0;

    return-object p0
.end method

.method public static final OooO0OO(Llyiahf/vczjk/x02;)Llyiahf/vczjk/hc3;
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/p72;->OooO0oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object p0

    invoke-virtual {p0}, Llyiahf/vczjk/ic3;->OooO0Oo()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    move-object p0, v1

    :goto_0
    if-eqz p0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/ic3;->OooO0oO()Llyiahf/vczjk/hc3;

    move-result-object p0

    return-object p0

    :cond_1
    return-object v1
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/un;)Llyiahf/vczjk/by0;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Llyiahf/vczjk/un;->getType()Llyiahf/vczjk/uk4;

    move-result-object p0

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p0

    instance-of v0, p0, Llyiahf/vczjk/by0;

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/by0;

    return-object p0

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public static final OooO0o(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/hy0;
    .locals 3

    if-eqz p0, :cond_1

    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    if-eqz v0, :cond_1

    instance-of v1, v0, Llyiahf/vczjk/hh6;

    const-string v2, "getName(...)"

    if-eqz v1, :cond_0

    new-instance v1, Llyiahf/vczjk/hy0;

    check-cast v0, Llyiahf/vczjk/hh6;

    check-cast v0, Llyiahf/vczjk/ih6;

    invoke-interface {p0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object p0

    invoke-static {p0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, v0, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    invoke-direct {v1, v0, p0}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    return-object v1

    :cond_0
    instance-of v1, v0, Llyiahf/vczjk/hz0;

    if-eqz v1, :cond_1

    check-cast v0, Llyiahf/vczjk/gz0;

    invoke-static {v0}, Llyiahf/vczjk/p72;->OooO0o(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/hy0;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-interface {p0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object p0

    invoke-static {p0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Llyiahf/vczjk/hy0;->OooO0Oo(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hy0;

    move-result-object p0

    return-object p0

    :cond_1
    const/4 p0, 0x0

    return-object p0
.end method

.method public static final OooO0o0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hk4;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/p72;->OooOO0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/cm5;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/cm5;->OooOO0O()Llyiahf/vczjk/hk4;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hc3;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/n72;->OooO0oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hc3;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/n72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object v0

    invoke-interface {p0}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object p0

    invoke-virtual {v0, p0}, Llyiahf/vczjk/ic3;->OooO00o(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/ic3;

    move-result-object p0

    invoke-virtual {p0}, Llyiahf/vczjk/ic3;->OooO0oO()Llyiahf/vczjk/hc3;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO0oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/n72;->OooO0oO(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object p0

    const-string v0, "getFqName(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public static final OooOO0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/cm5;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/n72;->OooO0Oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/cm5;

    move-result-object p0

    const-string v0, "getContainingModule(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public static final OooOO0O(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/eo0;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p0, Llyiahf/vczjk/ka7;

    if-eqz v0, :cond_0

    check-cast p0, Llyiahf/vczjk/ka7;

    check-cast p0, Llyiahf/vczjk/la7;

    invoke-virtual {p0}, Llyiahf/vczjk/la7;->o0000O0()Llyiahf/vczjk/sa7;

    move-result-object p0

    const-string v0, "getCorrespondingProperty(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_0
    return-object p0
.end method

.method public static final OooOO0o(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/oz2;
    .locals 6

    const/4 v0, 0x0

    const/4 v1, 0x1

    const-string v2, "<this>"

    invoke-static {p0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-array v2, v1, [Llyiahf/vczjk/eo0;

    aput-object p0, v2, v0

    invoke-static {v2}, Llyiahf/vczjk/sy;->Oooooo([Ljava/lang/Object;)Llyiahf/vczjk/wf8;

    move-result-object v2

    invoke-interface {p0}, Llyiahf/vczjk/eo0;->OooOOO0()Ljava/util/Collection;

    move-result-object p0

    const-string v3, "getOverriddenDescriptors(...)"

    invoke-static {p0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Ljava/lang/Iterable;

    invoke-static {p0}, Llyiahf/vczjk/d21;->Oooooo(Ljava/lang/Iterable;)Llyiahf/vczjk/vy;

    move-result-object p0

    new-instance v3, Llyiahf/vczjk/m5a;

    const/4 v4, 0x3

    invoke-direct {v3, v4}, Llyiahf/vczjk/m5a;-><init>(I)V

    new-instance v4, Llyiahf/vczjk/oz2;

    sget-object v5, Llyiahf/vczjk/dg8;->OooOOO:Llyiahf/vczjk/dg8;

    invoke-direct {v4, p0, v3, v5}, Llyiahf/vczjk/oz2;-><init>(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    const/4 p0, 0x2

    new-array p0, p0, [Llyiahf/vczjk/wf8;

    aput-object v2, p0, v0

    aput-object v4, p0, v1

    invoke-static {p0}, Llyiahf/vczjk/sy;->Oooooo([Ljava/lang/Object;)Llyiahf/vczjk/wf8;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/ag8;->Oooo0O0(Llyiahf/vczjk/wf8;)Llyiahf/vczjk/oz2;

    move-result-object p0

    return-object p0
.end method
