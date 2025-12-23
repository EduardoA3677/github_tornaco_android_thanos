.class public abstract Llyiahf/vczjk/iz7;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/hy0;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/hc3;

    const-string v1, "java.lang.Void"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/hy0;

    invoke-virtual {v0}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v2

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    sput-object v1, Llyiahf/vczjk/iz7;->OooO00o:Llyiahf/vczjk/hy0;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/yd4;
    .locals 4

    new-instance v0, Llyiahf/vczjk/yd4;

    new-instance v1, Llyiahf/vczjk/ae4;

    invoke-static {p0}, Llyiahf/vczjk/dl6;->OooO0o0(Llyiahf/vczjk/rf3;)Ljava/lang/String;

    move-result-object v2

    if-nez v2, :cond_2

    instance-of v2, p0, Llyiahf/vczjk/va7;

    const-string v3, "asString(...)"

    if-eqz v2, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/p72;->OooOO0O(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/eo0;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v2

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2}, Llyiahf/vczjk/bd4;->OooO00o(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    goto :goto_0

    :cond_0
    instance-of v2, p0, Llyiahf/vczjk/hb7;

    if-eqz v2, :cond_1

    invoke-static {p0}, Llyiahf/vczjk/p72;->OooOO0O(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/eo0;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/v02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v2

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2}, Llyiahf/vczjk/bd4;->OooO0O0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    goto :goto_0

    :cond_1
    move-object v2, p0

    check-cast v2, Llyiahf/vczjk/w02;

    invoke-virtual {v2}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v2

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_2
    :goto_0
    const/4 v3, 0x1

    invoke-static {p0, v3}, Llyiahf/vczjk/r02;->OooOO0(Llyiahf/vczjk/rf3;I)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v1, v2, p0}, Llyiahf/vczjk/ae4;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/yd4;-><init>(Llyiahf/vczjk/ae4;)V

    return-object v0
.end method

.method public static OooO0O0(Llyiahf/vczjk/sa7;)Llyiahf/vczjk/t51;
    .locals 6

    const-string v0, "possiblyOverriddenProperty"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/n72;->OooOo00(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/eo0;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/sa7;

    invoke-interface {p0}, Llyiahf/vczjk/sa7;->OooO00o()Llyiahf/vczjk/sa7;

    move-result-object v1

    const-string p0, "getOriginal(...)"

    invoke-static {v1, p0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of p0, v1, Llyiahf/vczjk/t82;

    const/4 v0, 0x0

    if-eqz p0, :cond_0

    move-object p0, v1

    check-cast p0, Llyiahf/vczjk/t82;

    sget-object v2, Llyiahf/vczjk/ue4;->OooO0Oo:Llyiahf/vczjk/ug3;

    const-string v3, "propertySignature"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v3, v2

    iget-object v2, p0, Llyiahf/vczjk/t82;->Oooo:Llyiahf/vczjk/xc7;

    invoke-static {v2, v3}, Llyiahf/vczjk/tn6;->OooOOO(Llyiahf/vczjk/sg3;Llyiahf/vczjk/ug3;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/oe4;

    if-eqz v3, :cond_a

    new-instance v0, Llyiahf/vczjk/he4;

    iget-object v4, p0, Llyiahf/vczjk/t82;->OoooO00:Llyiahf/vczjk/rt5;

    iget-object v5, p0, Llyiahf/vczjk/t82;->OoooO0:Llyiahf/vczjk/h87;

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/he4;-><init>(Llyiahf/vczjk/sa7;Llyiahf/vczjk/xc7;Llyiahf/vczjk/oe4;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;)V

    return-object v0

    :cond_0
    instance-of p0, v1, Llyiahf/vczjk/r64;

    if-eqz p0, :cond_a

    move-object p0, v1

    check-cast p0, Llyiahf/vczjk/r64;

    invoke-virtual {p0}, Llyiahf/vczjk/y02;->OooO0oO()Llyiahf/vczjk/sx8;

    move-result-object v2

    instance-of v3, v2, Llyiahf/vczjk/hz7;

    if-eqz v3, :cond_1

    check-cast v2, Llyiahf/vczjk/hz7;

    goto :goto_0

    :cond_1
    move-object v2, v0

    :goto_0
    if-eqz v2, :cond_2

    iget-object v2, v2, Llyiahf/vczjk/hz7;->OooOOO0:Llyiahf/vczjk/gm7;

    goto :goto_1

    :cond_2
    move-object v2, v0

    :goto_1
    instance-of v3, v2, Llyiahf/vczjk/im7;

    if-eqz v3, :cond_3

    new-instance p0, Llyiahf/vczjk/fe4;

    check-cast v2, Llyiahf/vczjk/im7;

    iget-object v0, v2, Llyiahf/vczjk/im7;->OooO00o:Ljava/lang/reflect/Field;

    invoke-direct {p0, v0}, Llyiahf/vczjk/fe4;-><init>(Ljava/lang/reflect/Field;)V

    return-object p0

    :cond_3
    instance-of v3, v2, Llyiahf/vczjk/lm7;

    if-eqz v3, :cond_9

    new-instance v1, Llyiahf/vczjk/ge4;

    check-cast v2, Llyiahf/vczjk/lm7;

    iget-object v2, v2, Llyiahf/vczjk/lm7;->OooO00o:Ljava/lang/reflect/Method;

    iget-object p0, p0, Llyiahf/vczjk/ua7;->Oooo0o:Llyiahf/vczjk/hb7;

    if-eqz p0, :cond_4

    invoke-virtual {p0}, Llyiahf/vczjk/y02;->OooO0oO()Llyiahf/vczjk/sx8;

    move-result-object p0

    goto :goto_2

    :cond_4
    move-object p0, v0

    :goto_2
    instance-of v3, p0, Llyiahf/vczjk/hz7;

    if-eqz v3, :cond_5

    check-cast p0, Llyiahf/vczjk/hz7;

    goto :goto_3

    :cond_5
    move-object p0, v0

    :goto_3
    if-eqz p0, :cond_6

    iget-object p0, p0, Llyiahf/vczjk/hz7;->OooOOO0:Llyiahf/vczjk/gm7;

    goto :goto_4

    :cond_6
    move-object p0, v0

    :goto_4
    instance-of v3, p0, Llyiahf/vczjk/lm7;

    if-eqz v3, :cond_7

    check-cast p0, Llyiahf/vczjk/lm7;

    goto :goto_5

    :cond_7
    move-object p0, v0

    :goto_5
    if-eqz p0, :cond_8

    iget-object v0, p0, Llyiahf/vczjk/lm7;->OooO00o:Ljava/lang/reflect/Method;

    :cond_8
    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/ge4;-><init>(Ljava/lang/reflect/Method;Ljava/lang/reflect/Method;)V

    return-object v1

    :cond_9
    new-instance p0, Llyiahf/vczjk/es1;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v3, "Incorrect resolution sequence for Java field "

    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " (source = "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p0, v0}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_a
    invoke-interface {v1}, Llyiahf/vczjk/sa7;->OooO0O0()Llyiahf/vczjk/va7;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {p0}, Llyiahf/vczjk/iz7;->OooO00o(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/yd4;

    move-result-object p0

    invoke-interface {v1}, Llyiahf/vczjk/sa7;->OooO0OO()Llyiahf/vczjk/hb7;

    move-result-object v1

    if-eqz v1, :cond_b

    invoke-static {v1}, Llyiahf/vczjk/iz7;->OooO00o(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/yd4;

    move-result-object v0

    :cond_b
    new-instance v1, Llyiahf/vczjk/ie4;

    invoke-direct {v1, p0, v0}, Llyiahf/vczjk/ie4;-><init>(Llyiahf/vczjk/yd4;Llyiahf/vczjk/yd4;)V

    return-object v1
.end method

.method public static OooO0OO(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/ng0;
    .locals 8

    const-string v0, "possiblySubstitutedFunction"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/n72;->OooOo00(Llyiahf/vczjk/eo0;)Llyiahf/vczjk/eo0;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/rf3;

    invoke-interface {v0}, Llyiahf/vczjk/rf3;->OooO00o()Llyiahf/vczjk/rf3;

    move-result-object v0

    const-string v1, "getOriginal(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v1, v0, Llyiahf/vczjk/y72;

    if-eqz v1, :cond_9

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/m82;

    invoke-interface {v1}, Llyiahf/vczjk/m82;->OooOooo()Llyiahf/vczjk/pi5;

    move-result-object v2

    instance-of v3, v2, Llyiahf/vczjk/pc7;

    if-eqz v3, :cond_0

    sget-object v3, Llyiahf/vczjk/ve4;->OooO00o:Llyiahf/vczjk/iu2;

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/pc7;

    invoke-interface {v1}, Llyiahf/vczjk/m82;->OoooOo0()Llyiahf/vczjk/rt5;

    move-result-object v4

    invoke-interface {v1}, Llyiahf/vczjk/m82;->OoooO0O()Llyiahf/vczjk/h87;

    move-result-object v5

    invoke-static {v3, v4, v5}, Llyiahf/vczjk/ve4;->OooO0OO(Llyiahf/vczjk/pc7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;)Llyiahf/vczjk/ae4;

    move-result-object v3

    if-eqz v3, :cond_0

    new-instance p0, Llyiahf/vczjk/yd4;

    invoke-direct {p0, v3}, Llyiahf/vczjk/yd4;-><init>(Llyiahf/vczjk/ae4;)V

    return-object p0

    :cond_0
    instance-of v3, v2, Llyiahf/vczjk/cc7;

    if-eqz v3, :cond_8

    sget-object v3, Llyiahf/vczjk/ve4;->OooO00o:Llyiahf/vczjk/iu2;

    check-cast v2, Llyiahf/vczjk/cc7;

    invoke-interface {v1}, Llyiahf/vczjk/m82;->OoooOo0()Llyiahf/vczjk/rt5;

    move-result-object v3

    invoke-interface {v1}, Llyiahf/vczjk/m82;->OoooO0O()Llyiahf/vczjk/h87;

    move-result-object v1

    invoke-static {v2, v3, v1}, Llyiahf/vczjk/ve4;->OooO00o(Llyiahf/vczjk/cc7;Llyiahf/vczjk/rt5;Llyiahf/vczjk/h87;)Llyiahf/vczjk/ae4;

    move-result-object v1

    if-eqz v1, :cond_8

    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    const-string v2, "getContainingDeclaration(...)"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/uz3;->OooO0O0(Llyiahf/vczjk/v02;)Z

    move-result v0

    if-eqz v0, :cond_1

    new-instance p0, Llyiahf/vczjk/yd4;

    invoke-direct {p0, v1}, Llyiahf/vczjk/yd4;-><init>(Llyiahf/vczjk/ae4;)V

    return-object p0

    :cond_1
    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object v0

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/uz3;->OooO0Oo(Llyiahf/vczjk/v02;)Z

    move-result v0

    if-eqz v0, :cond_7

    check-cast p0, Llyiahf/vczjk/il1;

    invoke-interface {p0}, Llyiahf/vczjk/il1;->OooOoOO()Z

    move-result v0

    const/4 v2, 0x0

    const-string v3, ")V"

    const-string v4, "constructor-impl"

    const-string v5, "Invalid signature: "

    iget-object v6, v1, Llyiahf/vczjk/ae4;->OooO:Ljava/lang/String;

    iget-object v7, v1, Llyiahf/vczjk/ae4;->OooOO0:Ljava/lang/String;

    if-eqz v0, :cond_3

    invoke-static {v6, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p0

    if-eqz p0, :cond_2

    invoke-static {v7, v3, v2}, Llyiahf/vczjk/g79;->OooOoOO(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result p0

    if-eqz p0, :cond_2

    goto :goto_0

    :cond_2
    new-instance p0, Ljava/lang/StringBuilder;

    invoke-direct {p0, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_3
    invoke-static {v6, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_6

    invoke-interface {p0}, Llyiahf/vczjk/il1;->OooOoo0()Llyiahf/vczjk/by0;

    move-result-object p0

    const-string v0, "getConstructedClass(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/p72;->OooO0o(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/hy0;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {p0}, Llyiahf/vczjk/hy0;->OooO0O0()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/ny0;->OooO0O0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-static {v7, v3, v2}, Llyiahf/vczjk/g79;->OooOoOO(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v0

    if-eqz v0, :cond_4

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "V"

    invoke-static {v7, v1}, Llyiahf/vczjk/z69;->Ooooo00(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    const-string v0, "name"

    invoke-static {v6, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "desc"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/ae4;

    invoke-direct {v1, v6, p0}, Llyiahf/vczjk/ae4;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_0

    :cond_4
    invoke-static {v7, p0, v2}, Llyiahf/vczjk/g79;->OooOoOO(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result p0

    if-eqz p0, :cond_5

    :goto_0
    new-instance p0, Llyiahf/vczjk/yd4;

    invoke-direct {p0, v1}, Llyiahf/vczjk/yd4;-><init>(Llyiahf/vczjk/ae4;)V

    return-object p0

    :cond_5
    new-instance p0, Ljava/lang/StringBuilder;

    invoke-direct {p0, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_6
    new-instance p0, Ljava/lang/StringBuilder;

    invoke-direct {p0, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_7
    new-instance p0, Llyiahf/vczjk/xd4;

    invoke-direct {p0, v1}, Llyiahf/vczjk/xd4;-><init>(Llyiahf/vczjk/ae4;)V

    return-object p0

    :cond_8
    invoke-static {v0}, Llyiahf/vczjk/iz7;->OooO00o(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/yd4;

    move-result-object p0

    return-object p0

    :cond_9
    instance-of p0, v0, Llyiahf/vczjk/o64;

    const/4 v1, 0x0

    if-eqz p0, :cond_e

    move-object p0, v0

    check-cast p0, Llyiahf/vczjk/o64;

    invoke-virtual {p0}, Llyiahf/vczjk/y02;->OooO0oO()Llyiahf/vczjk/sx8;

    move-result-object p0

    instance-of v2, p0, Llyiahf/vczjk/hz7;

    if-eqz v2, :cond_a

    check-cast p0, Llyiahf/vczjk/hz7;

    goto :goto_1

    :cond_a
    move-object p0, v1

    :goto_1
    if-eqz p0, :cond_b

    iget-object p0, p0, Llyiahf/vczjk/hz7;->OooOOO0:Llyiahf/vczjk/gm7;

    goto :goto_2

    :cond_b
    move-object p0, v1

    :goto_2
    instance-of v2, p0, Llyiahf/vczjk/lm7;

    if-eqz v2, :cond_c

    move-object v1, p0

    check-cast v1, Llyiahf/vczjk/lm7;

    :cond_c
    if-eqz v1, :cond_d

    iget-object p0, v1, Llyiahf/vczjk/lm7;->OooO00o:Ljava/lang/reflect/Method;

    if-eqz p0, :cond_d

    new-instance v0, Llyiahf/vczjk/wd4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/wd4;-><init>(Ljava/lang/reflect/Method;)V

    return-object v0

    :cond_d
    new-instance p0, Llyiahf/vczjk/es1;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Incorrect resolution sequence for Java method "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p0, v0}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_e
    instance-of p0, v0, Llyiahf/vczjk/e64;

    const/16 v2, 0x29

    const-string v3, " ("

    if-eqz p0, :cond_13

    move-object p0, v0

    check-cast p0, Llyiahf/vczjk/e64;

    invoke-virtual {p0}, Llyiahf/vczjk/y02;->OooO0oO()Llyiahf/vczjk/sx8;

    move-result-object p0

    instance-of v4, p0, Llyiahf/vczjk/hz7;

    if-eqz v4, :cond_f

    check-cast p0, Llyiahf/vczjk/hz7;

    goto :goto_3

    :cond_f
    move-object p0, v1

    :goto_3
    if-eqz p0, :cond_10

    iget-object v1, p0, Llyiahf/vczjk/hz7;->OooOOO0:Llyiahf/vczjk/gm7;

    :cond_10
    instance-of p0, v1, Llyiahf/vczjk/fm7;

    if-eqz p0, :cond_11

    new-instance p0, Llyiahf/vczjk/vd4;

    check-cast v1, Llyiahf/vczjk/fm7;

    iget-object v0, v1, Llyiahf/vczjk/fm7;->OooO00o:Ljava/lang/reflect/Constructor;

    invoke-direct {p0, v0}, Llyiahf/vczjk/vd4;-><init>(Ljava/lang/reflect/Constructor;)V

    return-object p0

    :cond_11
    instance-of p0, v1, Llyiahf/vczjk/cm7;

    if-eqz p0, :cond_12

    move-object p0, v1

    check-cast p0, Llyiahf/vczjk/cm7;

    iget-object v4, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v4}, Ljava/lang/Class;->isAnnotation()Z

    move-result v4

    if-eqz v4, :cond_12

    new-instance v0, Llyiahf/vczjk/ud4;

    iget-object p0, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ud4;-><init>(Ljava/lang/Class;)V

    return-object v0

    :cond_12
    new-instance p0, Llyiahf/vczjk/es1;

    new-instance v4, Ljava/lang/StringBuilder;

    const-string v5, "Incorrect resolution sequence for Java constructor "

    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p0, v0}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_13
    move-object p0, v0

    check-cast p0, Llyiahf/vczjk/w02;

    invoke-virtual {p0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v1

    sget-object v4, Llyiahf/vczjk/x09;->OooO0OO:Llyiahf/vczjk/qt5;

    invoke-virtual {v1, v4}, Llyiahf/vczjk/qt5;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_14

    invoke-static {v0}, Llyiahf/vczjk/dn8;->o00O0O(Llyiahf/vczjk/rf3;)Z

    move-result v1

    if-eqz v1, :cond_14

    goto :goto_4

    :cond_14
    invoke-virtual {p0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v1

    sget-object v4, Llyiahf/vczjk/x09;->OooO00o:Llyiahf/vczjk/qt5;

    invoke-virtual {v1, v4}, Llyiahf/vczjk/qt5;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_15

    invoke-static {v0}, Llyiahf/vczjk/dn8;->o00O0O(Llyiahf/vczjk/rf3;)Z

    move-result v1

    if-eqz v1, :cond_15

    goto :goto_4

    :cond_15
    invoke-virtual {p0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object p0

    sget-object v1, Llyiahf/vczjk/g01;->OooO0o0:Llyiahf/vczjk/qt5;

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p0

    if-eqz p0, :cond_16

    invoke-interface {v0}, Llyiahf/vczjk/co0;->OoooOOO()Ljava/util/List;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    move-result p0

    if-eqz p0, :cond_16

    :goto_4
    invoke-static {v0}, Llyiahf/vczjk/iz7;->OooO00o(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/yd4;

    move-result-object p0

    return-object p0

    :cond_16
    new-instance p0, Llyiahf/vczjk/es1;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v4, "Unknown origin of "

    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p0, v0}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw p0
.end method
