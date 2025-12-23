.class public final Llyiahf/vczjk/bg4;
.super Llyiahf/vczjk/ff4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/lf3;
.implements Llyiahf/vczjk/zf4;
.implements Llyiahf/vczjk/eg3;


# static fields
.field public static final synthetic OooOo0:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooOOOO:Llyiahf/vczjk/yf4;

.field public final OooOOOo:Ljava/lang/String;

.field public final OooOOo:Llyiahf/vczjk/wm7;

.field public final OooOOo0:Ljava/lang/Object;

.field public final OooOOoo:Ljava/lang/Object;

.field public final OooOo00:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/bg4;

    const-string v2, "descriptor"

    const-string v3, "getDescriptor()Lorg/jetbrains/kotlin/descriptors/FunctionDescriptor;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v1, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const/4 v1, 0x1

    new-array v1, v1, [Llyiahf/vczjk/th4;

    aput-object v0, v1, v4

    sput-object v1, Llyiahf/vczjk/bg4;->OooOo0:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/yf4;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/rf3;Ljava/lang/Object;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/ff4;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bg4;->OooOOOO:Llyiahf/vczjk/yf4;

    iput-object p3, p0, Llyiahf/vczjk/bg4;->OooOOOo:Ljava/lang/String;

    iput-object p5, p0, Llyiahf/vczjk/bg4;->OooOOo0:Ljava/lang/Object;

    new-instance p1, Llyiahf/vczjk/o0O000;

    const/16 p3, 0x13

    const/4 p5, 0x0

    invoke-direct {p1, p3, p0, p2, p5}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    invoke-static {p4, p1}, Llyiahf/vczjk/vo6;->OooOO0o(Llyiahf/vczjk/eo0;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wm7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/bg4;->OooOOo:Llyiahf/vczjk/wm7;

    sget-object p1, Llyiahf/vczjk/ww4;->OooOOO0:Llyiahf/vczjk/ww4;

    new-instance p2, Llyiahf/vczjk/ag4;

    const/4 p3, 0x0

    invoke-direct {p2, p0, p3}, Llyiahf/vczjk/ag4;-><init>(Llyiahf/vczjk/bg4;I)V

    invoke-static {p1, p2}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/bg4;->OooOOoo:Ljava/lang/Object;

    new-instance p2, Llyiahf/vczjk/ag4;

    const/4 p3, 0x1

    invoke-direct {p2, p0, p3}, Llyiahf/vczjk/ag4;-><init>(Llyiahf/vczjk/bg4;I)V

    invoke-static {p1, p2}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/bg4;->OooOo00:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/yf4;Llyiahf/vczjk/rf3;)V
    .locals 7

    const-string v0, "container"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "descriptor"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/w02;

    invoke-virtual {v0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v3

    const-string v0, "asString(...)"

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p2}, Llyiahf/vczjk/iz7;->OooO0OO(Llyiahf/vczjk/rf3;)Llyiahf/vczjk/ng0;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ng0;->OooOO0()Ljava/lang/String;

    move-result-object v4

    sget-object v6, Llyiahf/vczjk/fo0;->OooOOO0:Llyiahf/vczjk/fo0;

    move-object v1, p0

    move-object v2, p1

    move-object v5, p2

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/bg4;-><init>(Llyiahf/vczjk/yf4;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/rf3;Ljava/lang/Object;)V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    filled-new-array {p1, p2, p3, p4}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ff4;->OooO0oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/ff4;->OooO0oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0Oo(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/io/Serializable;)Ljava/lang/Object;
    .locals 0

    filled-new-array/range {p1 .. p7}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ff4;->OooO0oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ff4;->OooO0oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    filled-new-array {p1, p2, p3}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ff4;->OooO0oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    filled-new-array {p1, p2, p3, p4, p5}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ff4;->OooO0oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0O()Llyiahf/vczjk/so0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bg4;->OooOOoo:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/so0;

    return-object v0
.end method

.method public final OooOO0o()Llyiahf/vczjk/yf4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bg4;->OooOOOO:Llyiahf/vczjk/yf4;

    return-object v0
.end method

.method public final bridge synthetic OooOOO()Llyiahf/vczjk/eo0;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOO0()Llyiahf/vczjk/so0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bg4;->OooOo00:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/so0;

    return-object v0
.end method

.method public final OooOOo()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/rf3;->OooOOo()Z

    move-result v0

    return v0
.end method

.method public final OooOOo0()Z
    .locals 2

    sget-object v0, Llyiahf/vczjk/fo0;->OooOOO0:Llyiahf/vczjk/fo0;

    iget-object v1, p0, Llyiahf/vczjk/bg4;->OooOOo0:Ljava/lang/Object;

    if-eq v1, v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOoo(Ljava/lang/reflect/Constructor;Llyiahf/vczjk/rf3;Z)Llyiahf/vczjk/jp0;
    .locals 10

    iget-object v2, p0, Llyiahf/vczjk/bg4;->OooOOo0:Ljava/lang/Object;

    const-string v3, "getGenericParameterTypes(...)"

    const-string v4, "getDeclaringClass(...)"

    const-string v5, "constructor"

    const/4 v6, 0x0

    if-nez p3, :cond_9

    instance-of v7, p2, Llyiahf/vczjk/ux0;

    if-eqz v7, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/ux0;

    goto :goto_0

    :cond_0
    move-object v0, v6

    :goto_0
    if-nez v0, :cond_1

    goto/16 :goto_2

    :cond_1
    move-object v7, v0

    check-cast v7, Llyiahf/vczjk/tf3;

    invoke-virtual {v7}, Llyiahf/vczjk/tf3;->OooO0Oo()Llyiahf/vczjk/q72;

    move-result-object v8

    invoke-static {v8}, Llyiahf/vczjk/r72;->OooO0o0(Llyiahf/vczjk/q72;)Z

    move-result v8

    if-eqz v8, :cond_2

    goto/16 :goto_2

    :cond_2
    invoke-virtual {v0}, Llyiahf/vczjk/ux0;->OooOoo0()Llyiahf/vczjk/by0;

    move-result-object v8

    const-string v9, "getConstructedClass(...)"

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v8}, Llyiahf/vczjk/uz3;->OooO0o(Llyiahf/vczjk/v02;)Z

    move-result v8

    if-eqz v8, :cond_3

    goto/16 :goto_2

    :cond_3
    invoke-virtual {v0}, Llyiahf/vczjk/ux0;->OooOoo0()Llyiahf/vczjk/by0;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/n72;->OooOOo0(Llyiahf/vczjk/v02;)Z

    move-result v0

    if-eqz v0, :cond_4

    goto/16 :goto_2

    :cond_4
    invoke-virtual {v7}, Llyiahf/vczjk/tf3;->OoooOOO()Ljava/util/List;

    move-result-object v0

    const-string v7, "getValueParameters(...)"

    invoke-static {v0, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v7

    if-eqz v7, :cond_5

    goto :goto_2

    :cond_5
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_6
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_9

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/tca;

    check-cast v7, Llyiahf/vczjk/bda;

    invoke-virtual {v7}, Llyiahf/vczjk/bda;->getType()Llyiahf/vczjk/uk4;

    move-result-object v7

    const-string v8, "getType(...)"

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v7}, Llyiahf/vczjk/tg0;->Oooo0(Llyiahf/vczjk/uk4;)Z

    move-result v7

    if-eqz v7, :cond_6

    invoke-virtual {p0}, Llyiahf/vczjk/bg4;->OooOOo0()Z

    move-result v0

    if-eqz v0, :cond_7

    new-instance v0, Llyiahf/vczjk/to0;

    invoke-virtual {p0}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v3

    invoke-static {v2, v3}, Llyiahf/vczjk/qu6;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/eo0;)Ljava/lang/Object;

    move-result-object v2

    const/4 v3, 0x0

    invoke-direct {v0, p1, v2, v3}, Llyiahf/vczjk/to0;-><init>(Ljava/lang/reflect/Constructor;Ljava/lang/Object;I)V

    return-object v0

    :cond_7
    new-instance v0, Llyiahf/vczjk/uo0;

    invoke-static {p1, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/reflect/Constructor;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v2

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/reflect/Constructor;->getGenericParameterTypes()[Ljava/lang/reflect/Type;

    move-result-object v4

    invoke-static {v4, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    array-length v3, v4

    const/4 v5, 0x0

    const/4 v7, 0x1

    if-gt v3, v7, :cond_8

    new-array v3, v5, [Ljava/lang/reflect/Type;

    goto :goto_1

    :cond_8
    array-length v3, v4

    sub-int/2addr v3, v7

    invoke-static {v5, v3, v4}, Llyiahf/vczjk/sy;->o0ooOO0(II[Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v3

    :goto_1
    move-object v4, v3

    check-cast v4, [Ljava/lang/reflect/Type;

    const/4 v5, 0x0

    move-object v1, p1

    move-object v3, v6

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/uo0;-><init>(Ljava/lang/reflect/Member;Ljava/lang/reflect/Type;Ljava/lang/Class;[Ljava/lang/reflect/Type;I)V

    return-object v0

    :cond_9
    :goto_2
    invoke-virtual {p0}, Llyiahf/vczjk/bg4;->OooOOo0()Z

    move-result v0

    if-eqz v0, :cond_a

    new-instance v0, Llyiahf/vczjk/to0;

    invoke-virtual {p0}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v3

    invoke-static {v2, v3}, Llyiahf/vczjk/qu6;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/eo0;)Ljava/lang/Object;

    move-result-object v2

    const/4 v3, 0x1

    invoke-direct {v0, p1, v2, v3}, Llyiahf/vczjk/to0;-><init>(Ljava/lang/reflect/Constructor;Ljava/lang/Object;I)V

    return-object v0

    :cond_a
    new-instance v0, Llyiahf/vczjk/uo0;

    invoke-static {p1, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/reflect/Constructor;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v2

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/reflect/Constructor;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/Class;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v5

    if-eqz v5, :cond_b

    invoke-virtual {v4}, Ljava/lang/Class;->getModifiers()I

    move-result v4

    invoke-static {v4}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result v4

    if-nez v4, :cond_b

    move-object v6, v5

    :cond_b
    invoke-virtual {p1}, Ljava/lang/reflect/Constructor;->getGenericParameterTypes()[Ljava/lang/reflect/Type;

    move-result-object v4

    invoke-static {v4, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v5, 0x1

    move-object v1, p1

    move-object v3, v6

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/uo0;-><init>(Ljava/lang/reflect/Member;Ljava/lang/reflect/Type;Ljava/lang/Class;[Ljava/lang/reflect/Type;I)V

    return-object v0
.end method

.method public final OooOo0()Llyiahf/vczjk/rf3;
    .locals 2

    sget-object v0, Llyiahf/vczjk/bg4;->OooOo0:[Llyiahf/vczjk/th4;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    iget-object v0, p0, Llyiahf/vczjk/bg4;->OooOOo:Llyiahf/vczjk/wm7;

    invoke-virtual {v0}, Llyiahf/vczjk/wm7;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    const-string v1, "getValue(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/rf3;

    return-object v0
.end method

.method public final OooOo00(Ljava/lang/reflect/Method;Z)Llyiahf/vczjk/ip0;
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/bg4;->OooOOo0()Z

    move-result v0

    if-eqz v0, :cond_1

    new-instance v0, Llyiahf/vczjk/fp0;

    invoke-virtual {p0}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/co0;->Oooooo0()Llyiahf/vczjk/mp4;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/bg4;->OooOOo0:Ljava/lang/Object;

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Llyiahf/vczjk/mp4;->getType()Llyiahf/vczjk/uk4;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/uz3;->OooO0OO(Llyiahf/vczjk/uk4;)Z

    move-result v1

    const/4 v3, 0x1

    if-ne v1, v3, :cond_0

    invoke-virtual {p1}, Ljava/lang/reflect/Method;->getParameterTypes()[Ljava/lang/Class;

    move-result-object v1

    const-string v4, "getParameterTypes(...)"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/sy;->o000OOo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Class;

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Ljava/lang/Class;->isInterface()Z

    move-result v1

    if-ne v1, v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v1

    invoke-static {v2, v1}, Llyiahf/vczjk/qu6;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/eo0;)Ljava/lang/Object;

    move-result-object v2

    :goto_0
    invoke-direct {v0, p1, p2, v2}, Llyiahf/vczjk/fp0;-><init>(Ljava/lang/reflect/Method;ZLjava/lang/Object;)V

    return-object v0

    :cond_1
    new-instance p2, Llyiahf/vczjk/hp0;

    const/4 v0, 0x2

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/hp0;-><init>(Ljava/lang/reflect/Method;I)V

    return-object p2
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    invoke-static {p1}, Llyiahf/vczjk/mba;->OooO0O0(Ljava/lang/Object;)Llyiahf/vczjk/bg4;

    move-result-object p1

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return v0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/bg4;->OooOOOO:Llyiahf/vczjk/yf4;

    iget-object v2, p1, Llyiahf/vczjk/bg4;->OooOOOO:Llyiahf/vczjk/yf4;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/bg4;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/bg4;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/bg4;->OooOOOo:Ljava/lang/String;

    iget-object v2, p1, Llyiahf/vczjk/bg4;->OooOOOo:Ljava/lang/String;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/bg4;->OooOOo0:Ljava/lang/Object;

    iget-object p1, p1, Llyiahf/vczjk/bg4;->OooOOo0:Ljava/lang/Object;

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    const/4 p1, 0x1

    return p1

    :cond_1
    return v0
.end method

.method public final getArity()I
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/bg4;->OooOO0O()Llyiahf/vczjk/so0;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->Oooo(Llyiahf/vczjk/so0;)I

    move-result v0

    return v0
.end method

.method public final getName()Ljava/lang/String;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/w02;

    invoke-virtual {v0}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v0

    const-string v1, "asString(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/bg4;->OooOOOO:Llyiahf/vczjk/yf4;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    invoke-virtual {p0}, Llyiahf/vczjk/bg4;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    mul-int/lit8 v1, v1, 0x1f

    iget-object v0, p0, Llyiahf/vczjk/bg4;->OooOOOo:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    move-result v0

    add-int/2addr v0, v1

    return v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    filled-new-array {p1, p2}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ff4;->OooO0oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    sget-object v0, Llyiahf/vczjk/en7;->OooO00o:Llyiahf/vczjk/h72;

    invoke-virtual {p0}, Llyiahf/vczjk/bg4;->OooOo0()Llyiahf/vczjk/rf3;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/en7;->OooO0O0(Llyiahf/vczjk/rf3;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
