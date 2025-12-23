.class public final Llyiahf/vczjk/cm7;
.super Llyiahf/vczjk/gm7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/b64;
.implements Llyiahf/vczjk/e74;


# instance fields
.field public final OooO00o:Ljava/lang/Class;


# direct methods
.method public constructor <init>(Ljava/lang/Class;)V
    .locals 1

    const-string v0, "klass"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/sl7;
    .locals 1

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredAnnotations()[Ljava/lang/annotation/Annotation;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-static {v0, p1}, Llyiahf/vczjk/rd3;->OooOOo0([Ljava/lang/annotation/Annotation;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/sl7;

    move-result-object p1

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooO0O0()Ljava/util/List;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    move-result-object v0

    const-string v1, "getDeclaredFields(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/sy;->Oooooo([Ljava/lang/Object;)Llyiahf/vczjk/wf8;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/zl7;->OooOOO:Llyiahf/vczjk/zl7;

    new-instance v2, Llyiahf/vczjk/e13;

    const/4 v3, 0x0

    invoke-direct {v2, v0, v3, v1}, Llyiahf/vczjk/e13;-><init>(Llyiahf/vczjk/wf8;ZLlyiahf/vczjk/oe3;)V

    sget-object v0, Llyiahf/vczjk/am7;->OooOOO:Llyiahf/vczjk/am7;

    invoke-static {v2, v0}, Llyiahf/vczjk/ag8;->Oooo0oo(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/jy9;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/ag8;->OoooO00(Llyiahf/vczjk/wf8;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0OO()Llyiahf/vczjk/hc3;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0Oo()Ljava/util/List;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredMethods()[Ljava/lang/reflect/Method;

    move-result-object v0

    const-string v1, "getDeclaredMethods(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/sy;->Oooooo([Ljava/lang/Object;)Llyiahf/vczjk/wf8;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/oo000o;

    const/16 v2, 0x17

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/oo000o;-><init>(Ljava/lang/Object;I)V

    new-instance v2, Llyiahf/vczjk/e13;

    const/4 v3, 0x1

    invoke-direct {v2, v0, v3, v1}, Llyiahf/vczjk/e13;-><init>(Llyiahf/vczjk/wf8;ZLlyiahf/vczjk/oe3;)V

    sget-object v0, Llyiahf/vczjk/bm7;->OooOOO:Llyiahf/vczjk/bm7;

    invoke-static {v2, v0}, Llyiahf/vczjk/ag8;->Oooo0oo(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/jy9;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/ag8;->OoooO00(Llyiahf/vczjk/wf8;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0o()Ljava/util/ArrayList;
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    const-string v1, "clazz"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/l4a;->OooOO0O:Llyiahf/vczjk/ld9;

    const/4 v3, 0x0

    if-nez v1, :cond_0

    const-class v1, Ljava/lang/Class;

    :try_start_0
    new-instance v4, Llyiahf/vczjk/ld9;

    const-string v2, "isSealed"

    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v5

    const-string v2, "getPermittedSubclasses"

    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v6

    const-string v2, "isRecord"

    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v7

    const-string v2, "getRecordComponents"

    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v8

    const/16 v9, 0x13

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/ld9;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0

    move-object v1, v4

    goto :goto_0

    :catch_0
    new-instance v2, Llyiahf/vczjk/ld9;

    const/16 v7, 0x13

    move-object v4, v3

    move-object v5, v3

    move-object v6, v3

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/ld9;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    move-object v1, v2

    :goto_0
    sput-object v1, Llyiahf/vczjk/l4a;->OooOO0O:Llyiahf/vczjk/ld9;

    :cond_0
    iget-object v1, v1, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast v1, Ljava/lang/reflect/Method;

    if-nez v1, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v1, v0, v3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    move-object v3, v0

    check-cast v3, [Ljava/lang/Object;

    :goto_1
    const/4 v0, 0x0

    if-nez v3, :cond_2

    new-array v3, v0, [Ljava/lang/Object;

    :cond_2
    new-instance v1, Ljava/util/ArrayList;

    array-length v2, v3

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    array-length v2, v3

    :goto_2
    if-ge v0, v2, :cond_3

    aget-object v4, v3, v0

    new-instance v5, Llyiahf/vczjk/om7;

    invoke-direct {v5, v4}, Llyiahf/vczjk/om7;-><init>(Ljava/lang/Object;)V

    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v0, v0, 0x1

    goto :goto_2

    :cond_3
    return-object v1
.end method

.method public final OooO0o0()Llyiahf/vczjk/qt5;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->isAnonymousClass()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    const-string v1, "."

    invoke-static {v0, v1, v0}, Llyiahf/vczjk/z69;->Ooooooo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v0

    return-object v0

    :cond_0
    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0oO()Z
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    const-string v1, "clazz"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/l4a;->OooOO0O:Llyiahf/vczjk/ld9;

    const/4 v3, 0x0

    if-nez v1, :cond_0

    const-class v1, Ljava/lang/Class;

    :try_start_0
    new-instance v4, Llyiahf/vczjk/ld9;

    const-string v2, "isSealed"

    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v5

    const-string v2, "getPermittedSubclasses"

    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v6

    const-string v2, "isRecord"

    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v7

    const-string v2, "getRecordComponents"

    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v8

    const/16 v9, 0x13

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/ld9;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0

    move-object v1, v4

    goto :goto_0

    :catch_0
    new-instance v2, Llyiahf/vczjk/ld9;

    const/16 v7, 0x13

    move-object v4, v3

    move-object v5, v3

    move-object v6, v3

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/ld9;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    move-object v1, v2

    :goto_0
    sput-object v1, Llyiahf/vczjk/l4a;->OooOO0O:Llyiahf/vczjk/ld9;

    :cond_0
    iget-object v1, v1, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Ljava/lang/reflect/Method;

    if-nez v1, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v1, v0, v3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    const-string v1, "null cannot be cast to non-null type kotlin.Boolean"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v3, v0

    check-cast v3, Ljava/lang/Boolean;

    :goto_1
    if-eqz v3, :cond_2

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0

    :cond_2
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0oo()Z
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    const-string v1, "clazz"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/l4a;->OooOO0O:Llyiahf/vczjk/ld9;

    const/4 v3, 0x0

    if-nez v1, :cond_0

    const-class v1, Ljava/lang/Class;

    :try_start_0
    new-instance v4, Llyiahf/vczjk/ld9;

    const-string v2, "isSealed"

    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v5

    const-string v2, "getPermittedSubclasses"

    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v6

    const-string v2, "isRecord"

    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v7

    const-string v2, "getRecordComponents"

    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v8

    const/16 v9, 0x13

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/ld9;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0

    move-object v1, v4

    goto :goto_0

    :catch_0
    new-instance v2, Llyiahf/vczjk/ld9;

    const/16 v7, 0x13

    move-object v4, v3

    move-object v5, v3

    move-object v6, v3

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/ld9;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    move-object v1, v2

    :goto_0
    sput-object v1, Llyiahf/vczjk/l4a;->OooOO0O:Llyiahf/vczjk/ld9;

    :cond_0
    iget-object v1, v1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Ljava/lang/reflect/Method;

    if-nez v1, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v1, v0, v3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    const-string v1, "null cannot be cast to non-null type kotlin.Boolean"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v3, v0

    check-cast v3, Ljava/lang/Boolean;

    :goto_1
    if-eqz v3, :cond_2

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0

    :cond_2
    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOO()Ljava/util/ArrayList;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->getTypeParameters()[Ljava/lang/reflect/TypeVariable;

    move-result-object v0

    const-string v1, "getTypeParameters(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Ljava/util/ArrayList;

    array-length v2, v0

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    array-length v2, v0

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_0

    aget-object v4, v0, v3

    new-instance v5, Llyiahf/vczjk/qm7;

    invoke-direct {v5, v4}, Llyiahf/vczjk/qm7;-><init>(Ljava/lang/reflect/TypeVariable;)V

    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    return-object v1
.end method

.method public final OooOOo0()Ljava/util/Collection;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredAnnotations()[Ljava/lang/annotation/Annotation;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/rd3;->OooOOo([Ljava/lang/annotation/Annotation;)Ljava/util/ArrayList;

    move-result-object v0

    return-object v0

    :cond_0
    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/cm7;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/cm7;

    iget-object p1, p1, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    iget-object v0, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

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

    iget-object v0, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-class v1, Llyiahf/vczjk/cm7;

    const-string v2, ": "

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/ii5;->OooOOoo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
