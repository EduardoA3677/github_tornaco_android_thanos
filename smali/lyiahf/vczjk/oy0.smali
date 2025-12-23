.class public Llyiahf/vczjk/oy0;
.super Llyiahf/vczjk/e4a;
.source "SourceFile"


# instance fields
.field public final OooO0OO:Llyiahf/vczjk/zy6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/a4a;Llyiahf/vczjk/zy6;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/e4a;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/a4a;)V

    iput-object p3, p0, Llyiahf/vczjk/oy0;->OooO0OO:Llyiahf/vczjk/zy6;

    return-void
.end method


# virtual methods
.method public OooO00o(Ljava/lang/Object;)Ljava/lang/String;
    .locals 2

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/e4a;->OooO00o:Llyiahf/vczjk/a4a;

    invoke-virtual {p0, p1, v0, v1}, Llyiahf/vczjk/oy0;->OooO0o0(Ljava/lang/Object;Ljava/lang/Class;Llyiahf/vczjk/a4a;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0O0(Ljava/lang/String;Llyiahf/vczjk/v72;)Llyiahf/vczjk/x64;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/oy0;->OooO0o(Ljava/lang/String;Llyiahf/vczjk/v72;)Llyiahf/vczjk/x64;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0OO()Ljava/lang/String;
    .locals 1

    const-string v0, "class name used as type id"

    return-object v0
.end method

.method public final OooO0Oo(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/e4a;->OooO00o:Llyiahf/vczjk/a4a;

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/oy0;->OooO0o0(Ljava/lang/Object;Ljava/lang/Class;Llyiahf/vczjk/a4a;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public OooO0o(Ljava/lang/String;Llyiahf/vczjk/v72;)Llyiahf/vczjk/x64;
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/e4a;->OooO0O0:Llyiahf/vczjk/x64;

    iget-object v1, p0, Llyiahf/vczjk/oy0;->OooO0OO:Llyiahf/vczjk/zy6;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 v2, 0x3c

    invoke-virtual {p1, v2}, Ljava/lang/String;->indexOf(I)I

    move-result v2

    const-string v3, ") denied resolution"

    const-string v4, "Configured `PolymorphicTypeValidator` (of type "

    const-string v5, "Not a subtype"

    const/4 v6, 0x2

    const/4 v7, 0x0

    if-lez v2, :cond_2

    invoke-virtual {p1, v7, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    invoke-virtual {v1}, Llyiahf/vczjk/zy6;->OooO0O0()I

    move-result v2

    if-eq v2, v6, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/mc4;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-result-object v1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/a4a;->OooO0oO(Ljava/lang/String;)Llyiahf/vczjk/x64;

    move-result-object v1

    iget-object v2, v0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/x64;->o00Oo0(Ljava/lang/Class;)Z

    move-result v2

    if-eqz v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p2, v0, p1, v5}, Llyiahf/vczjk/mc4;->Oooo(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/k44;

    move-result-object p1

    throw p1

    :cond_1
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/vy0;->OooO0o0(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p2, v0, p1, v1}, Llyiahf/vczjk/mc4;->Oooo(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/k44;

    move-result-object p1

    throw p1

    :cond_2
    invoke-virtual {p2}, Llyiahf/vczjk/mc4;->Oooo00O()Llyiahf/vczjk/ec5;

    move-result-object v2

    invoke-virtual {v1}, Llyiahf/vczjk/zy6;->OooO0O0()I

    move-result v8

    if-eq v8, v6, :cond_5

    :try_start_0
    invoke-virtual {p2}, Llyiahf/vczjk/mc4;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-result-object v1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/a4a;->OooOOO0(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v1
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/x64;->o00Ooo(Ljava/lang/Class;)Z

    move-result v3

    if-eqz v3, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/ec5;->OooOOOO()Llyiahf/vczjk/a4a;

    move-result-object v2

    invoke-virtual {v2, v0, v1, v7}, Llyiahf/vczjk/a4a;->OooOO0(Llyiahf/vczjk/x64;Ljava/lang/Class;Z)Llyiahf/vczjk/x64;

    move-result-object v1

    goto :goto_0

    :cond_3
    invoke-virtual {p2, v0, p1, v5}, Llyiahf/vczjk/mc4;->Oooo(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/k44;

    move-result-object p1

    throw p1

    :catch_0
    move-exception v1

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-static {v1}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v1

    const-string v3, "problem: ("

    const-string v4, ") "

    invoke-static {v3, v2, v4, v1}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p2, v0, p1, v1}, Llyiahf/vczjk/mc4;->Oooo(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/k44;

    move-result-object p1

    throw p1

    :catch_1
    const/4 v1, 0x0

    :goto_0
    if-nez v1, :cond_4

    const-string v1, "no such class found"

    invoke-virtual {p2, v0, p1, v1}, Llyiahf/vczjk/v72;->o00000OO(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;)V

    const/4 p1, 0x0

    return-object p1

    :cond_4
    return-object v1

    :cond_5
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/vy0;->OooO0o0(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p2, v0, p1, v1}, Llyiahf/vczjk/mc4;->Oooo(Llyiahf/vczjk/x64;Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/k44;

    move-result-object p1

    throw p1
.end method

.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Class;Llyiahf/vczjk/a4a;)Ljava/lang/String;
    .locals 3

    sget-object v0, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    const-class v0, Ljava/lang/Enum;

    invoke-virtual {v0, p2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {p2}, Ljava/lang/Class;->isEnum()Z

    move-result v1

    if-nez v1, :cond_0

    invoke-virtual {p2}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    move-result-object p2

    :cond_0
    invoke-virtual {p2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    const-string v2, "java.util."

    invoke-virtual {v1, v2}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v2

    if-eqz v2, :cond_8

    instance-of p2, p1, Ljava/util/EnumSet;

    const/4 v2, 0x0

    if-eqz p2, :cond_4

    check-cast p1, Ljava/util/EnumSet;

    invoke-virtual {p1}, Ljava/util/AbstractCollection;->isEmpty()Z

    move-result p2

    if-nez p2, :cond_1

    invoke-virtual {p1}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Enum;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    move-result-object p2

    if-eq p2, v0, :cond_2

    invoke-virtual {p1}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    move-result-object p1

    goto :goto_0

    :cond_1
    sget-object p2, Llyiahf/vczjk/uy0;->OooO0OO:Llyiahf/vczjk/uy0;

    iget-object p2, p2, Llyiahf/vczjk/uy0;->OooO00o:Ljava/lang/reflect/Field;

    if-eqz p2, :cond_3

    :try_start_0
    invoke-virtual {p2, p1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    check-cast p1, Ljava/lang/Class;

    :cond_2
    :goto_0
    sget-object p2, Llyiahf/vczjk/a4a;->OooOOOO:Llyiahf/vczjk/i3a;

    invoke-virtual {p3, v2, p1, p2}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object p1

    const-class p2, Ljava/util/EnumSet;

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/a4a;->OooO0o(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/a21;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/w11;->o0OO00O()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :catch_0
    move-exception p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    throw p2

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "Cannot figure out type for EnumSet (odd JDK platform?)"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_4
    instance-of p2, p1, Ljava/util/EnumMap;

    if-eqz p2, :cond_9

    check-cast p1, Ljava/util/EnumMap;

    invoke-virtual {p1}, Ljava/util/AbstractMap;->isEmpty()Z

    move-result p2

    if-nez p2, :cond_5

    invoke-virtual {p1}, Ljava/util/EnumMap;->keySet()Ljava/util/Set;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Enum;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    move-result-object p2

    if-eq p2, v0, :cond_6

    invoke-virtual {p1}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;

    move-result-object p1

    goto :goto_1

    :cond_5
    sget-object p2, Llyiahf/vczjk/uy0;->OooO0OO:Llyiahf/vczjk/uy0;

    iget-object p2, p2, Llyiahf/vczjk/uy0;->OooO0O0:Ljava/lang/reflect/Field;

    if-eqz p2, :cond_7

    :try_start_1
    invoke-virtual {p2, p1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    check-cast p1, Ljava/lang/Class;

    :cond_6
    :goto_1
    sget-object p2, Llyiahf/vczjk/a4a;->OooOOOO:Llyiahf/vczjk/i3a;

    invoke-virtual {p3, v2, p1, p2}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object p1

    const-class v0, Ljava/lang/Object;

    invoke-virtual {p3, v2, v0, p2}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object p2

    const-class v0, Ljava/util/EnumMap;

    invoke-virtual {p3, v0, p1, p2}, Llyiahf/vczjk/a4a;->OooO(Ljava/lang/Class;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;)Llyiahf/vczjk/wb5;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/ub5;->o0OO00O()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :catch_1
    move-exception p1

    new-instance p2, Ljava/lang/IllegalArgumentException;

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    throw p2

    :cond_7
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "Cannot figure out type for EnumMap (odd JDK platform?)"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_8
    const/16 p1, 0x24

    invoke-virtual {v1, p1}, Ljava/lang/String;->indexOf(I)I

    move-result p1

    if-ltz p1, :cond_9

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOOO(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object p1

    if-eqz p1, :cond_9

    iget-object p1, p0, Llyiahf/vczjk/e4a;->OooO0O0:Llyiahf/vczjk/x64;

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOOO(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object p2

    if-nez p2, :cond_9

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_9
    return-object v1
.end method
