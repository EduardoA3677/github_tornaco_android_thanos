.class public final Llyiahf/vczjk/mm;
.super Llyiahf/vczjk/pm;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field public final transient OooOo0o:Ljava/lang/reflect/Field;

.field protected _serialization:Llyiahf/vczjk/lm;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/a5a;Ljava/lang/reflect/Field;Llyiahf/vczjk/ao;)V
    .locals 0

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/pm;-><init>(Llyiahf/vczjk/a5a;Llyiahf/vczjk/ao;)V

    iput-object p2, p0, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/lm;)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, v0, v0}, Llyiahf/vczjk/pm;-><init>(Llyiahf/vczjk/a5a;Llyiahf/vczjk/ao;)V

    iput-object v0, p0, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    iput-object p1, p0, Llyiahf/vczjk/mm;->_serialization:Llyiahf/vczjk/lm;

    return-void
.end method


# virtual methods
.method public final OooOo0()Ljava/lang/reflect/AnnotatedElement;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    return-object v0
.end method

.method public final OooOoOO()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    invoke-virtual {v0}, Ljava/lang/reflect/Field;->getType()Ljava/lang/Class;

    move-result-object v0

    return-object v0
.end method

.method public final OooOoo()Llyiahf/vczjk/x64;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    invoke-virtual {v0}, Ljava/lang/reflect/Field;->getGenericType()Ljava/lang/reflect/Type;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/pm;->OooOo0:Llyiahf/vczjk/a5a;

    invoke-interface {v1, v0}, Llyiahf/vczjk/a5a;->OooO(Ljava/lang/reflect/Type;)Llyiahf/vczjk/x64;

    move-result-object v0

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    const/4 v0, 0x1

    if-ne p1, p0, :cond_0

    return v0

    :cond_0
    const-class v1, Llyiahf/vczjk/mm;

    invoke-static {v1, p1}, Llyiahf/vczjk/vy0;->OooOOo0(Ljava/lang/Class;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    check-cast p1, Llyiahf/vczjk/mm;

    iget-object p1, p1, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    iget-object v1, p0, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    if-ne p1, v1, :cond_1

    return v0

    :cond_1
    const/4 p1, 0x0

    return p1
.end method

.method public final getName()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    invoke-virtual {v0}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    invoke-virtual {v0}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    move-result v0

    return v0
.end method

.method public final o00oO0o()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    invoke-virtual {v0}, Ljava/lang/reflect/Field;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v0

    return-object v0
.end method

.method public final o0Oo0oo(Llyiahf/vczjk/ao;)Llyiahf/vczjk/u34;
    .locals 3

    new-instance v0, Llyiahf/vczjk/mm;

    iget-object v1, p0, Llyiahf/vczjk/pm;->OooOo0:Llyiahf/vczjk/a5a;

    iget-object v2, p0, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    invoke-direct {v0, v1, v2, p1}, Llyiahf/vczjk/mm;-><init>(Llyiahf/vczjk/a5a;Ljava/lang/reflect/Field;Llyiahf/vczjk/ao;)V

    return-object v0
.end method

.method public final o0ooOO0()Ljava/lang/reflect/Member;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    return-object v0
.end method

.method public final o0ooOOo(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    invoke-virtual {v0, p1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p1

    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Failed to getValue() for field "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/pm;->o00oO0O()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, ": "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0
.end method

.method public readResolve()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/mm;->_serialization:Llyiahf/vczjk/lm;

    iget-object v1, v0, Llyiahf/vczjk/lm;->clazz:Ljava/lang/Class;

    :try_start_0
    iget-object v0, v0, Llyiahf/vczjk/lm;->name:Ljava/lang/String;

    invoke-virtual {v1, v0}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/reflect/AccessibleObject;->isAccessible()Z

    move-result v2

    if-nez v2, :cond_0

    const/4 v2, 0x0

    invoke-static {v0, v2}, Llyiahf/vczjk/vy0;->OooO0Oo(Ljava/lang/reflect/Member;Z)V

    :cond_0
    new-instance v2, Llyiahf/vczjk/mm;

    const/4 v3, 0x0

    invoke-direct {v2, v3, v0, v3}, Llyiahf/vczjk/mm;-><init>(Llyiahf/vczjk/a5a;Ljava/lang/reflect/Field;Llyiahf/vczjk/ao;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object v2

    :catch_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Could not find method \'"

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v3, p0, Llyiahf/vczjk/mm;->_serialization:Llyiahf/vczjk/lm;

    iget-object v3, v3, Llyiahf/vczjk/lm;->name:Ljava/lang/String;

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, "\' from Class \'"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "[field "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/pm;->o00oO0O()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, "]"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public writeReplace()Ljava/lang/Object;
    .locals 4

    new-instance v0, Llyiahf/vczjk/mm;

    new-instance v1, Llyiahf/vczjk/lm;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    iget-object v2, p0, Llyiahf/vczjk/mm;->OooOo0o:Ljava/lang/reflect/Field;

    invoke-virtual {v2}, Ljava/lang/reflect/Field;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v3

    iput-object v3, v1, Llyiahf/vczjk/lm;->clazz:Ljava/lang/Class;

    invoke-virtual {v2}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/lm;->name:Ljava/lang/String;

    invoke-direct {v0, v1}, Llyiahf/vczjk/mm;-><init>(Llyiahf/vczjk/lm;)V

    return-object v0
.end method
