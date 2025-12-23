.class public abstract Llyiahf/vczjk/x64;
.super Llyiahf/vczjk/ok6;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;
.implements Ljava/lang/reflect/Type;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _asStatic:Z

.field protected final _class:Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation
.end field

.field protected final _hash:I

.field protected final _typeHandler:Ljava/lang/Object;

.field protected final _valueHandler:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/Class;ILjava/lang/Object;Ljava/lang/Object;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/String;->hashCode()I

    move-result p1

    add-int/2addr p1, p2

    iput p1, p0, Llyiahf/vczjk/x64;->_hash:I

    iput-object p3, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    iput-boolean p5, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    return-void
.end method


# virtual methods
.method public bridge synthetic OooOo0O()Llyiahf/vczjk/x64;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/x64;->OoooOO0()Llyiahf/vczjk/x64;

    move-result-object v0

    return-object v0
.end method

.method public abstract Oooo(Ljava/lang/StringBuilder;)Ljava/lang/StringBuilder;
.end method

.method public abstract Oooo0O0(I)Llyiahf/vczjk/x64;
.end method

.method public abstract Oooo0OO()I
.end method

.method public abstract Oooo0o(Ljava/lang/Class;)Llyiahf/vczjk/x64;
.end method

.method public final Oooo0o0(I)Llyiahf/vczjk/x64;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/x64;->Oooo0O0(I)Llyiahf/vczjk/x64;

    move-result-object p1

    if-nez p1, :cond_0

    invoke-static {}, Llyiahf/vczjk/a4a;->OooOOOo()Llyiahf/vczjk/ep8;

    move-result-object p1

    :cond_0
    return-object p1
.end method

.method public abstract Oooo0oO()Llyiahf/vczjk/i3a;
.end method

.method public Oooo0oo()Llyiahf/vczjk/x64;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OoooO()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    return-object v0
.end method

.method public abstract OoooO0()Ljava/util/List;
.end method

.method public abstract OoooO00(Ljava/lang/StringBuilder;)Ljava/lang/StringBuilder;
.end method

.method public OoooO0O()Llyiahf/vczjk/x64;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public OoooOO0()Llyiahf/vczjk/x64;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OoooOOO()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    return-object v0
.end method

.method public final OoooOOo()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    return-object v0
.end method

.method public OoooOo0()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public OoooOoO()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/x64;->Oooo0OO()I

    move-result v0

    if-lez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public OoooOoo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    return v0

    :cond_1
    :goto_0
    const/4 v0, 0x1

    return v0
.end method

.method public final Ooooo00(Ljava/lang/Class;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    if-ne v0, p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public Ooooo0o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->getModifiers()I

    move-result v0

    invoke-static {v0}, Ljava/lang/reflect/Modifier;->isAbstract(I)Z

    move-result v0

    return v0
.end method

.method public OooooO0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public OooooOO()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->getModifiers()I

    move-result v0

    and-int/lit16 v0, v0, 0x600

    if-nez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->isPrimitive()Z

    move-result v0

    return v0
.end method

.method public abstract OooooOo()Z
.end method

.method public final Oooooo()Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    const-class v1, Ljava/lang/Enum;

    invoke-virtual {v1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    return v0
.end method

.method public final Oooooo0()Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    const-class v1, Ljava/lang/Enum;

    invoke-virtual {v1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    if-eq v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OoooooO()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->getModifiers()I

    move-result v0

    invoke-static {v0}, Ljava/lang/reflect/Modifier;->isFinal(I)Z

    move-result v0

    return v0
.end method

.method public final Ooooooo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->isInterface()Z

    move-result v0

    return v0
.end method

.method public abstract equals(Ljava/lang/Object;)Z
.end method

.method public final hashCode()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/x64;->_hash:I

    return v0
.end method

.method public abstract o000oOoO()Llyiahf/vczjk/x64;
.end method

.method public final o00O0O()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->isPrimitive()Z

    move-result v0

    return v0
.end method

.method public final o00Oo0(Ljava/lang/Class;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    if-eq v0, p1, :cond_1

    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    return p1

    :cond_1
    :goto_0
    const/4 p1, 0x1

    return p1
.end method

.method public final o00Ooo(Ljava/lang/Class;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    if-eq v0, p1, :cond_1

    invoke-virtual {v0, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    return p1

    :cond_1
    :goto_0
    const/4 p1, 0x1

    return p1
.end method

.method public abstract o00o0O(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;
.end method

.method public abstract o00oO0O(Llyiahf/vczjk/e94;)Llyiahf/vczjk/x64;
.end method

.method public abstract o00oO0o(Ljava/lang/Object;)Llyiahf/vczjk/x64;
.end method

.method public final o00ooo()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    return v0
.end method

.method public abstract o0OOO0o(Ljava/lang/Object;)Llyiahf/vczjk/x64;
.end method

.method public final o0OoOo0()Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    const-class v1, Ljava/lang/Object;

    if-ne v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public o0ooOO0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;
    .locals 2

    iget-object v0, p1, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    if-eq v0, v1, :cond_0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/x64;->o0ooOoO(Ljava/lang/Object;)Llyiahf/vczjk/x64;

    move-result-object v0

    goto :goto_0

    :cond_0
    move-object v0, p0

    :goto_0
    iget-object p1, p1, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    if-eq p1, v1, :cond_1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->o0OOO0o(Ljava/lang/Object;)Llyiahf/vczjk/x64;

    move-result-object p1

    return-object p1

    :cond_1
    return-object v0
.end method

.method public abstract o0ooOOo()Llyiahf/vczjk/x64;
.end method

.method public abstract o0ooOoO(Ljava/lang/Object;)Llyiahf/vczjk/x64;
.end method

.method public abstract oo000o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;
.end method

.method public ooOO()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public abstract toString()Ljava/lang/String;
.end method
