.class public final Llyiahf/vczjk/vm;
.super Llyiahf/vczjk/pm;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _index:I

.field protected final _owner:Llyiahf/vczjk/gn;

.field protected final _type:Llyiahf/vczjk/x64;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gn;Llyiahf/vczjk/x64;Llyiahf/vczjk/a5a;Llyiahf/vczjk/ao;I)V
    .locals 0

    invoke-direct {p0, p3, p4}, Llyiahf/vczjk/pm;-><init>(Llyiahf/vczjk/a5a;Llyiahf/vczjk/ao;)V

    iput-object p1, p0, Llyiahf/vczjk/vm;->_owner:Llyiahf/vczjk/gn;

    iput-object p2, p0, Llyiahf/vczjk/vm;->_type:Llyiahf/vczjk/x64;

    iput p5, p0, Llyiahf/vczjk/vm;->_index:I

    return-void
.end method


# virtual methods
.method public final OooOo0()Ljava/lang/reflect/AnnotatedElement;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooOoOO()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vm;->_type:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    return-object v0
.end method

.method public final OooOoo()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vm;->_type:Llyiahf/vczjk/x64;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    const/4 v0, 0x1

    if-ne p1, p0, :cond_0

    return v0

    :cond_0
    const-class v1, Llyiahf/vczjk/vm;

    invoke-static {v1, p1}, Llyiahf/vczjk/vy0;->OooOOo0(Ljava/lang/Class;Ljava/lang/Object;)Z

    move-result v1

    const/4 v2, 0x0

    if-nez v1, :cond_1

    return v2

    :cond_1
    check-cast p1, Llyiahf/vczjk/vm;

    iget-object v1, p1, Llyiahf/vczjk/vm;->_owner:Llyiahf/vczjk/gn;

    iget-object v3, p0, Llyiahf/vczjk/vm;->_owner:Llyiahf/vczjk/gn;

    invoke-virtual {v1, v3}, Llyiahf/vczjk/u34;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    iget p1, p1, Llyiahf/vczjk/vm;->_index:I

    iget v1, p0, Llyiahf/vczjk/vm;->_index:I

    if-ne p1, v1, :cond_2

    return v0

    :cond_2
    return v2
.end method

.method public final getName()Ljava/lang/String;
    .locals 1

    const-string v0, ""

    return-object v0
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/vm;->_owner:Llyiahf/vczjk/gn;

    invoke-virtual {v0}, Llyiahf/vczjk/u34;->hashCode()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/vm;->_index:I

    add-int/2addr v0, v1

    return v0
.end method

.method public final o00oO0o()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vm;->_owner:Llyiahf/vczjk/gn;

    invoke-virtual {v0}, Llyiahf/vczjk/pm;->o00oO0o()Ljava/lang/Class;

    move-result-object v0

    return-object v0
.end method

.method public final o0OO00O()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/vm;->_index:I

    return v0
.end method

.method public final o0Oo0oo(Llyiahf/vczjk/ao;)Llyiahf/vczjk/u34;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/pm;->OooOo0O:Llyiahf/vczjk/ao;

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/vm;->_owner:Llyiahf/vczjk/gn;

    iget v1, p0, Llyiahf/vczjk/vm;->_index:I

    iget-object v2, v0, Llyiahf/vczjk/gn;->_paramAnnotations:[Llyiahf/vczjk/ao;

    aput-object p1, v2, v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/gn;->o000OOo(I)Llyiahf/vczjk/vm;

    move-result-object p1

    return-object p1
.end method

.method public final o0ooOO0()Ljava/lang/reflect/Member;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vm;->_owner:Llyiahf/vczjk/gn;

    invoke-virtual {v0}, Llyiahf/vczjk/pm;->o0ooOO0()Ljava/lang/reflect/Member;

    move-result-object v0

    return-object v0
.end method

.method public final o0ooOOo(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    iget-object v0, p0, Llyiahf/vczjk/vm;->_owner:Llyiahf/vczjk/gn;

    invoke-virtual {v0}, Llyiahf/vczjk/pm;->o00oO0o()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    const-string v1, "Cannot call getValue() on constructor parameter of "

    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final oo0o0Oo()Llyiahf/vczjk/gn;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vm;->_owner:Llyiahf/vczjk/gn;

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "[parameter #"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget v1, p0, Llyiahf/vczjk/vm;->_index:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ", annotations: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/pm;->OooOo0O:Llyiahf/vczjk/ao;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "]"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
