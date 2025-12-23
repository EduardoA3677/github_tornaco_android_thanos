.class public final Llyiahf/vczjk/oy;
.super Llyiahf/vczjk/e3a;
.source "SourceFile"


# static fields
.field public static final synthetic OooOOOO:I = 0x0

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _componentType:Llyiahf/vczjk/x64;

.field protected final _emptyArray:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/i3a;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V
    .locals 9

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->hashCode()I

    move-result v5

    const/4 v3, 0x0

    const/4 v4, 0x0

    move-object v0, p0

    move-object v2, p2

    move-object v6, p4

    move-object v7, p5

    move v8, p6

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/e3a;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;ILjava/lang/Object;Ljava/lang/Object;Z)V

    iput-object p1, v0, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    iput-object p3, v0, Llyiahf/vczjk/oy;->_emptyArray:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final Oooo(Ljava/lang/StringBuilder;)Ljava/lang/StringBuilder;
    .locals 1

    const/16 v0, 0x5b

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-object v0, p0, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->Oooo(Ljava/lang/StringBuilder;)Ljava/lang/StringBuilder;

    move-result-object p1

    return-object p1
.end method

.method public final Oooo0oo()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    return-object v0
.end method

.method public final OoooO00(Ljava/lang/StringBuilder;)Ljava/lang/StringBuilder;
    .locals 1

    const/16 v0, 0x5b

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-object v0, p0, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->OoooO00(Ljava/lang/StringBuilder;)Ljava/lang/StringBuilder;

    move-result-object p1

    return-object p1
.end method

.method public final OoooOoO()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooOoO()Z

    move-result v0

    return v0
.end method

.method public final OoooOoo()Z
    .locals 1

    invoke-super {p0}, Llyiahf/vczjk/x64;->OoooOoo()Z

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooOoo()Z

    move-result v0

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

.method public final Ooooo0o()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooooOO()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooooOo()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    if-ne p1, p0, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 v0, 0x0

    if-nez p1, :cond_1

    return v0

    :cond_1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    const-class v2, Llyiahf/vczjk/oy;

    if-eq v1, v2, :cond_2

    return v0

    :cond_2
    check-cast p1, Llyiahf/vczjk/oy;

    iget-object v0, p0, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    iget-object p1, p1, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->equals(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final o00o0O(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public final o00oO0O(Llyiahf/vczjk/e94;)Llyiahf/vczjk/x64;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v0

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v1, Llyiahf/vczjk/oy;

    iget-object v0, p0, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->o0OOO0o(Ljava/lang/Object;)Llyiahf/vczjk/x64;

    move-result-object v2

    iget-object v3, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    iget-object v4, p0, Llyiahf/vczjk/oy;->_emptyArray:Ljava/lang/Object;

    iget-object v5, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    iget-object v6, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    iget-boolean v7, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/oy;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/i3a;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    return-object v1
.end method

.method public final o00oO0o(Ljava/lang/Object;)Llyiahf/vczjk/x64;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooOOO()Ljava/lang/Object;

    move-result-object v0

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v1, Llyiahf/vczjk/oy;

    iget-object v0, p0, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->o0ooOoO(Ljava/lang/Object;)Llyiahf/vczjk/x64;

    move-result-object v2

    iget-object v3, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    iget-object v4, p0, Llyiahf/vczjk/oy;->_emptyArray:Ljava/lang/Object;

    iget-object v5, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    iget-object v6, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    iget-boolean v7, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/oy;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/i3a;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    return-object v1
.end method

.method public final o0OOO0o(Ljava/lang/Object;)Llyiahf/vczjk/x64;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v1, Llyiahf/vczjk/oy;

    iget-object v2, p0, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    iget-object v3, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    iget-object v4, p0, Llyiahf/vczjk/oy;->_emptyArray:Ljava/lang/Object;

    iget-object v6, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    iget-boolean v7, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    move-object v5, p1

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/oy;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/i3a;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    return-object v1
.end method

.method public final o0ooOOo()Llyiahf/vczjk/x64;
    .locals 8

    iget-boolean v0, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    if-eqz v0, :cond_0

    return-object p0

    :cond_0
    new-instance v1, Llyiahf/vczjk/oy;

    iget-object v0, p0, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->o0ooOOo()Llyiahf/vczjk/x64;

    move-result-object v2

    iget-object v3, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    iget-object v4, p0, Llyiahf/vczjk/oy;->_emptyArray:Ljava/lang/Object;

    iget-object v5, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    iget-object v6, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    const/4 v7, 0x1

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/oy;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/i3a;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    return-object v1
.end method

.method public final o0ooOoO(Ljava/lang/Object;)Llyiahf/vczjk/x64;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v1, Llyiahf/vczjk/oy;

    iget-object v2, p0, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    iget-object v3, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    iget-object v4, p0, Llyiahf/vczjk/oy;->_emptyArray:Ljava/lang/Object;

    iget-object v5, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    iget-boolean v7, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    move-object v6, p1

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/oy;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/i3a;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    return-object v1
.end method

.method public final oo000o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;
    .locals 9

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    const/4 v1, 0x0

    invoke-static {v0, v1}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;I)Ljava/lang/Object;

    move-result-object v5

    new-instance v2, Llyiahf/vczjk/oy;

    iget-object v4, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    iget-object v6, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    iget-object v7, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    iget-boolean v8, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    move-object v3, p1

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/oy;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/i3a;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    return-object v2
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "[array type, component type: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/oy;->_componentType:Llyiahf/vczjk/x64;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "]"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
