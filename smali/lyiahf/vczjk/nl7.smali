.class public final Llyiahf/vczjk/nl7;
.super Llyiahf/vczjk/ep8;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _anchorType:Llyiahf/vczjk/x64;

.field protected final _referencedType:Llyiahf/vczjk/x64;


# direct methods
.method public constructor <init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Ljava/lang/Object;Ljava/lang/Object;Z)V
    .locals 9

    invoke-virtual {p5}, Llyiahf/vczjk/x64;->hashCode()I

    move-result v5

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    move-object/from16 v6, p7

    move-object/from16 v7, p8

    move/from16 v8, p9

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/e3a;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;ILjava/lang/Object;Ljava/lang/Object;Z)V

    iput-object p5, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    if-nez p6, :cond_0

    move-object p6, p0

    :cond_0
    iput-object p6, p0, Llyiahf/vczjk/nl7;->_anchorType:Llyiahf/vczjk/x64;

    return-void
.end method


# virtual methods
.method public final OooOo0O()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    return-object v0
.end method

.method public final OooOoO0()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final Oooo(Ljava/lang/StringBuilder;)Ljava/lang/StringBuilder;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    const/4 v1, 0x1

    invoke-static {v0, p1, v1}, Llyiahf/vczjk/e3a;->o0Oo0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Z)V

    return-object p1
.end method

.method public final Oooo0oo()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    return-object v0
.end method

.method public final OoooO00(Ljava/lang/StringBuilder;)Ljava/lang/StringBuilder;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    const/4 v1, 0x0

    invoke-static {v0, p1, v1}, Llyiahf/vczjk/e3a;->o0Oo0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Z)V

    const/16 v0, 0x3c

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-object v0, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->OoooO00(Ljava/lang/StringBuilder;)Ljava/lang/StringBuilder;

    move-result-object p1

    const-string v0, ">;"

    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    return-object p1
.end method

.method public final OoooOO0()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    return-object v0
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

    const-class v2, Llyiahf/vczjk/nl7;

    if-eq v1, v2, :cond_2

    return v0

    :cond_2
    check-cast p1, Llyiahf/vczjk/nl7;

    iget-object v1, p1, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    iget-object v2, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    if-eq v1, v2, :cond_3

    return v0

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    iget-object p1, p1, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->equals(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final o00000()Llyiahf/vczjk/nl7;
    .locals 11

    iget-boolean v0, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    if-eqz v0, :cond_0

    return-object p0

    :cond_0
    new-instance v1, Llyiahf/vczjk/nl7;

    iget-object v2, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    iget-object v3, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    iget-object v4, p0, Llyiahf/vczjk/e3a;->_superClass:Llyiahf/vczjk/x64;

    iget-object v5, p0, Llyiahf/vczjk/e3a;->_superInterfaces:[Llyiahf/vczjk/x64;

    iget-object v0, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->o0ooOOo()Llyiahf/vczjk/x64;

    move-result-object v6

    iget-object v7, p0, Llyiahf/vczjk/nl7;->_anchorType:Llyiahf/vczjk/x64;

    iget-object v8, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    iget-object v9, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    const/4 v10, 0x1

    invoke-direct/range {v1 .. v10}, Llyiahf/vczjk/nl7;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Ljava/lang/Object;Ljava/lang/Object;Z)V

    return-object v1
.end method

.method public final o000000(Ljava/lang/Object;)Llyiahf/vczjk/ep8;
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v1, Llyiahf/vczjk/nl7;

    iget-object v2, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    iget-object v3, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    iget-object v4, p0, Llyiahf/vczjk/e3a;->_superClass:Llyiahf/vczjk/x64;

    iget-object v5, p0, Llyiahf/vczjk/e3a;->_superInterfaces:[Llyiahf/vczjk/x64;

    iget-object v6, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    iget-object v7, p0, Llyiahf/vczjk/nl7;->_anchorType:Llyiahf/vczjk/x64;

    iget-object v8, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    iget-boolean v10, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    move-object v9, p1

    invoke-direct/range {v1 .. v10}, Llyiahf/vczjk/nl7;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Ljava/lang/Object;Ljava/lang/Object;Z)V

    return-object v1
.end method

.method public final o000000O(Ljava/lang/Object;)Llyiahf/vczjk/ep8;
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v1, Llyiahf/vczjk/nl7;

    iget-object v2, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    iget-object v3, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    iget-object v4, p0, Llyiahf/vczjk/e3a;->_superClass:Llyiahf/vczjk/x64;

    iget-object v5, p0, Llyiahf/vczjk/e3a;->_superInterfaces:[Llyiahf/vczjk/x64;

    iget-object v6, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    iget-object v7, p0, Llyiahf/vczjk/nl7;->_anchorType:Llyiahf/vczjk/x64;

    iget-object v9, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    iget-boolean v10, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    move-object v8, p1

    invoke-direct/range {v1 .. v10}, Llyiahf/vczjk/nl7;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Ljava/lang/Object;Ljava/lang/Object;Z)V

    return-object v1
.end method

.method public final o000000o(Llyiahf/vczjk/e94;)Llyiahf/vczjk/nl7;
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v0

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->o0OOO0o(Ljava/lang/Object;)Llyiahf/vczjk/x64;

    move-result-object v6

    new-instance v1, Llyiahf/vczjk/nl7;

    iget-object v2, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    iget-object v3, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    iget-object v4, p0, Llyiahf/vczjk/e3a;->_superClass:Llyiahf/vczjk/x64;

    iget-object v5, p0, Llyiahf/vczjk/e3a;->_superInterfaces:[Llyiahf/vczjk/x64;

    iget-object v7, p0, Llyiahf/vczjk/nl7;->_anchorType:Llyiahf/vczjk/x64;

    iget-object v8, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    iget-object v9, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    iget-boolean v10, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    invoke-direct/range {v1 .. v10}, Llyiahf/vczjk/nl7;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Ljava/lang/Object;Ljava/lang/Object;Z)V

    return-object v1
.end method

.method public final bridge synthetic o000OOo()Llyiahf/vczjk/ep8;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/nl7;->o00000()Llyiahf/vczjk/nl7;

    move-result-object v0

    return-object v0
.end method

.method public final o00o0O(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;
    .locals 10

    new-instance v0, Llyiahf/vczjk/nl7;

    iget-object v2, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    iget-object v5, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    iget-object v6, p0, Llyiahf/vczjk/nl7;->_anchorType:Llyiahf/vczjk/x64;

    iget-object v7, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    iget-object v8, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    iget-boolean v9, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    move-object v1, p1

    move-object v3, p3

    move-object v4, p4

    invoke-direct/range {v0 .. v9}, Llyiahf/vczjk/nl7;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Ljava/lang/Object;Ljava/lang/Object;Z)V

    return-object v0
.end method

.method public final bridge synthetic o00oO0O(Llyiahf/vczjk/e94;)Llyiahf/vczjk/x64;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/nl7;->o000000o(Llyiahf/vczjk/e94;)Llyiahf/vczjk/nl7;

    move-result-object p1

    return-object p1
.end method

.method public final o00oO0o(Ljava/lang/Object;)Llyiahf/vczjk/x64;
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooOOO()Ljava/lang/Object;

    move-result-object v0

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v1, Llyiahf/vczjk/nl7;

    iget-object v2, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    iget-object v3, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    iget-object v4, p0, Llyiahf/vczjk/e3a;->_superClass:Llyiahf/vczjk/x64;

    iget-object v5, p0, Llyiahf/vczjk/e3a;->_superInterfaces:[Llyiahf/vczjk/x64;

    iget-object v0, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x64;->o0ooOoO(Ljava/lang/Object;)Llyiahf/vczjk/x64;

    move-result-object v6

    iget-object v7, p0, Llyiahf/vczjk/nl7;->_anchorType:Llyiahf/vczjk/x64;

    iget-object v8, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    iget-object v9, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    iget-boolean v10, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    invoke-direct/range {v1 .. v10}, Llyiahf/vczjk/nl7;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Ljava/lang/Object;Ljava/lang/Object;Z)V

    return-object v1
.end method

.method public final bridge synthetic o0O0O00(Llyiahf/vczjk/e94;)Llyiahf/vczjk/ep8;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/nl7;->o000000o(Llyiahf/vczjk/e94;)Llyiahf/vczjk/nl7;

    move-result-object p1

    return-object p1
.end method

.method public final o0OO00O()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x3c

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    invoke-virtual {v1}, Llyiahf/vczjk/ok6;->Oooo00O()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x3e

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final o0OOO0o(Ljava/lang/Object;)Llyiahf/vczjk/x64;
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v1, Llyiahf/vczjk/nl7;

    iget-object v2, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    iget-object v3, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    iget-object v4, p0, Llyiahf/vczjk/e3a;->_superClass:Llyiahf/vczjk/x64;

    iget-object v5, p0, Llyiahf/vczjk/e3a;->_superInterfaces:[Llyiahf/vczjk/x64;

    iget-object v6, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    iget-object v7, p0, Llyiahf/vczjk/nl7;->_anchorType:Llyiahf/vczjk/x64;

    iget-object v9, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    iget-boolean v10, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    move-object v8, p1

    invoke-direct/range {v1 .. v10}, Llyiahf/vczjk/nl7;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Ljava/lang/Object;Ljava/lang/Object;Z)V

    return-object v1
.end method

.method public final bridge synthetic o0ooOOo()Llyiahf/vczjk/x64;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/nl7;->o00000()Llyiahf/vczjk/nl7;

    move-result-object v0

    return-object v0
.end method

.method public final o0ooOoO(Ljava/lang/Object;)Llyiahf/vczjk/x64;
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v1, Llyiahf/vczjk/nl7;

    iget-object v2, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    iget-object v3, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    iget-object v4, p0, Llyiahf/vczjk/e3a;->_superClass:Llyiahf/vczjk/x64;

    iget-object v5, p0, Llyiahf/vczjk/e3a;->_superInterfaces:[Llyiahf/vczjk/x64;

    iget-object v6, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    iget-object v7, p0, Llyiahf/vczjk/nl7;->_anchorType:Llyiahf/vczjk/x64;

    iget-object v8, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    iget-boolean v10, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    move-object v9, p1

    invoke-direct/range {v1 .. v10}, Llyiahf/vczjk/nl7;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Ljava/lang/Object;Ljava/lang/Object;Z)V

    return-object v1
.end method

.method public final oo000o(Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    if-ne v0, p1, :cond_0

    return-object p0

    :cond_0
    new-instance v1, Llyiahf/vczjk/nl7;

    iget-object v2, p0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    iget-object v3, p0, Llyiahf/vczjk/e3a;->_bindings:Llyiahf/vczjk/i3a;

    iget-object v4, p0, Llyiahf/vczjk/e3a;->_superClass:Llyiahf/vczjk/x64;

    iget-object v5, p0, Llyiahf/vczjk/e3a;->_superInterfaces:[Llyiahf/vczjk/x64;

    iget-object v7, p0, Llyiahf/vczjk/nl7;->_anchorType:Llyiahf/vczjk/x64;

    iget-object v8, p0, Llyiahf/vczjk/x64;->_valueHandler:Ljava/lang/Object;

    iget-object v9, p0, Llyiahf/vczjk/x64;->_typeHandler:Ljava/lang/Object;

    iget-boolean v10, p0, Llyiahf/vczjk/x64;->_asStatic:Z

    move-object v6, p1

    invoke-direct/range {v1 .. v10}, Llyiahf/vczjk/nl7;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Ljava/lang/Object;Ljava/lang/Object;Z)V

    return-object v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    const/16 v0, 0x28

    const-string v1, "[reference type, class "

    invoke-static {v0, v1}, Llyiahf/vczjk/ix8;->OooOOO0(ILjava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/nl7;->o0OO00O()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x3c

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/nl7;->_referencedType:Llyiahf/vczjk/x64;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ">]"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
