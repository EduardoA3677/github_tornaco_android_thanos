.class public final Llyiahf/vczjk/nr4;
.super Llyiahf/vczjk/cy0;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f64;


# instance fields
.field public final OooOOoo:Llyiahf/vczjk/ld9;

.field public final OooOo:Llyiahf/vczjk/ly0;

.field public final OooOo0:Llyiahf/vczjk/by0;

.field public final OooOo00:Llyiahf/vczjk/cm7;

.field public final OooOo0O:Llyiahf/vczjk/ld9;

.field public final OooOo0o:Llyiahf/vczjk/sc9;

.field public final OooOoO:Llyiahf/vczjk/oO0Oo0oo;

.field public final OooOoO0:Llyiahf/vczjk/yk5;

.field public final OooOoOO:Z

.field public final OooOoo:Llyiahf/vczjk/rr4;

.field public final OooOoo0:Llyiahf/vczjk/f82;

.field public final OooOooO:Llyiahf/vczjk/z88;

.field public final OooOooo:Llyiahf/vczjk/zz3;

.field public final Oooo000:Llyiahf/vczjk/fs4;

.field public final Oooo00O:Llyiahf/vczjk/lr4;

.field public final Oooo00o:Llyiahf/vczjk/o45;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    const-string v5, "notifyAll"

    const-string v6, "toString"

    const-string v0, "equals"

    const-string v1, "hashCode"

    const-string v2, "getClass"

    const-string v3, "wait"

    const-string v4, "notify"

    filled-new-array/range {v0 .. v6}, [Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/sy;->o0000O0O([Ljava/lang/Object;)Ljava/util/Set;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/v02;Llyiahf/vczjk/cm7;Llyiahf/vczjk/by0;)V
    .locals 7

    const-string v0, "outerContext"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "containingDeclaration"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "jClass"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v1, v0, Llyiahf/vczjk/s64;->OooO00o:Llyiahf/vczjk/q45;

    invoke-virtual {p3}, Llyiahf/vczjk/cm7;->OooO0o0()Llyiahf/vczjk/qt5;

    move-result-object v2

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooOO0:Llyiahf/vczjk/rp3;

    invoke-virtual {v0, p3}, Llyiahf/vczjk/rp3;->OooOo0O(Llyiahf/vczjk/k64;)Llyiahf/vczjk/hz7;

    move-result-object v0

    invoke-direct {p0, v1, p2, v2, v0}, Llyiahf/vczjk/cy0;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/v02;Llyiahf/vczjk/qt5;Llyiahf/vczjk/sx8;)V

    iput-object p1, p0, Llyiahf/vczjk/nr4;->OooOOoo:Llyiahf/vczjk/ld9;

    iput-object p3, p0, Llyiahf/vczjk/nr4;->OooOo00:Llyiahf/vczjk/cm7;

    iput-object p4, p0, Llyiahf/vczjk/nr4;->OooOo0:Llyiahf/vczjk/by0;

    const/4 p2, 0x4

    invoke-static {p1, p0, p3, p2}, Llyiahf/vczjk/l4a;->OooOOO0(Llyiahf/vczjk/ld9;Llyiahf/vczjk/py0;Llyiahf/vczjk/cm7;I)Llyiahf/vczjk/ld9;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/nr4;->OooOo0O:Llyiahf/vczjk/ld9;

    iget-object p1, v1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s64;

    iget-object p2, p1, Llyiahf/vczjk/s64;->OooO0oO:Llyiahf/vczjk/vp3;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p2, Llyiahf/vczjk/mr4;

    const/4 v0, 0x0

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/mr4;-><init>(Llyiahf/vczjk/nr4;I)V

    invoke-static {p2}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/nr4;->OooOo0o:Llyiahf/vczjk/sc9;

    iget-object p2, p3, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {p2}, Ljava/lang/Class;->isAnnotation()Z

    move-result v0

    if-eqz v0, :cond_0

    sget-object v0, Llyiahf/vczjk/ly0;->OooOOo0:Llyiahf/vczjk/ly0;

    goto :goto_0

    :cond_0
    invoke-virtual {p2}, Ljava/lang/Class;->isInterface()Z

    move-result v0

    if-eqz v0, :cond_1

    sget-object v0, Llyiahf/vczjk/ly0;->OooOOO:Llyiahf/vczjk/ly0;

    goto :goto_0

    :cond_1
    invoke-virtual {p2}, Ljava/lang/Class;->isEnum()Z

    move-result v0

    if-eqz v0, :cond_2

    sget-object v0, Llyiahf/vczjk/ly0;->OooOOOO:Llyiahf/vczjk/ly0;

    goto :goto_0

    :cond_2
    sget-object v0, Llyiahf/vczjk/ly0;->OooOOO0:Llyiahf/vczjk/ly0;

    :goto_0
    iput-object v0, p0, Llyiahf/vczjk/nr4;->OooOo:Llyiahf/vczjk/ly0;

    invoke-virtual {p2}, Ljava/lang/Class;->isAnnotation()Z

    move-result v0

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-nez v0, :cond_9

    invoke-virtual {p2}, Ljava/lang/Class;->isEnum()Z

    move-result v0

    if-eqz v0, :cond_3

    goto :goto_3

    :cond_3
    sget-object v0, Llyiahf/vczjk/yk5;->OooOOO0:Llyiahf/vczjk/wp3;

    invoke-virtual {p3}, Llyiahf/vczjk/cm7;->OooO0oo()Z

    move-result v4

    invoke-virtual {p3}, Llyiahf/vczjk/cm7;->OooO0oo()Z

    move-result v5

    if-nez v5, :cond_5

    invoke-virtual {p2}, Ljava/lang/Class;->getModifiers()I

    move-result v5

    invoke-static {v5}, Ljava/lang/reflect/Modifier;->isAbstract(I)Z

    move-result v5

    if-nez v5, :cond_5

    invoke-virtual {p2}, Ljava/lang/Class;->isInterface()Z

    move-result v5

    if-eqz v5, :cond_4

    goto :goto_1

    :cond_4
    move v5, v2

    goto :goto_2

    :cond_5
    :goto_1
    move v5, v3

    :goto_2
    invoke-virtual {p2}, Ljava/lang/Class;->getModifiers()I

    move-result v6

    invoke-static {v6}, Ljava/lang/reflect/Modifier;->isFinal(I)Z

    move-result v6

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-eqz v4, :cond_6

    sget-object v0, Llyiahf/vczjk/yk5;->OooOOOO:Llyiahf/vczjk/yk5;

    goto :goto_4

    :cond_6
    if-eqz v5, :cond_7

    sget-object v0, Llyiahf/vczjk/yk5;->OooOOo0:Llyiahf/vczjk/yk5;

    goto :goto_4

    :cond_7
    if-nez v6, :cond_8

    sget-object v0, Llyiahf/vczjk/yk5;->OooOOOo:Llyiahf/vczjk/yk5;

    goto :goto_4

    :cond_8
    sget-object v0, Llyiahf/vczjk/yk5;->OooOOO:Llyiahf/vczjk/yk5;

    goto :goto_4

    :cond_9
    :goto_3
    sget-object v0, Llyiahf/vczjk/yk5;->OooOOO:Llyiahf/vczjk/yk5;

    :goto_4
    iput-object v0, p0, Llyiahf/vczjk/nr4;->OooOoO0:Llyiahf/vczjk/yk5;

    invoke-virtual {p2}, Ljava/lang/Class;->getModifiers()I

    move-result v0

    invoke-static {v0}, Ljava/lang/reflect/Modifier;->isPublic(I)Z

    move-result v4

    if-eqz v4, :cond_a

    sget-object v0, Llyiahf/vczjk/zja;->OooOOOo:Llyiahf/vczjk/zja;

    goto :goto_5

    :cond_a
    invoke-static {v0}, Ljava/lang/reflect/Modifier;->isPrivate(I)Z

    move-result v4

    if-eqz v4, :cond_b

    sget-object v0, Llyiahf/vczjk/wja;->OooOOOo:Llyiahf/vczjk/wja;

    goto :goto_5

    :cond_b
    invoke-static {v0}, Ljava/lang/reflect/Modifier;->isProtected(I)Z

    move-result v4

    if-eqz v4, :cond_d

    invoke-static {v0}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result v0

    if-eqz v0, :cond_c

    sget-object v0, Llyiahf/vczjk/p74;->OooOOOo:Llyiahf/vczjk/p74;

    goto :goto_5

    :cond_c
    sget-object v0, Llyiahf/vczjk/o74;->OooOOOo:Llyiahf/vczjk/o74;

    goto :goto_5

    :cond_d
    sget-object v0, Llyiahf/vczjk/n74;->OooOOOo:Llyiahf/vczjk/n74;

    :goto_5
    iput-object v0, p0, Llyiahf/vczjk/nr4;->OooOoO:Llyiahf/vczjk/oO0Oo0oo;

    invoke-virtual {p2}, Ljava/lang/Class;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v0

    if-eqz v0, :cond_e

    new-instance v4, Llyiahf/vczjk/cm7;

    invoke-direct {v4, v0}, Llyiahf/vczjk/cm7;-><init>(Ljava/lang/Class;)V

    goto :goto_6

    :cond_e
    const/4 v4, 0x0

    :goto_6
    if-eqz v4, :cond_f

    invoke-virtual {p2}, Ljava/lang/Class;->getModifiers()I

    move-result p2

    invoke-static {p2}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result p2

    if-nez p2, :cond_f

    move p2, v3

    goto :goto_7

    :cond_f
    move p2, v2

    :goto_7
    iput-boolean p2, p0, Llyiahf/vczjk/nr4;->OooOoOO:Z

    new-instance p2, Llyiahf/vczjk/f82;

    invoke-direct {p2, p0}, Llyiahf/vczjk/f82;-><init>(Llyiahf/vczjk/nr4;)V

    iput-object p2, p0, Llyiahf/vczjk/nr4;->OooOoo0:Llyiahf/vczjk/f82;

    new-instance v0, Llyiahf/vczjk/rr4;

    if-eqz p4, :cond_10

    move v4, v3

    goto :goto_8

    :cond_10
    move v4, v2

    :goto_8
    const/4 v5, 0x0

    move-object v2, p0

    move-object v3, p3

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/rr4;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/by0;Llyiahf/vczjk/cm7;ZLlyiahf/vczjk/rr4;)V

    iput-object v0, v2, Llyiahf/vczjk/nr4;->OooOoo:Llyiahf/vczjk/rr4;

    sget-object p2, Llyiahf/vczjk/z88;->OooO0Oo:Llyiahf/vczjk/pp3;

    iget-object p3, p1, Llyiahf/vczjk/s64;->OooO00o:Llyiahf/vczjk/q45;

    iget-object p1, p1, Llyiahf/vczjk/s64;->OooOo0:Llyiahf/vczjk/v06;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Llyiahf/vczjk/oo000o;

    const/16 p4, 0xf

    invoke-direct {p1, p0, p4}, Llyiahf/vczjk/oo000o;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string p2, "storageManager"

    invoke-static {p3, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p2, Llyiahf/vczjk/z88;

    invoke-direct {p2, p0, p3, p1}, Llyiahf/vczjk/z88;-><init>(Llyiahf/vczjk/oo0o0Oo;Llyiahf/vczjk/q45;Llyiahf/vczjk/oe3;)V

    iput-object p2, v2, Llyiahf/vczjk/nr4;->OooOooO:Llyiahf/vczjk/z88;

    new-instance p1, Llyiahf/vczjk/zz3;

    invoke-direct {p1, v0}, Llyiahf/vczjk/zz3;-><init>(Llyiahf/vczjk/jg5;)V

    iput-object p1, v2, Llyiahf/vczjk/nr4;->OooOooo:Llyiahf/vczjk/zz3;

    new-instance p1, Llyiahf/vczjk/fs4;

    invoke-direct {p1, v1, v3, p0}, Llyiahf/vczjk/fs4;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/cm7;Llyiahf/vczjk/nr4;)V

    iput-object p1, v2, Llyiahf/vczjk/nr4;->Oooo000:Llyiahf/vczjk/fs4;

    invoke-static {v1, v3}, Llyiahf/vczjk/dn8;->o00oO0o(Llyiahf/vczjk/ld9;Llyiahf/vczjk/b64;)Llyiahf/vczjk/lr4;

    move-result-object p1

    iput-object p1, v2, Llyiahf/vczjk/nr4;->Oooo00O:Llyiahf/vczjk/lr4;

    new-instance p1, Llyiahf/vczjk/mr4;

    const/4 p2, 0x1

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/mr4;-><init>(Llyiahf/vczjk/nr4;I)V

    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p2, Llyiahf/vczjk/o45;

    invoke-direct {p2, p3, p1}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p2, v2, Llyiahf/vczjk/nr4;->Oooo00o:Llyiahf/vczjk/o45;

    return-void
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/yk5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nr4;->OooOoO0:Llyiahf/vczjk/yk5;

    return-object v0
.end method

.method public final OooO0Oo()Llyiahf/vczjk/q72;
    .locals 3

    sget-object v0, Llyiahf/vczjk/r72;->OooO00o:Llyiahf/vczjk/q72;

    iget-object v1, p0, Llyiahf/vczjk/nr4;->OooOoO:Llyiahf/vczjk/oO0Oo0oo;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/nr4;->OooOo00:Llyiahf/vczjk/cm7;

    iget-object v0, v0, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v0

    if-eqz v0, :cond_0

    new-instance v2, Llyiahf/vczjk/cm7;

    invoke-direct {v2, v0}, Llyiahf/vczjk/cm7;-><init>(Ljava/lang/Class;)V

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    :goto_0
    if-nez v2, :cond_1

    sget-object v0, Llyiahf/vczjk/j64;->OooO00o:Llyiahf/vczjk/q72;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-object v0

    :cond_1
    invoke-static {v1}, Llyiahf/vczjk/ht6;->OooOoOO(Llyiahf/vczjk/oO0Oo0oo;)Llyiahf/vczjk/q72;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0o()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOO0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOOo0()Llyiahf/vczjk/ko;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nr4;->Oooo00O:Llyiahf/vczjk/lr4;

    return-object v0
.end method

.method public final OooOo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOo00()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nr4;->Oooo00o:Llyiahf/vczjk/o45;

    invoke-virtual {v0}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/List;

    return-object v0
.end method

.method public final OooOo0o()Llyiahf/vczjk/n3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nr4;->OooOoo0:Llyiahf/vczjk/f82;

    return-object v0
.end method

.method public final OooOoO()Ljava/util/Collection;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nr4;->OooOoo:Llyiahf/vczjk/rr4;

    iget-object v0, v0, Llyiahf/vczjk/rr4;->OooOOo0:Llyiahf/vczjk/o45;

    invoke-virtual {v0}, Llyiahf/vczjk/o45;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/List;

    return-object v0
.end method

.method public final OooOoo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo00o()Ljava/util/Collection;
    .locals 11

    sget-object v0, Llyiahf/vczjk/yk5;->OooOOOO:Llyiahf/vczjk/yk5;

    iget-object v1, p0, Llyiahf/vczjk/nr4;->OooOoO0:Llyiahf/vczjk/yk5;

    if-ne v1, v0, :cond_7

    sget-object v0, Llyiahf/vczjk/j5a;->OooOOO:Llyiahf/vczjk/j5a;

    const/4 v1, 0x7

    const/4 v2, 0x0

    const/4 v4, 0x0

    invoke-static {v0, v2, v4, v1}, Llyiahf/vczjk/nqa;->OoooO00(Llyiahf/vczjk/j5a;ZLlyiahf/vczjk/hs4;I)Llyiahf/vczjk/a74;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/nr4;->OooOo00:Llyiahf/vczjk/cm7;

    iget-object v1, v1, Llyiahf/vczjk/cm7;->OooO00o:Ljava/lang/Class;

    const-string v3, "clazz"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/l4a;->OooOO0O:Llyiahf/vczjk/ld9;

    if-nez v3, :cond_0

    const-class v3, Ljava/lang/Class;

    :try_start_0
    new-instance v5, Llyiahf/vczjk/ld9;

    const-string v6, "isSealed"

    invoke-virtual {v3, v6, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v6

    const-string v7, "getPermittedSubclasses"

    invoke-virtual {v3, v7, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v7

    const-string v8, "isRecord"

    invoke-virtual {v3, v8, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v8

    const-string v9, "getRecordComponents"

    invoke-virtual {v3, v9, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v9

    const/16 v10, 0x13

    invoke-direct/range {v5 .. v10}, Llyiahf/vczjk/ld9;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0

    move-object v3, v5

    goto :goto_0

    :catch_0
    new-instance v3, Llyiahf/vczjk/ld9;

    const/16 v8, 0x13

    move-object v5, v4

    move-object v6, v4

    move-object v7, v4

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/ld9;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    :goto_0
    sput-object v3, Llyiahf/vczjk/l4a;->OooOO0O:Llyiahf/vczjk/ld9;

    :cond_0
    iget-object v3, v3, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Ljava/lang/reflect/Method;

    if-nez v3, :cond_1

    move-object v1, v4

    goto :goto_1

    :cond_1
    invoke-virtual {v3, v1, v4}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    const-string v3, "null cannot be cast to non-null type kotlin.Array<java.lang.Class<*>>"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, [Ljava/lang/Class;

    :goto_1
    if-eqz v1, :cond_3

    new-instance v3, Ljava/util/ArrayList;

    array-length v5, v1

    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    array-length v5, v1

    :goto_2
    if-ge v2, v5, :cond_2

    aget-object v6, v1, v2

    new-instance v7, Llyiahf/vczjk/em7;

    invoke-direct {v7, v6}, Llyiahf/vczjk/em7;-><init>(Ljava/lang/reflect/Type;)V

    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v2, v2, 0x1

    goto :goto_2

    :cond_2
    invoke-static {v3}, Llyiahf/vczjk/d21;->Oooooo(Ljava/lang/Iterable;)Llyiahf/vczjk/vy;

    move-result-object v1

    goto :goto_3

    :cond_3
    sget-object v1, Llyiahf/vczjk/fn2;->OooO00o:Llyiahf/vczjk/fn2;

    :goto_3
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v1}, Llyiahf/vczjk/wf8;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_4
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_6

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/em7;

    iget-object v5, p0, Llyiahf/vczjk/nr4;->OooOo0O:Llyiahf/vczjk/ld9;

    iget-object v5, v5, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/uqa;

    invoke-virtual {v5, v3, v0}, Llyiahf/vczjk/uqa;->Oooo0oo(Llyiahf/vczjk/y64;Llyiahf/vczjk/a74;)Llyiahf/vczjk/uk4;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v3

    invoke-interface {v3}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v3

    instance-of v5, v3, Llyiahf/vczjk/by0;

    if-eqz v5, :cond_5

    check-cast v3, Llyiahf/vczjk/by0;

    goto :goto_5

    :cond_5
    move-object v3, v4

    :goto_5
    if-eqz v3, :cond_4

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_4

    :cond_6
    new-instance v0, Llyiahf/vczjk/c60;

    const/16 v1, 0xe

    invoke-direct {v0, v1}, Llyiahf/vczjk/c60;-><init>(I)V

    invoke-static {v2, v0}, Llyiahf/vczjk/d21;->o0000O00(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :cond_7
    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object v0
.end method

.method public final Oooo0O0()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/nr4;->OooOoOO:Z

    return v0
.end method

.method public final Oooo0oO(Llyiahf/vczjk/al4;)Llyiahf/vczjk/jg5;
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/nr4;->OooOooO:Llyiahf/vczjk/z88;

    iget-object v0, p1, Llyiahf/vczjk/z88;->OooO00o:Llyiahf/vczjk/oo0o0Oo;

    invoke-static {v0}, Llyiahf/vczjk/p72;->OooOO0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/cm5;

    iget-object p1, p1, Llyiahf/vczjk/z88;->OooO0OO:Llyiahf/vczjk/o45;

    sget-object v0, Llyiahf/vczjk/z88;->OooO0o0:[Llyiahf/vczjk/th4;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    invoke-static {p1, v0}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/jg5;

    check-cast p1, Llyiahf/vczjk/rr4;

    return-object p1
.end method

.method public final OoooO0()Llyiahf/vczjk/jg5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nr4;->Oooo000:Llyiahf/vczjk/fs4;

    return-object v0
.end method

.method public final OoooO00()Llyiahf/vczjk/ux0;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final getKind()Llyiahf/vczjk/ly0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nr4;->OooOo:Llyiahf/vczjk/ly0;

    return-object v0
.end method

.method public final o000000O()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final o00ooo()Llyiahf/vczjk/rr4;
    .locals 1

    invoke-super {p0}, Llyiahf/vczjk/oo0o0Oo;->o0OO00O()Llyiahf/vczjk/jg5;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/rr4;

    return-object v0
.end method

.method public final o0OO00O()Llyiahf/vczjk/jg5;
    .locals 1

    invoke-super {p0}, Llyiahf/vczjk/oo0o0Oo;->o0OO00O()Llyiahf/vczjk/jg5;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/rr4;

    return-object v0
.end method

.method public final o0ooOO0()Llyiahf/vczjk/jg5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nr4;->OooOooo:Llyiahf/vczjk/zz3;

    return-object v0
.end method

.method public final o0ooOOo()Llyiahf/vczjk/fca;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final oo0o0Oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Lazy Java class "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/p72;->OooO0oo(Llyiahf/vczjk/v02;)Llyiahf/vczjk/ic3;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
