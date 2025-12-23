.class public final Llyiahf/vczjk/om;
.super Llyiahf/vczjk/l21;
.source "SourceFile"


# instance fields
.field public final OooOOo:Llyiahf/vczjk/ec5;

.field public final OooOOo0:Llyiahf/vczjk/a4a;

.field public final OooOOoo:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yn;Llyiahf/vczjk/a4a;Llyiahf/vczjk/ec5;Z)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/l21;-><init>(Ljava/lang/Object;I)V

    iput-object p2, p0, Llyiahf/vczjk/om;->OooOOo0:Llyiahf/vczjk/a4a;

    if-nez p1, :cond_0

    const/4 p3, 0x0

    :cond_0
    iput-object p3, p0, Llyiahf/vczjk/om;->OooOOo:Llyiahf/vczjk/ec5;

    iput-boolean p4, p0, Llyiahf/vczjk/om;->OooOOoo:Z

    return-void
.end method


# virtual methods
.method public final o0000oo(Llyiahf/vczjk/a5a;Llyiahf/vczjk/x64;)Ljava/util/Map;
    .locals 9

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->o000oOoO()Llyiahf/vczjk/x64;

    move-result-object v0

    if-nez v0, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p2

    new-instance v1, Llyiahf/vczjk/bp8;

    iget-object v2, p0, Llyiahf/vczjk/om;->OooOOo0:Llyiahf/vczjk/a4a;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->Oooo0oO()Llyiahf/vczjk/i3a;

    move-result-object v3

    const/4 v4, 0x3

    invoke-direct {v1, v4, v2, v3}, Llyiahf/vczjk/bp8;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {p0, v1, v0}, Llyiahf/vczjk/om;->o0000oo(Llyiahf/vczjk/a5a;Llyiahf/vczjk/x64;)Ljava/util/Map;

    move-result-object v0

    invoke-virtual {p2}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    move-result-object v1

    array-length v2, v1

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v4, v2, :cond_5

    aget-object v5, v1, v4

    invoke-virtual {v5}, Ljava/lang/reflect/Field;->isSynthetic()Z

    move-result v6

    if-eqz v6, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v5}, Ljava/lang/reflect/Field;->getModifiers()I

    move-result v6

    invoke-static {v6}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result v6

    if-eqz v6, :cond_2

    goto :goto_1

    :cond_2
    if-nez v0, :cond_3

    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    :cond_3
    new-instance v6, Llyiahf/vczjk/nm;

    invoke-direct {v6, p1, v5}, Llyiahf/vczjk/nm;-><init>(Llyiahf/vczjk/a5a;Ljava/lang/reflect/Field;)V

    iget-boolean v7, p0, Llyiahf/vczjk/om;->OooOOoo:Z

    if-eqz v7, :cond_4

    sget-object v7, Llyiahf/vczjk/jn;->OooOOOO:Llyiahf/vczjk/jn;

    invoke-virtual {v5}, Ljava/lang/reflect/Field;->getDeclaredAnnotations()[Ljava/lang/annotation/Annotation;

    move-result-object v8

    invoke-virtual {p0, v7, v8}, Llyiahf/vczjk/l21;->o00000OO(Llyiahf/vczjk/yi4;[Ljava/lang/annotation/Annotation;)Llyiahf/vczjk/yi4;

    move-result-object v7

    iput-object v7, v6, Llyiahf/vczjk/nm;->OooO0OO:Llyiahf/vczjk/yi4;

    :cond_4
    invoke-virtual {v5}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    move-result-object v5

    invoke-interface {v0, v5, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :goto_1
    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_5
    if-eqz v0, :cond_a

    iget-object p1, p0, Llyiahf/vczjk/om;->OooOOo:Llyiahf/vczjk/ec5;

    if-eqz p1, :cond_a

    check-cast p1, Llyiahf/vczjk/fc5;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fc5;->OooO00o(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object p1

    if-eqz p1, :cond_a

    const/4 v1, 0x1

    invoke-static {p1, p2, v1}, Llyiahf/vczjk/vy0;->OooOO0O(Ljava/lang/Class;Ljava/lang/Class;Z)Ljava/util/ArrayList;

    move-result-object p1

    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_6
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_a

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Class;

    invoke-virtual {p2}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    move-result-object p2

    array-length v1, p2

    move v2, v3

    :goto_2
    if-ge v2, v1, :cond_6

    aget-object v4, p2, v2

    invoke-virtual {v4}, Ljava/lang/reflect/Field;->isSynthetic()Z

    move-result v5

    if-eqz v5, :cond_7

    goto :goto_3

    :cond_7
    invoke-virtual {v4}, Ljava/lang/reflect/Field;->getModifiers()I

    move-result v5

    invoke-static {v5}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result v5

    if-eqz v5, :cond_8

    goto :goto_3

    :cond_8
    invoke-virtual {v4}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    move-result-object v5

    invoke-interface {v0, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/nm;

    if-eqz v5, :cond_9

    iget-object v6, v5, Llyiahf/vczjk/nm;->OooO0OO:Llyiahf/vczjk/yi4;

    invoke-virtual {v4}, Ljava/lang/reflect/Field;->getDeclaredAnnotations()[Ljava/lang/annotation/Annotation;

    move-result-object v4

    invoke-virtual {p0, v6, v4}, Llyiahf/vczjk/l21;->o00000OO(Llyiahf/vczjk/yi4;[Ljava/lang/annotation/Annotation;)Llyiahf/vczjk/yi4;

    move-result-object v4

    iput-object v4, v5, Llyiahf/vczjk/nm;->OooO0OO:Llyiahf/vczjk/yi4;

    :cond_9
    :goto_3
    add-int/lit8 v2, v2, 0x1

    goto :goto_2

    :cond_a
    return-object v0
.end method
