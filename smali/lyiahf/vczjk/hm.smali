.class public final Llyiahf/vczjk/hm;
.super Llyiahf/vczjk/u34;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/a5a;


# static fields
.field public static final Oooo0:Llyiahf/vczjk/uqa;


# instance fields
.field public final OooOo:Ljava/util/List;

.field public final OooOo0:Llyiahf/vczjk/x64;

.field public final OooOo0O:Ljava/lang/Class;

.field public final OooOo0o:Llyiahf/vczjk/i3a;

.field public final OooOoO:Llyiahf/vczjk/a4a;

.field public final OooOoO0:Llyiahf/vczjk/yn;

.field public final OooOoOO:Llyiahf/vczjk/ec5;

.field public final OooOoo:Z

.field public final OooOoo0:Ljava/lang/Class;

.field public final OooOooO:Llyiahf/vczjk/lo;

.field public OooOooo:Llyiahf/vczjk/uqa;

.field public Oooo000:Llyiahf/vczjk/um;

.field public Oooo00O:Ljava/util/List;

.field public transient Oooo00o:Ljava/lang/Boolean;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/uqa;

    const/4 v1, 0x0

    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    const/4 v3, 0x5

    invoke-direct {v0, v1, v2, v3, v2}, Llyiahf/vczjk/uqa;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    sput-object v0, Llyiahf/vczjk/hm;->Oooo0:Llyiahf/vczjk/uqa;

    return-void
.end method

.method public constructor <init>(Ljava/lang/Class;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/hm;->OooOo0:Llyiahf/vczjk/x64;

    iput-object p1, p0, Llyiahf/vczjk/hm;->OooOo0O:Ljava/lang/Class;

    sget-object p1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object p1, p0, Llyiahf/vczjk/hm;->OooOo:Ljava/util/List;

    iput-object v0, p0, Llyiahf/vczjk/hm;->OooOoo0:Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/yi4;->OooO00o:Llyiahf/vczjk/ln;

    iput-object p1, p0, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    sget-object p1, Llyiahf/vczjk/i3a;->OooOOOO:Llyiahf/vczjk/i3a;

    iput-object p1, p0, Llyiahf/vczjk/hm;->OooOo0o:Llyiahf/vczjk/i3a;

    iput-object v0, p0, Llyiahf/vczjk/hm;->OooOoO0:Llyiahf/vczjk/yn;

    iput-object v0, p0, Llyiahf/vczjk/hm;->OooOoOO:Llyiahf/vczjk/ec5;

    iput-object v0, p0, Llyiahf/vczjk/hm;->OooOoO:Llyiahf/vczjk/a4a;

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/hm;->OooOoo:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/x64;Ljava/lang/Class;Ljava/util/List;Ljava/lang/Class;Llyiahf/vczjk/lo;Llyiahf/vczjk/i3a;Llyiahf/vczjk/yn;Llyiahf/vczjk/ec5;Llyiahf/vczjk/a4a;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/hm;->OooOo0:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/hm;->OooOo0O:Ljava/lang/Class;

    iput-object p3, p0, Llyiahf/vczjk/hm;->OooOo:Ljava/util/List;

    iput-object p4, p0, Llyiahf/vczjk/hm;->OooOoo0:Ljava/lang/Class;

    iput-object p5, p0, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    iput-object p6, p0, Llyiahf/vczjk/hm;->OooOo0o:Llyiahf/vczjk/i3a;

    iput-object p7, p0, Llyiahf/vczjk/hm;->OooOoO0:Llyiahf/vczjk/yn;

    iput-object p8, p0, Llyiahf/vczjk/hm;->OooOoOO:Llyiahf/vczjk/ec5;

    iput-object p9, p0, Llyiahf/vczjk/hm;->OooOoO:Llyiahf/vczjk/a4a;

    iput-boolean p10, p0, Llyiahf/vczjk/hm;->OooOoo:Z

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/reflect/Type;)Llyiahf/vczjk/x64;
    .locals 2

    instance-of v0, p1, Ljava/lang/Class;

    iget-object v1, p0, Llyiahf/vczjk/hm;->OooOoO:Llyiahf/vczjk/a4a;

    if-eqz v0, :cond_0

    invoke-virtual {v1, p1}, Llyiahf/vczjk/a4a;->OooOO0O(Ljava/lang/reflect/Type;)Llyiahf/vczjk/x64;

    move-result-object p1

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/hm;->OooOo0o:Llyiahf/vczjk/i3a;

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/a4a;->OooOO0o(Ljava/lang/reflect/Type;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object p1

    return-object p1
.end method

.method public final OooOo0O(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/hm;->OooOooO:Llyiahf/vczjk/lo;

    invoke-interface {v0, p1}, Llyiahf/vczjk/lo;->OooO00o(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    move-result-object p1

    return-object p1
.end method

.method public final OooOoOO()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/hm;->OooOo0O:Ljava/lang/Class;

    return-object v0
.end method

.method public final OooOoo()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/hm;->OooOo0:Llyiahf/vczjk/x64;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    const/4 v0, 0x1

    if-ne p1, p0, :cond_0

    return v0

    :cond_0
    const-class v1, Llyiahf/vczjk/hm;

    invoke-static {v1, p1}, Llyiahf/vczjk/vy0;->OooOOo0(Ljava/lang/Class;Ljava/lang/Object;)Z

    move-result v1

    const/4 v2, 0x0

    if-nez v1, :cond_1

    return v2

    :cond_1
    check-cast p1, Llyiahf/vczjk/hm;

    iget-object p1, p1, Llyiahf/vczjk/hm;->OooOo0O:Ljava/lang/Class;

    iget-object v1, p0, Llyiahf/vczjk/hm;->OooOo0O:Ljava/lang/Class;

    if-ne p1, v1, :cond_2

    return v0

    :cond_2
    return v2
.end method

.method public final getName()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/hm;->OooOo0O:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/hm;->OooOo0O:Ljava/lang/Class;

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    move-result v0

    return v0
.end method

.method public final o00oO0O()Ljava/util/List;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/hm;->Oooo00O:Ljava/util/List;

    if-nez v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/hm;->OooOo0:Llyiahf/vczjk/x64;

    if-nez v0, :cond_0

    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    goto :goto_1

    :cond_0
    new-instance v1, Llyiahf/vczjk/om;

    iget-object v2, p0, Llyiahf/vczjk/hm;->OooOoO0:Llyiahf/vczjk/yn;

    iget-object v3, p0, Llyiahf/vczjk/hm;->OooOoO:Llyiahf/vczjk/a4a;

    iget-object v4, p0, Llyiahf/vczjk/hm;->OooOoOO:Llyiahf/vczjk/ec5;

    iget-boolean v5, p0, Llyiahf/vczjk/hm;->OooOoo:Z

    invoke-direct {v1, v2, v3, v4, v5}, Llyiahf/vczjk/om;-><init>(Llyiahf/vczjk/yn;Llyiahf/vczjk/a4a;Llyiahf/vczjk/ec5;Z)V

    invoke-virtual {v1, p0, v0}, Llyiahf/vczjk/om;->o0000oo(Llyiahf/vczjk/a5a;Llyiahf/vczjk/x64;)Ljava/util/Map;

    move-result-object v0

    if-nez v0, :cond_1

    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    goto :goto_1

    :cond_1
    new-instance v1, Ljava/util/ArrayList;

    invoke-interface {v0}, Ljava/util/Map;->size()I

    move-result v2

    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/nm;

    new-instance v3, Llyiahf/vczjk/mm;

    iget-object v4, v2, Llyiahf/vczjk/nm;->OooO0OO:Llyiahf/vczjk/yi4;

    invoke-virtual {v4}, Llyiahf/vczjk/yi4;->OooOoOO()Llyiahf/vczjk/ao;

    move-result-object v4

    iget-object v5, v2, Llyiahf/vczjk/nm;->OooO00o:Llyiahf/vczjk/a5a;

    iget-object v2, v2, Llyiahf/vczjk/nm;->OooO0O0:Ljava/lang/reflect/Field;

    invoke-direct {v3, v5, v2, v4}, Llyiahf/vczjk/mm;-><init>(Llyiahf/vczjk/a5a;Ljava/lang/reflect/Field;Llyiahf/vczjk/ao;)V

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_2
    move-object v0, v1

    :goto_1
    iput-object v0, p0, Llyiahf/vczjk/hm;->Oooo00O:Ljava/util/List;

    :cond_3
    return-object v0
.end method

.method public final o00oO0o()Llyiahf/vczjk/um;
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/hm;->Oooo000:Llyiahf/vczjk/um;

    if-nez v0, :cond_a

    iget-object v0, p0, Llyiahf/vczjk/hm;->OooOo0:Llyiahf/vczjk/x64;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/um;

    invoke-direct {v0}, Llyiahf/vczjk/um;-><init>()V

    goto/16 :goto_5

    :cond_0
    new-instance v1, Llyiahf/vczjk/tm;

    iget-object v2, p0, Llyiahf/vczjk/hm;->OooOoOO:Llyiahf/vczjk/ec5;

    iget-boolean v3, p0, Llyiahf/vczjk/hm;->OooOoo:Z

    iget-object v4, p0, Llyiahf/vczjk/hm;->OooOoO0:Llyiahf/vczjk/yn;

    invoke-direct {v1, v4, v2, v3}, Llyiahf/vczjk/tm;-><init>(Llyiahf/vczjk/yn;Llyiahf/vczjk/ec5;Z)V

    new-instance v2, Ljava/util/LinkedHashMap;

    invoke-direct {v2}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v3

    iget-object v4, p0, Llyiahf/vczjk/hm;->OooOoo0:Ljava/lang/Class;

    invoke-virtual {v1, p0, v3, v2, v4}, Llyiahf/vczjk/tm;->o0000oo(Llyiahf/vczjk/a5a;Ljava/lang/Class;Ljava/util/LinkedHashMap;Ljava/lang/Class;)V

    iget-object v3, p0, Llyiahf/vczjk/hm;->OooOo:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    iget-object v5, v1, Llyiahf/vczjk/tm;->OooOOo0:Llyiahf/vczjk/ec5;

    const/4 v6, 0x0

    if-eqz v4, :cond_2

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/x64;

    if-nez v5, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v4}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v6

    check-cast v5, Llyiahf/vczjk/fc5;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/fc5;->OooO00o(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object v6

    :goto_1
    new-instance v5, Llyiahf/vczjk/bp8;

    invoke-virtual {v4}, Llyiahf/vczjk/x64;->Oooo0oO()Llyiahf/vczjk/i3a;

    move-result-object v7

    iget-object v8, p0, Llyiahf/vczjk/hm;->OooOoO:Llyiahf/vczjk/a4a;

    const/4 v9, 0x3

    invoke-direct {v5, v9, v8, v7}, Llyiahf/vczjk/bp8;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v4}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v4

    invoke-virtual {v1, v5, v4, v2, v6}, Llyiahf/vczjk/tm;->o0000oo(Llyiahf/vczjk/a5a;Ljava/lang/Class;Ljava/util/LinkedHashMap;Ljava/lang/Class;)V

    goto :goto_0

    :cond_2
    if-eqz v5, :cond_5

    check-cast v5, Llyiahf/vczjk/fc5;

    const-class v3, Ljava/lang/Object;

    invoke-virtual {v5, v3}, Llyiahf/vczjk/fc5;->OooO00o(Ljava/lang/Class;)Ljava/lang/Class;

    move-result-object v4

    if-eqz v4, :cond_5

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v1, p0, v0, v2, v4}, Llyiahf/vczjk/tm;->o0000oO(Llyiahf/vczjk/a5a;Ljava/lang/Class;Ljava/util/LinkedHashMap;Ljava/lang/Class;)V

    iget-object v0, v1, Llyiahf/vczjk/l21;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yn;

    if-eqz v0, :cond_5

    invoke-interface {v2}, Ljava/util/Map;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_5

    invoke-virtual {v2}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :catch_0
    :cond_3
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_5

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/util/Map$Entry;

    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/fg5;

    iget-object v7, v5, Llyiahf/vczjk/fg5;->OooO00o:Ljava/lang/String;

    const-string v8, "hashCode"

    invoke-virtual {v8, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_3

    iget-object v7, v5, Llyiahf/vczjk/fg5;->OooO0O0:[Ljava/lang/Class;

    array-length v7, v7

    if-eqz v7, :cond_4

    goto :goto_2

    :cond_4
    :try_start_0
    iget-object v5, v5, Llyiahf/vczjk/fg5;->OooO00o:Ljava/lang/String;

    invoke-virtual {v3, v5, v6}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v5

    if-eqz v5, :cond_3

    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/sm;

    iget-object v7, v4, Llyiahf/vczjk/sm;->OooO0OO:Llyiahf/vczjk/yi4;

    invoke-virtual {v5}, Ljava/lang/reflect/Method;->getDeclaredAnnotations()[Ljava/lang/annotation/Annotation;

    move-result-object v8

    invoke-virtual {v1, v7, v8}, Llyiahf/vczjk/l21;->o00000o0(Llyiahf/vczjk/yi4;[Ljava/lang/annotation/Annotation;)Llyiahf/vczjk/yi4;

    move-result-object v7

    iput-object v7, v4, Llyiahf/vczjk/sm;->OooO0OO:Llyiahf/vczjk/yi4;

    iput-object v5, v4, Llyiahf/vczjk/sm;->OooO0O0:Ljava/lang/reflect/Method;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_2

    :cond_5
    invoke-interface {v2}, Ljava/util/Map;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_6

    new-instance v0, Llyiahf/vczjk/um;

    invoke-direct {v0}, Llyiahf/vczjk/um;-><init>()V

    goto :goto_5

    :cond_6
    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-interface {v2}, Ljava/util/Map;->size()I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/LinkedHashMap;-><init>(I)V

    invoke-virtual {v2}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_7
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_9

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/Map$Entry;

    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/sm;

    iget-object v4, v3, Llyiahf/vczjk/sm;->OooO0O0:Ljava/lang/reflect/Method;

    if-nez v4, :cond_8

    move-object v5, v6

    goto :goto_4

    :cond_8
    new-instance v5, Llyiahf/vczjk/rm;

    iget-object v7, v3, Llyiahf/vczjk/sm;->OooO00o:Llyiahf/vczjk/a5a;

    iget-object v3, v3, Llyiahf/vczjk/sm;->OooO0OO:Llyiahf/vczjk/yi4;

    invoke-virtual {v3}, Llyiahf/vczjk/yi4;->OooOoOO()Llyiahf/vczjk/ao;

    move-result-object v3

    invoke-direct {v5, v7, v4, v3, v6}, Llyiahf/vczjk/rm;-><init>(Llyiahf/vczjk/a5a;Ljava/lang/reflect/Method;Llyiahf/vczjk/ao;[Llyiahf/vczjk/ao;)V

    :goto_4
    if-eqz v5, :cond_7

    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v2

    invoke-interface {v0, v2, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_3

    :cond_9
    new-instance v1, Llyiahf/vczjk/um;

    invoke-direct {v1}, Llyiahf/vczjk/um;-><init>()V

    iput-object v0, v1, Llyiahf/vczjk/um;->OooOOO:Ljava/io/Serializable;

    move-object v0, v1

    :goto_5
    iput-object v0, p0, Llyiahf/vczjk/hm;->Oooo000:Llyiahf/vczjk/um;

    :cond_a
    return-object v0
.end method

.method public final oo000o()Llyiahf/vczjk/uqa;
    .locals 21

    move-object/from16 v0, p0

    iget-object v1, v0, Llyiahf/vczjk/hm;->OooOooo:Llyiahf/vczjk/uqa;

    if-nez v1, :cond_26

    iget-object v1, v0, Llyiahf/vczjk/hm;->OooOo0:Llyiahf/vczjk/x64;

    if-nez v1, :cond_0

    sget-object v1, Llyiahf/vczjk/hm;->Oooo0:Llyiahf/vczjk/uqa;

    goto/16 :goto_16

    :cond_0
    iget-object v2, v0, Llyiahf/vczjk/hm;->OooOoo0:Ljava/lang/Class;

    if-eqz v2, :cond_1

    const/4 v4, 0x1

    goto :goto_0

    :cond_1
    const/4 v4, 0x0

    :goto_0
    iget-boolean v5, v0, Llyiahf/vczjk/hm;->OooOoo:Z

    or-int/2addr v4, v5

    new-instance v5, Llyiahf/vczjk/km;

    iget-object v6, v0, Llyiahf/vczjk/hm;->OooOoO0:Llyiahf/vczjk/yn;

    iget-object v7, v0, Llyiahf/vczjk/hm;->OooOoO:Llyiahf/vczjk/a4a;

    invoke-direct {v5, v6, v7, v0, v4}, Llyiahf/vczjk/km;-><init>(Llyiahf/vczjk/yn;Llyiahf/vczjk/a4a;Llyiahf/vczjk/hm;Z)V

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->Oooooo()Z

    move-result v4

    const/4 v6, 0x0

    if-nez v4, :cond_6

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/vy0;->OooOOO0(Ljava/lang/Class;)[Llyiahf/vczjk/ty0;

    move-result-object v4

    array-length v7, v4

    move-object v9, v6

    move-object v10, v9

    const/4 v8, 0x0

    :goto_1
    if-ge v8, v7, :cond_7

    aget-object v11, v4, v8

    iget-object v12, v11, Llyiahf/vczjk/ty0;->OooO00o:Ljava/lang/reflect/Constructor;

    invoke-virtual {v12}, Ljava/lang/reflect/Constructor;->isSynthetic()Z

    move-result v12

    if-eqz v12, :cond_2

    goto :goto_2

    :cond_2
    iget v12, v11, Llyiahf/vczjk/ty0;->OooO0Oo:I

    if-gez v12, :cond_3

    iget-object v12, v11, Llyiahf/vczjk/ty0;->OooO00o:Ljava/lang/reflect/Constructor;

    invoke-virtual {v12}, Ljava/lang/reflect/Constructor;->getParameterTypes()[Ljava/lang/Class;

    move-result-object v12

    array-length v12, v12

    iput v12, v11, Llyiahf/vczjk/ty0;->OooO0Oo:I

    :cond_3
    if-nez v12, :cond_4

    move-object v9, v11

    goto :goto_2

    :cond_4
    if-nez v10, :cond_5

    new-instance v10, Ljava/util/ArrayList;

    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    :cond_5
    invoke-interface {v10, v11}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :goto_2
    add-int/lit8 v8, v8, 0x1

    goto :goto_1

    :cond_6
    move-object v9, v6

    move-object v10, v9

    :cond_7
    if-nez v10, :cond_9

    sget-object v4, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    if-nez v9, :cond_8

    move-object/from16 v16, v1

    move-object/from16 v17, v2

    goto/16 :goto_a

    :cond_8
    const/4 v7, 0x0

    goto :goto_4

    :cond_9
    invoke-interface {v10}, Ljava/util/List;->size()I

    move-result v4

    new-instance v7, Ljava/util/ArrayList;

    invoke-direct {v7, v4}, Ljava/util/ArrayList;-><init>(I)V

    const/4 v8, 0x0

    :goto_3
    if-ge v8, v4, :cond_a

    invoke-virtual {v7, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v8, v8, 0x1

    goto :goto_3

    :cond_a
    move-object/from16 v20, v7

    move v7, v4

    move-object/from16 v4, v20

    :goto_4
    sget-object v8, Llyiahf/vczjk/l21;->OooOOOO:[Llyiahf/vczjk/ao;

    iget-object v11, v5, Llyiahf/vczjk/km;->OooOOo0:Llyiahf/vczjk/hm;

    if-eqz v2, :cond_11

    invoke-static {v2}, Llyiahf/vczjk/vy0;->OooOOO0(Ljava/lang/Class;)[Llyiahf/vczjk/ty0;

    move-result-object v12

    array-length v13, v12

    move-object v15, v6

    const/4 v14, 0x0

    :goto_5
    if-ge v14, v13, :cond_11

    aget-object v3, v12, v14

    iget v6, v3, Llyiahf/vczjk/ty0;->OooO0Oo:I

    move-object/from16 v16, v1

    iget-object v1, v3, Llyiahf/vczjk/ty0;->OooO00o:Ljava/lang/reflect/Constructor;

    if-gez v6, :cond_b

    invoke-virtual {v1}, Ljava/lang/reflect/Constructor;->getParameterTypes()[Ljava/lang/Class;

    move-result-object v6

    array-length v6, v6

    iput v6, v3, Llyiahf/vczjk/ty0;->OooO0Oo:I

    :cond_b
    if-nez v6, :cond_d

    if-eqz v9, :cond_c

    new-instance v1, Llyiahf/vczjk/jm;

    invoke-virtual {v5, v9, v3}, Llyiahf/vczjk/km;->o0000oo(Llyiahf/vczjk/ty0;Llyiahf/vczjk/ty0;)Llyiahf/vczjk/ao;

    move-result-object v3

    iget-object v6, v9, Llyiahf/vczjk/ty0;->OooO00o:Ljava/lang/reflect/Constructor;

    invoke-direct {v1, v11, v6, v3, v8}, Llyiahf/vczjk/jm;-><init>(Llyiahf/vczjk/a5a;Ljava/lang/reflect/Constructor;Llyiahf/vczjk/ao;[Llyiahf/vczjk/ao;)V

    iput-object v1, v5, Llyiahf/vczjk/km;->OooOo00:Llyiahf/vczjk/jm;

    move-object/from16 v17, v2

    const/4 v9, 0x0

    goto :goto_8

    :cond_c
    move-object/from16 v17, v2

    goto :goto_8

    :cond_d
    if-eqz v10, :cond_c

    if-nez v15, :cond_e

    new-array v15, v7, [Llyiahf/vczjk/fg5;

    const/4 v6, 0x0

    :goto_6
    if-ge v6, v7, :cond_e

    move-object/from16 v17, v2

    new-instance v2, Llyiahf/vczjk/fg5;

    invoke-interface {v10, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v18

    move/from16 v19, v6

    move-object/from16 v6, v18

    check-cast v6, Llyiahf/vczjk/ty0;

    iget-object v6, v6, Llyiahf/vczjk/ty0;->OooO00o:Ljava/lang/reflect/Constructor;

    invoke-direct {v2, v6}, Llyiahf/vczjk/fg5;-><init>(Ljava/lang/reflect/Constructor;)V

    aput-object v2, v15, v19

    add-int/lit8 v6, v19, 0x1

    move-object/from16 v2, v17

    goto :goto_6

    :cond_e
    move-object/from16 v17, v2

    new-instance v2, Llyiahf/vczjk/fg5;

    invoke-direct {v2, v1}, Llyiahf/vczjk/fg5;-><init>(Ljava/lang/reflect/Constructor;)V

    const/4 v1, 0x0

    :goto_7
    if-ge v1, v7, :cond_10

    aget-object v6, v15, v1

    invoke-virtual {v2, v6}, Llyiahf/vczjk/fg5;->equals(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_f

    invoke-interface {v10, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ty0;

    invoke-virtual {v5, v2, v3}, Llyiahf/vczjk/km;->o0000O0O(Llyiahf/vczjk/ty0;Llyiahf/vczjk/ty0;)Llyiahf/vczjk/jm;

    move-result-object v2

    invoke-interface {v4, v1, v2}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    goto :goto_8

    :cond_f
    add-int/lit8 v1, v1, 0x1

    goto :goto_7

    :cond_10
    :goto_8
    add-int/lit8 v14, v14, 0x1

    move-object/from16 v1, v16

    move-object/from16 v2, v17

    const/4 v6, 0x0

    goto :goto_5

    :cond_11
    move-object/from16 v16, v1

    move-object/from16 v17, v2

    if-eqz v9, :cond_12

    new-instance v1, Llyiahf/vczjk/jm;

    const/4 v2, 0x0

    invoke-virtual {v5, v9, v2}, Llyiahf/vczjk/km;->o0000oo(Llyiahf/vczjk/ty0;Llyiahf/vczjk/ty0;)Llyiahf/vczjk/ao;

    move-result-object v3

    iget-object v2, v9, Llyiahf/vczjk/ty0;->OooO00o:Ljava/lang/reflect/Constructor;

    invoke-direct {v1, v11, v2, v3, v8}, Llyiahf/vczjk/jm;-><init>(Llyiahf/vczjk/a5a;Ljava/lang/reflect/Constructor;Llyiahf/vczjk/ao;[Llyiahf/vczjk/ao;)V

    iput-object v1, v5, Llyiahf/vczjk/km;->OooOo00:Llyiahf/vczjk/jm;

    :cond_12
    const/4 v1, 0x0

    :goto_9
    if-ge v1, v7, :cond_14

    invoke-interface {v4, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/jm;

    if-nez v2, :cond_13

    invoke-interface {v10, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ty0;

    const/4 v3, 0x0

    invoke-virtual {v5, v2, v3}, Llyiahf/vczjk/km;->o0000O0O(Llyiahf/vczjk/ty0;Llyiahf/vczjk/ty0;)Llyiahf/vczjk/jm;

    move-result-object v2

    invoke-interface {v4, v1, v2}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    :cond_13
    add-int/lit8 v1, v1, 0x1

    goto :goto_9

    :cond_14
    :goto_a
    invoke-virtual/range {v16 .. v16}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/vy0;->OooOO0o(Ljava/lang/Class;)[Ljava/lang/reflect/Method;

    move-result-object v1

    array-length v2, v1

    const/4 v3, 0x0

    const/4 v6, 0x0

    :goto_b
    if-ge v6, v2, :cond_17

    aget-object v7, v1, v6

    invoke-virtual {v7}, Ljava/lang/reflect/Method;->getModifiers()I

    move-result v8

    invoke-static {v8}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result v8

    if-nez v8, :cond_15

    goto :goto_c

    :cond_15
    if-nez v3, :cond_16

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    :cond_16
    invoke-interface {v3, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    :goto_c
    add-int/lit8 v6, v6, 0x1

    goto :goto_b

    :cond_17
    if-nez v3, :cond_18

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    goto/16 :goto_13

    :cond_18
    new-instance v1, Llyiahf/vczjk/fk7;

    iget-object v2, v5, Llyiahf/vczjk/km;->OooOOo:Llyiahf/vczjk/a4a;

    invoke-direct {v1, v2}, Llyiahf/vczjk/fk7;-><init>(Ljava/lang/Object;)V

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v2

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6, v2}, Ljava/util/ArrayList;-><init>(I)V

    const/4 v7, 0x0

    :goto_d
    if-ge v7, v2, :cond_19

    const/4 v8, 0x0

    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v7, v7, 0x1

    goto :goto_d

    :cond_19
    if-eqz v17, :cond_1e

    invoke-virtual/range {v17 .. v17}, Ljava/lang/Class;->getDeclaredMethods()[Ljava/lang/reflect/Method;

    move-result-object v7

    array-length v8, v7

    const/4 v9, 0x0

    const/4 v10, 0x0

    :goto_e
    if-ge v10, v8, :cond_1e

    aget-object v11, v7, v10

    invoke-virtual {v11}, Ljava/lang/reflect/Method;->getModifiers()I

    move-result v12

    invoke-static {v12}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    move-result v12

    if-nez v12, :cond_1a

    goto :goto_11

    :cond_1a
    if-nez v9, :cond_1b

    new-array v9, v2, [Llyiahf/vczjk/fg5;

    const/4 v12, 0x0

    :goto_f
    if-ge v12, v2, :cond_1b

    new-instance v13, Llyiahf/vczjk/fg5;

    invoke-interface {v3, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Ljava/lang/reflect/Method;

    invoke-direct {v13, v14}, Llyiahf/vczjk/fg5;-><init>(Ljava/lang/reflect/Method;)V

    aput-object v13, v9, v12

    add-int/lit8 v12, v12, 0x1

    goto :goto_f

    :cond_1b
    new-instance v12, Llyiahf/vczjk/fg5;

    invoke-direct {v12, v11}, Llyiahf/vczjk/fg5;-><init>(Ljava/lang/reflect/Method;)V

    const/4 v13, 0x0

    :goto_10
    if-ge v13, v2, :cond_1d

    aget-object v14, v9, v13

    invoke-virtual {v12, v14}, Llyiahf/vczjk/fg5;->equals(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_1c

    invoke-interface {v3, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Ljava/lang/reflect/Method;

    invoke-virtual {v5, v12, v1, v11}, Llyiahf/vczjk/km;->o0000O0(Ljava/lang/reflect/Method;Llyiahf/vczjk/fk7;Ljava/lang/reflect/Method;)Llyiahf/vczjk/rm;

    move-result-object v11

    invoke-virtual {v6, v13, v11}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    goto :goto_11

    :cond_1c
    add-int/lit8 v13, v13, 0x1

    goto :goto_10

    :cond_1d
    :goto_11
    add-int/lit8 v10, v10, 0x1

    goto :goto_e

    :cond_1e
    const/4 v7, 0x0

    :goto_12
    if-ge v7, v2, :cond_20

    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/rm;

    if-nez v8, :cond_1f

    invoke-interface {v3, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/lang/reflect/Method;

    const/4 v9, 0x0

    invoke-virtual {v5, v8, v1, v9}, Llyiahf/vczjk/km;->o0000O0(Ljava/lang/reflect/Method;Llyiahf/vczjk/fk7;Ljava/lang/reflect/Method;)Llyiahf/vczjk/rm;

    move-result-object v8

    invoke-virtual {v6, v7, v8}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    :cond_1f
    add-int/lit8 v7, v7, 0x1

    goto :goto_12

    :cond_20
    move-object v1, v6

    :goto_13
    iget-boolean v2, v5, Llyiahf/vczjk/km;->OooOOoo:Z

    if-eqz v2, :cond_25

    iget-object v2, v5, Llyiahf/vczjk/km;->OooOo00:Llyiahf/vczjk/jm;

    iget-object v3, v5, Llyiahf/vczjk/l21;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/yn;

    if-eqz v2, :cond_21

    invoke-virtual {v3, v2}, Llyiahf/vczjk/yn;->Oooooo0(Llyiahf/vczjk/pm;)Z

    move-result v2

    if-eqz v2, :cond_21

    const/4 v2, 0x0

    iput-object v2, v5, Llyiahf/vczjk/km;->OooOo00:Llyiahf/vczjk/jm;

    :cond_21
    invoke-interface {v4}, Ljava/util/List;->size()I

    move-result v2

    :cond_22
    :goto_14
    add-int/lit8 v2, v2, -0x1

    if-ltz v2, :cond_23

    invoke-interface {v4, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/pm;

    invoke-virtual {v3, v6}, Llyiahf/vczjk/yn;->Oooooo0(Llyiahf/vczjk/pm;)Z

    move-result v6

    if-eqz v6, :cond_22

    invoke-interface {v4, v2}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    goto :goto_14

    :cond_23
    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v2

    :cond_24
    :goto_15
    add-int/lit8 v2, v2, -0x1

    if-ltz v2, :cond_25

    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/pm;

    invoke-virtual {v3, v6}, Llyiahf/vczjk/yn;->Oooooo0(Llyiahf/vczjk/pm;)Z

    move-result v6

    if-eqz v6, :cond_24

    invoke-interface {v1, v2}, Ljava/util/List;->remove(I)Ljava/lang/Object;

    goto :goto_15

    :cond_25
    new-instance v2, Llyiahf/vczjk/uqa;

    iget-object v3, v5, Llyiahf/vczjk/km;->OooOo00:Llyiahf/vczjk/jm;

    const/4 v5, 0x5

    invoke-direct {v2, v3, v4, v5, v1}, Llyiahf/vczjk/uqa;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    move-object v1, v2

    :goto_16
    iput-object v1, v0, Llyiahf/vczjk/hm;->OooOooo:Llyiahf/vczjk/uqa;

    :cond_26
    return-object v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "[AnnotedClass "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/hm;->OooOo0O:Ljava/lang/Class;

    const-string v2, "]"

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/ii5;->OooO0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
