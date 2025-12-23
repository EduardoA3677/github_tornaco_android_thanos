.class public final Llyiahf/vczjk/h90;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooOO0:[Ljava/lang/Class;


# instance fields
.field public final OooO:Llyiahf/vczjk/t66;

.field public final OooO00o:Llyiahf/vczjk/x64;

.field public final OooO0O0:Llyiahf/vczjk/yg6;

.field public final OooO0OO:Llyiahf/vczjk/ec5;

.field public final OooO0Oo:Llyiahf/vczjk/yn;

.field public OooO0o:[Ljava/lang/Class;

.field public final OooO0o0:Llyiahf/vczjk/hm;

.field public OooO0oO:Z

.field public OooO0oo:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Class;

    sput-object v0, Llyiahf/vczjk/h90;->OooOO0:[Ljava/lang/Class;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ec5;Llyiahf/vczjk/x64;Llyiahf/vczjk/hm;)V
    .locals 1

    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    invoke-direct {p0, p2}, Llyiahf/vczjk/h90;-><init>(Llyiahf/vczjk/x64;)V

    const/4 p2, 0x0

    iput-object p2, p0, Llyiahf/vczjk/h90;->OooO0O0:Llyiahf/vczjk/yg6;

    iput-object p1, p0, Llyiahf/vczjk/h90;->OooO0OO:Llyiahf/vczjk/ec5;

    if-nez p1, :cond_0

    iput-object p2, p0, Llyiahf/vczjk/h90;->OooO0Oo:Llyiahf/vczjk/yn;

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/h90;->OooO0Oo:Llyiahf/vczjk/yn;

    :goto_0
    iput-object p3, p0, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    iput-object v0, p0, Llyiahf/vczjk/h90;->OooO0oo:Ljava/util/List;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/x64;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/yg6;)V
    .locals 2

    iget-object v0, p1, Llyiahf/vczjk/yg6;->OooO0Oo:Llyiahf/vczjk/x64;

    invoke-direct {p0, v0}, Llyiahf/vczjk/h90;-><init>(Llyiahf/vczjk/x64;)V

    iput-object p1, p0, Llyiahf/vczjk/h90;->OooO0O0:Llyiahf/vczjk/yg6;

    iget-object v0, p1, Llyiahf/vczjk/yg6;->OooO00o:Llyiahf/vczjk/fc5;

    iput-object v0, p0, Llyiahf/vczjk/h90;->OooO0OO:Llyiahf/vczjk/ec5;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/h90;->OooO0Oo:Llyiahf/vczjk/yn;

    iget-object v0, p1, Llyiahf/vczjk/yg6;->OooO0o0:Llyiahf/vczjk/hm;

    iput-object v0, p0, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    iget-object p1, p1, Llyiahf/vczjk/yg6;->OooO0oO:Llyiahf/vczjk/yn;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/yn;->OooOoO0(Llyiahf/vczjk/u34;)Llyiahf/vczjk/t66;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/yn;->OooOoO(Llyiahf/vczjk/u34;Llyiahf/vczjk/t66;)Llyiahf/vczjk/t66;

    move-result-object v1

    :cond_0
    iput-object v1, p0, Llyiahf/vczjk/h90;->OooO:Llyiahf/vczjk/t66;

    return-void
.end method

.method public static OooO0o(Llyiahf/vczjk/ec5;Llyiahf/vczjk/x64;Llyiahf/vczjk/hm;)Llyiahf/vczjk/h90;
    .locals 2

    new-instance v0, Llyiahf/vczjk/h90;

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/h90;-><init>(Llyiahf/vczjk/ec5;Llyiahf/vczjk/x64;Llyiahf/vczjk/hm;)V

    return-object v0
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/xa7;)Z
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/h90;->OooO0O0()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/eb0;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/eb0;->OooOo0O(Llyiahf/vczjk/xa7;)Z

    move-result v2

    if-eqz v2, :cond_0

    goto :goto_0

    :cond_1
    const/4 v1, 0x0

    :goto_0
    if-eqz v1, :cond_2

    const/4 p1, 0x1

    return p1

    :cond_2
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/gp1;
    .locals 3

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/gp1;

    if-eqz v0, :cond_1

    check-cast p1, Llyiahf/vczjk/gp1;

    return-object p1

    :cond_1
    instance-of v0, p1, Ljava/lang/Class;

    if-eqz v0, :cond_5

    check-cast p1, Ljava/lang/Class;

    const-class v0, Llyiahf/vczjk/ep1;

    if-eq p1, v0, :cond_4

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOOo(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_2

    goto :goto_0

    :cond_2
    const-class v0, Llyiahf/vczjk/gp1;

    invoke-virtual {v0, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/h90;->OooO0OO:Llyiahf/vczjk/ec5;

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooOO0O()V

    invoke-virtual {v0}, Llyiahf/vczjk/ec5;->OooO0O0()Z

    move-result v0

    invoke-static {p1, v0}, Llyiahf/vczjk/vy0;->OooO0oO(Ljava/lang/Class;Z)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gp1;

    return-object p1

    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "AnnotationIntrospector returned Class "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    const-string v2, "; expected Class<Converter>"

    invoke-static {p1, v1, v2}, Llyiahf/vczjk/ii5;->OooO0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_4
    :goto_0
    const/4 p1, 0x0

    return-object p1

    :cond_5
    new-instance v0, Ljava/lang/IllegalStateException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "AnnotationIntrospector returned Converter definition of type "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, "; expected type Converter or Class<Converter> instead"

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OooO0O0()Ljava/util/List;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/h90;->OooO0oo:Ljava/util/List;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/h90;->OooO0O0:Llyiahf/vczjk/yg6;

    iget-boolean v1, v0, Llyiahf/vczjk/yg6;->OooOO0:Z

    if-nez v1, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/yg6;->OooO0o()V

    :cond_0
    iget-object v0, v0, Llyiahf/vczjk/yg6;->OooOO0O:Ljava/util/LinkedHashMap;

    new-instance v1, Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    move-result-object v0

    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v1, p0, Llyiahf/vczjk/h90;->OooO0oo:Ljava/util/List;

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/h90;->OooO0oo:Ljava/util/List;

    return-object v0
.end method

.method public final OooO0OO()[Ljava/lang/Class;
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/h90;->OooO0oO:Z

    if-nez v0, :cond_2

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/h90;->OooO0oO:Z

    iget-object v0, p0, Llyiahf/vczjk/h90;->OooO0Oo:Llyiahf/vczjk/yn;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    goto :goto_0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/yn;->OoooOoO(Llyiahf/vczjk/u34;)[Ljava/lang/Class;

    move-result-object v0

    :goto_0
    if-nez v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/h90;->OooO0OO:Llyiahf/vczjk/ec5;

    sget-object v2, Llyiahf/vczjk/gc5;->OooOoo:Llyiahf/vczjk/gc5;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result v1

    if-nez v1, :cond_1

    sget-object v0, Llyiahf/vczjk/h90;->OooOO0:[Ljava/lang/Class;

    :cond_1
    iput-object v0, p0, Llyiahf/vczjk/h90;->OooO0o:[Ljava/lang/Class;

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/h90;->OooO0o:[Ljava/lang/Class;

    return-object v0
.end method

.method public final OooO0Oo()Llyiahf/vczjk/q94;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    iget-object v1, p0, Llyiahf/vczjk/h90;->OooO0Oo:Llyiahf/vczjk/yn;

    if-eqz v1, :cond_0

    invoke-virtual {v1, v0}, Llyiahf/vczjk/yn;->OooOOO(Llyiahf/vczjk/u34;)Llyiahf/vczjk/q94;

    move-result-object v1

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    iget-object v0, v0, Llyiahf/vczjk/hm;->OooOo0O:Ljava/lang/Class;

    iget-object v2, p0, Llyiahf/vczjk/h90;->OooO0OO:Llyiahf/vczjk/ec5;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/ec5;->OooO(Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object v0

    if-eqz v0, :cond_2

    if-nez v1, :cond_1

    return-object v0

    :cond_1
    invoke-virtual {v1, v0}, Llyiahf/vczjk/q94;->OooOO0o(Llyiahf/vczjk/q94;)Llyiahf/vczjk/q94;

    move-result-object v0

    return-object v0

    :cond_2
    return-object v1
.end method

.method public final OooO0o0()Llyiahf/vczjk/pm;
    .locals 5

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/h90;->OooO0O0:Llyiahf/vczjk/yg6;

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    iget-boolean v2, v1, Llyiahf/vczjk/yg6;->OooOO0:Z

    if-nez v2, :cond_1

    invoke-virtual {v1}, Llyiahf/vczjk/yg6;->OooO0o()V

    :cond_1
    iget-object v2, v1, Llyiahf/vczjk/yg6;->OooOOOo:Ljava/util/LinkedList;

    if-eqz v2, :cond_3

    invoke-virtual {v2}, Ljava/util/LinkedList;->size()I

    move-result v2

    const/4 v3, 0x0

    const/4 v4, 0x1

    if-gt v2, v4, :cond_2

    iget-object v0, v1, Llyiahf/vczjk/yg6;->OooOOOo:Ljava/util/LinkedList;

    invoke-virtual {v0, v3}, Ljava/util/LinkedList;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/pm;

    return-object v0

    :cond_2
    iget-object v2, v1, Llyiahf/vczjk/yg6;->OooOOOo:Ljava/util/LinkedList;

    invoke-virtual {v2, v3}, Ljava/util/LinkedList;->get(I)Ljava/lang/Object;

    move-result-object v2

    iget-object v3, v1, Llyiahf/vczjk/yg6;->OooOOOo:Ljava/util/LinkedList;

    invoke-virtual {v3, v4}, Ljava/util/LinkedList;->get(I)Ljava/lang/Object;

    move-result-object v3

    filled-new-array {v2, v3}, [Ljava/lang/Object;

    move-result-object v2

    const-string v3, "Multiple \'as-value\' properties defined (%s vs %s)"

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/yg6;->OooO0oO(Ljava/lang/String;[Ljava/lang/Object;)V

    throw v0

    :cond_3
    :goto_0
    return-object v0
.end method

.method public final OooO0oO()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    iget-object v0, v0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    return-object v0
.end method

.method public final OooO0oo()Ljava/util/List;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/h90;->OooO0o0:Llyiahf/vczjk/hm;

    invoke-virtual {v0}, Llyiahf/vczjk/hm;->oo000o()Llyiahf/vczjk/uqa;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    return-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    const/4 v1, 0x0

    :cond_1
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/rm;

    invoke-virtual {p0, v2}, Llyiahf/vczjk/h90;->OooOO0(Llyiahf/vczjk/rm;)Z

    move-result v3

    if-eqz v3, :cond_1

    if-nez v1, :cond_2

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    :cond_2
    invoke-interface {v1, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_3
    if-nez v1, :cond_4

    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    return-object v0

    :cond_4
    return-object v1
.end method

.method public final OooOO0(Llyiahf/vczjk/rm;)Z
    .locals 3

    iget-object v0, p1, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    invoke-virtual {v0}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/h90;->OooO0oO()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/h90;->OooO0Oo:Llyiahf/vczjk/yn;

    iget-object v1, p0, Llyiahf/vczjk/h90;->OooO0OO:Llyiahf/vczjk/ec5;

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/yn;->OooO0o0(Llyiahf/vczjk/ec5;Llyiahf/vczjk/u34;)Llyiahf/vczjk/a94;

    move-result-object v0

    const/4 v1, 0x1

    if-eqz v0, :cond_1

    sget-object v2, Llyiahf/vczjk/a94;->OooOOO:Llyiahf/vczjk/a94;

    if-eq v0, v2, :cond_1

    goto :goto_0

    :cond_1
    iget-object v0, p1, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    invoke-virtual {v0}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    move-result-object v0

    const-string v2, "valueOf"

    invoke-virtual {v2, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/rm;->o00000()[Ljava/lang/Class;

    move-result-object v2

    array-length v2, v2

    if-ne v2, v1, :cond_2

    goto :goto_0

    :cond_2
    const-string v2, "fromString"

    invoke-virtual {v2, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/rm;->o00000()[Ljava/lang/Class;

    move-result-object v0

    array-length v0, v0

    if-ne v0, v1, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/rm;->o000000o()Ljava/lang/Class;

    move-result-object p1

    const-class v0, Ljava/lang/String;

    if-eq p1, v0, :cond_3

    const-class v0, Ljava/lang/CharSequence;

    invoke-virtual {v0, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result p1

    if-eqz p1, :cond_4

    :cond_3
    :goto_0
    return v1

    :cond_4
    :goto_1
    const/4 p1, 0x0

    return p1
.end method
