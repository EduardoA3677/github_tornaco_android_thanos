.class public final Llyiahf/vczjk/a4a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/a4a;

.field public static final OooOOO0:[Llyiahf/vczjk/x64;

.field public static final OooOOOO:Llyiahf/vczjk/i3a;

.field public static final OooOOOo:Ljava/lang/Class;

.field public static final OooOOo:Ljava/lang/Class;

.field public static final OooOOo0:Ljava/lang/Class;

.field public static final OooOOoo:Ljava/lang/Class;

.field public static final OooOo:Ljava/lang/Class;

.field public static final OooOo0:Ljava/lang/Class;

.field public static final OooOo00:Ljava/lang/Class;

.field public static final OooOo0O:Ljava/lang/Class;

.field public static final OooOo0o:Ljava/lang/Class;

.field public static final OooOoO:Llyiahf/vczjk/ep8;

.field public static final OooOoO0:Llyiahf/vczjk/ep8;

.field public static final OooOoOO:Llyiahf/vczjk/ep8;

.field public static final OooOoo:Llyiahf/vczjk/ep8;

.field public static final OooOoo0:Llyiahf/vczjk/ep8;

.field public static final OooOooO:Llyiahf/vczjk/ep8;

.field public static final OooOooo:Llyiahf/vczjk/ep8;

.field public static final Oooo000:Llyiahf/vczjk/ep8;

.field public static final Oooo00O:Llyiahf/vczjk/ep8;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _classLoader:Ljava/lang/ClassLoader;

.field protected final _modifiers:[Llyiahf/vczjk/r4a;

.field protected final _parser:Llyiahf/vczjk/y4a;

.field protected final _typeCache:Llyiahf/vczjk/kl4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/kl4;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 10

    const/4 v0, 0x0

    new-array v0, v0, [Llyiahf/vczjk/x64;

    sput-object v0, Llyiahf/vczjk/a4a;->OooOOO0:[Llyiahf/vczjk/x64;

    new-instance v0, Llyiahf/vczjk/a4a;

    invoke-direct {v0}, Llyiahf/vczjk/a4a;-><init>()V

    sput-object v0, Llyiahf/vczjk/a4a;->OooOOO:Llyiahf/vczjk/a4a;

    sget-object v0, Llyiahf/vczjk/i3a;->OooOOOO:Llyiahf/vczjk/i3a;

    sput-object v0, Llyiahf/vczjk/a4a;->OooOOOO:Llyiahf/vczjk/i3a;

    const-class v0, Ljava/lang/String;

    sput-object v0, Llyiahf/vczjk/a4a;->OooOOOo:Ljava/lang/Class;

    const-class v1, Ljava/lang/Object;

    sput-object v1, Llyiahf/vczjk/a4a;->OooOOo0:Ljava/lang/Class;

    const-class v2, Ljava/lang/Comparable;

    sput-object v2, Llyiahf/vczjk/a4a;->OooOOo:Ljava/lang/Class;

    const-class v3, Ljava/lang/Class;

    sput-object v3, Llyiahf/vczjk/a4a;->OooOOoo:Ljava/lang/Class;

    const-class v4, Ljava/lang/Enum;

    sput-object v4, Llyiahf/vczjk/a4a;->OooOo00:Ljava/lang/Class;

    const-class v5, Llyiahf/vczjk/qa4;

    sput-object v5, Llyiahf/vczjk/a4a;->OooOo0:Ljava/lang/Class;

    sget-object v6, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    sput-object v6, Llyiahf/vczjk/a4a;->OooOo0O:Ljava/lang/Class;

    sget-object v7, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    sput-object v7, Llyiahf/vczjk/a4a;->OooOo0o:Ljava/lang/Class;

    sget-object v8, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    sput-object v8, Llyiahf/vczjk/a4a;->OooOo:Ljava/lang/Class;

    new-instance v9, Llyiahf/vczjk/ep8;

    invoke-direct {v9, v6}, Llyiahf/vczjk/ep8;-><init>(Ljava/lang/Class;)V

    sput-object v9, Llyiahf/vczjk/a4a;->OooOoO0:Llyiahf/vczjk/ep8;

    new-instance v6, Llyiahf/vczjk/ep8;

    invoke-direct {v6, v7}, Llyiahf/vczjk/ep8;-><init>(Ljava/lang/Class;)V

    sput-object v6, Llyiahf/vczjk/a4a;->OooOoO:Llyiahf/vczjk/ep8;

    new-instance v6, Llyiahf/vczjk/ep8;

    invoke-direct {v6, v8}, Llyiahf/vczjk/ep8;-><init>(Ljava/lang/Class;)V

    sput-object v6, Llyiahf/vczjk/a4a;->OooOoOO:Llyiahf/vczjk/ep8;

    new-instance v6, Llyiahf/vczjk/ep8;

    invoke-direct {v6, v0}, Llyiahf/vczjk/ep8;-><init>(Ljava/lang/Class;)V

    sput-object v6, Llyiahf/vczjk/a4a;->OooOoo0:Llyiahf/vczjk/ep8;

    new-instance v0, Llyiahf/vczjk/ep8;

    invoke-direct {v0, v1}, Llyiahf/vczjk/ep8;-><init>(Ljava/lang/Class;)V

    sput-object v0, Llyiahf/vczjk/a4a;->OooOoo:Llyiahf/vczjk/ep8;

    new-instance v0, Llyiahf/vczjk/ep8;

    invoke-direct {v0, v2}, Llyiahf/vczjk/ep8;-><init>(Ljava/lang/Class;)V

    sput-object v0, Llyiahf/vczjk/a4a;->OooOooO:Llyiahf/vczjk/ep8;

    new-instance v0, Llyiahf/vczjk/ep8;

    invoke-direct {v0, v4}, Llyiahf/vczjk/ep8;-><init>(Ljava/lang/Class;)V

    sput-object v0, Llyiahf/vczjk/a4a;->OooOooo:Llyiahf/vczjk/ep8;

    new-instance v0, Llyiahf/vczjk/ep8;

    invoke-direct {v0, v3}, Llyiahf/vczjk/ep8;-><init>(Ljava/lang/Class;)V

    sput-object v0, Llyiahf/vczjk/a4a;->Oooo000:Llyiahf/vczjk/ep8;

    new-instance v0, Llyiahf/vczjk/ep8;

    invoke-direct {v0, v5}, Llyiahf/vczjk/ep8;-><init>(Ljava/lang/Class;)V

    sput-object v0, Llyiahf/vczjk/a4a;->Oooo00O:Llyiahf/vczjk/ep8;

    return-void
.end method

.method public constructor <init>()V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/kl4;

    const/16 v1, 0x10

    const/16 v2, 0xc8

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/kl4;-><init>(II)V

    iput-object v0, p0, Llyiahf/vczjk/a4a;->_typeCache:Llyiahf/vczjk/kl4;

    new-instance v0, Llyiahf/vczjk/y4a;

    invoke-direct {v0, p0}, Llyiahf/vczjk/y4a;-><init>(Llyiahf/vczjk/a4a;)V

    iput-object v0, p0, Llyiahf/vczjk/a4a;->_parser:Llyiahf/vczjk/y4a;

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/a4a;->_modifiers:[Llyiahf/vczjk/r4a;

    iput-object v0, p0, Llyiahf/vczjk/a4a;->_classLoader:Ljava/lang/ClassLoader;

    return-void
.end method

.method public static OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/ep8;
    .locals 1

    invoke-virtual {p0}, Ljava/lang/Class;->isPrimitive()Z

    move-result v0

    if-eqz v0, :cond_2

    sget-object v0, Llyiahf/vczjk/a4a;->OooOo0O:Ljava/lang/Class;

    if-ne p0, v0, :cond_0

    sget-object p0, Llyiahf/vczjk/a4a;->OooOoO0:Llyiahf/vczjk/ep8;

    return-object p0

    :cond_0
    sget-object v0, Llyiahf/vczjk/a4a;->OooOo0o:Ljava/lang/Class;

    if-ne p0, v0, :cond_1

    sget-object p0, Llyiahf/vczjk/a4a;->OooOoO:Llyiahf/vczjk/ep8;

    return-object p0

    :cond_1
    sget-object v0, Llyiahf/vczjk/a4a;->OooOo:Ljava/lang/Class;

    if-ne p0, v0, :cond_5

    sget-object p0, Llyiahf/vczjk/a4a;->OooOoOO:Llyiahf/vczjk/ep8;

    return-object p0

    :cond_2
    sget-object v0, Llyiahf/vczjk/a4a;->OooOOOo:Ljava/lang/Class;

    if-ne p0, v0, :cond_3

    sget-object p0, Llyiahf/vczjk/a4a;->OooOoo0:Llyiahf/vczjk/ep8;

    return-object p0

    :cond_3
    sget-object v0, Llyiahf/vczjk/a4a;->OooOOo0:Ljava/lang/Class;

    if-ne p0, v0, :cond_4

    sget-object p0, Llyiahf/vczjk/a4a;->OooOoo:Llyiahf/vczjk/ep8;

    return-object p0

    :cond_4
    sget-object v0, Llyiahf/vczjk/a4a;->OooOo0:Ljava/lang/Class;

    if-ne p0, v0, :cond_5

    sget-object p0, Llyiahf/vczjk/a4a;->Oooo00O:Llyiahf/vczjk/ep8;

    return-object p0

    :cond_5
    const/4 p0, 0x0

    return-object p0
.end method

.method public static OooO0o0(Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;)Z
    .locals 6

    instance-of v0, p1, Llyiahf/vczjk/rw6;

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/rw6;

    iput-object p0, p1, Llyiahf/vczjk/rw6;->_actualType:Llyiahf/vczjk/x64;

    return v1

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v2

    const/4 v3, 0x0

    if-eq v0, v2, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/x64;->Oooo0oO()Llyiahf/vczjk/i3a;

    move-result-object p0

    invoke-virtual {p0}, Llyiahf/vczjk/i3a;->OooO0oO()Ljava/util/List;

    move-result-object p0

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->Oooo0oO()Llyiahf/vczjk/i3a;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/i3a;->OooO0oO()Ljava/util/List;

    move-result-object p1

    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result v0

    move v2, v3

    :goto_0
    if-ge v2, v0, :cond_3

    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/x64;

    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/x64;

    invoke-static {v4, v5}, Llyiahf/vczjk/a4a;->OooO0o0(Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;)Z

    move-result v4

    if-nez v4, :cond_2

    :goto_1
    return v3

    :cond_2
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_3
    return v1
.end method

.method public static OooO0oo(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;
    .locals 2

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    if-ne v0, p0, :cond_0

    return-object p1

    :cond_0
    invoke-virtual {p1, p0}, Llyiahf/vczjk/x64;->Oooo0o(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v1

    if-nez v1, :cond_2

    invoke-virtual {p0, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-nez v0, :cond_1

    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    filled-new-array {p0, p1}, [Ljava/lang/Object;

    move-result-object p0

    const-string p1, "Class %s not a super-type of %s"

    invoke-static {p1, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    filled-new-array {p0, p1}, [Ljava/lang/Object;

    move-result-object p0

    const-string p1, "Internal error: class %s not included as super-type for %s"

    invoke-static {p1, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_2
    return-object v1
.end method

.method public static OooOOO(Ljava/lang/Class;Llyiahf/vczjk/x64;)[Llyiahf/vczjk/x64;
    .locals 0

    invoke-virtual {p1, p0}, Llyiahf/vczjk/x64;->Oooo0o(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object p0

    if-nez p0, :cond_0

    sget-object p0, Llyiahf/vczjk/a4a;->OooOOO0:[Llyiahf/vczjk/x64;

    return-object p0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/x64;->Oooo0oO()Llyiahf/vczjk/i3a;

    move-result-object p0

    invoke-virtual {p0}, Llyiahf/vczjk/i3a;->OooO()[Llyiahf/vczjk/x64;

    move-result-object p0

    return-object p0
.end method

.method public static OooOOOO(Ljava/lang/Class;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/a4a;->OooOOOO:Llyiahf/vczjk/i3a;

    invoke-virtual {v0}, Llyiahf/vczjk/i3a;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/a4a;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/ep8;

    move-result-object v1

    if-eqz v1, :cond_0

    return-void

    :cond_0
    new-instance v1, Llyiahf/vczjk/ep8;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v0, v2, v2}, Llyiahf/vczjk/ep8;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;)V

    return-void
.end method

.method public static OooOOOo()Llyiahf/vczjk/ep8;
    .locals 1

    sget-object v0, Llyiahf/vczjk/a4a;->OooOOO:Llyiahf/vczjk/a4a;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/a4a;->OooOoo:Llyiahf/vczjk/ep8;

    return-object v0
.end method


# virtual methods
.method public final OooO(Ljava/lang/Class;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;)Llyiahf/vczjk/wb5;
    .locals 7

    filled-new-array {p2, p3}, [Llyiahf/vczjk/x64;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/i3a;->OooOOO0:[Ljava/lang/String;

    invoke-virtual {p1}, Ljava/lang/Class;->getTypeParameters()[Ljava/lang/reflect/TypeVariable;

    move-result-object v1

    const/4 v2, 0x0

    if-eqz v1, :cond_3

    array-length v3, v1

    if-nez v3, :cond_0

    goto :goto_1

    :cond_0
    array-length v3, v1

    new-array v4, v3, [Ljava/lang/String;

    const/4 v5, 0x0

    :goto_0
    if-ge v5, v3, :cond_1

    aget-object v6, v1, v5

    invoke-interface {v6}, Ljava/lang/reflect/TypeVariable;->getName()Ljava/lang/String;

    move-result-object v6

    aput-object v6, v4, v5

    add-int/lit8 v5, v5, 0x1

    goto :goto_0

    :cond_1
    const/4 v1, 0x2

    if-ne v3, v1, :cond_2

    new-instance v1, Llyiahf/vczjk/i3a;

    invoke-direct {v1, v4, v0, v2}, Llyiahf/vczjk/i3a;-><init>([Ljava/lang/String;[Llyiahf/vczjk/x64;[Ljava/lang/String;)V

    goto :goto_2

    :cond_2
    new-instance p2, Ljava/lang/IllegalArgumentException;

    new-instance p3, Ljava/lang/StringBuilder;

    const-string v0, "Cannot create TypeBindings for class "

    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, " with 2 type parameter"

    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, "s"

    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, ": class expects "

    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p3, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_3
    :goto_1
    sget-object v1, Llyiahf/vczjk/i3a;->OooOOOO:Llyiahf/vczjk/i3a;

    :goto_2
    invoke-virtual {p0, v2, p1, v1}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/wb5;

    invoke-virtual {v1}, Llyiahf/vczjk/i3a;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_6

    const-class v1, Ljava/util/Map;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/e3a;->Oooo0o(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooO0O()Llyiahf/vczjk/x64;

    move-result-object v2

    invoke-virtual {v2, p2}, Llyiahf/vczjk/x64;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object p2

    invoke-virtual {p2, p3}, Llyiahf/vczjk/x64;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_4

    goto :goto_3

    :cond_4
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1, p3, p2}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "Non-generic Map class %s did not resolve to something with value type %s but %s "

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_5
    new-instance p3, Ljava/lang/IllegalArgumentException;

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1, p2, v2}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "Non-generic Map class %s did not resolve to something with key type %s but %s "

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p3, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p3

    :cond_6
    :goto_3
    return-object v0
.end method

.method public final OooO0O0(Llyiahf/vczjk/uqa;Ljava/lang/reflect/Type;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;
    .locals 9

    instance-of v0, p2, Ljava/lang/Class;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    check-cast p2, Ljava/lang/Class;

    sget-object p3, Llyiahf/vczjk/a4a;->OooOOOO:Llyiahf/vczjk/i3a;

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object p1

    goto/16 :goto_3

    :cond_0
    instance-of v0, p2, Ljava/lang/reflect/ParameterizedType;

    if-eqz v0, :cond_7

    check-cast p2, Ljava/lang/reflect/ParameterizedType;

    invoke-interface {p2}, Ljava/lang/reflect/ParameterizedType;->getRawType()Ljava/lang/reflect/Type;

    move-result-object v0

    check-cast v0, Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/a4a;->OooOo00:Ljava/lang/Class;

    if-ne v0, v2, :cond_1

    sget-object p1, Llyiahf/vczjk/a4a;->OooOooo:Llyiahf/vczjk/ep8;

    goto/16 :goto_3

    :cond_1
    sget-object v2, Llyiahf/vczjk/a4a;->OooOOo:Ljava/lang/Class;

    if-ne v0, v2, :cond_2

    sget-object p1, Llyiahf/vczjk/a4a;->OooOooO:Llyiahf/vczjk/ep8;

    goto/16 :goto_3

    :cond_2
    sget-object v2, Llyiahf/vczjk/a4a;->OooOOoo:Ljava/lang/Class;

    if-ne v0, v2, :cond_3

    sget-object p1, Llyiahf/vczjk/a4a;->Oooo000:Llyiahf/vczjk/ep8;

    goto/16 :goto_3

    :cond_3
    invoke-interface {p2}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    move-result-object p2

    if-nez p2, :cond_4

    move v2, v1

    goto :goto_0

    :cond_4
    array-length v2, p2

    :goto_0
    if-nez v2, :cond_5

    sget-object p2, Llyiahf/vczjk/a4a;->OooOOOO:Llyiahf/vczjk/i3a;

    goto :goto_2

    :cond_5
    new-array v3, v2, [Llyiahf/vczjk/x64;

    move v4, v1

    :goto_1
    if-ge v4, v2, :cond_6

    aget-object v5, p2, v4

    invoke-virtual {p0, p1, v5, p3}, Llyiahf/vczjk/a4a;->OooO0O0(Llyiahf/vczjk/uqa;Ljava/lang/reflect/Type;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object v5

    aput-object v5, v3, v4

    add-int/lit8 v4, v4, 0x1

    goto :goto_1

    :cond_6
    invoke-static {v0, v3}, Llyiahf/vczjk/i3a;->OooO0Oo(Ljava/lang/Class;[Llyiahf/vczjk/x64;)Llyiahf/vczjk/i3a;

    move-result-object p2

    :goto_2
    invoke-virtual {p0, p1, v0, p2}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object p1

    goto/16 :goto_3

    :cond_7
    instance-of v0, p2, Llyiahf/vczjk/x64;

    if-eqz v0, :cond_8

    check-cast p2, Llyiahf/vczjk/x64;

    return-object p2

    :cond_8
    instance-of v0, p2, Ljava/lang/reflect/GenericArrayType;

    if-eqz v0, :cond_9

    check-cast p2, Ljava/lang/reflect/GenericArrayType;

    invoke-interface {p2}, Ljava/lang/reflect/GenericArrayType;->getGenericComponentType()Ljava/lang/reflect/Type;

    move-result-object p2

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/a4a;->OooO0O0(Llyiahf/vczjk/uqa;Ljava/lang/reflect/Type;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object v3

    sget p1, Llyiahf/vczjk/oy;->OooOOOO:I

    invoke-virtual {v3}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p1

    invoke-static {p1, v1}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;I)Ljava/lang/Object;

    move-result-object v5

    new-instance v2, Llyiahf/vczjk/oy;

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    move-object v4, p3

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/oy;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/i3a;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    move-object p1, v2

    goto :goto_3

    :cond_9
    move-object v4, p3

    instance-of p3, p2, Ljava/lang/reflect/TypeVariable;

    if-eqz p3, :cond_d

    check-cast p2, Ljava/lang/reflect/TypeVariable;

    invoke-interface {p2}, Ljava/lang/reflect/TypeVariable;->getName()Ljava/lang/String;

    move-result-object p3

    if-eqz v4, :cond_c

    invoke-virtual {v4, p3}, Llyiahf/vczjk/i3a;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/x64;

    move-result-object v0

    if-eqz v0, :cond_a

    move-object p1, v0

    goto :goto_3

    :cond_a
    invoke-virtual {v4, p3}, Llyiahf/vczjk/i3a;->OooO0oo(Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_b

    sget-object p1, Llyiahf/vczjk/a4a;->OooOoo:Llyiahf/vczjk/ep8;

    goto :goto_3

    :cond_b
    invoke-virtual {v4, p3}, Llyiahf/vczjk/i3a;->OooOO0(Ljava/lang/String;)Llyiahf/vczjk/i3a;

    move-result-object p3

    monitor-enter p2

    :try_start_0
    invoke-interface {p2}, Ljava/lang/reflect/TypeVariable;->getBounds()[Ljava/lang/reflect/Type;

    move-result-object v0

    monitor-exit p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    aget-object p2, v0, v1

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/a4a;->OooO0O0(Llyiahf/vczjk/uqa;Ljava/lang/reflect/Type;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object p1

    goto :goto_3

    :catchall_0
    move-exception v0

    move-object p1, v0

    :try_start_1
    monitor-exit p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1

    :cond_c
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "Null `bindings` passed (type variable \""

    const-string v0, "\")"

    invoke-static {p2, p3, v0}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_d
    instance-of p3, p2, Ljava/lang/reflect/WildcardType;

    if-eqz p3, :cond_10

    check-cast p2, Ljava/lang/reflect/WildcardType;

    invoke-interface {p2}, Ljava/lang/reflect/WildcardType;->getUpperBounds()[Ljava/lang/reflect/Type;

    move-result-object p2

    aget-object p2, p2, v1

    invoke-virtual {p0, p1, p2, v4}, Llyiahf/vczjk/a4a;->OooO0O0(Llyiahf/vczjk/uqa;Ljava/lang/reflect/Type;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object p1

    :goto_3
    iget-object p2, p0, Llyiahf/vczjk/a4a;->_modifiers:[Llyiahf/vczjk/r4a;

    if-nez p2, :cond_e

    goto :goto_4

    :cond_e
    invoke-virtual {p1}, Llyiahf/vczjk/x64;->Oooo0oO()Llyiahf/vczjk/i3a;

    iget-object p2, p0, Llyiahf/vczjk/a4a;->_modifiers:[Llyiahf/vczjk/r4a;

    array-length p3, p2

    if-gtz p3, :cond_f

    :goto_4
    return-object p1

    :cond_f
    aget-object p1, p2, v1

    const/4 p1, 0x0

    throw p1

    :cond_10
    new-instance p1, Ljava/lang/IllegalArgumentException;

    new-instance p3, Ljava/lang/StringBuilder;

    const-string v0, "Unrecognized Type: "

    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    if-nez p2, :cond_11

    const-string p2, "[null]"

    goto :goto_5

    :cond_11
    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p2

    :goto_5
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;
    .locals 19

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move-object/from16 v3, p3

    const/4 v11, 0x1

    invoke-static {v2}, Llyiahf/vczjk/a4a;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/ep8;

    move-result-object v4

    if-eqz v4, :cond_0

    return-object v4

    :cond_0
    if-eqz v3, :cond_2

    invoke-virtual {v3}, Llyiahf/vczjk/i3a;->isEmpty()Z

    move-result v4

    if-eqz v4, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {v3, v2}, Llyiahf/vczjk/i3a;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/g3a;

    move-result-object v4

    move-object v12, v4

    goto :goto_1

    :cond_2
    :goto_0
    move-object v12, v2

    :goto_1
    iget-object v4, v0, Llyiahf/vczjk/a4a;->_typeCache:Llyiahf/vczjk/kl4;

    iget-object v4, v4, Llyiahf/vczjk/kl4;->OooOOO:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v4, v12}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/x64;

    if-eqz v4, :cond_3

    return-object v4

    :cond_3
    const/4 v13, 0x0

    if-nez v1, :cond_4

    new-instance v1, Llyiahf/vczjk/uqa;

    invoke-direct {v1, v13, v2}, Llyiahf/vczjk/uqa;-><init>(Llyiahf/vczjk/uqa;Ljava/lang/Class;)V

    move-object v14, v1

    goto :goto_4

    :cond_4
    iget-object v5, v1, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v5, Ljava/lang/Class;

    if-ne v5, v2, :cond_5

    move-object v10, v1

    goto :goto_3

    :cond_5
    iget-object v5, v1, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    :goto_2
    check-cast v5, Llyiahf/vczjk/uqa;

    if-eqz v5, :cond_7

    iget-object v6, v5, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v6, Ljava/lang/Class;

    if-ne v6, v2, :cond_6

    move-object v10, v5

    goto :goto_3

    :cond_6
    iget-object v5, v5, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    goto :goto_2

    :cond_7
    move-object v10, v13

    :goto_3
    if-eqz v10, :cond_9

    new-instance v1, Llyiahf/vczjk/qr7;

    const/4 v8, 0x0

    const/4 v9, 0x0

    sget-object v3, Llyiahf/vczjk/a4a;->OooOOOO:Llyiahf/vczjk/i3a;

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    invoke-direct/range {v1 .. v9}, Llyiahf/vczjk/e3a;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;ILjava/lang/Object;Ljava/lang/Object;Z)V

    iget-object v2, v10, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Ljava/util/ArrayList;

    if-nez v2, :cond_8

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    iput-object v2, v10, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    :cond_8
    iget-object v2, v10, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-object v1

    :cond_9
    new-instance v5, Llyiahf/vczjk/uqa;

    invoke-direct {v5, v1, v2}, Llyiahf/vczjk/uqa;-><init>(Llyiahf/vczjk/uqa;Ljava/lang/Class;)V

    move-object v14, v5

    :goto_4
    invoke-virtual {v2}, Ljava/lang/Class;->isArray()Z

    move-result v1

    const/4 v15, 0x0

    if-eqz v1, :cond_a

    invoke-virtual {v2}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v0, v14, v1, v3}, Llyiahf/vczjk/a4a;->OooO0O0(Llyiahf/vczjk/uqa;Ljava/lang/reflect/Type;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object v2

    sget v1, Llyiahf/vczjk/oy;->OooOOOO:I

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v1

    invoke-static {v1, v15}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;I)Ljava/lang/Object;

    move-result-object v4

    new-instance v1, Llyiahf/vczjk/oy;

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/oy;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/i3a;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    goto/16 :goto_12

    :cond_a
    invoke-virtual {v2}, Ljava/lang/Class;->isInterface()Z

    move-result v1

    if-eqz v1, :cond_b

    invoke-virtual {v0, v14, v2, v3}, Llyiahf/vczjk/a4a;->OooO0Oo(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)[Llyiahf/vczjk/x64;

    move-result-object v1

    move-object v5, v1

    move-object v1, v13

    goto :goto_6

    :cond_b
    sget-object v1, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    invoke-virtual {v2}, Ljava/lang/Class;->getGenericSuperclass()Ljava/lang/reflect/Type;

    move-result-object v1

    if-nez v1, :cond_c

    move-object v1, v13

    goto :goto_5

    :cond_c
    invoke-virtual {v0, v14, v1, v3}, Llyiahf/vczjk/a4a;->OooO0O0(Llyiahf/vczjk/uqa;Ljava/lang/reflect/Type;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object v1

    :goto_5
    invoke-virtual {v0, v14, v2, v3}, Llyiahf/vczjk/a4a;->OooO0Oo(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)[Llyiahf/vczjk/x64;

    move-result-object v5

    :goto_6
    sget-object v6, Llyiahf/vczjk/a4a;->OooOoo0:Llyiahf/vczjk/ep8;

    const-class v7, Ljava/util/Properties;

    if-ne v2, v7, :cond_d

    move-object v4, v1

    new-instance v1, Llyiahf/vczjk/wb5;

    const/4 v10, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    move-object/from16 v16, v7

    move-object v7, v6

    move-object/from16 v13, v16

    invoke-direct/range {v1 .. v10}, Llyiahf/vczjk/ub5;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Ljava/lang/Object;Ljava/lang/Object;Z)V

    move-object/from16 v18, v3

    move-object v3, v2

    move-object/from16 v2, v18

    goto :goto_7

    :cond_d
    move-object v13, v4

    move-object v4, v1

    move-object v1, v13

    move-object v13, v3

    move-object v3, v2

    move-object v2, v13

    move-object v13, v7

    if-eqz v4, :cond_e

    invoke-virtual {v4, v3, v2, v4, v5}, Llyiahf/vczjk/x64;->o00o0O(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object v1

    :cond_e
    :goto_7
    if-nez v1, :cond_1e

    if-nez v2, :cond_f

    sget-object v1, Llyiahf/vczjk/a4a;->OooOOOO:Llyiahf/vczjk/i3a;

    goto :goto_8

    :cond_f
    move-object v1, v2

    :goto_8
    sget-object v7, Llyiahf/vczjk/a4a;->OooOoo:Llyiahf/vczjk/ep8;

    const-class v8, Ljava/util/Map;

    if-ne v3, v8, :cond_14

    if-ne v3, v13, :cond_10

    move-object v3, v1

    move-object v7, v6

    goto :goto_a

    :cond_10
    invoke-virtual {v1}, Llyiahf/vczjk/i3a;->OooO0oO()Ljava/util/List;

    move-result-object v6

    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v8

    if-eqz v8, :cond_13

    const/4 v7, 0x2

    if-eq v8, v7, :cond_12

    new-instance v2, Ljava/lang/IllegalArgumentException;

    invoke-static {v3}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v3

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    if-ne v8, v11, :cond_11

    const-string v5, ""

    goto :goto_9

    :cond_11
    const-string v5, "s"

    :goto_9
    filled-new-array {v3, v4, v5, v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v3, "Strange Map type %s with %d type parameter%s (%s), can not resolve"

    invoke-static {v3, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {v2, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v2

    :cond_12
    invoke-interface {v6, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/x64;

    invoke-interface {v6, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/x64;

    move-object v3, v7

    move-object v7, v6

    move-object v6, v3

    move-object v3, v1

    goto :goto_a

    :cond_13
    move-object v3, v1

    move-object v6, v7

    :goto_a
    new-instance v1, Llyiahf/vczjk/wb5;

    const/4 v10, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    move-object v13, v2

    move-object/from16 v2, p2

    invoke-direct/range {v1 .. v10}, Llyiahf/vczjk/ub5;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Ljava/lang/Object;Ljava/lang/Object;Z)V

    goto/16 :goto_f

    :cond_14
    move-object v13, v2

    move-object v2, v3

    move-object v3, v1

    const-class v1, Ljava/util/Collection;

    const-string v6, ": cannot determine type parameters"

    if-ne v2, v1, :cond_17

    invoke-virtual {v3}, Llyiahf/vczjk/i3a;->OooO0oO()Ljava/util/List;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    move-result v8

    if-eqz v8, :cond_15

    :goto_b
    move-object v6, v7

    goto :goto_c

    :cond_15
    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v7

    if-ne v7, v11, :cond_16

    invoke-interface {v1, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    move-object v7, v1

    check-cast v7, Llyiahf/vczjk/x64;

    goto :goto_b

    :goto_c
    new-instance v1, Llyiahf/vczjk/a21;

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v7, 0x0

    invoke-direct/range {v1 .. v9}, Llyiahf/vczjk/w11;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Ljava/lang/Object;Ljava/lang/Object;Z)V

    goto :goto_f

    :cond_16
    new-instance v1, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Strange Collection type "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-static {v2, v3, v6}, Llyiahf/vczjk/ii5;->OooO0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_17
    const-class v1, Ljava/util/concurrent/atomic/AtomicReference;

    if-ne v2, v1, :cond_1a

    invoke-virtual {v3}, Llyiahf/vczjk/i3a;->OooO0oO()Ljava/util/List;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    move-result v8

    if-eqz v8, :cond_18

    :goto_d
    move-object v6, v7

    goto :goto_e

    :cond_18
    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v7

    if-ne v7, v11, :cond_19

    invoke-interface {v1, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    move-object v7, v1

    check-cast v7, Llyiahf/vczjk/x64;

    goto :goto_d

    :goto_e
    new-instance v1, Llyiahf/vczjk/nl7;

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    invoke-direct/range {v1 .. v10}, Llyiahf/vczjk/nl7;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Ljava/lang/Object;Ljava/lang/Object;Z)V

    goto :goto_f

    :cond_19
    new-instance v1, Ljava/lang/IllegalArgumentException;

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Strange Reference type "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-static {v2, v3, v6}, Llyiahf/vczjk/ii5;->OooO0oo(Ljava/lang/Class;Ljava/lang/StringBuilder;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1a
    const/4 v1, 0x0

    :goto_f
    if-nez v1, :cond_1e

    array-length v1, v5

    :goto_10
    if-ge v15, v1, :cond_1c

    aget-object v3, v5, v15

    invoke-virtual {v3, v2, v13, v4, v5}, Llyiahf/vczjk/x64;->o00o0O(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object v3

    if-eqz v3, :cond_1b

    move-object/from16 v17, v3

    goto :goto_11

    :cond_1b
    add-int/2addr v15, v11

    goto :goto_10

    :cond_1c
    const/16 v17, 0x0

    :goto_11
    if-nez v17, :cond_1d

    new-instance v1, Llyiahf/vczjk/ep8;

    invoke-direct {v1, v2, v13, v4, v5}, Llyiahf/vczjk/ep8;-><init>(Ljava/lang/Class;Llyiahf/vczjk/i3a;Llyiahf/vczjk/x64;[Llyiahf/vczjk/x64;)V

    goto :goto_12

    :cond_1d
    move-object/from16 v1, v17

    :cond_1e
    :goto_12
    iget-object v2, v14, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Ljava/util/ArrayList;

    if-eqz v2, :cond_20

    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_13
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_20

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/qr7;

    iget-object v4, v3, Llyiahf/vczjk/qr7;->_referencedType:Llyiahf/vczjk/x64;

    if-nez v4, :cond_1f

    iput-object v1, v3, Llyiahf/vczjk/qr7;->_referencedType:Llyiahf/vczjk/x64;

    goto :goto_13

    :cond_1f
    new-instance v2, Ljava/lang/IllegalStateException;

    new-instance v4, Ljava/lang/StringBuilder;

    const-string v5, "Trying to re-set self reference; old value = "

    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v3, v3, Llyiahf/vczjk/qr7;->_referencedType:Llyiahf/vczjk/x64;

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v3, ", new = "

    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v2, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v2

    :cond_20
    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooOoo()Z

    move-result v2

    if-nez v2, :cond_21

    iget-object v2, v0, Llyiahf/vczjk/a4a;->_typeCache:Llyiahf/vczjk/kl4;

    invoke-virtual {v2, v1, v12}, Llyiahf/vczjk/kl4;->OooO0O0(Ljava/io/Serializable;Ljava/lang/Object;)V

    :cond_21
    return-object v1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)[Llyiahf/vczjk/x64;
    .locals 4

    sget-object v0, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    invoke-virtual {p2}, Ljava/lang/Class;->getGenericInterfaces()[Ljava/lang/reflect/Type;

    move-result-object p2

    if-eqz p2, :cond_2

    array-length v0, p2

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    array-length v0, p2

    new-array v1, v0, [Llyiahf/vczjk/x64;

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v0, :cond_1

    aget-object v3, p2, v2

    invoke-virtual {p0, p1, v3, p3}, Llyiahf/vczjk/a4a;->OooO0O0(Llyiahf/vczjk/uqa;Ljava/lang/reflect/Type;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object v3

    aput-object v3, v1, v2

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    return-object v1

    :cond_2
    :goto_1
    sget-object p1, Llyiahf/vczjk/a4a;->OooOOO0:[Llyiahf/vczjk/x64;

    return-object p1
.end method

.method public final OooO0o(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/a21;
    .locals 5

    sget-object v0, Llyiahf/vczjk/i3a;->OooOOO0:[Ljava/lang/String;

    invoke-virtual {p1}, Ljava/lang/Class;->getTypeParameters()[Ljava/lang/reflect/TypeVariable;

    move-result-object v0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    move v2, v1

    goto :goto_0

    :cond_0
    array-length v2, v0

    :goto_0
    const/4 v3, 0x0

    if-nez v2, :cond_1

    sget-object v0, Llyiahf/vczjk/i3a;->OooOOOO:Llyiahf/vczjk/i3a;

    goto :goto_1

    :cond_1
    const/4 v4, 0x1

    if-ne v2, v4, :cond_4

    new-instance v2, Llyiahf/vczjk/i3a;

    aget-object v0, v0, v1

    invoke-interface {v0}, Ljava/lang/reflect/TypeVariable;->getName()Ljava/lang/String;

    move-result-object v0

    filled-new-array {v0}, [Ljava/lang/String;

    move-result-object v0

    filled-new-array {p2}, [Llyiahf/vczjk/x64;

    move-result-object v1

    invoke-direct {v2, v0, v1, v3}, Llyiahf/vczjk/i3a;-><init>([Ljava/lang/String;[Llyiahf/vczjk/x64;[Ljava/lang/String;)V

    move-object v0, v2

    :goto_1
    invoke-virtual {p0, v3, p1, v0}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/a21;

    invoke-virtual {v0}, Llyiahf/vczjk/i3a;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_3

    if-eqz p2, :cond_3

    const-class v0, Ljava/util/Collection;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/e3a;->Oooo0o(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v0

    invoke-virtual {v0, p2}, Llyiahf/vczjk/x64;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_2

    goto :goto_2

    :cond_2
    new-instance v1, Ljava/lang/IllegalArgumentException;

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1, p2, v0}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "Non-generic Collection class %s did not resolve to something with element type %s but %s "

    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {v1, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_3
    :goto_2
    return-object v1

    :cond_4
    new-instance p2, Ljava/lang/IllegalArgumentException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Cannot create TypeBindings for class "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, " with 1 type parameter: class expects "

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2
.end method

.method public final OooO0oO(Ljava/lang/String;)Llyiahf/vczjk/x64;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/a4a;->_parser:Llyiahf/vczjk/y4a;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/x4a;

    invoke-virtual {p1}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v1, p1}, Llyiahf/vczjk/x4a;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/y4a;->OooO0O0(Llyiahf/vczjk/x4a;)Llyiahf/vczjk/x64;

    move-result-object p1

    invoke-virtual {v1}, Llyiahf/vczjk/x4a;->hasMoreTokens()Z

    move-result v0

    if-nez v0, :cond_0

    return-object p1

    :cond_0
    const-string p1, "Unexpected tokens after complete type"

    invoke-static {v1, p1}, Llyiahf/vczjk/y4a;->OooO00o(Llyiahf/vczjk/x4a;Ljava/lang/String;)Ljava/lang/IllegalArgumentException;

    move-result-object p1

    throw p1
.end method

.method public final OooOO0(Llyiahf/vczjk/x64;Ljava/lang/Class;Z)Llyiahf/vczjk/x64;
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v3

    if-ne v3, v2, :cond_0

    goto :goto_0

    :cond_0
    const-class v4, Ljava/lang/Object;

    sget-object v5, Llyiahf/vczjk/a4a;->OooOOOO:Llyiahf/vczjk/i3a;

    const/4 v6, 0x0

    if-ne v3, v4, :cond_1

    invoke-virtual {v0, v6, v2, v5}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object v2

    goto/16 :goto_9

    :cond_1
    invoke-virtual {v3, v2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v7

    if-eqz v7, :cond_15

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OooooOo()Z

    move-result v7

    if-eqz v7, :cond_6

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->ooOO()Z

    move-result v7

    if-eqz v7, :cond_3

    const-class v3, Ljava/util/HashMap;

    if-eq v2, v3, :cond_2

    const-class v3, Ljava/util/LinkedHashMap;

    if-eq v2, v3, :cond_2

    const-class v3, Ljava/util/EnumMap;

    if-eq v2, v3, :cond_2

    const-class v3, Ljava/util/TreeMap;

    if-ne v2, v3, :cond_6

    :cond_2
    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooO0O()Llyiahf/vczjk/x64;

    move-result-object v3

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v4

    invoke-static {v2, v3, v4}, Llyiahf/vczjk/i3a;->OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;)Llyiahf/vczjk/i3a;

    move-result-object v3

    invoke-virtual {v0, v6, v2, v3}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object v2

    goto/16 :goto_9

    :cond_3
    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OooooO0()Z

    move-result v7

    if-eqz v7, :cond_6

    const-class v7, Ljava/util/ArrayList;

    if-eq v2, v7, :cond_5

    const-class v7, Ljava/util/LinkedList;

    if-eq v2, v7, :cond_5

    const-class v7, Ljava/util/HashSet;

    if-eq v2, v7, :cond_5

    const-class v7, Ljava/util/TreeSet;

    if-ne v2, v7, :cond_4

    goto :goto_1

    :cond_4
    const-class v7, Ljava/util/EnumSet;

    if-ne v3, v7, :cond_6

    :goto_0
    return-object v1

    :cond_5
    :goto_1
    invoke-virtual {v1}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v3

    invoke-static {v2, v3}, Llyiahf/vczjk/i3a;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/i3a;

    move-result-object v3

    invoke-virtual {v0, v6, v2, v3}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object v2

    goto/16 :goto_9

    :cond_6
    invoke-virtual {v1}, Llyiahf/vczjk/x64;->Oooo0oO()Llyiahf/vczjk/i3a;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/i3a;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_7

    invoke-virtual {v0, v6, v2, v5}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object v2

    goto/16 :goto_9

    :cond_7
    invoke-virtual {v2}, Ljava/lang/Class;->getTypeParameters()[Ljava/lang/reflect/TypeVariable;

    move-result-object v3

    array-length v3, v3

    if-nez v3, :cond_8

    invoke-virtual {v0, v6, v2, v5}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object v2

    goto/16 :goto_9

    :cond_8
    new-array v5, v3, [Llyiahf/vczjk/rw6;

    const/4 v7, 0x0

    move v8, v7

    :goto_2
    if-ge v8, v3, :cond_9

    new-instance v9, Llyiahf/vczjk/rw6;

    invoke-direct {v9, v8}, Llyiahf/vczjk/rw6;-><init>(I)V

    aput-object v9, v5, v8

    add-int/lit8 v8, v8, 0x1

    goto :goto_2

    :cond_9
    invoke-static {v2, v5}, Llyiahf/vczjk/i3a;->OooO0Oo(Ljava/lang/Class;[Llyiahf/vczjk/x64;)Llyiahf/vczjk/i3a;

    move-result-object v8

    invoke-virtual {v0, v6, v2, v8}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object v8

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v9

    invoke-virtual {v8, v9}, Llyiahf/vczjk/x64;->Oooo0o(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v8

    if-eqz v8, :cond_14

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->Oooo0oO()Llyiahf/vczjk/i3a;

    move-result-object v9

    invoke-virtual {v9}, Llyiahf/vczjk/i3a;->OooO0oO()Ljava/util/List;

    move-result-object v9

    invoke-virtual {v8}, Llyiahf/vczjk/x64;->Oooo0oO()Llyiahf/vczjk/i3a;

    move-result-object v8

    invoke-virtual {v8}, Llyiahf/vczjk/i3a;->OooO0oO()Ljava/util/List;

    move-result-object v8

    invoke-interface {v8}, Ljava/util/List;->size()I

    move-result v10

    invoke-interface {v9}, Ljava/util/List;->size()I

    move-result v11

    move v12, v7

    :goto_3
    if-ge v12, v11, :cond_f

    invoke-interface {v9, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/x64;

    if-ge v12, v10, :cond_a

    invoke-interface {v8, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/x64;

    goto :goto_4

    :cond_a
    invoke-static {}, Llyiahf/vczjk/a4a;->OooOOOo()Llyiahf/vczjk/ep8;

    move-result-object v14

    :goto_4
    invoke-static {v13, v14}, Llyiahf/vczjk/a4a;->OooO0o0(Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;)Z

    move-result v15

    if-nez v15, :cond_e

    invoke-virtual {v13, v4}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v15

    if-eqz v15, :cond_b

    goto :goto_5

    :cond_b
    if-nez v12, :cond_c

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->ooOO()Z

    move-result v15

    if-eqz v15, :cond_c

    invoke-virtual {v14, v4}, Llyiahf/vczjk/x64;->Ooooo00(Ljava/lang/Class;)Z

    move-result v15

    if-eqz v15, :cond_c

    goto :goto_5

    :cond_c
    invoke-virtual {v13}, Llyiahf/vczjk/x64;->Ooooooo()Z

    move-result v15

    if-eqz v15, :cond_d

    invoke-virtual {v14}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v15

    invoke-virtual {v13, v15}, Llyiahf/vczjk/x64;->o00Ooo(Ljava/lang/Class;)Z

    move-result v15

    if-eqz v15, :cond_d

    goto :goto_5

    :cond_d
    add-int/lit8 v12, v12, 0x1

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    check-cast v13, Llyiahf/vczjk/e3a;

    invoke-virtual {v13}, Llyiahf/vczjk/e3a;->o0OO00O()Ljava/lang/String;

    move-result-object v9

    check-cast v14, Llyiahf/vczjk/e3a;

    invoke-virtual {v14}, Llyiahf/vczjk/e3a;->o0OO00O()Ljava/lang/String;

    move-result-object v10

    filled-new-array {v4, v8, v9, v10}, [Ljava/lang/Object;

    move-result-object v4

    const-string v8, "Type parameter #%d/%d differs; can not specialize %s with %s"

    invoke-static {v8, v4}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v4

    goto :goto_6

    :cond_e
    :goto_5
    add-int/lit8 v12, v12, 0x1

    goto :goto_3

    :cond_f
    move-object v4, v6

    :goto_6
    if-eqz v4, :cond_11

    if-eqz p3, :cond_10

    goto :goto_7

    :cond_10
    new-instance v3, Ljava/lang/IllegalArgumentException;

    new-instance v5, Ljava/lang/StringBuilder;

    const-string v6, "Failed to specialize base type "

    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    check-cast v1, Llyiahf/vczjk/e3a;

    invoke-virtual {v1}, Llyiahf/vczjk/e3a;->o0OO00O()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " as "

    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ", problem: "

    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v3, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v3

    :cond_11
    :goto_7
    new-array v4, v3, [Llyiahf/vczjk/x64;

    :goto_8
    if-ge v7, v3, :cond_13

    aget-object v8, v5, v7

    iget-object v8, v8, Llyiahf/vczjk/rw6;->_actualType:Llyiahf/vczjk/x64;

    if-nez v8, :cond_12

    invoke-static {}, Llyiahf/vczjk/a4a;->OooOOOo()Llyiahf/vczjk/ep8;

    move-result-object v8

    :cond_12
    aput-object v8, v4, v7

    add-int/lit8 v7, v7, 0x1

    goto :goto_8

    :cond_13
    invoke-static {v2, v4}, Llyiahf/vczjk/i3a;->OooO0Oo(Ljava/lang/Class;[Llyiahf/vczjk/x64;)Llyiahf/vczjk/i3a;

    move-result-object v3

    invoke-virtual {v0, v6, v2, v3}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object v2

    :goto_9
    invoke-virtual {v2, v1}, Llyiahf/vczjk/x64;->o0ooOO0(Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object v1

    return-object v1

    :cond_14
    new-instance v3, Ljava/lang/IllegalArgumentException;

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    const-string v4, "Internal error: unable to locate supertype ("

    const-string v5, ") from resolved subtype "

    invoke-static {v4, v1, v5, v2}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {v3, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v3

    :cond_15
    new-instance v3, Ljava/lang/IllegalArgumentException;

    invoke-static {v2}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v2

    invoke-static {v1}, Llyiahf/vczjk/vy0;->OooOOOo(Llyiahf/vczjk/x64;)Ljava/lang/String;

    move-result-object v1

    const-string v4, "Class "

    const-string v5, " not subtype of "

    invoke-static {v4, v2, v5, v1}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-direct {v3, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v3
.end method

.method public final OooOO0O(Ljava/lang/reflect/Type;)Llyiahf/vczjk/x64;
    .locals 2

    const/4 v0, 0x0

    sget-object v1, Llyiahf/vczjk/a4a;->OooOOOO:Llyiahf/vczjk/i3a;

    invoke-virtual {p0, v0, p1, v1}, Llyiahf/vczjk/a4a;->OooO0O0(Llyiahf/vczjk/uqa;Ljava/lang/reflect/Type;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0o(Ljava/lang/reflect/Type;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;
    .locals 2

    instance-of v0, p1, Ljava/lang/Class;

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    check-cast p1, Ljava/lang/Class;

    invoke-virtual {p0, v1, p1, p2}, Llyiahf/vczjk/a4a;->OooO0OO(Llyiahf/vczjk/uqa;Ljava/lang/Class;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/a4a;->_modifiers:[Llyiahf/vczjk/r4a;

    if-nez p2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/x64;->Oooo0oO()Llyiahf/vczjk/i3a;

    iget-object p2, p0, Llyiahf/vczjk/a4a;->_modifiers:[Llyiahf/vczjk/r4a;

    array-length v0, p2

    if-gtz v0, :cond_1

    :goto_0
    return-object p1

    :cond_1
    const/4 p1, 0x0

    aget-object p1, p2, p1

    throw v1

    :cond_2
    invoke-virtual {p0, v1, p1, p2}, Llyiahf/vczjk/a4a;->OooO0O0(Llyiahf/vczjk/uqa;Ljava/lang/reflect/Type;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object p1

    return-object p1
.end method

.method public final OooOOO0(Ljava/lang/String;)Ljava/lang/Class;
    .locals 2

    const/16 v0, 0x2e

    invoke-virtual {p1, v0}, Ljava/lang/String;->indexOf(I)I

    move-result v0

    const/4 v1, 0x0

    if-gez v0, :cond_9

    const-string v0, "int"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    sget-object v0, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    goto :goto_0

    :cond_0
    const-string v0, "long"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    sget-object v0, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    goto :goto_0

    :cond_1
    const-string v0, "float"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    sget-object v0, Ljava/lang/Float;->TYPE:Ljava/lang/Class;

    goto :goto_0

    :cond_2
    const-string v0, "double"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_3

    sget-object v0, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    goto :goto_0

    :cond_3
    const-string v0, "boolean"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_4

    sget-object v0, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    goto :goto_0

    :cond_4
    const-string v0, "byte"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_5

    sget-object v0, Ljava/lang/Byte;->TYPE:Ljava/lang/Class;

    goto :goto_0

    :cond_5
    const-string v0, "char"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_6

    sget-object v0, Ljava/lang/Character;->TYPE:Ljava/lang/Class;

    goto :goto_0

    :cond_6
    const-string v0, "short"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_7

    sget-object v0, Ljava/lang/Short;->TYPE:Ljava/lang/Class;

    goto :goto_0

    :cond_7
    const-string v0, "void"

    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_8

    sget-object v0, Ljava/lang/Void;->TYPE:Ljava/lang/Class;

    goto :goto_0

    :cond_8
    move-object v0, v1

    :goto_0
    if-eqz v0, :cond_9

    return-object v0

    :cond_9
    iget-object v0, p0, Llyiahf/vczjk/a4a;->_classLoader:Ljava/lang/ClassLoader;

    if-nez v0, :cond_a

    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Thread;->getContextClassLoader()Ljava/lang/ClassLoader;

    move-result-object v0

    :cond_a
    if-eqz v0, :cond_b

    const/4 v1, 0x1

    :try_start_0
    invoke-static {p1, v1, v0}, Ljava/lang/Class;->forName(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooOOOO(Ljava/lang/Exception;)Ljava/lang/Throwable;

    move-result-object v1

    :cond_b
    :try_start_1
    invoke-static {p1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object p1
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    return-object p1

    :catch_1
    move-exception p1

    if-nez v1, :cond_c

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOOOO(Ljava/lang/Exception;)Ljava/lang/Throwable;

    move-result-object v1

    :cond_c
    invoke-static {v1}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    new-instance p1, Ljava/lang/ClassNotFoundException;

    invoke-virtual {v1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0, v1}, Ljava/lang/ClassNotFoundException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw p1
.end method
