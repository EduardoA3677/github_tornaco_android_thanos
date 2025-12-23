.class public final Llyiahf/vczjk/q82;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooOO0:[Llyiahf/vczjk/th4;


# instance fields
.field public final synthetic OooO:Llyiahf/vczjk/r82;

.field public final OooO00o:Ljava/util/LinkedHashMap;

.field public final OooO0O0:Ljava/util/LinkedHashMap;

.field public final OooO0OO:Ljava/util/LinkedHashMap;

.field public final OooO0Oo:Llyiahf/vczjk/l45;

.field public final OooO0o:Llyiahf/vczjk/r60;

.field public final OooO0o0:Llyiahf/vczjk/l45;

.field public final OooO0oO:Llyiahf/vczjk/o45;

.field public final OooO0oo:Llyiahf/vczjk/o45;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/q82;

    const-string v2, "functionNames"

    const-string v3, "getFunctionNames()Ljava/util/Set;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v2, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const-string v3, "variableNames"

    const-string v5, "getVariableNames()Ljava/util/Set;"

    invoke-static {v1, v3, v5, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v1

    const/4 v2, 0x2

    new-array v2, v2, [Llyiahf/vczjk/th4;

    aput-object v0, v2, v4

    const/4 v0, 0x1

    aput-object v1, v2, v0

    sput-object v2, Llyiahf/vczjk/q82;->OooOO0:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/r82;Ljava/util/List;Ljava/util/List;Ljava/util/List;)V
    .locals 4

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/q82;->OooO:Llyiahf/vczjk/r82;

    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/pi5;

    iget-object v3, p1, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object v3, v3, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/rt5;

    check-cast v2, Llyiahf/vczjk/pc7;

    invoke-virtual {v2}, Llyiahf/vczjk/pc7;->Oooo0oO()I

    move-result v2

    invoke-static {v3, v2}, Llyiahf/vczjk/l4a;->OooOo(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    if-nez v3, :cond_0

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0, v2, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    check-cast v3, Ljava/util/List;

    invoke-interface {v3, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    invoke-static {v0}, Llyiahf/vczjk/q82;->OooO0OO(Ljava/util/LinkedHashMap;)Ljava/util/LinkedHashMap;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/q82;->OooO00o:Ljava/util/LinkedHashMap;

    iget-object p1, p0, Llyiahf/vczjk/q82;->OooO:Llyiahf/vczjk/r82;

    new-instance p2, Ljava/util/LinkedHashMap;

    invoke-direct {p2}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-interface {p3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p3

    :goto_1
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/pi5;

    iget-object v2, p1, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object v2, v2, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/rt5;

    check-cast v1, Llyiahf/vczjk/xc7;

    invoke-virtual {v1}, Llyiahf/vczjk/xc7;->Oooo0o()I

    move-result v1

    invoke-static {v2, v1}, Llyiahf/vczjk/l4a;->OooOo(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-virtual {p2, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_2

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p2, v1, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_2
    check-cast v2, Ljava/util/List;

    invoke-interface {v2, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_3
    invoke-static {p2}, Llyiahf/vczjk/q82;->OooO0OO(Ljava/util/LinkedHashMap;)Ljava/util/LinkedHashMap;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/q82;->OooO0O0:Ljava/util/LinkedHashMap;

    iget-object p1, p0, Llyiahf/vczjk/q82;->OooO:Llyiahf/vczjk/r82;

    iget-object p1, p1, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object p1, p1, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s72;

    iget-object p1, p1, Llyiahf/vczjk/s72;->OooO0OO:Llyiahf/vczjk/pp3;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p1, p0, Llyiahf/vczjk/q82;->OooO:Llyiahf/vczjk/r82;

    new-instance p2, Ljava/util/LinkedHashMap;

    invoke-direct {p2}, Ljava/util/LinkedHashMap;-><init>()V

    invoke-interface {p4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p3

    :goto_2
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    move-result p4

    if-eqz p4, :cond_5

    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p4

    move-object v0, p4

    check-cast v0, Llyiahf/vczjk/pi5;

    iget-object v1, p1, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object v1, v1, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/rt5;

    check-cast v0, Llyiahf/vczjk/jd7;

    invoke-virtual {v0}, Llyiahf/vczjk/jd7;->Oooo00O()I

    move-result v0

    invoke-static {v1, v0}, Llyiahf/vczjk/l4a;->OooOo(Llyiahf/vczjk/rt5;I)Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-virtual {p2, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_4

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p2, v0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_4
    check-cast v1, Ljava/util/List;

    invoke-interface {v1, p4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_5
    invoke-static {p2}, Llyiahf/vczjk/q82;->OooO0OO(Ljava/util/LinkedHashMap;)Ljava/util/LinkedHashMap;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/q82;->OooO0OO:Ljava/util/LinkedHashMap;

    iget-object p1, p0, Llyiahf/vczjk/q82;->OooO:Llyiahf/vczjk/r82;

    iget-object p1, p1, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object p1, p1, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s72;

    iget-object p1, p1, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance p2, Llyiahf/vczjk/o82;

    const/4 p3, 0x0

    invoke-direct {p2, p0, p3}, Llyiahf/vczjk/o82;-><init>(Llyiahf/vczjk/q82;I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/q45;->OooO0O0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/l45;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/q82;->OooO0Oo:Llyiahf/vczjk/l45;

    iget-object p1, p0, Llyiahf/vczjk/q82;->OooO:Llyiahf/vczjk/r82;

    iget-object p1, p1, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object p1, p1, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s72;

    iget-object p1, p1, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance p2, Llyiahf/vczjk/o82;

    const/4 p3, 0x1

    invoke-direct {p2, p0, p3}, Llyiahf/vczjk/o82;-><init>(Llyiahf/vczjk/q82;I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/q45;->OooO0O0(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/l45;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/q82;->OooO0o0:Llyiahf/vczjk/l45;

    iget-object p1, p0, Llyiahf/vczjk/q82;->OooO:Llyiahf/vczjk/r82;

    iget-object p1, p1, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object p1, p1, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s72;

    iget-object p1, p1, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance p2, Llyiahf/vczjk/o82;

    const/4 p3, 0x2

    invoke-direct {p2, p0, p3}, Llyiahf/vczjk/o82;-><init>(Llyiahf/vczjk/q82;I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/q45;->OooO0OO(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/r60;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/q82;->OooO0o:Llyiahf/vczjk/r60;

    iget-object p1, p0, Llyiahf/vczjk/q82;->OooO:Llyiahf/vczjk/r82;

    iget-object p2, p1, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object p2, p2, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/s72;

    iget-object p2, p2, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance p3, Llyiahf/vczjk/p82;

    const/4 p4, 0x0

    invoke-direct {p3, p0, p1, p4}, Llyiahf/vczjk/p82;-><init>(Llyiahf/vczjk/q82;Llyiahf/vczjk/r82;I)V

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Llyiahf/vczjk/o45;

    invoke-direct {p1, p2, p3}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p1, p0, Llyiahf/vczjk/q82;->OooO0oO:Llyiahf/vczjk/o45;

    iget-object p1, p0, Llyiahf/vczjk/q82;->OooO:Llyiahf/vczjk/r82;

    iget-object p2, p1, Llyiahf/vczjk/r82;->OooO0O0:Llyiahf/vczjk/u72;

    iget-object p2, p2, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/s72;

    iget-object p2, p2, Llyiahf/vczjk/s72;->OooO00o:Llyiahf/vczjk/q45;

    new-instance p3, Llyiahf/vczjk/p82;

    const/4 p4, 0x1

    invoke-direct {p3, p0, p1, p4}, Llyiahf/vczjk/p82;-><init>(Llyiahf/vczjk/q82;Llyiahf/vczjk/r82;I)V

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Llyiahf/vczjk/o45;

    invoke-direct {p1, p2, p3}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object p1, p0, Llyiahf/vczjk/q82;->OooO0oo:Llyiahf/vczjk/o45;

    return-void
.end method

.method public static OooO0OO(Ljava/util/LinkedHashMap;)Ljava/util/LinkedHashMap;
    .locals 9

    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-interface {p0}, Ljava/util/Map;->size()I

    move-result v1

    invoke-static {v1}, Llyiahf/vczjk/lc5;->o00oO0o(I)I

    move-result v1

    invoke-direct {v0, v1}, Ljava/util/LinkedHashMap;-><init>(I)V

    invoke-virtual {p0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    move-result-object p0

    check-cast p0, Ljava/lang/Iterable;

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Map$Entry;

    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v2

    new-instance v3, Ljava/io/ByteArrayOutputStream;

    invoke-direct {v3}, Ljava/io/ByteArrayOutputStream;-><init>()V

    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Iterable;

    new-instance v4, Ljava/util/ArrayList;

    const/16 v5, 0xa

    invoke-static {v1, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v5

    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/o00O0;

    invoke-interface {v5}, Llyiahf/vczjk/pi5;->getSerializedSize()I

    move-result v6

    invoke-static {v6}, Llyiahf/vczjk/n11;->OooO(I)I

    move-result v7

    add-int/2addr v7, v6

    const/16 v8, 0x1000

    if-le v7, v8, :cond_0

    move v7, v8

    :cond_0
    invoke-static {v3, v7}, Llyiahf/vczjk/n11;->OooOo0(Ljava/io/OutputStream;I)Llyiahf/vczjk/n11;

    move-result-object v7

    invoke-virtual {v7, v6}, Llyiahf/vczjk/n11;->Oooo0O0(I)V

    invoke-interface {v5, v7}, Llyiahf/vczjk/pi5;->OooO00o(Llyiahf/vczjk/n11;)V

    invoke-virtual {v7}, Llyiahf/vczjk/n11;->OooOO0o()V

    sget-object v5, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_1
    invoke-virtual {v3}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    move-result-object v1

    invoke-interface {v0, v2, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_2
    return-object v0
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;
    .locals 2

    const-string p2, "name"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p2, p0, Llyiahf/vczjk/q82;->OooO0oO:Llyiahf/vczjk/o45;

    sget-object v0, Llyiahf/vczjk/q82;->OooOO0:[Llyiahf/vczjk/th4;

    const/4 v1, 0x0

    aget-object v0, v0, v1

    invoke-static {p2, v0}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/util/Set;

    invoke-interface {p2, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_0

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1

    :cond_0
    iget-object p2, p0, Llyiahf/vczjk/q82;->OooO0Oo:Llyiahf/vczjk/l45;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/l45;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    return-object p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Ljava/util/Collection;
    .locals 2

    const-string p2, "name"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p2, p0, Llyiahf/vczjk/q82;->OooO0oo:Llyiahf/vczjk/o45;

    sget-object v0, Llyiahf/vczjk/q82;->OooOO0:[Llyiahf/vczjk/th4;

    const/4 v1, 0x1

    aget-object v0, v0, v1

    invoke-static {p2, v0}, Llyiahf/vczjk/xr6;->OooOO0o(Llyiahf/vczjk/t26;Llyiahf/vczjk/th4;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/util/Set;

    invoke-interface {p2, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_0

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1

    :cond_0
    iget-object p2, p0, Llyiahf/vczjk/q82;->OooO0o0:Llyiahf/vczjk/l45;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/l45;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    return-object p1
.end method
